# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2016 Reiner Herrmann <reiner@reiner-h.de>
# Copyright © 2016-2020 Chris Lamb <lamby@debian.org>
#
# diffoscope is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# diffoscope is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with diffoscope.  If not, see <https://www.gnu.org/licenses/>.

import re
import os.path
import logging
import itertools
import subprocess

from diffoscope.difference import Difference
from diffoscope.tools import tool_required, find_executable
from diffoscope.tempfiles import get_temporary_directory

from .utils.file import File
from .utils.archive import Archive
from .utils.command import Command
from .utils.compare import compare_files
from .zip import ZipContainer, zipinfo_differences
from .missing_file import MissingFile

logger = logging.getLogger(__name__)


class ApkContainer(Archive):
    @property
    def path(self):
        return self._path

    @tool_required("apktool")
    @tool_required("zipinfo")
    def open_archive(self):
        self._members = []
        self._unpacked = os.path.join(
            get_temporary_directory().name, os.path.basename(self.source.name)
        )
        self._andmanifest = None
        self._andmanifest_orig = None

        logger.debug("Extracting %s to %s", self.source.name, self._unpacked)

        subprocess.check_call(
            (
                "apktool",
                "d",
                "-k",
                "-m",
                "-o",
                self._unpacked,
                self.source.path,
            ),
            stderr=None,
            stdout=subprocess.PIPE,
        )

        # Optionally extract a few files that apktool does not
        for x in ("classes.dex", "resources.arsc"):
            subprocess.call(
                ("unzip", "-d", self._unpacked, self.source.path, x),
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )

        # ... including "classes2.dex", "classes3.dex", etc.
        for x in itertools.count(2):
            try:
                subprocess.check_call(
                    (
                        "unzip",
                        "-d",
                        self._unpacked,
                        self.source.path,
                        "classes{}.dex".format(x),
                    ),
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
            except subprocess.CalledProcessError:
                break

        for root, _, files in os.walk(self._unpacked):
            current_dir = []

            for filename in files:
                abspath = os.path.join(root, filename)

                # apktool.yml is a file created by apktool and containing
                # metadata information. Rename it to clarify and always make it
                # appear at the beginning of the directory listing for
                # reproducibility.
                if filename == "apktool.yml":
                    abspath = filter_apk_metadata(
                        abspath, os.path.basename(self.source.name)
                    )
                    relpath = abspath[len(self._unpacked) + 1 :]
                    current_dir.insert(0, relpath)
                    continue

                relpath = abspath[len(self._unpacked) + 1 :]

                if filename == "AndroidManifest.xml":
                    containing_dir = root[len(self._unpacked) + 1 :]
                    if containing_dir == "original":
                        self._andmanifest_orig = relpath
                    if containing_dir == "":
                        self._andmanifest = relpath
                    continue

                current_dir.append(relpath)

            self._members.extend(current_dir)

        return self

    def get_android_manifest(self):
        return (
            self.get_member(self._andmanifest) if self._andmanifest else None
        )

    def get_original_android_manifest(self):
        if self._andmanifest_orig:
            return self.get_member(self._andmanifest_orig)
        return MissingFile("/dev/null", self._andmanifest_orig)

    def close_archive(self):
        pass

    def get_member_names(self):
        return self._members

    def extract(self, member_name, dest_dir):
        return os.path.join(self._unpacked, member_name)

    def compare_manifests(self, other):
        my_android_manifest = self.get_android_manifest()
        other_android_manifest = other.get_android_manifest()
        comment = None
        diff_manifests = None
        if my_android_manifest and other_android_manifest:
            source = "AndroidManifest.xml (decoded)"
            diff_manifests = compare_files(
                my_android_manifest, other_android_manifest, source=source
            )
            if diff_manifests is None:
                comment = "No difference found for decoded AndroidManifest.xml"
        else:
            comment = (
                "No decoded AndroidManifest.xml found "
                + "for one of the APK files."
            )
        if diff_manifests:
            return diff_manifests

        source = "AndroidManifest.xml (original / undecoded)"
        diff_manifests = compare_files(
            self.get_original_android_manifest(),
            other.get_original_android_manifest(),
            source=source,
        )
        if diff_manifests is not None:
            diff_manifests.add_comment(comment)
        return diff_manifests

    def compare(self, other, *args, **kwargs):
        differences = []
        try:
            differences.append(self.compare_manifests(other))
        except AttributeError:  # no apk-specific methods, e.g. MissingArchive
            pass
        differences.extend(super().compare(other, *args, **kwargs))
        return differences


class Apksigner(Command):
    VALID_RETURNCODES = {0, 1}

    @tool_required("apksigner")
    def cmdline(self):
        # In Debian, the `apksigner` binary is a symbolic link to the .jar file
        # itself, requiring binfmt_misc support to execute directly. We
        # therefore resolve its location and pass that to `java -jar`.
        apksigner_jar = find_executable("apksigner")

        return [
            "java",
            "-jar",
            apksigner_jar,
            "verify",
            "--verbose",
            "--print-certs",
            self.path,
        ]


class ApkFile(File):
    DESCRIPTION = "Android APK files"
    FILE_TYPE_HEADER_PREFIX = b"PK\x03\x04"
    FILE_TYPE_RE = re.compile(r"^((Java|Zip) archive data|Dalvik dex file)\b")
    FILE_EXTENSION_SUFFIX = ".apk"
    CONTAINER_CLASSES = [ApkContainer, ZipContainer]

    def compare_details(self, other, source=None):
        differences = zipinfo_differences(self, other)

        x = Difference.from_command(Apksigner, self.path, other.path)
        if x is not None:
            differences.insert(0, x)

        return differences


def filter_apk_metadata(filepath, archive_name):
    new_filename = os.path.join(os.path.dirname(filepath), "APK metadata")

    logger.debug("Moving APK metadata from %s to %s", filepath, new_filename)

    re_filename = re.compile(
        r"^apkFileName: %s" % re.escape(os.path.basename(archive_name))
    )

    with open(filepath) as in_, open(new_filename, "w") as out:
        out.writelines(x for x in in_ if not re_filename.match(x))

    os.remove(filepath)

    return new_filename
