# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2017-2020 Chris Lamb <lamby@debian.org>
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
import logging
import subprocess

from diffoscope.tools import tool_required
from diffoscope.difference import Difference

from .text import TextFile
from .utils.file import File
from .utils.command import Command, our_check_output

logger = logging.getLogger(__name__)


class Pgpdump(Command):
    @tool_required("pgpdump")
    def cmdline(self):
        return (
            "pgpdump",
            "-i",  # Dump integer packets
            "-l",  # Dump literal packets
            "-m",  # Dump marker packets
            "-p",  # Dump private packets
            "-u",  # Display UTC time
            self.path,
        )


class PgpFile(File):
    DESCRIPTION = "PGP signed/encrypted messages"
    FILE_TYPE_RE = re.compile(r"^PGP message\b")
    FALLBACK_FILE_EXTENSION_SUFFIX = {".pgp", ".asc", ".pub", ".sec", ".gpg"}

    @classmethod
    def fallback_recognizes(cls, file):
        if file.magic_file_type == "data":
            try:
                our_check_output(
                    ("pgpdump", file.path), stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                pass
            else:
                logger.debug("%s is a PGP file", file.path)
                return True

            logger.debug("%s is not a PGP file", file.path)

        return False

    def compare_details(self, other, source=None):
        return [
            Difference.from_command(
                Pgpdump, self.path, other.path, source="pgpdump"
            )
        ]


class PgpSignature(TextFile):
    DESCRIPTION = "PGP signatures"
    FILE_TYPE_RE = re.compile(r"^PGP signature\b")

    def compare(self, other, source=None):
        # Don't display signatures as hexdumps; use TextFile's comparisons...
        difference = super().compare(other, source)

        # ... but attach pgpdump of outout
        difference.add_details(
            [
                Difference.from_command(
                    Pgpdump, self.path, other.path, source="pgpdump"
                )
            ]
        )

        return difference
