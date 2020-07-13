# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2015 Reiner Herrmann <reiner@reiner-h.de>
# Copyright © 2015 Jérémy Bobbio <lunar@debian.org>
# Copyright © 2016, 2018-2019 Chris Lamb <lamby@debian.org>
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

from diffoscope.tools import tool_required
from diffoscope.difference import Difference
from diffoscope.exc import RequiredToolNotFound

from .utils.file import File
from .utils.command import Command

logger = logging.getLogger(__name__)


class ProcyonDecompiler(Command):
    TOOL = "procyon"

    def __init__(self, path, *args, **kwargs):
        super().__init__(path, *args, **kwargs)
        self.real_path = os.path.realpath(path)

    @tool_required(TOOL)
    def cmdline(self):
        return [self.TOOL, "-ec", self.path]

    def filter(self, line):
        if re.match(r"^(//)", line.decode("utf-8")):
            return b""
        return line


class Javap(Command):
    TOOL = "javap"

    def __init__(self, path, *args, **kwargs):
        super().__init__(path, *args, **kwargs)
        self.real_path = os.path.realpath(path)

    @tool_required(TOOL)
    def cmdline(self):
        return [
            self.TOOL,
            "-verbose",
            "-constants",
            "-s",
            "-l",
            "-private",
            self.path,
        ]

    def filter(self, line):
        regex = r"^(Classfile {}$|  Last modified |  MD5 checksum )".format(
            re.escape(self.real_path)
        )
        if re.match(regex, line.decode("utf-8")):
            return b""
        return line


class ClassFile(File):
    DESCRIPTION = "Java .class files"
    FILE_TYPE_RE = re.compile(r"^compiled Java class data\b")

    decompilers = [ProcyonDecompiler, Javap]

    def compare_details(self, other, source=None):
        diff = []

        for decompiler in self.decompilers:
            try:
                single_diff = Difference.from_command(
                    decompiler, self.path, other.path
                )
                if single_diff:
                    diff.append(single_diff)
                    break
            except RequiredToolNotFound:
                logger.debug(
                    "Unable to find %s. Falling back...", decompiler.TOOL,
                )

        if not diff:
            raise RequiredToolNotFound(self.decompilers[-1].TOOL)

        return diff
