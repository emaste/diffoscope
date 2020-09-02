# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2020 Chris Lamb <lamby@debian.org>
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

from diffoscope.tools import tool_required
from diffoscope.difference import Difference

from .utils.file import File
from .utils.command import Command


class Objdump(Command):
    @tool_required("objdump")
    def cmdline(self):
        return (
            "objdump",
            "--all-headers",
            "--disassemble-all",
            "--line-numbers",
            "--no-show-raw-insn",
            self.path,
        )

    def filter(self, line):
        if line.startswith(self.path.encode("utf-8")):
            return b""

        return line


class Pe32PlusFile(File):
    DESCRIPTION = "PE32 files"
    FILE_TYPE_RE = re.compile(r"^PE32\+")

    def compare_details(self, other, source=None):
        return [
            Difference.from_operation(
                Objdump, self.path, other.path, source="objdump"
            )
        ]
