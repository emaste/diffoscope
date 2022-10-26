#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2014-2015 Jérémy Bobbio <lunar@debian.org>
# Copyright © 2015-2018, 2020, 2022 Chris Lamb <lamby@debian.org>
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

from diffoscope.exc import RequiredToolNotFound
from diffoscope.tools import tool_required
from diffoscope.difference import Difference

from .utils.file import File
from .utils.command import Command


class Showttf(Command):
    @tool_required("showttf")
    def cmdline(self):
        return ["showttf", self.path]

    def filter(self, line):
        return line.decode("latin-1").encode("utf-8")


class Ttx(Command):
    @tool_required("ttx")
    def cmdline(self):
        return ["ttx", "-o-", self.path]


class TtfFile(File):
    DESCRIPTION = "TrueType font files"
    FILE_TYPE_RE = re.compile(r"^(TrueType|OpenType) font data", re.IGNORECASE)

    def compare_details(self, other, source=None):
        xs = []

        for x in (Showttf, Ttx):
            try:
                xs.append(Difference.from_operation(x, self.path, other.path))
            except RequiredToolNotFound as exc:
                self.add_comment(exc.get_comment())

        return xs
