# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2019 Chris Lamb <lamby@debian.org>
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


def format_cmdline(cmd, replace=(), truncate=None):
    def fn(x):
        if x in replace:
            return '{}'
        x = repr(x)
        if ' ' not in x:
            x = x[1:-1]
        return x

    result = ' '.join(fn(x) for x in cmd)

    if truncate is not None and len(result) > truncate:
        result = result[: truncate + 4] + " […]"

    return result
