#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2021 Chris Lamb <lamby@debian.org>
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

import pytest

from diffoscope.comparators.python import PycFile

from ..utils.data import assert_diff, load_fixture


pyc1 = load_fixture("test1.pyc-renamed")
pyc2 = load_fixture("test2.pyc-renamed")


def test_identification(pyc1, pyc2):
    assert isinstance(pyc1, PycFile)
    assert isinstance(pyc2, PycFile)


def test_no_differences(pyc1):
    assert pyc1.compare(pyc1) is None


@pytest.fixture
def differences(pyc1, pyc2):
    return pyc1.compare(pyc2).details


def test_diff(differences):
    assert_diff(differences[0], "pyc_expected_diff")
