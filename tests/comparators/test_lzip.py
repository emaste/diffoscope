#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2022 Christopher Baines <mail@cbaines.net>
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

import shutil
import pytest

from diffoscope.comparators.lzip import LzipFile
from diffoscope.comparators.binary import FilesystemFile
from diffoscope.comparators.utils.specialize import specialize

from ..utils.data import load_fixture, assert_diff
from ..utils.tools import skip_unless_tools_exist
from ..utils.nonexisting import assert_non_existing

lzip1 = load_fixture("test1.lzip")
lzip2 = load_fixture("test2.lzip")


def test_identification(lzip1):
    assert isinstance(lzip1, LzipFile)


def test_no_differences(lzip1):
    difference = lzip1.compare(lzip1)
    assert difference is None


@pytest.fixture
def differences(lzip1, lzip2):
    return lzip1.compare(lzip2).details


@skip_unless_tools_exist("lzip")
def test_content_source(differences):
    assert differences[0].source1 == "test1"
    assert differences[0].source2 == "test2"


@skip_unless_tools_exist("lzip")
def test_content_source_without_extension(tmpdir, lzip1, lzip2):
    path1 = str(tmpdir.join("test1"))
    path2 = str(tmpdir.join("test2"))
    shutil.copy(lzip1.path, path1)
    shutil.copy(lzip2.path, path2)
    lzip1 = specialize(FilesystemFile(path1))
    lzip2 = specialize(FilesystemFile(path2))
    difference = lzip1.compare(lzip2).details
    assert difference[0].source1 == "test1-content"
    assert difference[0].source2 == "test2-content"


@skip_unless_tools_exist("lzip")
def test_content_diff(differences):
    assert_diff(differences[0], "text_ascii_expected_diff")


@skip_unless_tools_exist("lzip")
def test_compare_non_existing(monkeypatch, lzip1):
    assert_non_existing(monkeypatch, lzip1)
