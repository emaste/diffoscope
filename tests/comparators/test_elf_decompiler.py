# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2015 Jérémy Bobbio <lunar@debian.org>
# Copyright © 2015-2019 Chris Lamb <lamby@debian.org>
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

from diffoscope.config import Config
from diffoscope.comparators.missing_file import MissingFile

from ..utils.data import load_fixture, get_data
from ..utils.tools import (
    skip_unless_tools_exist,
    skip_unless_module_exists,
    skip_unless_radare2_command_exists,
)


@pytest.fixture(scope="function", autouse=True)
def init_tests(request, monkeypatch):
    # Ignore readelf and objdump as they are already tested by test_elf.py
    monkeypatch.setattr(
        Config(), "exclude_commands", ["^readelf.*", "^objdump.*"]
    )


obj1 = load_fixture("test1.o")
obj2 = load_fixture("test2.o")


@pytest.fixture
def obj_differences(obj1, obj2):
    return obj1.compare(obj2).details


@skip_unless_tools_exist("radare2")
@skip_unless_module_exists("r2pipe")
@skip_unless_radare2_command_exists("pdgj")
def test_obj_compare_non_existing(monkeypatch, obj1):
    monkeypatch.setattr(Config(), "new_file", True)
    monkeypatch.setattr(Config(), "decompiler", "ghidra")
    difference = obj1.compare(MissingFile("/nonexisting", obj1))
    assert difference.source2 == "/nonexisting"
    assert len(difference.details) > 0


@skip_unless_tools_exist("radare2")
@skip_unless_module_exists("r2pipe")
@skip_unless_radare2_command_exists("pdgj")
def test_diff_ghidra(monkeypatch, obj1, obj2):
    monkeypatch.setattr(Config(), "decompiler", "ghidra")
    obj_differences = obj1.compare(obj2).details
    assert len(obj_differences) == 1
    expected_diff = get_data("elf_obj_ghidra_expected_diff")
    assert obj_differences[0].unified_diff == expected_diff


@skip_unless_tools_exist("radare2")
@skip_unless_module_exists("r2pipe")
def test_diff_radare2(monkeypatch, obj1, obj2):
    monkeypatch.setattr(Config(), "decompiler", "radare2")
    obj_differences = obj1.compare(obj2).details
    assert len(obj_differences) == 1
    expected_diff = get_data("elf_obj_radare2_expected_diff")
    assert obj_differences[0].unified_diff == expected_diff
