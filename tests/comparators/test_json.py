#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2016-2017, 2020, 2022 Chris Lamb <lamby@debian.org>
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

from diffoscope.comparators.json import JSONFile

from ..utils.data import load_fixture, assert_diff
from ..utils.nonexisting import assert_non_existing


json1 = load_fixture("test1.json")
json2 = load_fixture("test2.json")
json3a = load_fixture("order1a.json")
json3b = load_fixture("order1b.json")
invalid_json = load_fixture("test_invalid.json")


def test_identification(json1):
    assert isinstance(json1, JSONFile)


def test_invalid(invalid_json):
    assert not isinstance(invalid_json, JSONFile)


def test_no_differences(json1):
    assert json1.compare(json1) is None


@pytest.fixture
def differences(json1, json2):
    return json1.compare(json2).details


def test_diff(differences):
    assert_diff(differences[0], "json_expected_diff")


def test_compare_non_existing(monkeypatch, json1):
    assert_non_existing(monkeypatch, json1)


def test_ordering_differences(json3a, json3b):
    diff = json3a.compare(json3b)
    assert diff.details[0].comments == ["Ordering differences only"]
    assert_diff(diff.details[0], "json_expected_ordering_diff")
