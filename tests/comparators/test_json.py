# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2016 Chris Lamb <lamby@debian.org>
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
# along with diffoscope.  If not, see <http://www.gnu.org/licenses/>.

import pytest

from diffoscope.comparators.json import JSONFile

from utils import data, load_fixture

json1 = load_fixture(data('test1.json'))
json2 = load_fixture(data('test2.json'))

def test_identification(json1):
    assert isinstance(json1, JSONFile)

def test_no_differences(json1):
    assert json1.compare(json1) is None

@pytest.fixture
def differences(json1, json2):
    return json1.compare(json2).details

def test_diff(differences):
    with open(data('json_expected_diff')) as f:
        expected_diff = f.read()
    assert differences[0].unified_diff == expected_diff
