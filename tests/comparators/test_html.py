#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2022 Chris Lamb <lamby@debian.org>
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

from diffoscope.comparators.html import HtmlFile

from ..utils.data import assert_diff, load_fixture
from ..utils.tools import skip_unless_tools_exist


html1 = load_fixture("test1.html")
html2 = load_fixture("test2.html")


def test_identification(html1, html2):
    assert isinstance(html1, HtmlFile)
    assert isinstance(html2, HtmlFile)


def test_no_differences(html1):
    assert html1.compare(html1) is None


@pytest.fixture
def differences(html1, html2):
    return html1.compare(html2)


@skip_unless_tools_exist("html2text")
def test_diff(differences):
    assert_diff(differences, "html_expected_diff")
    assert_diff(differences.details[0], "html_text_expected_diff")
