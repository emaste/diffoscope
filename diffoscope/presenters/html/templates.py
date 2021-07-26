#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2017, 2019-2021 Chris Lamb <lamby@debian.org>
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

HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="x-ua-compatible" content="IE=edge">
  <meta name="referrer" content="no-referrer" />
  <meta name="generator" content="diffoscope" />
  <link rel="icon" type="image/png" href="%(favicon)s" />
  <title>%(title)s</title>
%(css_style)s%(css_link)s</head>
<body class="diffoscope">
"""

FOOTER = """<div class="footer">
Generated by
<a href="https://diffoscope.org" rel="noopener noreferrer" target="_blank">
diffoscope</a> %(version)s
</div>
</body>
</html>
"""

STYLES = """body.diffoscope {
  background: white;
  color: black;
}
.diffoscope .footer {
  font-size: small;
}
.diffoscope .difference {
  border: outset #888 1px;
  background: #E8E8E8;
  background: rgba(0,0,0,.1);
  padding: 0.5em;
  margin: 0.5em 0;
}
.diffoscope .difference table {
  table-layout: fixed;
  width: 100%;
  border: 0;
}
.diffoscope .difference th,
.diffoscope .difference td {
  border: 0;
}
.diffoscope table.diff {
  border: 0;
  border-collapse:collapse;
  font-size:0.75em;
  font-family: 'Lucida Console', monospace;
  word-break: break-word;
}
.diffoscope table.diff tr:hover td {
  background: #FFFF00;
}
.diffoscope .line {
  color:#8080a0
}
.diffoscope th {
  background: black;
  color: white
}
.diffoscope .diffunmodified td {
  background: #D0D0E0
}
.diffoscope .diffhunk td {
  background: #A0A0A0
}
.diffoscope .diffadded td {
  background: #CCFFCC
}
.diffoscope .diffdeleted td {
  background: #FFCCCC
}
.diffoscope .diffchanged td {
  background: #FFFFA0
}
.diffoscope ins, del {
  background: #E0C880;
  text-decoration: none
}
.diffoscope .dp {
  color: #B08080
}
.diffoscope .comment {
  font-style: italic;
}
.diffoscope .comment.multiline {
  font-style: normal;
  font-family: monospace;
  white-space: pre;
}
.diffoscope .source {
  font-weight: bold;
}
.diffoscope .error {
  border: solid black 1px;
  background: red;
  color: white;
  padding: 0.2em;
}
.diffoscope .anchor {
  margin-left: 0.5em;
  font-size: 80%;
  color: #333;
  text-decoration: none;
  display: none;
}
.diffoscope .diffheader:hover .anchor {
  display: inline;
}
.diffoscope .diffcontrol, .diffoscope .diffcontrol-nochildren {
  float: left;
  margin-right: 0.3em;
  cursor: pointer;
  display: none; /* currently, only available in html-dir output where jquery is enabled */
}
.diffoscope .colines {
  width: 3em;
}
.diffoscope .coldiff {
  width: 99%;
}
.diffoscope .diffsize {
  float: right;
}
.diffoscope table.diff tr.ondemand td, .diffoscope div.ondemand-details {
  background: #f99;
  text-align: center;
  padding: 0.5em 0;
}
.diffoscope table.diff tr.ondemand:hover td, .diffoscope div.ondemand-details:hover {
  background: #faa;
  cursor: pointer;
}
"""

SCRIPTS = r"""<script src="%(jquery_url)s"></script>
<script type="text/javascript">
$(function() {
  // activate [+]/[-] controls
  var diffcontrols = $(".diffcontrol");
  $(".diffheader").on('click', function(evt) {
    var control = $(this).find(".diffcontrol");
    var parent = control.parent();
    var target = parent.siblings('table.diff, div.difference, div.comment');
    var orig = target;
    if (evt.shiftKey) {
        var gparent = parent.parent();
        target = gparent.find('table.diff, div.comment, div.difference');
        control = target.parent().not(gparent).find('.diffcontrol');
    }
    if (orig.is(":visible")) {
        target.hide();
        control.text("⊞");
    } else {
        target.show();
        control.text("⊟");
    }
  });
  diffcontrols.attr('title','shift-click to show/hide all children too.');
  diffcontrols.show();
  $(".diffcontrol-nochildren").show();
});
</script>
<style>
.diffoscope .diffheader {
  cursor: pointer;
}
.diffoscope .diffheader:hover .diffcontrol {
  color: #080;
  font-weight: bold;
}
.diffoscope .diffcontrol-double {
  line-height: 250%%;
}
</style>
"""

DIFFNODE_LAZY_LOAD = """<div class="ondemand-details" title="the size refers to the raw diff and includes all children">... <a
href="%(pagename)s.html" target="_blank">open details (total %(size)s)</a> ...</div>
"""

DIFFNODE_LIMIT = """<div class="error">Max HTML report size reached</div>
"""

UD_TABLE_HEADER = """<table class="diff">
<colgroup><col class="colines"/><col class="coldiff"/>
<col class="colines"/><col class="coldiff"/></colgroup>
<tr style="display:none;"><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>
"""

UD_TABLE_FOOTER = """<tr class="ondemand"><td colspan="4">
... <a href="%(filename)s" target="_blank">%(text)s</a> ...
</td></tr>
"""

UD_TABLE_LIMIT_FOOTER = """<tr class="error"><td colspan="4">
Max %(limit_type)s reached; %(bytes_left)s/%(bytes_total)s bytes (%(percent).2f%%) of diff not shown.
</td></tr>"""

EXPANDED_UD_HEADER = """<div class="difference">"""

EXPANDED_UD_FOOTER = """</div>"""
