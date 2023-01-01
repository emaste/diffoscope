#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2014-2015 Jérémy Bobbio <lunar@debian.org>
# Copyright © 2015-2016, 2018-2022 Chris Lamb <lamby@debian.org>
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

import logging
import os
import re

from diffoscope.tools import (
    python_module_missing,
    tool_required,
    get_package_provider,
)
from diffoscope.difference import Difference

from .utils.file import File
from .utils.command import Command

logger = logging.getLogger(__name__)

try:
    import PyPDF2

    try:
        # PyPDF 2.x
        from PyPDF2.errors import PdfReadError
    except ImportError:
        # PyPDF 1.x
        from PyPDF2.utils import PdfReadError

except ImportError:  # noqa
    python_module_missing("PyPDF2")
    PyPDF2 = None


class Pdftotext(Command):
    @tool_required("pdftotext")
    def cmdline(self):
        return ["pdftotext", self.path, "-"]


class Dumppdf(Command):
    @tool_required("dumppdf")
    def cmdline(self):
        return ["dumppdf", "-adt", self.path]


class PdfFile(File):
    DESCRIPTION = "PDF documents"
    FILE_TYPE_RE = re.compile(r"^PDF document\b")

    def compare_details(self, other, source=None):
        xs = []

        if PyPDF2 is None:
            pkg = get_package_provider("pypdf2")
            infix = f" from the '{pkg}' package " if pkg else " "
            self.add_comment(
                f"Installing the 'PyPDF2' Python module{infix}may produce a better output."
            )
        else:
            difference = Difference.from_text(
                self.dump_pypdf2_metadata(self),
                self.dump_pypdf2_metadata(other),
                self.name,
                other.name,
            )
            if difference:
                difference.add_comment("Document info")
            xs.append(difference)

            difference = Difference.from_text(
                self.dump_pypdf2_annotations(self),
                self.dump_pypdf2_annotations(other),
                self.name,
                other.name,
            )
            if difference:
                difference.add_comment("Annotations")
            xs.append(difference)

        xs.append(Difference.from_operation(Pdftotext, self.path, other.path))

        # Don't include verbose dumppdf output unless we won't see any any
        # differences without it.
        if not any(xs):
            xs.append(
                Difference.from_operation(Dumppdf, self.path, other.path)
            )

        return xs

    def dump_pypdf2_metadata(self, file):
        try:
            pdf = PyPDF2.PdfFileReader(file.path)
            document_info = pdf.getDocumentInfo()

            if document_info is None:
                return ""

            xs = []
            for k, v in sorted(document_info.items()):
                xs.append("{}: {!r}".format(k.lstrip("/"), v))

            return "\n".join(xs)
        except PdfReadError as e:
            msg = f"Could not extract PyPDF2 metadata from {os.path.basename(file.name)}: {e}"
            self.add_comment(msg)
            logger.error(msg)
            return ""

    def dump_pypdf2_annotations(self, file):
        try:
            pdf = PyPDF2.PdfFileReader(file.path)

            xs = []
            for x in range(pdf.getNumPages()):
                page = pdf.getPage(x)

                try:
                    for annot in page["/Annots"]:
                        subtype = annot.getObject()["/Subtype"]
                        if subtype == "/Text":
                            xs.append(annot.getObject()["/Contents"])
                except:
                    pass

            return "\n".join(xs)
        except PdfReadError as e:
            msg = f"Could not extract PyPDF2 annotations from {os.path.basename(file.name)}: {e}"
            file.add_comment(msg)
            logger.error(msg)
            return ""
