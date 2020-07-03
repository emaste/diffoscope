# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2020 Jean-Romain Garnier <salsa@jean-romain.com>
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
import sys
import abc
import logging

try:
    import r2pipe
except:
    from diffoscope.tools import python_module_missing

    python_module_missing("r2pipe")
    r2pipe = None

try:
    import tlsh
except:
    tlsh = None

from .file import File
from .command import Command
from .container import Container

from diffoscope.config import Config
from diffoscope.difference import Difference
from diffoscope.excludes import command_excluded
from diffoscope.tools import tool_required, tool_check_installed

logger = logging.getLogger(__name__)


if not tool_check_installed("radare2"):
    r2pipe = None
    logger.debug("radare2 not found, disabling decompiler")


class Decompile(Command, metaclass=abc.ABCMeta):
    def __init__(self, file, *args, **kwargs):
        super().__init__(file.path, *args, **kwargs)
        self.file = file

    def start(self):
        logger.debug("Executing %s", self.cmdline())
        if not isinstance(self.file, AsmFunction):
            self._stdout = ""
            return

        self._decompile()

    def _decompile(self):
        raise NotImplementedError()

    @tool_required("radare2")
    def cmdline(self):
        # This command isn't really executed, but we want the user to be able
        # to filter it out nicely using "--exclude-command"
        if isinstance(self.file, AsmFunction):
            return [Config().decompiler, self.file.func_name]
        else:
            # Probably an AbstractMissingFile instance
            return [Config().decompiler]

    @property
    def returncode(self):
        return 0

    @property
    def stdout(self):
        return self._stdout.encode("utf-8").splitlines(True)

    @property
    def stderr(self):
        return ""


class DecompileGhidra(Decompile):
    # Remove addresses from warnings as they can create a lot of
    # irrelevant noise
    _jumptable_warning_re = re.compile(rb"(^\s*// WARNING:.*)(0x[0-9a-f]+)")

    def _run_r2_command(self):
        self.file.decompiler.jump(self.file.offset)
        output = self.file.decompiler.r2.cmdj("pdgj")

        if not output:
            # Output is None if the pdg command doesn't exist
            output = {
                "errors": [
                    'Missing r2ghidra-dec, install it with "r2pm install r2ghidra-dec"'
                ]
            }

        return output

    @tool_required("radare2")
    def _decompile(self):
        ghidra_output = self._run_r2_command()

        try:
            self._stdout = ghidra_output["code"]
        except KeyError:
            # Show errors on stdout so a failed decompilation for 1 function
            # doesn't stop the diff for the whole file
            self._stdout = "\n".join(ghidra_output["errors"])
            logger.debug(
                "r2ghidra decompiler error for %s: %s",
                self.file.signature,
                self._stdout,
            )

    def filter(self, line):
        return self._jumptable_warning_re.sub(rb"\g<1>0xX", line)


class DecompileRadare2(Decompile):
    """
    Significantly faster than the ghidra decompiler, but still outputs assembly
    code, with added comments to make it more readable
    """

    def _run_r2_command(self):
        self.file.decompiler.jump(self.file.offset)
        return self.file.decompiler.r2.cmd("pdc")

    @tool_required("radare2")
    def _decompile(self):
        self._stdout = self._run_r2_command()


class AsmFunction(File):
    DESCRIPTION = "ASM Function"

    # Mapping between the Config().decompiler option and the command class
    DECOMPILER_COMMAND_MAP = {
        "ghidra": DecompileGhidra,
        "radare2": DecompileRadare2,
    }

    def __init__(self, decompiler, data_dict):
        super().__init__(container=decompiler)
        self.data_dict = data_dict
        self.decompiler = decompiler
        self._name = self.func_name

    @property
    def name(self):
        # Multiple functions can have the same name but a different signature,
        # so use the signature as name for diffoscope
        return self.signature

    @property
    def progress_name(self):
        return "{} [{}]".format(
            self.container.source.progress_name, super().progress_name
        )

    @property
    def path(self):
        return self.container.source.path

    def is_directory(self):
        return False

    def is_symlink(self):
        return False

    def is_device(self):
        return False

    if tlsh:

        @property
        def fuzzy_hash(self):
            if not hasattr(self, "_fuzzy_hash"):
                try:
                    hex_digest = tlsh.hash(self.asm.encode())
                except ValueError:
                    # File must contain a certain amount of randomness
                    return None

                # For short files, the hex_digest is an empty string, so turn
                # it into None
                self._fuzzy_hash = hex_digest or None

            return self._fuzzy_hash

    def has_same_content_as(self, other):
        logger.debug("has_same_content: %s %s", self, other)
        try:
            return self.asm == other.asm
        except AttributeError:
            # 'other' is not a function.
            logger.debug("has_same_content: Not an asm function: %s", other)
            return False

    @classmethod
    def recognizes(cls, file):
        # No file should be recognized as an asm function
        return False

    def compare(self, other, source=None):
        command_class = self.DECOMPILER_COMMAND_MAP[Config().decompiler]
        return Difference.from_command(command_class, self, other)

    @property
    def func_name(self):
        return self.data_dict["name"]

    @property
    def offset(self):
        return self.data_dict["offset"]

    @property
    def signature(self):
        return self.data_dict["signature"]

    @property
    def asm(self):
        if not hasattr(self, "_asm"):
            ops = self.decompiler.disassemble(self.offset)
            self._asm = "\n".join([instr["disasm"] for instr in ops])

        return self._asm


class DecompilableContainer(Container):
    auto_diff_metadata = False

    # Don't use @tool_required here so subclassing DecompilableContainer
    # doesn't block the new subclass from doing its work if radare2
    # isn't installed
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug("Creating DecompileContainer for %s", self.source.path)

        self._functions = {}

        # User didn't enable decompiler
        if Config().decompiler == "none":
            return

        # If the user asked for a decompiler, but a dependency is missing,
        # warn them about it
        if r2pipe is None:
            logger.warn(
                'Missing dependency for decompiler, run "diffoscope --list-missing-tools" for a list of missing tools'
            )
            return

        # Use "-2" flag to silence radare2 warnings
        self.r2 = r2pipe.open(self.source.path, flags=["-2"])
        self.r2.cmd("aa")  # Analyse all

        # Hide offset in asm as it serves the same purpose as line numbers,
        # which shouldn't be diffed
        self.r2.cmd("e asm.offset = false")

        for f in self.r2.cmdj("aj"):
            func = AsmFunction(self, f)
            self._functions[func.signature] = func
            logger.debug("Adding function %s", func.signature)

    def cleanup(self):
        self.r2.quit()

    def get_member_names(self):
        return self._functions.keys()

    def get_member(self, member_name):
        return self._functions[member_name]

    def jump(self, offset):
        self.r2.cmd("s {}".format(offset))

    def disassemble(self, offset):
        self.jump(offset)
        return self.r2.cmdj("pdfj")["ops"]
