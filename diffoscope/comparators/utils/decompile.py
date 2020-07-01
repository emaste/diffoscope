import sys
import logging
from functools import cached_property

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

from diffoscope.tools import tool_required, tool_check_installed
from diffoscope.difference import Difference
from diffoscope.excludes import command_excluded

logger = logging.getLogger(__name__)


class AsmFunction(File):
    DESCRIPTION = "ASM Function"

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
        return Difference.from_command(Decompile, self, other)

    @property
    def func_name(self):
        return self.data_dict["name"]

    @property
    def offset(self):
        return self.data_dict["offset"]

    @property
    def signature(self):
        return self.data_dict["signature"]

    @cached_property
    def asm(self):
        ops = self.decompiler.disassemble(self.offset)
        return "\n".join([instr["disasm"] for instr in ops])


class Decompile(Command):
    def __init__(self, file, *args, **kwargs):
        super().__init__(file.path, *args, **kwargs)
        self.file = file
        self._stdout = ""
        self._stderr = ""
        self._return_code = None

    def start(self):
        logger.debug("Executing %s", self.cmdline())
        if not isinstance(self.file, AsmFunction):
            self._stdout = ""
            self._return_code = 0
            return

        ghidra_output = self.file.decompiler.decompile(self.file.offset)
        try:
            self._stdout = ghidra_output["code"].strip()
            self._return_code = 0
        except KeyError:
            self._stderr = ghidra_output["errors"]
            self._return_code = 1
            logger.debug(
                "r2ghidra decompiler error for %s: %s",
                self.file.signature,
                self.stderr,
            )

    @tool_required("radare2")
    def cmdline(self):
        # This command isn't really executed, but we want the user to be able
        # to filter it out nicely using "--exclude-command"
        if isinstance(self.file, AsmFunction):
            return ["r2ghidra", self.file.func_name]
        else:
            # Probably an AbstractMissingFile instance
            return ["r2ghidra"]

    @property
    def returncode(self):
        return self._return_code

    @property
    def stdout(self):
        return self._stdout.encode("utf-8").splitlines(True)

    @property
    def stderr(self):
        return ", ".join(self._stderr)


class DecompilableContainer(Container):
    auto_diff_metadata = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug("Creating DecompileContainer for %s", self.source.path)

        self._functions = {}

        # Don't use @tool_required here so subclassing DecompilableContainer
        # doesn't block the new subclass from doing its work if radare2
        # isn't installed
        if not tool_check_installed("radare2"):
            r2pipe = None
            logger.debug("radare2 not found, skipping")

        if r2pipe:
            # Use "-2" flag to silence radare2 warnings
            self.r2 = r2pipe.open(self.source.path, flags=["-2"])
            self.r2.cmd("aa")  # Analyse all

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

    def decompile(self, offset):
        self.jump(offset)
        return self.r2.cmdj("pdgj")
