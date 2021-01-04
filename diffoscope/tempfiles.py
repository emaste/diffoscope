#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2016-2020 Chris Lamb <lamby@debian.org>
# Copyright © 2018 Mattia Rizzolo <mattia@debian.org>
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

import os
import logging
import tempfile

_BASEDIR = None
_FILES = []

logger = logging.getLogger(__name__)


def get_named_temporary_file(*args, **kwargs):
    kwargs["dir"] = kwargs.pop("dir", _get_base_temporary_directory())

    f = tempfile.NamedTemporaryFile(*args, **kwargs)
    _FILES.append(f.name)

    return f


def get_temporary_directory(*args, **kwargs):
    """
    Create and return a TemporaryDirectory

    Preferably use a "with" statement to control its lifetime:
        with get_temporary_directory() as tmpdir:

    The temporary directory is cleaned up at the end of the "with"
    statement. Otherwise it's cleaned up when the object is garbage collected.

    WARNING, don't do this:
        tmpdir = get_temporary_directory().name

    This will result to immediate removal of the directory, as there is no
    reference pointing to the TemporaryDirectory object.
    """
    kwargs["dir"] = kwargs.pop("dir", _get_base_temporary_directory())

    d = tempfile.TemporaryDirectory(*args, **kwargs)

    return d


def clean_all_temp_files():
    logger.debug("Cleaning %d temp files", len(_FILES))

    for x in _FILES:
        try:
            os.unlink(x)
        except FileNotFoundError:
            pass
        except:  # noqa
            logger.exception("Unable to delete %s", x)
    _FILES.clear()


def _get_base_temporary_directory():
    global _BASEDIR
    if _BASEDIR is None:
        _BASEDIR = tempfile.TemporaryDirectory(
            dir=tempfile.gettempdir(), prefix="diffoscope_"
        )
        logger.debug(
            "Created top-level temporary directory: %s", _BASEDIR.name
        )

    return _BASEDIR.name


def get_tempdir_free_space():
    """
    unsigned long f_frsize   Fundamental file system block size.
    fsblkcnt_t    f_blocks   Total number of blocks on file system in units of f_frsize.
    fsblkcnt_t    f_bfree    Total number of free blocks.
    fsblkcnt_t    f_bavail   Number of free blocks available to
                             non-privileged process.
    """
    statvfs = os.statvfs(tempfile.gettempdir())

    return statvfs.f_frsize * statvfs.f_bavail
