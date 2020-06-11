# -*- coding: utf-8 -*-
#
# diffoscope: in-depth comparison of files, archives, and directories
#
# Copyright © 2017-2020 Chris Lamb <lamby@debian.org>
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

EXTERNAL_TOOLS = {
    "abootimg": {"debian": "abootimg", "guix": "abootimg"},
    "apktool": {"debian": "apktool"},
    "apksigner": {"debian": "apksigner"},
    "db_dump": {"debian": "db-util", "guix": "bdb"},
    "bsdtar": {
        "debian": "libarchive-tools",
        "arch": "libarchive",
        "fedora": "bsdtar",
        "FreeBSD": "libarchive",
        "guix": "libarchive",
    },
    "dumppdf": {"debian": "python3-pdfminer"},
    "bzip2": {"debian": "bzip2", "arch": "bzip2", "guix": "bzip2"},
    "cbfstool": {},
    "cd-iccdump": {
        "debian": "colord",
        "arch": "colord",
        "FreeBSD": "colord",
        "guix": "colord",
    },
    "cmp": {"debian": "diffutils", "arch": "diffutils", "guix": "diffutils"},
    "compare": {
        "debian": "imagemagick",
        "arch": "imagemagick",
        "guix": "imagemagick",
    },
    "cpio": {"debian": "cpio", "arch": "cpio", "guix": "cpio"},
    "diff": {"debian": "diffutils", "arch": "diffutils", "guix": "diffutils"},
    "docx2txt": {"debian": "docx2txt", "arch": "docx2txt", "guix": "docx2txt"},
    "enjarify": {"debian": "enjarify", "arch": "enjarify", "guix": "enjarify"},
    "fdtdump": {
        "debian": "device-tree-compiler",
        "arch": "dtc",
        "guix": "dtc",
    },
    "ffprobe": {"debian": "ffmpeg", "guix": "ffmpeg"},
    "file": {"debian": "file", "arch": "file", "guix": "file"},
    "find": {"debian": "findutils", "arch": "findutils", "guix": "findutils"},
    "getfacl": {"debian": "acl", "arch": "acl", "guix": "acl"},
    "gifbuild": {
        "debian": "giflib-tools",
        "arch": "giflib",
        "guix": "giflib:bin",
    },
    "ghc": {"debian": "ghc", "arch": "ghc", "FreeBSD": "ghc", "guix": "ghc"},
    "gpg": {
        "debian": "gnupg",
        "arch": "gnupg",
        "FreeBSD": "gnupg",
        "guix": "gnupg",
    },
    "gzip": {"debian": "gzip", "arch": "gzip", "guix": "gzip"},
    "h5dump": {"debian": "hdf5-tools", "arch": "hdf5", "guix": "hdf5"},
    "identify": {
        "debian": "imagemagick",
        "arch": "imagemagick",
        "guix": "imagemagick",
    },
    "img2txt": {
        "debian": "caca-utils",
        "arch": "libcaca",
        "FreeBSD": "libcaca",
        "guix": "libcaca",
    },
    "isoinfo": {
        "debian": "genisoimage",
        "arch": "cdrtools",
        "FreeBSD": "cdrtools",
        "guix": "cdrtools",
    },
    "javap": {
        "debian": "default-jdk-headless | default-jdk | java-sdk",
        "arch": "java-environment",
        "guix": "openjdk:jdk",
    },
    "js-beautify": {
        "debian": "jsbeautifier",
        "arch": "python-jsbeautifier",
        "guix": "python-jsbeautifier",
    },
    "kbxutil": {"debian": "gnupg-utils", "guix": "gnupg"},
    "llvm-bcanalyzer": {"debian": "llvm", "arch": "llvm", "guix": "llvm"},
    "llvm-config": {"debian": "llvm", "arch": "llvm"},
    "llvm-dis": {"debian": "llvm", "arch": "llvm", "guix": "llvm"},
    "ls": {"debian": "coreutils", "arch": "coreutils", "guix": "coreutils"},
    "lsattr": {
        "debian": "e2fsprogs",
        "arch": "e2fsprogs",
        "FreeBSD": "e2fsprogs",
        "guix": "e2fsprogs",
    },
    "lz4": {"debian": "lz4 | liblz4-tool", "FreeBSD": "lz4", "guix": "lz4"},
    "msgunfmt": {
        "debian": "gettext",
        "arch": "gettext",
        "FreeBSD": "gettext-tools",
        "guix": "gettext",
    },
    "convert": {
        "debian": "imagemagick",
        "arch": "imagemagick",
        "guix": "imagemagick",
    },
    "nm": {
        "debian": "binutils-multiarch",
        "arch": "binutils",
        "guix": "binutils",
    },
    "objcopy": {
        "debian": "binutils-multiarch",
        "arch": "binutils",
        "guix": "binutils",
    },
    "objdump": {
        "debian": "binutils-multiarch",
        "arch": "binutils",
        "guix": "binutils",
    },
    "ocamlobjinfo": {"debian": "ocaml-nox", "guix": "ocaml"},
    "odt2txt": {"debian": "odt2txt", "arch": "odt2txt", "guix": "odt2txt"},
    "oggDump": {"debian": "oggvideotools"},
    "openssl": {"debian": "openssl", "guix": "openssl"},
    "pgpdump": {"debian": "pgpdump", "arch": "pgpdump", "guix": "pgpdump"},
    "pdftotext": {
        "debian": "poppler-utils",
        "arch": "poppler",
        "FreeBSD": "poppler-utils",
        "guix": "poppler",
    },
    "pedump": {
        "debian": "mono-utils",
        "arch": "mono",
        "FreeBSD": "mono",
        "guix": "mono",
    },
    "ppudump": {"debian": "fp-utils", "arch": "fpc", "FreeBSD": "fpc"},
    "ps2ascii": {
        "debian": "ghostscript",
        "arch": "ghostscript",
        "FreeBSD": "ghostscript9-base",
        "guix": "ghostscript",
    },
    "readelf": {
        "debian": "binutils-multiarch",
        "arch": "binutils",
        "guix": "binutils",
    },
    "rpm2cpio": {
        "debian": "rpm2cpio",
        "arch": "rpmextract",
        "FreeBSD": "rpm2cpio",
        "guix": "rpm",
    },
    "Rscript": {"debian": "r-base-core", "arch": "r", "guix": "r-minimal"},
    "showttf": {"debian": "fontforge-extras"},
    "sng": {"debian": "sng", "guix": "sng"},
    "ssconvert": {
        "debian": "gnumeric",
        "arch": "gnumeric",
        "guix": "gnumeric",
    },
    "ssh-keygen": {
        "debian": "openssh-client",
        "arch": "openssh",
        "guix": "openssh",
    },
    "stat": {"debian": "coreutils", "arch": "coreutils", "guix": "coreutils"},
    "strings": {"debian": "binutils-multiarch"},
    "sqlite3": {
        "debian": "sqlite3",
        "arch": "sqlite",
        "FreeBSD": "sqlite3",
        "guix": "sqlite",
    },
    "wasm2wat": {"debian": "wabt", "arch": "wabt", "guix": "wabt"},
    "tar": {"debian": "tar", "arch": "tar", "guix": "tar"},
    "tcpdump": {"debian": "tcpdump", "arch": "tcpdump", "guix": "tcpdump"},
    "unsquashfs": {
        "debian": "squashfs-tools",
        "arch": "squashfs-tools",
        "FreeBSD": "squashfs-tools",
        "guix": "squashfs-tools",
    },
    "xxd": {
        "debian": "xxd | vim-common",
        "arch": "vim",
        "FreeBSD": "vim | vim-lite",
        "guix": "xxd",
    },
    "xz": {"debian": "xz-utils", "arch": "xz", "guix": "xz"},
    "zipinfo": {
        "debian": "unzip",
        "arch": "unzip",
        "FreeBSD": "unzip",
        "guix": "unzip",
    },
    "zipnote": {"debian": "zip", "guix": "zip"},
    "procyon": {"debian": "procyon-decompiler"},
    "dumpxsb": {"debian": "xmlbeans"},
    "zstd": {"debian": "zstd", "guix": "zstd"},
}

# May be populated at runtime by remapped names like
# readelf -> arm-none-eabi-readelf, etc
# diff -> gdiff, etc
REMAPPED_TOOL_NAMES = {}

# GNU programs whose names differ on some non-GNU systems such as FreeBSD etc
# AND where the CLI or output of the programs differ from the non-GNU system
# versions. In these cases, add them here and make sure you wrap uses of them
# in get_tool_name() to pick up the alternate names.
#
# If we only use POSIX CLI options and the output is identical to the system
# version (so that our tests don't break) then it's unnecessary to add it here.
GNU_TOOL_NAMES = {"diff", "readelf", "objcopy", "objdump"}
