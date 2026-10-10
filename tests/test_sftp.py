# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
some unit tests to make sure sftp works.

a real actual sftp server is contacted, and a new folder is created there to
do test file operations in (so no existing files will be harmed).
"""

import errno
import os
import shutil
import socket
import sys
import threading
import warnings
from binascii import hexlify
from io import StringIO
from tempfile import mkstemp

import pytest

from paramiko import (
    RSAKey,
    SFTP,
    SFTPHandle,
    SFTP_FAILURE,
    SFTP_PERMISSION_DENIED,
    SFTPServer,
    SFTPServerInterface,
    Transport,
)
from paramiko.common import o777, o600, o666, o644
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_HANDLE,
    CMD_NAME,
    CMD_OPENDIR,
    CMD_READDIR,
    CMD_STATUS,
)
from paramiko.sftp_attr import SFTPAttributes
from paramiko.util import b, u
from tests import requireNonAsciiLocale

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer
from ._util import _support
from ._util import needs_builtin
from ._util import slow


ARTICLE = """
Insulin sensitivity and liver insulin receptor structure in ducks from two
genera

T. Constantine, B. Chevalier, M. Derouet and J. Simon
Station de Recherches Avicoles, Institut National de la Recherche Agronomique,
Nouzilly, France.

Insulin sensitivity and liver insulin receptor structure were studied in
5-wk-old ducks from two genera (Muscovy and Pekin). In the fasting state, both
duck types were equally resistant to exogenous insulin compared with chicken.
Despite the low potency of duck insulin, the number of insulin receptors was
lower in Muscovy duck and similar in Pekin duck and chicken liver membranes.
After 125I-insulin cross-linking, the size of the alpha-subunit of the
receptors from the three species was 135,000. Wheat germ agglutinin-purified
receptors from the three species were contaminated by an active and unusual
adenosinetriphosphatase (ATPase) contaminant (highest activity in Muscovy
duck). Sequential purification of solubilized receptor from both duck types on
lentil and then wheat germ agglutinin lectins led to a fraction of receptors
very poor in ATPase activity that exhibited a beta-subunit size (95,000) and
tyrosine kinase activity similar to those of ATPase-free chicken insulin
receptors. Therefore the ducks from the two genera exhibit an alpha-beta-
structure for liver insulin receptors and a clear difference in the number of
liver insulin receptors. Their sensitivity to insulin is, however, similarly
decreased compared with chicken.
"""


# Here is how unicode characters are encoded over 1 to 6 bytes in utf-8
# U-00000000 - U-0000007F:
#   0xxxxxxx
# U-00000080 - U-000007FF:
#   110xxxxx 10xxxxxx
# U-00000800 - U-0000FFFF:
#   1110xxxx 10xxxxxx 10xxxxxx
# U-00010000 - U-001FFFFF:
#   11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
# U-00200000 - U-03FFFFFF:
#   111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
# U-04000000 - U-7FFFFFFF:
#   1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
# Note that: hex(int('11000011',2)) == '0xc3'
# Thus, the following 2-bytes sequence is not valid utf8: "invalid continuation
# byte"
NON_UTF8_DATA = b"\xC3\xC3"

unicode_folder = "\u00fcnic\u00f8de"
utf8_folder = b"/\xc3\xbcnic\xc3\xb8\x64\x65"


@slow
class TestSFTP:
    def test_file(self, sftp):
        """
        verify that we can create a file.
        """
        f = sftp.open(sftp.FOLDER + "/test", "w")
        try:
            assert f.stat().st_size == 0
        finally:
            f.close()
            sftp.remove(sftp.FOLDER + "/test")

    def test_close(self, sftp):
        """
        Verify that SFTP session close() causes a socket error on next action.
        """
        sftp.close()
        with pytest.raises(socket.error, match="Socket is closed"):
            sftp.open(sftp.FOLDER + "/test2", "w")

    def test_sftp_can_be_used_as_context_manager(self, sftp):
        """
        verify that the sftp session is closed when exiting the context manager
        """
        with sftp:
            pass
        with pytest.raises(socket.error, match="Socket is closed"):
            sftp.open(sftp.FOLDER + "/test2", "w")

    def test_write(self, sftp):
        """
        verify that a file can be created and written, and the size is correct.
        """
        try:
            with sftp.open(sftp.FOLDER + "/duck.txt", "w") as f:
                f.write(ARTICLE)
            assert sftp.stat(sftp.FOLDER + "/duck.txt").st_size == 1486
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")

    def test_sftp_file_can_be_used_as_context_manager(self, sftp):
        """
        verify that an opened file can be used as a context manager
        """
        try:
            with sftp.open(sftp.FOLDER + "/duck.txt", "w") as f:
                f.write(ARTICLE)
            assert sftp.stat(sftp.FOLDER + "/duck.txt").st_size == 1486
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")

    def test_append(self, sftp):
        """
        verify that a file can be opened for append, and tell() still works.
        """
        try:
            with sftp.open(sftp.FOLDER + "/append.txt", "w") as f:
                f.write("first line\nsecond line\n")
                assert f.tell() == 23

            with sftp.open(sftp.FOLDER + "/append.txt", "a+") as f:
                f.write("third line!!!\n")
                assert f.tell() == 37
                assert f.stat().st_size == 37
                f.seek(-26, f.SEEK_CUR)
                assert f.readline() == "second line\n"
        finally:
            sftp.remove(sftp.FOLDER + "/append.txt")

    def test_rename(self, sftp):
        """
        verify that renaming a file works.
        """
        try:
            with sftp.open(sftp.FOLDER + "/first.txt", "w") as f:
                f.write("content!\n")
            sftp.rename(
                sftp.FOLDER + "/first.txt", sftp.FOLDER + "/second.txt"
            )
            with pytest.raises(IOError, match="No such file"):
                sftp.open(sftp.FOLDER + "/first.txt", "r")
            with sftp.open(sftp.FOLDER + "/second.txt", "r") as f:
                f.seek(-6, f.SEEK_END)
                assert u(f.read(4)) == "tent"
        finally:
            # TODO: this is gross, make some sort of 'remove if possible' / 'rm
            # -f' a-like, jeez
            try:
                sftp.remove(sftp.FOLDER + "/first.txt")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/second.txt")
            except:
                pass

    def testa_posix_rename(self, sftp):
        """Test posix-rename@openssh.com protocol extension."""
        try:
            # first check that the normal rename works as specified
            with sftp.open(sftp.FOLDER + "/a", "w") as f:
                f.write("one")
            sftp.rename(sftp.FOLDER + "/a", sftp.FOLDER + "/b")
            with sftp.open(sftp.FOLDER + "/a", "w") as f:
                f.write("two")
            with pytest.raises(IOError):  # actual message seems generic
                sftp.rename(sftp.FOLDER + "/a", sftp.FOLDER + "/b")

            # now check with the posix_rename
            sftp.posix_rename(sftp.FOLDER + "/a", sftp.FOLDER + "/b")
            with sftp.open(sftp.FOLDER + "/b", "r") as f:
                data = u(f.read())
            err = "Contents of renamed file not the same as original file"
            assert "two" == data, err

        finally:
            try:
                sftp.remove(sftp.FOLDER + "/a")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/b")
            except:
                pass

    def test_folder(self, sftp):
        """
        create a temporary folder, verify that we can create a file in it, then
        remove the folder and verify that we can't create a file in it anymore.
        """
        sftp.mkdir(sftp.FOLDER + "/subfolder")
        sftp.open(sftp.FOLDER + "/subfolder/test", "w").close()
        sftp.remove(sftp.FOLDER + "/subfolder/test")
        sftp.rmdir(sftp.FOLDER + "/subfolder")
        # shouldn't be able to create that file if dir removed
        with pytest.raises(IOError, match="No such file"):
            sftp.open(sftp.FOLDER + "/subfolder/test")

    def test_listdir(self, sftp):
        """
        verify that a folder can be created, a bunch of files can be placed in
        it, and those files show up in sftp.listdir.
        """
        try:
            sftp.open(sftp.FOLDER + "/duck.txt", "w").close()
            sftp.open(sftp.FOLDER + "/fish.txt", "w").close()
            sftp.open(sftp.FOLDER + "/tertiary.py", "w").close()

            x = sftp.listdir(sftp.FOLDER)
            assert len(x) == 3
            assert "duck.txt" in x
            assert "fish.txt" in x
            assert "tertiary.py" in x
            assert "random" not in x
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")
            sftp.remove(sftp.FOLDER + "/fish.txt")
            sftp.remove(sftp.FOLDER + "/tertiary.py")

    def test_listdir_iter(self, sftp):
        """
        listdir_iter version of above test
        """
        try:
            sftp.open(sftp.FOLDER + "/duck.txt", "w").close()
            sftp.open(sftp.FOLDER + "/fish.txt", "w").close()
            sftp.open(sftp.FOLDER + "/tertiary.py", "w").close()

            x = [x.filename for x in sftp.listdir_iter(sftp.FOLDER)]
            assert len(x) == 3
            assert "duck.txt" in x
            assert "fish.txt" in x
            assert "tertiary.py" in x
            assert "random" not in x
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")
            sftp.remove(sftp.FOLDER + "/fish.txt")
            sftp.remove(sftp.FOLDER + "/tertiary.py")

    @requireNonAsciiLocale()
    def test_listdir_in_locale(self, sftp):
        """Test listdir under a locale that uses non-ascii text."""
        sftp.open(sftp.FOLDER + "/canard.txt", "w").close()
        try:
            folder_contents = sftp.listdir(sftp.FOLDER)
            assert ["canard.txt"] == folder_contents
        finally:
            sftp.remove(sftp.FOLDER + "/canard.txt")

    def test_setstat(self, sftp):
        """
        verify that the setstat functions (chown, chmod, utime, truncate) work.
        """
        try:
            with sftp.open(sftp.FOLDER + "/special", "w") as f:
                f.write("x" * 1024)

            stat = sftp.stat(sftp.FOLDER + "/special")
            sftp.chmod(sftp.FOLDER + "/special", (stat.st_mode & ~o777) | o600)
            stat = sftp.stat(sftp.FOLDER + "/special")
            expected_mode = o600
            if sys.platform == "win32":
                # chmod not really functional on windows
                expected_mode = o666
            if sys.platform == "cygwin":
                # even worse.
                expected_mode = o644
            assert stat.st_mode & o777 == expected_mode
            assert stat.st_size == 1024

            mtime = stat.st_mtime - 3600
            atime = stat.st_atime - 1800
            sftp.utime(sftp.FOLDER + "/special", (atime, mtime))
            stat = sftp.stat(sftp.FOLDER + "/special")
            assert stat.st_mtime == mtime
            if sys.platform not in ("win32", "cygwin"):
                assert stat.st_atime == atime

            # can't really test chown, since we'd have to know a valid uid.

            sftp.truncate(sftp.FOLDER + "/special", 512)
            stat = sftp.stat(sftp.FOLDER + "/special")
            assert stat.st_size == 512
        finally:
            sftp.remove(sftp.FOLDER + "/special")

    def test_fsetstat(self, sftp):
        """
        verify that the fsetstat functions (chown, chmod, utime, truncate)
        work on open files.
        """
        try:
            with sftp.open(sftp.FOLDER + "/special", "w") as f:
                f.write("x" * 1024)

            with sftp.open(sftp.FOLDER + "/special", "r+") as f:
                stat = f.stat()
                f.chmod((stat.st_mode & ~o777) | o600)
                stat = f.stat()

                expected_mode = o600
                if sys.platform == "win32":
                    # chmod not really functional on windows
                    expected_mode = o666
                if sys.platform == "cygwin":
                    # even worse.
                    expected_mode = o644
                assert stat.st_mode & o777 == expected_mode
                assert stat.st_size == 1024

                mtime = stat.st_mtime - 3600
                atime = stat.st_atime - 1800
                f.utime((atime, mtime))
                stat = f.stat()
                assert stat.st_mtime == mtime
                if sys.platform not in ("win32", "cygwin"):
                    assert stat.st_atime == atime

                # can't really test chown, since we'd have to know a valid uid.

                f.truncate(512)
                stat = f.stat()
                assert stat.st_size == 512
        finally:
            sftp.remove(sftp.FOLDER + "/special")

    def test_readline_seek(self, sftp):
        """
        create a text file and write a bunch of text into it.  then count the
        lines in the file, and seek around to retrieve particular lines.  this
        should verify that read buffering and 'tell' work well together, and
        that read buffering is reset on 'seek'.
        """
        try:
            with sftp.open(sftp.FOLDER + "/duck.txt", "w") as f:
                f.write(ARTICLE)

            with sftp.open(sftp.FOLDER + "/duck.txt", "r+") as f:
                line_number = 0
                loc = 0
                pos_list = []
                for line in f:
                    line_number += 1
                    pos_list.append(loc)
                    loc = f.tell()
                assert f.seekable()
                f.seek(pos_list[6], f.SEEK_SET)
                assert f.readline(), "Nouzilly == France.\n"
                f.seek(pos_list[17], f.SEEK_SET)
                assert f.readline()[:4] == "duck"
                f.seek(pos_list[10], f.SEEK_SET)
                expected = "duck types were equally resistant to exogenous insulin compared with chicken.\n"  # noqa
                assert f.readline() == expected
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")

    def test_write_seek(self, sftp):
        """
        Create a text file, seek back, change it, and verify.
        """
        try:
            with sftp.open(sftp.FOLDER + "/testing.txt", "w") as f:
                f.write("hello kitty.\n")
                f.seek(-5, f.SEEK_CUR)
                f.write("dd")

            assert sftp.stat(sftp.FOLDER + "/testing.txt").st_size == 13
            with sftp.open(sftp.FOLDER + "/testing.txt", "r") as f:
                data = f.read(20)
            assert data == b"hello kiddy.\n"
        finally:
            sftp.remove(sftp.FOLDER + "/testing.txt")

    def test_symlink(self, sftp):
        """
        create a symlink and then check that lstat doesn't follow it.
        """
        if not hasattr(os, "symlink"):
            # skip symlink tests on windows
            return

        try:
            with sftp.open(sftp.FOLDER + "/original.txt", "w") as f:
                f.write("original\n")
            sftp.symlink("original.txt", sftp.FOLDER + "/link.txt")
            assert sftp.readlink(sftp.FOLDER + "/link.txt") == "original.txt"

            with sftp.open(sftp.FOLDER + "/link.txt", "r") as f:
                assert f.readlines() == ["original\n"]

            cwd = sftp.normalize(".")
            if cwd[-1] == "/":
                cwd = cwd[:-1]
            abs_path = cwd + "/" + sftp.FOLDER + "/original.txt"
            sftp.symlink(abs_path, sftp.FOLDER + "/link2.txt")
            assert abs_path == sftp.readlink(sftp.FOLDER + "/link2.txt")

            assert sftp.lstat(sftp.FOLDER + "/link.txt").st_size == 12
            assert sftp.stat(sftp.FOLDER + "/link.txt").st_size == 9
            # the sftp server may be hiding extra path members from us, so the
            # length may be longer than we expect:
            assert sftp.lstat(sftp.FOLDER + "/link2.txt").st_size >= len(
                abs_path
            )
            assert sftp.stat(sftp.FOLDER + "/link2.txt").st_size == 9
            assert sftp.stat(sftp.FOLDER + "/original.txt").st_size == 9
        finally:
            try:
                sftp.remove(sftp.FOLDER + "/link.txt")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/link2.txt")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/original.txt")
            except:
                pass

    def test_flush_seek(self, sftp):
        """
        verify that buffered writes are automatically flushed on seek.
        """
        try:
            with sftp.open(sftp.FOLDER + "/happy.txt", "w", 1) as f:
                f.write("full line.\n")
                f.write("partial")
                f.seek(9, f.SEEK_SET)
                f.write("?\n")

            with sftp.open(sftp.FOLDER + "/happy.txt", "r") as f:
                assert f.readline() == u("full line?\n")
                assert f.read(7) == b"partial"
        finally:
            try:
                sftp.remove(sftp.FOLDER + "/happy.txt")
            except:
                pass

    def test_realpath(self, sftp):
        """
        test that realpath is returning something non-empty and not an
        error.
        """
        pwd = sftp.normalize(".")
        assert len(pwd) > 0
        f = sftp.normalize("./" + sftp.FOLDER)
        assert len(f) > 0
        assert os.path.join(pwd, sftp.FOLDER) == f

    def test_mkdir(self, sftp):
        """
        verify that mkdir/rmdir work.
        """
        sftp.mkdir(sftp.FOLDER + "/subfolder")
        with pytest.raises(IOError):  # generic msg only
            sftp.mkdir(sftp.FOLDER + "/subfolder")
        sftp.rmdir(sftp.FOLDER + "/subfolder")
        with pytest.raises(IOError, match="No such file"):
            sftp.rmdir(sftp.FOLDER + "/subfolder")

    def test_chdir(self, sftp):
        """
        verify that chdir/getcwd work.
        """
        root = sftp.normalize(".")
        if root[-1] != "/":
            root += "/"
        try:
            sftp.mkdir(sftp.FOLDER + "/alpha")
            sftp.chdir(sftp.FOLDER + "/alpha")
            sftp.mkdir("beta")
            assert root + sftp.FOLDER + "/alpha" == sftp.getcwd()
            assert ["beta"] == sftp.listdir(".")

            sftp.chdir("beta")
            with sftp.open("fish", "w") as f:
                f.write("hello\n")
            sftp.chdir("..")
            assert ["fish"] == sftp.listdir("beta")
            sftp.chdir("..")
            assert ["fish"] == sftp.listdir("alpha/beta")
        finally:
            sftp.chdir(root)
            try:
                sftp.unlink(sftp.FOLDER + "/alpha/beta/fish")
            except:
                pass
            try:
                sftp.rmdir(sftp.FOLDER + "/alpha/beta")
            except:
                pass
            try:
                sftp.rmdir(sftp.FOLDER + "/alpha")
            except:
                pass

    def test_get_put(self, sftp):
        """
        verify that get/put work.
        """
        warnings.filterwarnings("ignore", "tempnam.*")

        fd, localname = mkstemp()
        os.close(fd)
        text = b"All I wanted was a plastic bunny rabbit.\n"
        with open(localname, "wb") as f:
            f.write(text)
        saved_progress = []

        def progress_callback(x, y):
            saved_progress.append((x, y))

        sftp.put(localname, sftp.FOLDER + "/bunny.txt", progress_callback)

        with sftp.open(sftp.FOLDER + "/bunny.txt", "rb") as f:
            assert text == f.read(128)
        assert [(41, 41)] == saved_progress

        os.unlink(localname)
        fd, localname = mkstemp()
        os.close(fd)
        saved_progress = []
        sftp.get(sftp.FOLDER + "/bunny.txt", localname, progress_callback)

        with open(localname, "rb") as f:
            assert text == f.read(128)
        assert [(41, 41)] == saved_progress

        os.unlink(localname)
        sftp.unlink(sftp.FOLDER + "/bunny.txt")

    def test_get_without_prefetch(self, sftp):
        """
        Create a 4MB file. Verify that pull works without prefetching
        using a lager file.
        """

        sftp_filename = sftp.FOLDER + "/dummy_file"
        num_chars = 1024 * 1024 * 4

        fd, localname = mkstemp()
        os.close(fd)

        with open(localname, "wb") as f:
            f.write(b"0" * num_chars)

        sftp.put(localname, sftp_filename)

        os.unlink(localname)
        fd, localname = mkstemp()
        os.close(fd)

        sftp.get(sftp_filename, localname, prefetch=False)

        assert os.stat(localname).st_size == num_chars

        os.unlink(localname)
        sftp.unlink(sftp_filename)

    def test_check(self, sftp):
        """
        verify that file.check() works against our own server.
        (it's an sftp extension that we support, and may be the only ones who
        support it.)
        """
        with sftp.open(sftp.FOLDER + "/kitty.txt", "w") as f:
            f.write("here kitty kitty" * 64)

        try:
            with sftp.open(sftp.FOLDER + "/kitty.txt", "r") as f:
                sum = f.check("sha1")
                assert (
                    "91059CFC6615941378D413CB5ADAF4C5EB293402"
                    == u(hexlify(sum)).upper()
                )
                sum = f.check("md5", 0, 512)
                assert (
                    "93DE4788FCA28D471516963A1FE3856A"
                    == u(hexlify(sum)).upper()
                )
                sum = f.check("md5", 0, 0, 510)
                expected = "EB3B45B8CD55A0707D99B177544A319F373183D241432BB2157AB9E46358C4AC90370B5CADE5D90336FC1716F90B36D6"  # noqa
                assert u(hexlify(sum)).upper() == expected
        finally:
            sftp.unlink(sftp.FOLDER + "/kitty.txt")

    def test_x_flag(self, sftp):
        """
        verify that the 'x' flag works when opening a file.
        """
        sftp.open(sftp.FOLDER + "/unusual.txt", "wx").close()

        try:
            with pytest.raises(IOError):
                sftp.open(sftp.FOLDER + "/unusual.txt", "wx")
        finally:
            sftp.unlink(sftp.FOLDER + "/unusual.txt")

    def test_utf8(self, sftp):
        """
        verify that unicode strings are encoded into utf8 correctly.
        """
        with sftp.open(sftp.FOLDER + "/something", "w") as f:
            f.write("okay")
        try:
            sftp.rename(
                sftp.FOLDER + "/something", sftp.FOLDER + "/" + unicode_folder
            )
            sftp.open(b(sftp.FOLDER) + utf8_folder, "r")
        finally:
            sftp.unlink(b(sftp.FOLDER) + utf8_folder)

    def test_utf8_chdir(self, sftp):
        sftp.mkdir(sftp.FOLDER + "/" + unicode_folder)
        try:
            sftp.chdir(sftp.FOLDER + "/" + unicode_folder)
            with sftp.open("something", "w") as f:
                f.write("okay")
            sftp.unlink("something")
        finally:
            sftp.chdir()
            sftp.rmdir(sftp.FOLDER + "/" + unicode_folder)

    def test_bad_readv(self, sftp):
        """
        verify that readv at the end of the file doesn't essplode.
        """
        sftp.open(sftp.FOLDER + "/zero", "w").close()
        try:
            with sftp.open(sftp.FOLDER + "/zero", "r") as f:
                f.readv([(0, 12)])

            with sftp.open(sftp.FOLDER + "/zero", "r") as f:
                file_size = f.stat().st_size
                f.prefetch(file_size)
                f.read(100)
        finally:
            sftp.unlink(sftp.FOLDER + "/zero")

    def test_put_without_confirm(self, sftp):
        """
        verify that get/put work without confirmation.
        """
        warnings.filterwarnings("ignore", "tempnam.*")

        fd, localname = mkstemp()
        os.close(fd)
        text = b"All I wanted was a plastic bunny rabbit.\n"
        with open(localname, "wb") as f:
            f.write(text)
        saved_progress = []

        def progress_callback(x, y):
            saved_progress.append((x, y))

        res = sftp.put(
            localname, sftp.FOLDER + "/bunny.txt", progress_callback, False
        )

        assert SFTPAttributes().attr == res.attr

        with sftp.open(sftp.FOLDER + "/bunny.txt", "r") as f:
            assert text == f.read(128)
        assert (41, 41) == saved_progress[-1]

        os.unlink(localname)
        sftp.unlink(sftp.FOLDER + "/bunny.txt")

    def test_getcwd(self, sftp):
        """
        verify that chdir/getcwd work.
        """
        assert sftp.getcwd() is None
        root = sftp.normalize(".")
        if root[-1] != "/":
            root += "/"
        try:
            sftp.mkdir(sftp.FOLDER + "/alpha")
            sftp.chdir(sftp.FOLDER + "/alpha")
            assert sftp.getcwd() == "/" + sftp.FOLDER + "/alpha"
        finally:
            sftp.chdir(root)
            try:
                sftp.rmdir(sftp.FOLDER + "/alpha")
            except:
                pass

    def test_seek_append(self, sftp):
        """
        verify that seek doesn't affect writes during append.

        does not work except through paramiko.  :(  openssh fails.
        """
        try:
            with sftp.open(sftp.FOLDER + "/append.txt", "a") as f:
                f.write("first line\nsecond line\n")
                f.seek(11, f.SEEK_SET)
                f.write("third line\n")

            with sftp.open(sftp.FOLDER + "/append.txt", "r") as f:
                assert f.stat().st_size == 34
                assert f.readline() == "first line\n"
                assert f.readline() == "second line\n"
                assert f.readline() == "third line\n"
        finally:
            sftp.remove(sftp.FOLDER + "/append.txt")

    def test_putfo_empty_file(self, sftp):
        """
        Send an empty file and confirm it is sent.
        """
        target = sftp.FOLDER + "/empty file.txt"
        stream = StringIO()
        try:
            attrs = sftp.putfo(stream, target)
            # the returned attributes should not be null
            assert attrs is not None
        finally:
            sftp.remove(target)

    # TODO: this test doesn't actually fail if the regression (removing '%'
    # expansion to '%%' within sftp.py's def _log()) is removed - stacktraces
    # appear but they're clearly emitted from subthreads that have no error
    # handling. No point running it until that is fixed somehow.
    @pytest.mark.skip("Doesn't prove anything right now")
    def test_file_with_percent(self, sftp):
        """
        verify that we can create a file with a '%' in the filename.
        ( it needs to be properly escaped by _log() )
        """
        f = sftp.open(sftp.FOLDER + "/test%file", "w")
        try:
            assert f.stat().st_size == 0
        finally:
            f.close()
            sftp.remove(sftp.FOLDER + "/test%file")

    def test_non_utf8_data(self, sftp):
        """Test write() and read() of non utf8 data"""
        try:
            with sftp.open(f"{sftp.FOLDER}/nonutf8data", "w") as f:
                f.write(NON_UTF8_DATA)
            with sftp.open(f"{sftp.FOLDER}/nonutf8data", "r") as f:
                data = f.read()
            assert data == NON_UTF8_DATA
            with sftp.open(f"{sftp.FOLDER}/nonutf8data", "wb") as f:
                f.write(NON_UTF8_DATA)
            with sftp.open(f"{sftp.FOLDER}/nonutf8data", "rb") as f:
                data = f.read()
            assert data == NON_UTF8_DATA
        finally:
            sftp.remove(f"{sftp.FOLDER}/nonutf8data")

    @requireNonAsciiLocale("LC_TIME")
    def test_sftp_attributes_locale_time(self, sftp):
        """Test SFTPAttributes under a locale with non-ascii time strings."""
        some_stat = os.stat(sftp.FOLDER)
        sftp_attributes = SFTPAttributes.from_stat(some_stat, u("a_directory"))
        assert b"a_directory" in sftp_attributes.asbytes()

    def test_sftp_attributes_empty_str(self, sftp):
        sftp_attributes = SFTPAttributes()
        assert (
            str(sftp_attributes)
            == "?---------   1 0        0               0 (unknown date) ?"
        )

    @needs_builtin("buffer")
    def test_write_buffer(self, sftp):
        """Test write() using a buffer instance."""
        data = 3 * b"A potentially large block of data to chunk up.\n"
        try:
            with sftp.open(f"{sftp.FOLDER}/write_buffer", "wb") as f:
                for offset in range(0, len(data), 8):
                    f.write(buffer(data, offset, 8))  # noqa

            with sftp.open(f"{sftp.FOLDER}/write_buffer", "rb") as f:
                assert f.read() == data
        finally:
            sftp.remove(f"{sftp.FOLDER}/write_buffer")

    @needs_builtin("memoryview")
    def test_write_memoryview(self, sftp):
        """Test write() using a memoryview instance."""
        data = 3 * b"A potentially large block of data to chunk up.\n"
        try:
            with sftp.open(f"{sftp.FOLDER}/write_memoryview", "wb") as f:
                view = memoryview(data)
                for offset in range(0, len(data), 8):
                    f.write(view[offset : offset + 8])

            with sftp.open(f"{sftp.FOLDER}/write_memoryview", "rb") as f:
                assert f.read() == data
        finally:
            sftp.remove(f"{sftp.FOLDER}/write_memoryview")


def _named_attr(name):
    attr = SFTPAttributes()
    attr.filename = name
    return attr


class TestSFTPHandleLazyFiles:
    """
    Unit tests for iterator-backed (lazy) directory handles, without a
    network connection.
    """

    def test_batches_of_16_then_eof(self):
        handle = SFTPHandle()
        closed = []

        def generate():
            try:
                for i in range(40):
                    yield _named_attr(f"f{i}")
            finally:
                closed.append(True)

        handle._set_files_iter(generate())
        batches = [handle._get_next_files() for _ in range(3)]
        assert [len(x) for x in batches] == [16, 16, 8]
        assert [a.filename for a in batches[0]] == [
            f"f{i}" for i in range(16)
        ]
        # exhausted listing stays at EOF, and the generator was released
        assert handle._get_next_files() == []
        assert handle._get_next_files() == []
        assert closed == [True]

    def test_close_stops_unconsumed_enumeration(self):
        handle = SFTPHandle()
        yielded = []
        closed = []

        def generate():
            try:
                for i in range(40):
                    yielded.append(i)
                    yield _named_attr(f"f{i}")
            finally:
                closed.append(True)

        handle._set_files_iter(generate())
        assert len(handle._get_next_files()) == 16
        handle.close()
        assert closed == [True]
        # the generator stopped at the first batch, and reads now hit EOF
        assert yielded == list(range(16))
        assert handle._get_next_files() == []

    def test_close_without_any_reads(self):
        # a generator whose body never started (no READDIR) is closed as a
        # no-op by Python; acquire resources *inside* the generator and
        # nothing has been opened yet at this point
        handle = SFTPHandle()
        started = []

        def generate():
            started.append(True)
            try:
                yield _named_attr("f0")
            finally:
                started.append(False)

        handle._set_files_iter(generate())
        handle.close()
        assert started == []
        assert handle._get_next_files() == []

    def test_oserror_becomes_sftp_status(self):
        handle = SFTPHandle()
        closed = []

        def generate():
            try:
                for i in range(17):
                    yield _named_attr(f"f{i}")
                raise OSError(errno.EACCES, "denied")
            finally:
                closed.append(True)

        handle._set_files_iter(generate())
        first = handle._get_next_files()
        assert [a.filename for a in first] == [f"f{i}" for i in range(16)]
        # the next batch hits the error and reports a status code
        assert handle._get_next_files() == SFTP_PERMISSION_DENIED
        assert closed == [True]
        # enumeration is over: subsequent reads just hit EOF
        assert handle._get_next_files() == []

    def test_generic_exception_becomes_failure(self):
        handle = SFTPHandle()

        def generate():
            for i in range(17):
                yield _named_attr(f"f{i}")
            raise RuntimeError("boom")

        handle._set_files_iter(generate())
        assert len(handle._get_next_files()) == 16
        assert handle._get_next_files() == SFTP_FAILURE
        assert handle._get_next_files() == []

    def test_close_swallows_exception_from_generator_teardown(self):
        handle = SFTPHandle()

        def generate():
            try:
                yield _named_attr("f0")
            finally:
                raise RuntimeError("boom during GeneratorExit")

        handle._set_files_iter(generate())
        handle._get_next_files()
        # closing the handle must succeed even if the generator raises
        # while unwinding
        handle.close()
        assert handle._get_next_files() == []

    def test_handles_are_independent(self):
        handle_a = SFTPHandle()
        handle_b = SFTPHandle()

        def generate(prefix):
            for i in range(20):
                yield _named_attr(f"{prefix}{i}")

        handle_a._set_files_iter(generate("a"))
        handle_b._set_files_iter(generate("b"))

        batch_a = handle_a._get_next_files()
        batch_b = handle_b._get_next_files()
        assert [x.filename for x in batch_a] == [f"a{i}" for i in range(16)]
        assert [x.filename for x in batch_b] == [f"b{i}" for i in range(16)]

        # closing B early does not affect A's position
        handle_b.close()
        rest_a = handle_a._get_next_files()
        assert [x.filename for x in rest_a] == [
            f"a{i}" for i in range(16, 20)
        ]
        assert handle_a._get_next_files() == []

    def test_legacy_materialized_list_still_works(self):
        handle = SFTPHandle()
        handle._set_files([_named_attr(f"f{i}") for i in range(40)])
        assert len(handle._get_next_files()) == 16
        assert len(handle._get_next_files()) == 16
        assert len(handle._get_next_files()) == 8
        assert handle._get_next_files() == []


class TestListFolderIterDefault:
    """
    The default list_folder_iter() must preserve list_folder()-based
    implementations: lists become iterators, error codes pass through.
    """

    def test_wraps_returned_list(self):
        attrs = [_named_attr("f0"), _named_attr("f1")]

        class Iface(SFTPServerInterface):
            def list_folder(self, path):
                return attrs

        assert list(Iface(None).list_folder_iter("/p")) == attrs

    def test_passes_error_code_through(self):
        class Iface(SFTPServerInterface):
            def list_folder(self, path):
                return SFTP_PERMISSION_DENIED

        assert Iface(None).list_folder_iter("/p") == SFTP_PERMISSION_DENIED


class _RecordingLazySFTPServer(StubSFTPServer):
    """
    Loopback SFTP interface that streams listings from a generator (using
    os.scandir), with knobs for failure injection and class-level recording
    of generator cleanup via try/finally.
    """

    closed = []
    fail_after = None
    open_error = None
    list_folder_calls = 0

    def list_folder(self, path):
        type(self).list_folder_calls += 1
        return super().list_folder(path)

    def list_folder_iter(self, path):
        realpath = self._realpath(path)
        cls = type(self)
        if cls.open_error is not None:
            error = cls.open_error
            cls.open_error = None
            return error

        def generate():
            try:
                # sorting keeps on-disk entry order irrelevant to batch
                # assertions, while scandir stays open across yields so the
                # early-close path really releases an OS resource
                with os.scandir(realpath) as entries:
                    ordered = sorted(entries, key=lambda entry: entry.name)
                    for index, entry in enumerate(ordered):
                        if (
                            cls.fail_after is not None
                            and index >= cls.fail_after
                        ):
                            raise OSError(errno.EIO, "synthetic failure")
                        attr = SFTPAttributes.from_stat(
                            entry.stat(follow_symlinks=False)
                        )
                        attr.filename = entry.name
                        yield attr
            finally:
                cls.closed.append(realpath)

        return generate()


LAZY_FOLDER = "paramiko-lazy-test-target"


@pytest.fixture
def lazy_sftp():
    # reset recording/knobs on the interface class
    _RecordingLazySFTPServer.closed = []
    _RecordingLazySFTPServer.fail_after = None
    _RecordingLazySFTPServer.open_error = None
    _RecordingLazySFTPServer.list_folder_calls = 0

    shutil.rmtree(LAZY_FOLDER, ignore_errors=True)
    os.mkdir(LAZY_FOLDER)

    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    ts.add_server_key(RSAKey.from_private_key_file(_support("rsa.key")))
    event = threading.Event()
    ts.set_subsystem_handler("sftp", SFTPServer, _RecordingLazySFTPServer)
    ts.start_server(event, StubServer())
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    client = SFTP.from_transport(tc)
    yield client
    client.close()
    tc.close()
    ts.close()
    shutil.rmtree(LAZY_FOLDER, ignore_errors=True)


def _server_realpath(*parts):
    return os.path.join(StubSFTPServer.ROOT, LAZY_FOLDER, *parts)


def _names_from_readdir_reply(msg):
    count = msg.get_int()
    names = set()
    for _ in range(count):
        names.add(msg.get_text())
        msg.get_text()  # longname
        SFTPAttributes._from_msg(msg)
    return names


@slow
class TestLazySFTPListing:
    """
    End-to-end (loopback SFTP) tests for streaming directory enumeration.
    """

    def _make_files(self, subdir=None, count=20, prefix="file"):
        target = (
            LAZY_FOLDER if subdir is None else f"{LAZY_FOLDER}/{subdir}"
        )
        os.makedirs(target, exist_ok=True)
        for i in range(count):
            with open(f"{target}/{prefix}{i:03d}", "w"):
                pass
        return target

    def test_full_streaming_listing(self, lazy_sftp):
        # more than one 16-entry batch, so multiple READDIR round trips
        self._make_files(count=40)
        names = lazy_sftp.listdir(LAZY_FOLDER)
        assert sorted(names) == sorted(f"file{i:03d}" for i in range(40))
        # the streaming hook served the listing; list_folder() was never
        # forced to build the complete list
        assert _RecordingLazySFTPServer.list_folder_calls == 0
        # consuming to EOF released the enumerator exactly once
        assert _RecordingLazySFTPServer.closed == [_server_realpath()]

    def test_early_client_close_releases_enumerator(self, lazy_sftp):
        self._make_files(count=40)
        t, msg = lazy_sftp._request(CMD_OPENDIR, LAZY_FOLDER)
        assert t == CMD_HANDLE
        handle = msg.get_binary()
        try:
            t, msg = lazy_sftp._request(CMD_READDIR, handle)
            assert t == CMD_NAME
            assert msg.get_int() == 16
            # 24 entries are still unread; the generator is merely suspended
            assert _RecordingLazySFTPServer.closed == []
        finally:
            t, msg = lazy_sftp._request(CMD_CLOSE, handle)
        assert t == CMD_STATUS
        # client CLOSE before EOF runs the generator's finally cleanup
        assert _RecordingLazySFTPServer.closed == [_server_realpath()]

    def test_failure_mid_listing(self, lazy_sftp):
        self._make_files(count=40)
        _RecordingLazySFTPServer.fail_after = 5
        t, msg = lazy_sftp._request(CMD_OPENDIR, LAZY_FOLDER)
        assert t == CMD_HANDLE
        handle = msg.get_binary()
        # the batch dies producing entry #6: failure status, and the
        # partially built batch is not sent
        with pytest.raises(IOError):
            lazy_sftp._request(CMD_READDIR, handle)
        # the dying enumerator is released immediately
        assert _RecordingLazySFTPServer.closed == [_server_realpath()]
        # the handle is still valid and closes cleanly afterwards
        t, msg = lazy_sftp._request(CMD_CLOSE, handle)
        assert t == CMD_STATUS
        # close after failure must not re-enter the dead generator
        assert _RecordingLazySFTPServer.closed == [_server_realpath()]

    def test_error_opening_directory(self, lazy_sftp):
        self._make_files(count=3)
        _RecordingLazySFTPServer.open_error = SFTP_PERMISSION_DENIED
        with pytest.raises(PermissionError):
            lazy_sftp.listdir(LAZY_FOLDER)
        # no enumerator was ever created
        assert _RecordingLazySFTPServer.closed == []

    def test_concurrent_open_directories_are_independent(self, lazy_sftp):
        self._make_files(subdir="a", count=20, prefix="a")
        self._make_files(subdir="b", count=20, prefix="b")
        t, msg_a = lazy_sftp._request(CMD_OPENDIR, f"{LAZY_FOLDER}/a")
        assert t == CMD_HANDLE
        handle_a = msg_a.get_binary()
        t, msg_b = lazy_sftp._request(CMD_OPENDIR, f"{LAZY_FOLDER}/b")
        assert t == CMD_HANDLE
        handle_b = msg_b.get_binary()
        try:
            _, reply_a = lazy_sftp._request(CMD_READDIR, handle_a)
            _, reply_b = lazy_sftp._request(CMD_READDIR, handle_b)
            first_a = _names_from_readdir_reply(reply_a)
            first_b = _names_from_readdir_reply(reply_b)
            assert first_a == {f"a{i:03d}" for i in range(16)}
            assert first_b == {f"b{i:03d}" for i in range(16)}

            # stop B early; A must keep its position and remain readable
            t, _ = lazy_sftp._request(CMD_CLOSE, handle_b)
            assert t == CMD_STATUS
            handle_b = None

            seen_a = set(first_a)
            while True:
                try:
                    _, reply = lazy_sftp._request(CMD_READDIR, handle_a)
                except EOFError:
                    break
                seen_a |= _names_from_readdir_reply(reply)
            assert seen_a == {f"a{i:03d}" for i in range(20)}
        finally:
            if handle_b is not None:
                lazy_sftp._request(CMD_CLOSE, handle_b)
            lazy_sftp._request(CMD_CLOSE, handle_a)

        assert set(_RecordingLazySFTPServer.closed) == {
            _server_realpath("a"),
            _server_realpath("b"),
        }
