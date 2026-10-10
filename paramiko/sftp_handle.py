# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
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
Abstraction of an SFTP file handle (for server mode).
"""

import os
from paramiko.sftp import SFTP_FAILURE, SFTP_OP_UNSUPPORTED, SFTP_OK
from paramiko.util import ClosingContextManager


class SFTPHandle(ClosingContextManager):
    """
    Abstract object representing a handle to an open file (or folder) in an
    SFTP server implementation.  Each handle has a string representation used
    by the client to refer to the underlying file.

    Server implementations can (and should) subclass SFTPHandle to implement
    features of a file handle, like `stat` or `chattr`.

    Instances of this class may be used as context managers.
    """

    def __init__(self, flags=0):
        """
        Create a new file handle representing a local file being served over
        SFTP.  If ``flags`` is passed in, it's used to determine if the file
        is open in append mode.

        :param int flags: optional flags as passed to
            `.SFTPServerInterface.open`
        """
        self.__flags = flags
        self.__name = None
        # for handles to folders: __files caches a fully materialized
        # listing, while __files_iter streams a (possibly lazy) listing
        self.__files = []
        self.__files_iter = None
        self.__tell = None

    def close(self):
        """
        When a client closes a file, this method is called on the handle.
        Normally you would use this method to close the underlying OS level
        file object(s).

        The default implementation checks for attributes on ``self`` named
        ``readfile`` and/or ``writefile``, and if either or both are present,
        their ``close()`` methods are called.  This means that if you are
        using the default implementations of `read` and `write`, this
        method's default implementation should be fine also.
        """
        readfile = getattr(self, "readfile", None)
        if readfile is not None:
            readfile.close()
        writefile = getattr(self, "writefile", None)
        if writefile is not None:
            writefile.close()
        # release any in-progress lazy directory enumeration
        self._close_files_iter()

    def read(self, offset, length):
        """
        Read up to ``length`` bytes from this file, starting at position
        ``offset``.  The offset may be a Python long, since SFTP allows it
        to be 64 bits.

        If the end of the file has been reached, this method may return an
        empty string to signify EOF, or it may also return ``SFTP_EOF``.

        The default implementation checks for an attribute on ``self`` named
        ``readfile``, and if present, performs the read operation on the Python
        file-like object found there.  (This is meant as a time saver for the
        common case where you are wrapping a Python file object.)

        :param offset: position in the file to start reading from.
        :param int length: number of bytes to attempt to read.
        :return: the `bytes` read, or an error code `int`.
        """
        readfile = getattr(self, "readfile", None)
        if readfile is None:
            return SFTP_OP_UNSUPPORTED
        try:
            if self.__tell is None:
                self.__tell = readfile.tell()
            if offset != self.__tell:
                readfile.seek(offset)
                self.__tell = offset
            data = readfile.read(length)
        except IOError as e:
            self.__tell = None
            return SFTPServer.convert_errno(e.errno)
        self.__tell += len(data)
        return data

    def write(self, offset, data):
        """
        Write ``data`` into this file at position ``offset``.  Extending the
        file past its original end is expected.  Unlike Python's normal
        ``write()`` methods, this method cannot do a partial write: it must
        write all of ``data`` or else return an error.

        The default implementation checks for an attribute on ``self`` named
        ``writefile``, and if present, performs the write operation on the
        Python file-like object found there.  The attribute is named
        differently from ``readfile`` to make it easy to implement read-only
        (or write-only) files, but if both attributes are present, they should
        refer to the same file.

        :param offset: position in the file to start reading from.
        :param bytes data: data to write into the file.
        :return: an SFTP error code like ``SFTP_OK``.
        """
        writefile = getattr(self, "writefile", None)
        if writefile is None:
            return SFTP_OP_UNSUPPORTED
        try:
            # in append mode, don't care about seeking
            if (self.__flags & os.O_APPEND) == 0:
                if self.__tell is None:
                    self.__tell = writefile.tell()
                if offset != self.__tell:
                    writefile.seek(offset)
                    self.__tell = offset
            writefile.write(data)
            writefile.flush()
        except IOError as e:
            self.__tell = None
            return SFTPServer.convert_errno(e.errno)
        if self.__tell is not None:
            self.__tell += len(data)
        return SFTP_OK

    def stat(self):
        """
        Return an `.SFTPAttributes` object referring to this open file, or an
        error code.  This is equivalent to `.SFTPServerInterface.stat`, except
        it's called on an open file instead of a path.

        :return:
            an attributes object for the given file, or an SFTP error code
            (like ``SFTP_PERMISSION_DENIED``).
        :rtype: `.SFTPAttributes` or error code
        """
        return SFTP_OP_UNSUPPORTED

    def chattr(self, attr):
        """
        Change the attributes of this file.  The ``attr`` object will contain
        only those fields provided by the client in its request, so you should
        check for the presence of fields before using them.

        :param .SFTPAttributes attr: the attributes to change on this file.
        :return: an `int` error code like ``SFTP_OK``.
        """
        return SFTP_OP_UNSUPPORTED

    # ...internals...

    def _set_files(self, files):
        """
        Used by the SFTP server code to cache a directory listing.  (In
        the SFTP protocol, listing a directory is a multi-stage process
        requiring a temporary handle.)
        """
        self.__files = files

    def _set_files_iter(self, files):
        """
        Used by the SFTP server code to attach a (possibly lazy) iterator
        of `.SFTPAttributes` to a directory handle, instead of caching a
        complete listing up front.
        """
        self.__files_iter = iter(files)

    def _close_files_iter(self):
        """
        Close a lazy directory listing iterator, running any cleanup
        (``finally`` blocks, context managers) in the underlying
        generator.  Safe to call more than once.
        """
        files_iter = self.__files_iter
        if files_iter is None:
            return
        self.__files_iter = None
        close = getattr(files_iter, "close", None)
        if close is None:
            return
        try:
            close()
        except Exception:
            # a generator may raise while unwinding (eg. from a finally
            # block); closing the handle must still succeed
            pass

    def _get_next_files(self):
        """
        Used by the SFTP server code to retrieve the next batch (up to 16
        entries) of a directory listing.

        Returns a list of `.SFTPAttributes` objects (empty when the
        listing is exhausted), or an SFTP error code `int` if a lazy
        iterator raises while producing entries.
        """
        if self.__files_iter is None:
            # cached, fully materialized listing
            fnlist = self.__files[:16]
            self.__files = self.__files[16:]
            return fnlist
        fnlist = []
        for _ in range(16):
            try:
                fnlist.append(next(self.__files_iter))
            except StopIteration:
                self._close_files_iter()
                break
            except OSError as e:
                self._close_files_iter()
                return SFTPServer.convert_errno(e.errno)
            except Exception:
                self._close_files_iter()
                return SFTP_FAILURE
        return fnlist

    def _get_name(self):
        return self.__name

    def _set_name(self, name):
        self.__name = name


from paramiko.sftp_server import SFTPServer
