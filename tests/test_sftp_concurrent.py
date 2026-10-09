# Copyright (C) 2026  Paramiko Engineers
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
Tests for the optional bounded-concurrency mode of the server-side SFTP
subsystem (`SFTPServer(max_concurrent_requests=...)`).
"""

import os
import shutil
import threading
import time

import pytest

from paramiko import RSAKey, SFTPServer, Transport
from paramiko.sftp import (
    CMD_ATTRS,
    CMD_DATA,
    CMD_READ,
    CMD_STAT,
    CMD_STATUS,
    CMD_WRITE,
    Message,
    int64,
)
from paramiko.sftp_client import SFTPClient
from paramiko.sftp_handle import SFTPHandle

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPHandle, StubSFTPServer
from ._util import _support, slow

FOLDER = "/paramiko-test-concurrent"
LOCAL_FOLDER = os.path.join(StubSFTPServer.ROOT, FOLDER.lstrip("/"))


class TrackingSFTPHandle(StubSFTPHandle):
    #: server-side record of ("write", offset, t) / ("close-start", t) /
    #: ("close-done", t)
    events = []

    def write(self, offset, data):
        self.events.append(("write", offset, time.monotonic()))
        if data == b"__slow__":
            time.sleep(0.3)
        return super().write(offset, data)

    def close(self):
        self.events.append(("close-start", time.monotonic()))
        super().close()
        self.events.append(("close-done", time.monotonic()))


class TrackingSFTPServer(StubSFTPServer):
    delay = 0.0
    slow_paths = frozenset()
    fail_paths = frozenset()
    in_flight = 0
    max_in_flight = 0
    counter_lock = threading.Lock()
    session_started_event = threading.Event()
    session_ended_event = threading.Event()

    def session_started(self):
        self.session_started_event.set()

    def session_ended(self):
        self.session_ended_event.set()

    def stat(self, path):
        if path in self.fail_paths:
            raise RuntimeError("boom (expected)")
        cls = type(self)
        with cls.counter_lock:
            cls.in_flight += 1
            cls.max_in_flight = max(cls.max_in_flight, cls.in_flight)
        try:
            if path in self.slow_paths:
                time.sleep(self.delay)
            return super().stat(path)
        finally:
            with cls.counter_lock:
                cls.in_flight -= 1

    def open(self, path, flags, attr):
        handle = super().open(path, flags, attr)
        if isinstance(handle, SFTPHandle):
            # swap in the tracking handle while keeping the exact internal
            # state (flags, readfile/writefile, filename, ...)
            tracked = TrackingSFTPHandle()
            tracked.__dict__.update(handle.__dict__)
            return tracked
        return handle


def _drain(client, request_numbers):
    """Read raw replies until every given request id was seen."""
    remaining = set(request_numbers)
    replies = {}
    while remaining:
        t, data = client._read_packet()
        msg = Message(data)
        num = msg.get_int()
        replies[num] = (t, msg)
        remaining.discard(num)
    return replies


@slow
class TestConcurrentSFTPServer:
    @pytest.fixture
    def session(self):
        # reset server-side state for each test
        TrackingSFTPServer.delay = 0.0
        TrackingSFTPServer.slow_paths = frozenset()
        TrackingSFTPServer.fail_paths = frozenset()
        TrackingSFTPServer.in_flight = 0
        TrackingSFTPServer.max_in_flight = 0
        TrackingSFTPServer.session_started_event = threading.Event()
        TrackingSFTPServer.session_ended_event = threading.Event()
        TrackingSFTPHandle.events = []

        shutil.rmtree(LOCAL_FOLDER, ignore_errors=True)
        os.mkdir(LOCAL_FOLDER)
        started = []

        def start(max_concurrent_requests):
            socks = LoopSocket()
            sockc = LoopSocket()
            sockc.link(socks)
            tc = Transport(sockc)
            ts = Transport(socks)
            ts.add_server_key(
                RSAKey.from_private_key_file(_support("rsa.key"))
            )
            ts.set_subsystem_handler(
                "sftp",
                SFTPServer,
                TrackingSFTPServer,
                max_concurrent_requests=max_concurrent_requests,
            )
            event = threading.Event()
            ts.start_server(event, StubServer())
            tc.connect(username="slowdive", password="pygmalion")
            assert event.wait(5.0)
            client = SFTPClient.from_transport(tc)
            started.append((tc, ts))
            assert TrackingSFTPServer.session_started_event.wait(5.0)
            return client, tc

        yield start

        for tc, ts in started:
            tc.close()
            ts.close()
        shutil.rmtree(LOCAL_FOLDER, ignore_errors=True)

    def test_independent_requests_overlap_and_reply_out_of_order(
        self, session
    ):
        # a slow request for one path must not hold up a fast, independent
        # request, and the fast reply arrives first even though the slow
        # request had the lower request id
        TrackingSFTPServer.delay = 0.3
        slow_path = FOLDER + "/slow"
        TrackingSFTPServer.slow_paths = frozenset([slow_path])
        client, _tc = session(4)
        client.open(slow_path, "w").close()

        slow_num = client._async_request(type(None), CMD_STAT, slow_path)
        fast_num = client._async_request(type(None), CMD_STAT, FOLDER)
        replies = _drain(client, [slow_num, fast_num])

        assert list(replies) == [fast_num, slow_num]
        assert replies[slow_num][0] == CMD_ATTRS
        assert replies[fast_num][0] == CMD_ATTRS
        assert TrackingSFTPServer.max_in_flight == 2

    def test_concurrency_is_bounded(self, session):
        # with a limit of 2, five slow requests run in three waves rather
        # than all at once
        TrackingSFTPServer.delay = 0.2
        paths = []
        client, _tc = session(2)
        for i in range(5):
            path = "{}/slow{}".format(FOLDER, i)
            client.open(path, "w").close()
            paths.append(path)
        TrackingSFTPServer.slow_paths = frozenset(paths)

        nums = [
            client._async_request(type(None), CMD_STAT, path) for path in paths
        ]
        start = time.monotonic()
        replies = _drain(client, nums)
        elapsed = time.monotonic() - start

        assert len(replies) == 5
        assert TrackingSFTPServer.max_in_flight == 2
        # ceil(5 / 2) waves * 0.2s = 0.6s; fully concurrent would be ~0.2s
        assert elapsed >= 0.45

    def test_same_handle_ops_stay_ordered_and_close_waits(self, session):
        client, _tc = session(4)
        f = client.open(FOLDER + "/order.bin", "w")
        TrackingSFTPHandle.events = []
        try:
            # slow write is pipelined first; close must not overtake it
            slow_num = client._async_request(
                type(None), CMD_WRITE, f.handle, int64(0), b"__slow__"
            )
            fast_num = client._async_request(
                type(None),
                CMD_WRITE,
                f.handle,
                int64(200),
                b"x" * 50,
            )
            replies = _drain(client, [slow_num, fast_num])
            for t, msg in replies.values():
                assert t == CMD_STATUS
                assert msg.get_int() == 0

            f.close()
            f = None

            events = list(TrackingSFTPHandle.events)
            writes = [
                (event[1], event[2])
                for event in events
                if event[0] == "write"
            ]
            assert [offset for offset, _t in writes] == [0, 200]
            close_start = next(
                event[1] for event in events if event[0] == "close-start"
            )
            # the close ran only after the 0.3s write had finished
            assert close_start >= writes[0][1] + 0.28
        finally:
            if f is not None:
                f.close()

        with open(os.path.join(LOCAL_FOLDER, "order.bin"), "rb") as fh:
            content = fh.read()
        assert content[:8] == b"__slow__"
        assert content[200:250] == b"x" * 50

    def test_reads_on_one_handle_return_correct_data(self, session):
        client, _tc = session(4)
        pattern = bytes((i * 7) % 256 for i in range(4096))
        path = FOLDER + "/pattern.bin"
        with client.open(path, "w") as f:
            f.write(pattern)

        f = client.open(path, "r")
        try:
            chunks = [(i * 100, 90) for i in range(40)]
            nums = [
                client._async_request(
                    type(None), CMD_READ, f.handle, int64(offset), length
                )
                for offset, length in chunks
            ]
            replies = _drain(client, nums)
            for num, (offset, length) in zip(nums, chunks):
                t, msg = replies[num]
                assert t == CMD_DATA
                assert msg.get_binary() == pattern[offset : offset + length]
        finally:
            f.close()

    def test_handler_exception_becomes_failure_and_session_continues(
        self, session
    ):
        fail_path = FOLDER + "/boom"
        TrackingSFTPServer.fail_paths = frozenset([fail_path])
        client, _tc = session(4)
        client.open(fail_path, "w").close()

        with pytest.raises(OSError):
            client.stat(fail_path)
        # the session is still alive and serves further requests
        attrs = client.stat(FOLDER)
        assert attrs is not None
        assert "boom" in client.listdir(FOLDER)

    def test_leftover_handles_closed_on_client_disconnect(self, session):
        client, tc = session(4)
        f = client.open(FOLDER + "/leftover", "w")
        f.write("still open at disconnect time")

        tc.close()

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            kinds = [event[0] for event in TrackingSFTPHandle.events]
            if (
                TrackingSFTPServer.session_ended_event.is_set()
                and "close-done" in kinds
            ):
                break
            time.sleep(0.02)
        assert TrackingSFTPServer.session_ended_event.is_set()
        assert "close-done" in [
            event[0] for event in TrackingSFTPHandle.events
        ]

    def test_disconnect_with_requests_in_flight(self, session):
        # disconnect while workers are busy and more requests are queued:
        # the session must still wind down promptly instead of hanging
        TrackingSFTPServer.delay = 0.5
        client, tc = session(2)
        paths = []
        for i in range(4):
            path = "{}/inflight{}".format(FOLDER, i)
            client.open(path, "w").close()
            paths.append(path)
        TrackingSFTPServer.slow_paths = frozenset(paths)

        for path in paths:
            client._async_request(type(None), CMD_STAT, path)
        tc.close()

        assert TrackingSFTPServer.session_ended_event.wait(5.0)
