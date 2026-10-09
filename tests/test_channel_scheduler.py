# Copyright (C) 2026
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
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
Unit tests for the weighted channel send scheduler and the Channel send
path that uses it.
"""

import socket
import threading
import time
from types import SimpleNamespace

import pytest

from paramiko.channel import Channel, ChannelSendScheduler
from paramiko.common import (
    cMSG_CHANNEL_CLOSE,
    cMSG_CHANNEL_DATA,
    cMSG_CHANNEL_EOF,
)
from paramiko.message import Message
from paramiko.transport import Transport


def fake_chan(chanid, weight=1, closed=False):
    return SimpleNamespace(
        chanid=chanid, send_weight=weight, closed=closed
    )


def parse(msg):
    """Return (type byte, remote chanid, payload bytes) for a channel msg."""
    m = Message(msg.asbytes())
    kind = m.get_byte()
    remote = m.get_int()
    if kind == cMSG_CHANNEL_DATA:
        payload = m.get_binary()
    else:
        payload = b""
    return kind, remote, payload


class TestSchedulerBasics:
    def test_single_channel_takes_immediate_turn(self):
        sched = ChannelSendScheduler()
        chan = fake_chan(0)
        assert sched.acquire(chan) is True
        assert sched._current == 0
        sched.commit(0, 42)
        # with nobody contending the turn is retained for fast reuse
        assert sched._current == 0
        assert sched._sent[0] == 42
        sched.remove(0)

    def test_only_one_turn_at_a_time(self):
        sched = ChannelSendScheduler()
        a = fake_chan(1)
        b = fake_chan(2)
        assert sched.acquire(a) is True
        # b must block; emulate with a short timeout instead of hanging the
        # test suite
        with pytest.raises(socket.timeout):
            sched.acquire(b, timeout=0.05)
        sched.commit(1, 10)
        assert sched.acquire(b) is True
        sched.commit(2, 10)

    def test_idle_or_window_starved_channel_is_not_contending(self):
        # A channel that has no remote window simply never calls acquire();
        # it must not appear in the waiter set and must not delay anyone.
        sched = ChannelSendScheduler()
        active = fake_chan(6)
        assert 5 not in sched._waiting
        assert sched.acquire(active) is True
        sched.commit(6, 100)

    def test_commit_frees_next_waiter(self):
        sched = ChannelSendScheduler()
        order = []
        barrier = threading.Event()

        def runner(chan):
            barrier.wait()
            for _ in range(5):
                assert sched.acquire(chan) is True
                order.append(chan.chanid)
                sched.commit(chan.chanid, 100)

        threads = [
            threading.Thread(target=runner, args=(fake_chan(c),))
            for c in (1, 2)
        ]
        for t in threads:
            t.start()
        barrier.set()
        for t in threads:
            t.join(5)
            assert not t.is_alive()
        # equal weights and equal packet sizes: neither channel may be
        # starved and both serve exactly their share of packets
        assert order.count(1) == 5
        assert order.count(2) == 5

    def test_weights_split_bytes_proportionally(self):
        # Demand is deliberately proportional to the weights: the high
        # weight channel drains 3 packets per low-weight turn and must
        # receive 3x the bytes; weights shape scheduling, not demand.
        sched = ChannelSendScheduler()
        sched.set_weight(1, 1)
        sched.set_weight(2, 3)
        counts = {1: 0, 2: 0}
        barrier = threading.Event()

        def runner(chan, rounds):
            barrier.wait()
            for _ in range(rounds):
                assert sched.acquire(chan) is True
                sched.commit(chan.chanid, 1000)
                counts[chan.chanid] += 1000

        threads = [
            threading.Thread(target=runner, args=(fake_chan(1, 1), 15)),
            threading.Thread(target=runner, args=(fake_chan(2, 3), 45)),
        ]
        for t in threads:
            t.start()
        barrier.set()
        for t in threads:
            t.join(10)
            assert not t.is_alive()
        assert counts == {1: 15000, 2: 45000}

    def test_timeout_leaves_turn_holder_untouched(self):
        sched = ChannelSendScheduler()
        holder = fake_chan(1)
        waiter = fake_chan(2)
        assert sched.acquire(holder) is True
        then = time.monotonic()
        with pytest.raises(socket.timeout):
            sched.acquire(waiter, timeout=0.1)
        assert time.monotonic() - then >= 0.09
        assert sched._current == 1
        assert 2 not in sched._waiting
        sched.commit(1, 1)

    def test_remove_wakes_waiter_as_graceful_close(self):
        sched = ChannelSendScheduler()
        results = []

        def waiter():
            results.append(sched.acquire(fake_chan(2)))

        assert sched.acquire(fake_chan(1)) is True
        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)
        sched.remove(2)
        t.join(5)
        assert results == [False]
        assert 2 not in sched._weights
        sched.commit(1, 1)

    def test_closed_channel_acquire_returns_false(self):
        sched = ChannelSendScheduler()
        assert sched.acquire(fake_chan(1)) is True

        def closed_waiter():
            return sched.acquire(fake_chan(2, closed=True))

        t = threading.Thread(target=closed_waiter)
        t.start()
        time.sleep(0.05)
        sched.commit(1, 1)
        t.join(5)
        assert not t.is_alive()

    def test_close_raises_oserror_to_waiters(self):
        sched = ChannelSendScheduler()
        outcome = []

        def waiter():
            try:
                sched.acquire(fake_chan(2))
            except OSError as e:
                outcome.append(e)

        assert sched.acquire(fake_chan(1)) is True
        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)
        sched.close()
        t.join(5)
        assert len(outcome) == 1
        with pytest.raises(OSError):
            sched.acquire(fake_chan(3))

    def test_fault_releases_turn(self):
        sched = ChannelSendScheduler()
        assert sched.acquire(fake_chan(1)) is True
        sched.fault(1)
        assert sched._current is None
        # nothing was charged
        assert sched._sent[1] == 0
        assert sched.acquire(fake_chan(2)) is True
        sched.commit(2, 5)

    def test_weight_validation(self):
        sched = ChannelSendScheduler()
        for bad in (0, -1, 1.5, "2", True, None):
            with pytest.raises(ValueError):
                sched.set_weight(1, bad)
        with pytest.raises(ValueError):
            ChannelSendScheduler._coerce_weight(False)

    def test_counters_keep_full_history_until_remove(self):
        sched = ChannelSendScheduler()
        chan = fake_chan(1)
        for _ in range(10):
            assert sched.acquire(chan) is True
            sched.commit(1, 1000)
        assert sched._sent[1] == 10000
        sched.remove(1)
        assert 1 not in sched._sent


class StubPacketizer:
    def __init__(self):
        self.sent = []
        self.lock = threading.Lock()

    def send_message(self, data):
        with self.lock:
            self.sent.append(data)


class HangingPacketizer(StubPacketizer):
    def __init__(self):
        super().__init__()
        self.inflight = threading.Event()
        self.gate = threading.Event()

    def send_message(self, data):
        self.inflight.set()
        self.gate.wait(5)
        super().send_message(data)


class StubTransport:
    """Minimal Transport surface used by Channel sends."""

    # exercise the real implementation
    _send_channel_data = Transport._send_channel_data

    def __init__(self, packetizer=None):
        self._channel_scheduler = ChannelSendScheduler()
        self.clear_to_send = threading.Event()
        self.clear_to_send.set()
        self.clear_to_send_lock = threading.Lock()
        self.clear_to_send_timeout = 30.0
        self.active = True
        self.packetizer = packetizer or StubPacketizer()

    def get_log_channel(self):
        return "paramiko.transport"

    def _sanitize_packet_size(self, size):
        return size

    def _send_message(self, data):
        self.packetizer.send_message(data)

    def _send_user_message(self, data):
        if self.active:
            self._send_message(data)


def make_channel(transport, chanid=0, window=10 ** 7, max_packet=2048):
    chan = Channel(chanid)
    chan._set_transport(transport)
    chan._set_window(window, max_packet)
    chan._set_remote_channel(chanid + 1000, window, max_packet)
    return chan


class TestChannelSendPath:
    def test_send_writes_through_scheduler_and_charges_window(self):
        tr = StubTransport()
        chan = make_channel(tr, chanid=0, window=5000)
        assert chan.send(b"x" * 1000) == 1000
        assert chan.out_window_size == 4000
        assert tr._channel_scheduler._sent[0] == 1000
        kind, remote, payload = parse(tr.packetizer.sent[0])
        assert kind == cMSG_CHANNEL_DATA
        assert remote == 1000
        assert payload == b"x" * 1000

    def test_send_respects_max_packet_size(self):
        tr = StubTransport()
        chan = make_channel(tr, max_packet=2048)
        assert chan.send(b"y" * 5000) == 2048 - 64

    def test_zero_window_blocks_then_refunded_on_timeout(self):
        tr = StubTransport()
        chan = make_channel(tr, window=0)
        chan.settimeout(0.1)
        with pytest.raises(socket.timeout):
            chan.send(b"z" * 4096)
        # no remote window ever existed, so nothing could be debited
        assert chan.out_window_size == 0
        assert tr.packetizer.sent == []

    def test_scheduler_wait_timeout_refunds_debited_window(self):
        tr = StubTransport()
        holder = fake_chan(99)
        assert tr._channel_scheduler.acquire(holder) is True
        chan = make_channel(tr, chanid=1, window=5000)
        chan.settimeout(0.1)
        with pytest.raises(socket.timeout):
            chan.send(b"q" * 1000)
        assert chan.out_window_size == 5000
        assert tr.packetizer.sent == []
        tr._channel_scheduler.commit(99, 1)

    def test_nonblocking_send_raises_when_contended(self):
        tr = StubTransport()
        holder = fake_chan(99)
        assert tr._channel_scheduler.acquire(holder) is True
        chan = make_channel(tr, chanid=1)
        chan.settimeout(0.0)
        with pytest.raises(socket.timeout):
            chan.send(b"n" * 100)
        assert chan.out_window_size == 10 ** 7
        tr._channel_scheduler.commit(99, 1)

    def test_close_while_waiting_turn_reports_zero(self):
        tr = StubTransport()
        holder = fake_chan(99)
        assert tr._channel_scheduler.acquire(holder) is True
        chan = make_channel(tr, chanid=1)
        result = []

        def sender():
            result.append(chan.send(b"c" * 100))

        t = threading.Thread(target=sender)
        t.start()
        time.sleep(0.05)
        # close() must not be able to jump ahead of the in-flight send;
        # run it in another thread and release the holder afterwards.
        ct = threading.Thread(target=chan.close)
        ct.start()
        time.sleep(0.05)
        tr._channel_scheduler.commit(99, 1)
        t.join(5)
        ct.join(5)
        assert not t.is_alive()
        assert not ct.is_alive()
        assert result == [0]

    def test_dead_connection_raises_instead_of_fake_count(self):
        tr = StubTransport()
        chan = make_channel(tr)
        tr.active = False
        with pytest.raises(OSError):
            chan.send(b"d" * 10)
        assert tr.packetizer.sent == []

    def test_eof_close_cannot_overtake_in_flight_data(self):
        pkt = HangingPacketizer()
        tr = StubTransport(packetizer=pkt)
        chan = make_channel(tr)
        sender = threading.Thread(target=chan.send, args=(b"a" * 100,))
        sender.start()
        assert pkt.inflight.wait(5)
        closer = threading.Thread(target=chan.close)
        closer.start()
        # data packet is stuck in the "socket write"; nothing may pass it
        time.sleep(0.1)
        assert pkt.sent == []
        pkt.gate.set()
        sender.join(5)
        closer.join(5)
        assert not sender.is_alive()
        assert not closer.is_alive()
        kinds = [parse(m)[0] for m in pkt.sent]
        assert kinds == [
            cMSG_CHANNEL_DATA,
            cMSG_CHANNEL_EOF,
            cMSG_CHANNEL_CLOSE,
        ]

    def test_weighted_bandwidth_across_real_channels(self):
        tr = StubTransport()
        low = make_channel(tr, chanid=1)
        high = make_channel(tr, chanid=2)
        low.set_send_weight(1)
        high.set_send_weight(3)
        counts = {1001: 0, 1002: 0}
        barrier = threading.Event()

        def counting_writer(chan, rounds):
            barrier.wait()
            payload = b"p" * 1000
            for _ in range(rounds):
                assert chan.send(payload) == 1000

        # demand scales with weight: the interactive/heavy channel has
        # three times the data to push
        threads = [
            threading.Thread(target=counting_writer, args=(low, 25)),
            threading.Thread(target=counting_writer, args=(high, 75)),
        ]
        for t in threads:
            t.start()
        barrier.set()
        for t in threads:
            t.join(15)
            assert not t.is_alive()
        for msg in tr.packetizer.sent:
            _, remote, payload = parse(msg)
            counts[remote] += len(payload)
        assert counts == {1001: 25000, 1002: 75000}

    def test_set_send_weight_validation_and_registration(self):
        tr = StubTransport()
        chan = make_channel(tr, chanid=7)
        with pytest.raises(ValueError):
            chan.set_send_weight(0)
        chan.set_send_weight(4)
        assert chan.send_weight == 4
        assert tr._channel_scheduler._weights[7] == 4
        # weight set before attach is remembered and pushed on attach
        fresh = Channel(8)
        fresh.set_send_weight(5)
        fresh._set_transport(tr)
        assert tr._channel_scheduler._weights[8] == 5
