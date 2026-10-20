"""Owner 1 framing regressions, using only local socket pairs."""
import json
import socket
import struct
import threading

import pytest

from securechat.protocol import (MAX_FRAME_BYTES, ProtocolError, _read_exact,
                                 canonical_json, pack_packet, recv_packet)


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    a.settimeout(2)
    b.settimeout(2)
    try:
        yield a, b
    finally:
        a.close()
        b.close()


def test_unicode_canonical_bytes_stay_compatible():
    value = {"z": "Tiếng Việt 🌸", "a": [1, True, None]}
    assert canonical_json(value) == json.dumps(value, ensure_ascii=False, sort_keys=True,
                                               separators=(",", ":")).encode("utf-8")
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_fragmented_and_coalesced_frames(pair):
    a, b = pair
    packet = {"type": "chat", "data": "Xin chào 🌸"}
    wire = pack_packet(packet)
    def write():
        for byte in wire:
            a.sendall(bytes([byte]))
        a.sendall(wire + wire)
    thread = threading.Thread(target=write)
    thread.start()
    try:
        assert [recv_packet(b) for _ in range(3)] == [packet] * 3
    finally:
        thread.join(2)
    assert not thread.is_alive()


@pytest.mark.parametrize("packet", [[], None, {}, {"type": 1}, {"type": ""},
    {"type": []}, {"type": "x", "x": float("nan")}, {"type": "x", "x": float("inf")},
    {"type": "x", "x": b"bad"}, {"type": "x", "x": {1: "value"}},
    {"type": "x", "x": "\ud800"}])
def test_invalid_outbound(packet):
    with pytest.raises(ProtocolError):
        pack_packet(packet)


@pytest.mark.parametrize("body", [b'{bad', b'[]', b'{}', b'{"type": []}',
    b'{"type":""}', b'{"type":"x","type":"y"}', b'{"type":"x","v":NaN}',
    b'{"type":"x","v":1e999}', b'{"type":"x","v":"\xff"}',
    b'{"type":"x","v":"\\ud800"}', b'{"type":"x"} trailing',
    b'{"type":"x","v":' + b'[' * 1000 + b'0' + b']' * 1000 + b'}'])
def test_invalid_inbound(pair, body):
    a, b = pair
    a.sendall(struct.pack("!I", len(body)) + body)
    with pytest.raises(ProtocolError):
        recv_packet(b)


@pytest.mark.parametrize("size", [0, 1, MAX_FRAME_BYTES + 1, 2**32 - 1])
def test_invalid_lengths(pair, size):
    a, b = pair
    a.sendall(struct.pack("!I", size))
    with pytest.raises(ProtocolError):
        recv_packet(b)


@pytest.mark.parametrize("wire", [b'', b'\x00\x00', struct.pack("!I", 20) + b'{}'])
def test_truncated_frame(pair, wire):
    a, b = pair
    a.sendall(wire)
    a.shutdown(socket.SHUT_WR)
    with pytest.raises(EOFError):
        recv_packet(b)


@pytest.mark.parametrize("size", [-1, True, 1.5, MAX_FRAME_BYTES + 1])
def test_read_size_rejected_before_socket_access(size):
    with pytest.raises(ProtocolError):
        _read_exact(None, size)


def test_exact_frame_limit_and_overflow(pair):
    packet = {"type": "x", "data": ""}
    packet["data"] = "a" * (MAX_FRAME_BYTES - len(canonical_json(packet)))
    wire = pack_packet(packet)
    assert len(wire) == MAX_FRAME_BYTES + 4
    a, b = pair
    thread = threading.Thread(target=a.sendall, args=(wire,))
    thread.start()
    try:
        assert recv_packet(b) == packet
    finally:
        thread.join(2)
    assert not thread.is_alive()
    packet["data"] += "a"
    with pytest.raises(ProtocolError):
        pack_packet(packet)


def test_cyclic_and_deep_values_rejected():
    cyclic = {"type": "x"}
    cyclic["self"] = cyclic
    with pytest.raises(ProtocolError):
        pack_packet(cyclic)


def test_socket_timeout_propagates(pair):
    _, b = pair
    b.settimeout(0.02)
    with pytest.raises(TimeoutError):
        recv_packet(b)
