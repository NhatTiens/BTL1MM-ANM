import socket
import struct

import pytest

from securechat.protocol import ProtocolError, pack_packet, recv_packet, send_packet


def test_frame_roundtrip():
    a, b = socket.socketpair()
    try:
        send_packet(a, {"type": "chat", "ciphertext": "not_plaintext", "seq": 1})
        assert recv_packet(b) == {"type": "chat", "ciphertext": "not_plaintext", "seq": 1}
    finally:
        a.close()
        b.close()


def test_bad_frame_length_is_rejected():
    a, b = socket.socketpair()
    try:
        a.sendall(struct.pack("!I", 99999999))
        with pytest.raises(ProtocolError):
            recv_packet(b)
    finally:
        a.close()
        b.close()


def test_requires_type_and_size_limit():
    with pytest.raises(ProtocolError):
        pack_packet({"message": "bad"})
    with pytest.raises(ProtocolError):
        pack_packet({"type": "chat", "data": "x" * 600000})
