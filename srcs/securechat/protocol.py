"""Owner 1 - Transport framing and versioned packet structures.

Protocol: 4-byte unsigned big-endian packet length, followed by a UTF-8 JSON object.
Only ciphertext and session metadata travel through the forwarding server.
"""
from __future__ import annotations

import json
import socket
import struct
from typing import Any

VERSION = 1
MAX_FRAME_BYTES = 512 * 1024
ROUTED_TYPES = frozenset({"session_init", "chat", "file_meta", "file_chunk", "file_done"})


class ProtocolError(ValueError):
    """Packet malformed or violates the protocol contract."""


def canonical_json(obj: dict[str, Any]) -> bytes:
    """Stable JSON representation for signatures and authenticated data (AAD)."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pack_packet(packet: dict[str, Any]) -> bytes:
    if not isinstance(packet, dict) or not isinstance(packet.get("type"), str):
        raise ProtocolError("Packet must be a JSON object with a 'type' string")
    body = canonical_json(packet)
    if len(body) > MAX_FRAME_BYTES:
        raise ProtocolError("Frame too large")
    return struct.pack("!I", len(body)) + body


def _read_exact(sock: socket.socket, size: int) -> bytes:
    pieces = bytearray()
    while len(pieces) < size:
        chunk = sock.recv(size - len(pieces))
        if not chunk:
            raise EOFError("Socket closed")
        pieces.extend(chunk)
    return bytes(pieces)


def recv_packet(sock: socket.socket) -> dict[str, Any]:
    (size,) = struct.unpack("!I", _read_exact(sock, 4))
    if size < 2 or size > MAX_FRAME_BYTES:
        raise ProtocolError("Invalid frame length")
    try:
        obj = json.loads(_read_exact(sock, size).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Malformed JSON") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
        raise ProtocolError("Invalid packet structure")
    return obj


def send_packet(sock: socket.socket, packet: dict[str, Any]) -> None:
    sock.sendall(pack_packet(packet))
