"""Version 1: unsigned 4-byte big-endian length followed by UTF-8 JSON."""
from __future__ import annotations

import json
import math
import socket
import struct
from typing import Any

VERSION = 1
MAX_FRAME_BYTES = 512 * 1024
ROUTED_TYPES = frozenset({"session_init", "chat", "file_meta", "file_chunk", "file_done"})


class ProtocolError(ValueError):
    """Malformed packet; a receiver must close instead of guessing frame boundaries."""


def _validate_json(value: Any, depth: int = 0) -> None:
    # Bound traversal and disallow lossy JSON conversions (e.g. integer dict keys).
    if depth > 64:
        raise ProtocolError("JSON nesting exceeds limit")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProtocolError("JSON object keys must be strings")
            _validate_json(key, depth + 1)
            _validate_json(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json(child, depth + 1)
    elif value is None or type(value) in (str, int, bool):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise ProtocolError("Invalid Unicode string") from exc
    elif type(value) is float and math.isfinite(value):
        return
    else:
        raise ProtocolError("Unsupported JSON value")


def canonical_json(obj: dict[str, Any]) -> bytes:
    """Keep the original sorted-key UTF-8 bytes for valid signatures and AAD."""
    if not isinstance(obj, dict):
        raise ProtocolError("Expected a JSON object")
    _validate_json(obj)
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("Cannot encode JSON object") from exc


def _validate_packet(packet: Any) -> None:
    if not isinstance(packet, dict) or not isinstance(packet.get("type"), str) or not packet["type"]:
        raise ProtocolError("Packet must be an object with a nonempty type string")
    _validate_json(packet)


def pack_packet(packet: dict[str, Any]) -> bytes:
    _validate_packet(packet)
    body = canonical_json(packet)
    if len(body) > MAX_FRAME_BYTES:
        raise ProtocolError("Frame too large")
    return struct.pack("!I", len(body)) + body


def _read_exact(sock: socket.socket, size: int) -> bytes:
    if type(size) is not int or not 0 <= size <= MAX_FRAME_BYTES:
        raise ProtocolError("Invalid read size")
    pieces = bytearray()
    while len(pieces) < size:
        chunk = sock.recv(size - len(pieces))
        if not chunk:
            raise EOFError("Socket closed before frame completed")
        pieces.extend(chunk)
    return bytes(pieces)


def _unique_object(pairs: list) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ProtocolError("Duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(value: str) -> None:
    raise ProtocolError("Non-finite JSON number")


def recv_packet(sock: socket.socket) -> dict[str, Any]:
    (size,) = struct.unpack("!I", _read_exact(sock, 4))
    if size < 2 or size > MAX_FRAME_BYTES:
        raise ProtocolError("Invalid frame length")
    body = _read_exact(sock, size)
    try:
        obj = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Malformed JSON") from exc
    _validate_packet(obj)
    return obj


def send_packet(sock: socket.socket, packet: dict[str, Any]) -> None:
    """Callers sharing a socket must serialize writes with their own lock."""
    sock.sendall(pack_packet(packet))
