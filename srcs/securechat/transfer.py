"""Owner 3 - Encrypted file streaming through session-managed AES-GCM envelopes.

The relay sees only packet type, sender, recipient and transfer ID. Filename,
file size, hash, and all file bytes are encrypted with the session key.
TODO[OWNER-3]: progress reporting, resumable transfers, multiple concurrent files.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import uuid
from pathlib import Path
from typing import Callable

from .session import SecureSessionError, SessionManager

CHUNK_SIZE = 32 * 1024
MAX_FILE_SIZE = 20 * 1024 * 1024  # local demo limit


class TransferError(ValueError):
    pass


def _safe_filename(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 200:
        raise TransferError("Invalid filename")
    normalized = name.replace("\\", "/").split("/")[-1]
    if normalized in {"", ".", ".."}:
        raise TransferError("Unsafe filename")
    safe = re.sub(r"[^\w.() -]", "_", normalized, flags=re.UNICODE)
    if not safe or safe in {".", ".."}:
        raise TransferError("Unsafe filename")
    return safe


def send_file(session: SessionManager, peer: str, file_path: Path,
              send_packet_fn: Callable[[dict], None]) -> str:
    path = Path(file_path)
    if not path.is_file():
        raise TransferError(f"Not a file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise TransferError(f"File exceeds the {MAX_FILE_SIZE} byte demo cap")
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            hasher.update(chunk)
    transfer_id = uuid.uuid4().hex
    meta = {"name": _safe_filename(path.name), "size": size,
            "sha256": hasher.hexdigest(), "total_chunks": math.ceil(size / CHUNK_SIZE)}
    send_packet_fn(session.encrypt_payload("file_meta", peer,
                                          json.dumps(meta, ensure_ascii=False).encode("utf-8"),
                                          transfer_id=transfer_id))
    with path.open("rb") as source:
        index = 0
        while chunk := source.read(CHUNK_SIZE):
            send_packet_fn(session.encrypt_payload("file_chunk", peer, chunk,
                                                   transfer_id=transfer_id, index=index))
            index += 1
    send_packet_fn(session.encrypt_payload("file_done", peer, b"", transfer_id=transfer_id))
    return transfer_id


class FileReceiver:
    def __init__(self, download_dir: Path):
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self._pending: dict[tuple[str, str], dict] = {}

    def handle(self, packet: dict, session: SessionManager) -> str | None:
        """Decrypt and process file packet. Return finished file's path if done."""
        kind = packet.get("type")
        if kind not in {"file_meta", "file_chunk", "file_done"}:
            raise TransferError("Not a file packet")
        plaintext = session.decrypt_payload(packet)
        transfer_id = packet.get("transfer_id")
        peer = packet.get("sender")
        if not isinstance(transfer_id, str) or not re.fullmatch(r"[a-f0-9]{32}", transfer_id):
            raise TransferError("Invalid transfer ID")
        identity = (peer, transfer_id)
        if kind == "file_meta":
            if identity in self._pending:
                raise TransferError("Duplicate transfer")
            try:
                meta = json.loads(plaintext)
                name = _safe_filename(meta["name"])
                size = meta["size"]
                count = meta["total_chunks"]
                digest = meta["sha256"]
                if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
                    raise ValueError("Invalid file size")
                if type(count) is not int or count != math.ceil(size / CHUNK_SIZE):
                    raise ValueError("Invalid chunk count")
                if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise ValueError("Invalid file digest")
            except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise TransferError("Invalid encrypted file metadata") from exc
            part_path = self.download_dir / f".{transfer_id}.part"
            if part_path.exists():
                raise TransferError("Transfer already exists on disk")
            with part_path.open("xb"):
                pass
            self._pending[identity] = {"meta": meta, "name": name, "path": part_path,
                                       "index": 0, "bytes": 0, "hash": hashlib.sha256()}
            return None
        state = self._pending.get(identity)
        if state is None:
            raise TransferError("File transfer not initialized")
        if kind == "file_chunk":
            index = packet.get("index")
            if type(index) is not int or index != state["index"]:
                raise TransferError("Out-of-order file chunk")
            if len(plaintext) > CHUNK_SIZE or state["bytes"] + len(plaintext) > state["meta"]["size"]:
                raise TransferError("Invalid chunk length")
            with state["path"].open("ab") as out:
                out.write(plaintext)
            state["index"] += 1
            state["bytes"] += len(plaintext)
            state["hash"].update(plaintext)
            return None
        # file_done
        if plaintext != b"" or state["bytes"] != state["meta"]["size"] or \
                state["index"] != state["meta"]["total_chunks"] or \
                state["hash"].hexdigest() != state["meta"]["sha256"]:
            state["path"].unlink(missing_ok=True)
            del self._pending[identity]
            raise TransferError("Incomplete or corrupted file")
        dest = self.download_dir / f"{transfer_id[:8]}_{state['name']}"
        if dest.exists():
            raise TransferError("Destination already exists; refusing overwrite")
        os.replace(state["path"], dest)
        del self._pending[identity]
        return str(dest)
