"""Owner 2 - Peer-to-peer session setup, public-key pinning and replay checks.

Public keys are provisioned and VERIFIED outside the untrusted server channel.
No trusted peer key = no session. Server messages cannot replace peer identities.
"""
from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any, Sequence

from . import crypto
from .protocol import canonical_json

ENCRYPTED_TYPES = frozenset({"chat", "file_meta", "file_chunk", "file_done"})


class SecureSessionError(ValueError):
    pass


class SessionManager:
    def __init__(self, name: str, mssvs: Sequence[str], identity_dir: Path, trust_dir: Path):
        self.name = name
        self.mssvs = crypto.validate_mssvs(mssvs)
        self.private_key = crypto.load_private(Path(identity_dir) / "private.pem")
        self.trust_dir = Path(trust_dir)
        self._outgoing: dict[str, dict[str, Any]] = {}
        self._incoming: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.RLock()

    def trusted_key(self, peer: str):
        if not peer or peer == self.name or not peer.replace("_", "").replace("-", "").isalnum():
            raise SecureSessionError("Invalid peer name")
        path = self.trust_dir / f"{peer}.pem"
        if not path.is_file():
            raise SecureSessionError(f"No pinned key for {peer}; verify their fingerprint out of band")
        return crypto.load_public(path)

    def create_session_init(self, peer: str) -> dict[str, Any]:
        """Start one outbound session. Recipient must explicitly /connect back to reply."""
        peer_key = self.trusted_key(peer)
        secret = crypto.make_session_key(self.mssvs)
        session_id = uuid.uuid4().hex
        packet = {
            "type": "session_init", "sender": self.name, "recipient": peer,
            "session_id": session_id, "group_seed_hash": crypto.group_seed(self.mssvs).hex(),
            "wrapped_key": crypto.wrap_key(peer_key, secret),
        }
        packet["signature"] = crypto.sign_object(self.private_key, packet)
        with self._lock:
            self._outgoing[peer] = {"key": secret, "session_id": session_id, "seq": 0}
        return packet

    def accept_session_init(self, packet: dict[str, Any]) -> str:
        peer = packet.get("sender")
        if not isinstance(peer, str) or packet.get("recipient") != self.name:
            raise SecureSessionError("Session recipient mismatch")
        peer_public = self.trusted_key(peer)
        payload = dict(packet)
        signature = payload.pop("signature", None)
        if not isinstance(signature, str):
            raise SecureSessionError("Missing handshake signature")
        if payload.get("type") != "session_init" or payload.get("group_seed_hash") != crypto.group_seed(self.mssvs).hex():
            raise SecureSessionError("Wrong group or handshake type")
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or len(session_id) != 32:
            raise SecureSessionError("Invalid session ID")
        crypto.verify_object(peer_public, payload, signature)
        key = crypto.unwrap_key(self.private_key, payload["wrapped_key"])
        identity = (peer, session_id)
        with self._lock:
            if identity in self._incoming:
                raise SecureSessionError("Replay of session setup")
            self._incoming[identity] = {"key": key, "seq": 0}
        return peer

    def has_outgoing(self, peer: str) -> bool:
        with self._lock:
            return peer in self._outgoing

    def encrypt_payload(self, kind: str, peer: str, payload: bytes, **metadata: Any) -> dict[str, Any]:
        if kind not in ENCRYPTED_TYPES:
            raise SecureSessionError("Unsupported encrypted packet type")
        if set(metadata) - {"transfer_id", "index"}:
            raise SecureSessionError("Unsupported encrypted packet metadata")
        with self._lock:
            state = self._outgoing.get(peer)
            if state is None:
                raise SecureSessionError(f"Run /connect {peer} before sending data")
            state["seq"] += 1
            header = {"type": kind, "sender": self.name, "recipient": peer,
                      "session_id": state["session_id"], "seq": state["seq"], **metadata}
            nonce, ciphertext = crypto.encrypt(state["key"], payload, canonical_json(header))
        return {**header, "nonce": nonce, "ciphertext": ciphertext}

    def decrypt_payload(self, packet: dict[str, Any]) -> bytes:
        peer = packet.get("sender")
        session_id = packet.get("session_id")
        if packet.get("type") not in ENCRYPTED_TYPES or packet.get("recipient") != self.name:
            raise SecureSessionError("Unexpected encrypted packet")
        if not isinstance(peer, str) or not isinstance(session_id, str):
            raise SecureSessionError("Missing sender or session")
        identity = (peer, session_id)
        with self._lock:
            state = self._incoming.get(identity)
            if state is None:
                raise SecureSessionError("Session not established or not trusted")
            seq = packet.get("seq")
            if type(seq) is not int or seq <= state["seq"]:
                raise SecureSessionError("Replay or invalid packet sequence")
            header = {k: v for k, v in packet.items() if k not in ("nonce", "ciphertext")}
            # AAD authenticates routing, file metadata and monotonic counter.
            plaintext = crypto.decrypt(state["key"], packet["nonce"],
                                       packet["ciphertext"], canonical_json(header))
            state["seq"] = seq
            return plaintext
