"""GUI-friendly secure client adapter.

The networking and encryption run without any GUI toolkit dependency. Events
arrive on the socket reader thread; a GUI must marshal them onto its UI thread.
Only signed sessions with *pre-pinned*, independently verified peer public keys
are accepted. Auto-replying to such a session does NOT auto-trust a new key.
"""
from __future__ import annotations

import socket
import threading
from pathlib import Path
from typing import Any, Callable

from . import crypto
from .protocol import VERSION, recv_packet, send_packet
from .session import SessionManager
from .transfer import FileReceiver, send_file

HEARTBEAT_INTERVAL = 20.0  # Must remain below the relay idle timeout (default 60s).

EventHandler = Callable[[dict[str, Any]], None]


class GuiChatClient:
    """A thread-safe E2EE client with callbacks instead of terminal prompts."""

    def __init__(
        self,
        name: str,
        mssvs: list[str],
        identity: Path,
        trust: Path,
        downloads: Path,
        host: str,
        port: int,
        on_event: EventHandler,
    ) -> None:
        self.name = name
        self.mssvs = crypto.validate_mssvs(mssvs)
        self.identity = Path(identity)
        self.trust = Path(trust)
        self.downloads = Path(downloads)
        self.host = host
        self.port = port
        self._callback = on_event
        self._socket: socket.socket | None = None
        self._send_lock = threading.Lock()
        # One transaction lock covers encryption sequence assignment AND socket send.
        # RLock permits send_message/send_file to establish a session inside it.
        self._operation_lock = threading.RLock()
        self._state_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._notified_disconnect = False
        self.session: SessionManager | None = None
        self.files: FileReceiver | None = None

    def _emit(self, kind: str, **details: Any) -> None:
        self._callback({"kind": kind, **details})

    def connect(self) -> None:
        """Blocking connect: call from a worker thread, never the Tk UI thread."""
        if self._stop.is_set():
            raise ConnectionError("Client has been closed")
        self.session = SessionManager(self.name, self.mssvs, self.identity, self.trust)
        self.files = FileReceiver(self.downloads)
        sock = socket.create_connection((self.host, self.port), timeout=5)
        try:
            sock.settimeout(8)
            send_packet(sock, {
                "type": "hello", "version": VERSION, "name": self.name,
                "mssvs": list(self.mssvs),
                "handshake": crypto.handshake_text(self.mssvs),
                "group_seed_hash": crypto.group_seed(self.mssvs).hex(),
            })
            welcome = recv_packet(sock)
            if welcome.get("type") != "welcome":
                raise ConnectionError(f"Server rejected connection: {welcome.get('message', welcome)}")
            peers = welcome.get("peers")
            if not isinstance(peers, list):
                raise ConnectionError("Malformed server welcome packet")
            sock.settimeout(None)
            with self._state_lock:
                if self._stop.is_set():
                    raise ConnectionError("Client has been closed")
                self._socket = sock
            self._emit("connected", peers=peers)
            self._thread = threading.Thread(target=self._receive_loop, daemon=True,
                                            name=f"gui-reader-{self.name}")
            self._thread.start()
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop, daemon=True, name=f"gui-heartbeat-{self.name}"
            )
            self._heartbeat_thread.start()
        except Exception:
            sock.close()
            raise

    def _send(self, packet: dict[str, Any]) -> None:
        with self._send_lock:
            if self._stop.is_set() or self._socket is None:
                raise ConnectionError("Not connected")
            send_packet(self._socket, packet)

    def _heartbeat_loop(self) -> None:
        """Prevent idle relay disconnect without weakening its connection limit."""
        while not self._stop.wait(HEARTBEAT_INTERVAL):
            try:
                self._send({"type": "ping"})
            except (OSError, ConnectionError) as exc:
                if not self._stop.is_set():
                    self._emit("warning", message=f"Heartbeat failed: {type(exc).__name__}")
                self.close()
                return

    def request_peers(self) -> None:
        self._send({"type": "list_peers"})

    def establish_session(self, peer: str) -> None:
        # Serializes simultaneous UI sends with signed session-init creation.
        with self._operation_lock:
            if peer == self.name:
                raise ValueError("Cannot send a message to yourself")
            assert self.session is not None
            if not self.session.has_outgoing(peer):
                self._send(self.session.create_session_init(peer))
                self._emit("session_ready", peer=peer, message="Đã gửi yêu cầu thiết lập khóa bảo mật")

    def send_message(self, peer: str, message: str) -> None:
        if not message.strip():
            return
        with self._operation_lock:
            self.establish_session(peer)
            assert self.session is not None
            self._send(self.session.encrypt_payload("chat", peer, message.encode("utf-8")))
            self._emit("message_sent", peer=peer, message=message)

    def send_encrypted_file(self, peer: str, path: Path) -> None:
        # Hold lock across the entire transfer; no chat packet may overtake a file chunk.
        with self._operation_lock:
            self.establish_session(peer)
            assert self.session is not None
            transfer_id = send_file(self.session, peer, Path(path), self._send)
            self._emit("file_sent", peer=peer, path=str(path), transfer_id=transfer_id)

    def _receive_loop(self) -> None:
        try:
            while not self._stop.is_set():
                assert self._socket is not None
                packet = recv_packet(self._socket)
                kind = packet.get("type")
                if kind == "session_init":
                    assert self.session is not None
                    peer = self.session.accept_session_init(packet)
                    self._emit("session_received", peer=peer)
                    # Mutual communication needs two *directional* sessions.
                    # A signed and PINNED peer may safely trigger our reply.
                    if not self.session.has_outgoing(peer):
                        self.establish_session(peer)
                elif kind == "chat":
                    assert self.session is not None
                    plaintext = self.session.decrypt_payload(packet).decode("utf-8")
                    self._emit("message_received", peer=packet["sender"], message=plaintext)
                elif kind in {"file_meta", "file_chunk", "file_done"}:
                    assert self.files is not None and self.session is not None
                    saved = self.files.handle(packet, self.session)
                    if kind == "file_meta":
                        self._emit("file_receiving", peer=packet["sender"])
                    if saved:
                        self._emit("file_received", peer=packet["sender"], path=saved)
                elif kind == "pong":
                    # Heartbeats are transport liveness, not a chat message.
                    pass
                elif kind == "peers":
                    if isinstance(packet.get("names"), list):
                        self._emit("peers", peers=packet["names"])
                    else:
                        self._emit("warning", message="Danh sách người dùng không hợp lệ")
                elif kind == "error":
                    self._emit("warning", message=str(packet.get("message", "Lỗi server")))
                else:
                    self._emit("warning", message="Nhận gói tin không xác định")
        except (EOFError, OSError) as exc:
            if not self._stop.is_set():
                self._emit("warning", message=f"Mất kết nối: {exc}")
        except Exception as exc:
            # Important: no plaintext downgrade following an authentication error.
            if not self._stop.is_set():
                self._emit("security_error", message=f"{type(exc).__name__}: {exc}")
        finally:
            self.close()

    def close(self) -> None:
        with self._state_lock:
            self._stop.set()
            sock, self._socket = self._socket, None
            first = not self._notified_disconnect
            self._notified_disconnect = True
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        if first:
            self._emit("disconnected")
