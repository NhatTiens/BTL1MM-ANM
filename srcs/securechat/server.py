"""Owner 1: bounded TCP relay; no private keys or payload decryption."""
from __future__ import annotations

import argparse
import hashlib
import logging
import math
import re
import select
import socket
import socketserver
import threading
import time

from .protocol import ProtocolError, ROUTED_TYPES, VERSION, recv_packet, send_packet

LOG = logging.getLogger("securechat.server")
NAME_RE = re.compile(r"[a-zA-Z0-9_-]{1,24}")
HEX32_RE = re.compile(r"[a-f0-9]{32}")
HEX64_RE = re.compile(r"[a-f0-9]{64}")


class _InterruptibleReader:
    """Keep framing intact while polling for handler/server cancellation.

    Do not depend on shutdown() in another thread waking a timed socket read.
    Only this handler reads the socket; concurrent writers keep their existing
    socket timeout. A poll interval is not a protocol or idle timeout.
    """

    def __init__(self, sock, server_stopped, handler_stopped):
        self.sock = sock
        self.server_stopped = server_stopped
        self.handler_stopped = handler_stopped

    def recv(self, size: int) -> bytes:
        timeout = self.sock.gettimeout()
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self.server_stopped.is_set() or self.handler_stopped.is_set():
                raise ConnectionAbortedError("Relay read cancelled")
            wait = 0.1
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Relay read timed out")
                wait = min(wait, remaining)
            readable, _, _ = select.select([self.sock], [], [], wait)
            if readable:
                if self.server_stopped.is_set() or self.handler_stopped.is_set():
                    raise ConnectionAbortedError("Relay read cancelled")
                return self.sock.recv(size)


def _matches(pattern, value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _validate_route(packet: dict) -> None:
    """Validate envelope, never interpret opaque ciphertext or verify crypto here.

    Legacy relay probes omit nonce/session_id for chat. Accept only the paired
    omission; production SessionManager always supplies both. Peers authenticate.
    """
    kind = packet["type"]
    if not _matches(NAME_RE, packet.get("recipient")):
        raise ProtocolError("Invalid recipient")
    if any(key in packet for key in ("plaintext", "message", "filename", "size")):
        raise ProtocolError("Plaintext payload fields are forbidden")
    if kind == "session_init":
        if not _matches(HEX32_RE, packet.get("session_id")) or not _matches(HEX64_RE, packet.get("group_seed_hash")):
            raise ProtocolError("Invalid session metadata")
        fields = ("wrapped_key", "signature")
    else:
        if type(packet.get("seq")) is not int or packet["seq"] <= 0:
            raise ProtocolError("Invalid sequence")
        fields = ("ciphertext",)
        if kind != "chat" or "session_id" in packet or "nonce" in packet:
            if not _matches(HEX32_RE, packet.get("session_id")):
                raise ProtocolError("Invalid session ID")
            fields += ("nonce",)
        if kind.startswith("file_") and not _matches(HEX32_RE, packet.get("transfer_id")):
            raise ProtocolError("Invalid transfer ID")
        if kind == "file_chunk" and (type(packet.get("index")) is not int or packet["index"] < 0):
            raise ProtocolError("Invalid chunk index")
    if any(not isinstance(packet.get(key), str) or not packet[key] for key in fields):
        raise ProtocolError("Missing or invalid envelope field")


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False
    block_on_close = True

    def __init__(self, address: tuple[str, int], *, max_connections: int = 64,
                 handshake_timeout: float = 10.0, idle_timeout: float = 60.0):
        if type(max_connections) is not int or max_connections < 1:
            raise ValueError("max_connections must be positive")
        if any(not math.isfinite(v) or v <= 0 for v in (handshake_timeout, idle_timeout)):
            raise ValueError("Timeouts must be finite and positive")
        self.max_connections = max_connections
        self.handshake_timeout = handshake_timeout
        self.idle_timeout = idle_timeout
        self.peers: dict[str, RelayHandler] = {}
        self.peers_lock = threading.RLock()
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.RLock()
        self._closing = False
        self._stop_handlers = threading.Event()
        super().__init__(address, RelayHandler)

    def process_request(self, request, client_address) -> None:
        # Reserve before starting a thread, including clients without a hello.
        with self._connections_lock:
            if self._closing or len(self._connections) >= self.max_connections:
                self.shutdown_request(request)
                LOG.warning("Connection rejected: capacity or shutdown")
                return
            self._connections.add(request)
            try:
                super().process_request(request, client_address)
            except Exception:
                self._connections.discard(request)
                self.shutdown_request(request)
                raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._connections_lock:
                self._connections.discard(request)

    def server_close(self) -> None:
        # Readers observe the event even if cross-thread shutdown does not wake
        # their OS wait. Keep shutdown for pending writes and join every handler.
        self._stop_handlers.set()
        with self._connections_lock:
            self._closing = True
            connections = list(self._connections)
        for request in connections:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        super().server_close()

    def register(self, name: str, handler: "RelayHandler") -> bool:
        with self.peers_lock:
            if not _matches(NAME_RE, name) or name in self.peers:
                return False
            self.peers[name] = handler
            return True

    def unregister(self, name: str, handler: "RelayHandler") -> None:
        with self.peers_lock:
            if self.peers.get(name) is handler:
                del self.peers[name]

    def list_names(self) -> list[str]:
        with self.peers_lock:
            return sorted(self.peers)

    def find(self, name: str):
        with self.peers_lock:
            return self.peers.get(name)


class RelayHandler(socketserver.BaseRequestHandler):
    def setup(self) -> None:
        self.name: str | None = None
        self.send_lock = threading.Lock()
        self.closed = threading.Event()
        self.reader = _InterruptibleReader(self.request, self.server._stop_handlers,
                                           self.closed)
        LOG.info("TCP connection opened")

    def reply(self, packet: dict) -> None:
        if not self.send_lock.acquire(timeout=self.server.idle_timeout):
            raise TimeoutError("Recipient send queue timed out")
        try:
            if self.closed.is_set():
                raise ConnectionError("Connection closed")
            send_packet(self.request, packet)
        finally:
            self.send_lock.release()

    def disconnect(self) -> None:
        self.closed.set()
        if self.name is not None:
            self.server.unregister(self.name, self)
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def error(self, message: str) -> None:
        self.reply({"type": "error", "message": message})

    def _hello(self, hello: dict) -> str:
        if hello["type"] != "hello" or type(hello.get("version")) is not int or hello["version"] != VERSION:
            raise ProtocolError("First packet must be hello/version=1")
        name, mssvs = hello.get("name"), hello.get("mssvs")
        if not _matches(NAME_RE, name):
            raise ProtocolError("Invalid client name")
        if not isinstance(mssvs, list) or not 2 <= len(mssvs) <= 4 or not all(
            isinstance(v, str) and v.isascii() and v.isdigit() for v in mssvs
        ):
            raise ProtocolError("Invalid MSSV list; expected 2 to 4 numeric strings")
        expected = "Hello, We are " + ", ".join(mssvs)
        digest = hashlib.sha256("".join(mssvs).encode("ascii")).hexdigest()
        if hello.get("handshake") != expected or hello.get("group_seed_hash") != digest:
            raise ProtocolError("Handshake/MSSV mismatch")
        return name

    def handle(self) -> None:
        self.request.settimeout(self.server.handshake_timeout)
        try:
            name = self._hello(recv_packet(self.reader))
            # Publish registration and welcome while holding the same write lock.
            # A concurrent sender cannot deliver data before this client's welcome.
            with self.send_lock:
                if not self.server.register(name, self):
                    send_packet(self.request, {"type": "error", "message": "Client name is already in use"})
                    return
                self.name = name
                send_packet(self.request, {"type": "welcome", "name": name, "peers": self.server.list_names()})
            self.request.settimeout(self.server.idle_timeout)
            LOG.info("Client joined name=%s clients=%d", name, len(self.server.list_names()))
            while True:
                packet = recv_packet(self.reader)
                kind = packet["type"]
                if kind == "list_peers":
                    self.reply({"type": "peers", "names": self.server.list_names()})
                elif kind == "ping":
                    if set(packet) != {"type"}:
                        self.error("Invalid heartbeat packet")
                    else:
                        self.reply({"type": "pong"})
                elif kind in ROUTED_TYPES:
                    if packet.get("sender") != self.name:
                        self.error("Sender does not match registered client")
                        continue
                    try:
                        _validate_route(packet)
                    except ProtocolError as exc:
                        self.error(str(exc))
                        continue
                    recipient = packet["recipient"]
                    target = self.server.find(recipient)
                    if target is None:
                        self.error(f"Peer {recipient} is offline")
                        continue
                    try:
                        target.reply(packet)
                    except OSError:
                        target.disconnect()
                        self.error(f"Peer {recipient} connection failed")
                        LOG.warning("Route failed name=%s kind=%s", self.name, kind)
                    else:
                        LOG.debug("Routed name=%s kind=%s", self.name, kind)
                else:
                    self.error("Unknown packet type")
        except ProtocolError as exc:
            LOG.warning("Protocol rejected name=%s", self.name or "unregistered")
            try:
                self.error(str(exc))
            except OSError:
                pass
        except (EOFError, OSError) as exc:
            LOG.info("Connection ended name=%s reason=%s", self.name or "unregistered", type(exc).__name__)
        except Exception as exc:
            # Avoid exception messages/tracebacks that may contain hostile input.
            LOG.error("Internal error name=%s class=%s", self.name or "unregistered", type(exc).__name__)
        finally:
            self.disconnect()
            LOG.info("Client left name=%s clients=%d", self.name or "unregistered", len(self.server.list_names()))


def main() -> None:
    parser = argparse.ArgumentParser(description="BTL1.1 blind relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9009)
    parser.add_argument("--max-connections", type=int, default=64)
    parser.add_argument("--handshake-timeout", type=float, default=10.0)
    parser.add_argument("--idle-timeout", type=float, default=60.0)
    parser.add_argument("--debug", action="store_true", help="Log routing events, never packet payloads")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    with RelayServer((args.host, args.port), max_connections=args.max_connections,
                     handshake_timeout=args.handshake_timeout, idle_timeout=args.idle_timeout) as server:
        LOG.info("Relay listening at %s:%s", *server.server_address)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        # serve_forever has exited: shutdown() here would deadlock in this thread.


if __name__ == "__main__":
    main()
