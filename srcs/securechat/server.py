"""Owner 1 - Blind relay TCP server (does not possess any user private key).

TODO[OWNER-1]: add rate limits, structured observability without plaintext logging,
clean disconnect notifications, and optional TLS transport as defense in depth.
"""
from __future__ import annotations

import argparse
import logging
import re
import socketserver
import threading

from . import crypto
from .protocol import ProtocolError, ROUTED_TYPES, VERSION, recv_packet, send_packet

LOG = logging.getLogger("securechat.server")
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,24}$")


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int]):
        super().__init__(address, RelayHandler)
        self.peers: dict[str, "RelayHandler"] = {}
        self.peers_lock = threading.RLock()

    def register(self, name: str, handler: "RelayHandler") -> bool:
        with self.peers_lock:
            if name in self.peers:
                return False
            self.peers[name] = handler
            return True

    def unregister(self, name: str, handler: "RelayHandler") -> None:
        with self.peers_lock:
            if self.peers.get(name) is handler:
                del self.peers[name]

    def list_names(self) -> list[str]:
        with self.peers_lock:
            return sorted(self.peers.keys())

    def find(self, name: str):
        with self.peers_lock:
            return self.peers.get(name)


class RelayHandler(socketserver.BaseRequestHandler):
    def setup(self) -> None:
        self.name: str | None = None
        self.send_lock = threading.Lock()

    def reply(self, packet: dict) -> None:
        with self.send_lock:
            send_packet(self.request, packet)

    def handle(self) -> None:
        self.request.settimeout(60.0)
        try:
            hello = recv_packet(self.request)
            if hello.get("type") != "hello" or hello.get("version") != VERSION:
                self.reply({"type": "error", "message": "First packet must be hello/version=1"})
                return
            name = hello.get("name")
            mssvs = hello.get("mssvs")
            if not isinstance(name, str) or not NAME_RE.fullmatch(name):
                self.reply({"type": "error", "message": "Invalid client name"})
                return
            if not isinstance(mssvs, list):
                self.reply({"type": "error", "message": "Missing MSSV list"})
                return
            try:
                expected = crypto.handshake_text(mssvs)
                digest = crypto.group_seed(mssvs).hex()
            except ValueError:
                self.reply({"type": "error", "message": "Invalid MSSV list"})
                return
            if hello.get("handshake") != expected or hello.get("group_seed_hash") != digest:
                self.reply({"type": "error", "message": "Handshake/MSSV mismatch"})
                return
            if not self.server.register(name, self):
                self.reply({"type": "error", "message": "Client name is already in use"})
                return
            self.name = name
            self.reply({"type": "welcome", "name": name, "peers": self.server.list_names()})
            LOG.info("Client joined: %s", name)
            while True:
                packet = recv_packet(self.request)
                kind = packet.get("type")
                if kind == "list_peers":
                    self.reply({"type": "peers", "names": self.server.list_names()})
                elif kind in ROUTED_TYPES:
                    if packet.get("sender") != self.name:
                        self.reply({"type": "error", "message": "Sender does not match registered client"})
                        continue
                    recipient = packet.get("recipient")
                    if not isinstance(recipient, str) or not NAME_RE.fullmatch(recipient):
                        self.reply({"type": "error", "message": "Invalid recipient"})
                        continue
                    target = self.server.find(recipient)
                    if target is None:
                        self.reply({"type": "error", "message": f"Peer {recipient} is offline"})
                        continue
                    try:
                        target.reply(packet)
                    except OSError:
                        self.reply({"type": "error", "message": f"Peer {recipient} connection failed"})
                else:
                    self.reply({"type": "error", "message": "Unknown packet type"})
        except (EOFError, ConnectionError, TimeoutError):
            pass
        except ProtocolError as exc:
            LOG.warning("Rejected malformed packet from %s: %s", self.name or "unknown", exc)
        except Exception:
            LOG.exception("Unexpected server error; no message payloads logged")
        finally:
            if self.name is not None:
                self.server.unregister(self.name, self)
                LOG.info("Client left: %s", self.name)


def main() -> None:
    parser = argparse.ArgumentParser(description="BTL1.1 blind relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9009)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    with RelayServer((args.host, args.port)) as server:
        LOG.info("Relay listening at %s:%s", *server.server_address)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
