"""Owner 3 - Command line client. TCP sends only encrypted chat/file payloads.

TODO[OWNER-3]: reconnect with re-handshake, upload progress, command help UX.
"""
from __future__ import annotations

import argparse
import socket
import threading
from pathlib import Path

from . import crypto
from .protocol import VERSION, recv_packet, send_packet
from .session import SecureSessionError, SessionManager
from .transfer import FileReceiver, TransferError, send_file


class ChatClient:
    def __init__(self, name: str, mssvs: list[str], identity: Path, trust: Path,
                 download_dir: Path, host: str, port: int):
        self.name = name
        self.mssvs = crypto.validate_mssvs(mssvs)
        self.session = SessionManager(name, self.mssvs, identity, trust)
        self.files = FileReceiver(download_dir)
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(None)
        self._send_lock = threading.Lock()
        self._stop = threading.Event()

    def send(self, packet: dict) -> None:
        with self._send_lock:
            send_packet(self.sock, packet)

    def connect(self) -> None:
        self.send({"type": "hello", "version": VERSION, "name": self.name,
                   "mssvs": list(self.mssvs), "handshake": crypto.handshake_text(self.mssvs),
                   "group_seed_hash": crypto.group_seed(self.mssvs).hex()})
        welcome = recv_packet(self.sock)
        if welcome.get("type") != "welcome":
            raise ConnectionError(f"Server rejected handshake: {welcome}")
        print(f"[{self.name}] Connected. Peers: {welcome['peers']}")
        print("Commands: /peers | /connect <peer> | /msg <peer> <text> | /file <peer> <path> | /quit")
        receiver = threading.Thread(target=self._receive_loop, name="receive", daemon=True)
        receiver.start()

    def _receive_loop(self) -> None:
        try:
            while not self._stop.is_set():
                packet = recv_packet(self.sock)
                kind = packet.get("type")
                if kind == "session_init":
                    peer = self.session.accept_session_init(packet)
                    print(f"\n[Secure] Verified session from {peer}. To reply, run /connect {peer}")
                elif kind == "chat":
                    msg = self.session.decrypt_payload(packet).decode("utf-8")
                    print(f"\n[{packet['sender']} -> you] {msg}")
                elif kind in {"file_meta", "file_chunk", "file_done"}:
                    finished = self.files.handle(packet, self.session)
                    if kind == "file_meta":
                        print(f"\n[File] Incoming encrypted file from {packet['sender']}")
                    if finished:
                        print(f"\n[File] Verified and saved: {finished}")
                elif kind == "peers":
                    print("\nOnline:", ", ".join(packet["names"]))
                elif kind == "error":
                    print("\n[Server error]", packet.get("message"))
                else:
                    print("\n[Info] Unknown server packet type")
        except (EOFError, OSError):
            if not self._stop.is_set():
                print("\n[Disconnected] Server connection closed")
        except Exception as exc:
            print(f"\n[Security/protocol error] {type(exc).__name__}: {exc}")
            # Never downgrade to plaintext on decryption failure.
            self.close()

    def command(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return True
        if line in {"/quit", "/exit"}:
            return False
        if line == "/peers":
            self.send({"type": "list_peers"})
            return True
        cmd, *rest = line.split(" ", maxsplit=2)
        if cmd == "/connect" and len(rest) == 1 and rest[0]:
            self.send(self.session.create_session_init(rest[0]))
            print(f"[Secure] Sent signed session setup to {rest[0]}")
        elif cmd == "/msg" and len(rest) == 2:
            peer, message = rest
            self.send(self.session.encrypt_payload("chat", peer, message.encode("utf-8")))
            print(f"[Encrypted -> {peer}] sent")
        elif cmd == "/file" and len(rest) == 2:
            peer, filename = rest
            transfer_id = send_file(self.session, peer, Path(filename), self.send)
            print(f"[Encrypted file -> {peer}] sent (ID {transfer_id[:8]})")
        else:
            print("Usage: /peers | /connect bob | /msg bob Hello | /file bob ./sample.txt | /quit")
        return True

    def run(self) -> None:
        self.connect()
        try:
            while not self._stop.is_set():
                try:
                    line = input(f"{self.name}> ")
                except EOFError:
                    break
                try:
                    if not self.command(line):
                        break
                except (SecureSessionError, TransferError, ValueError, FileNotFoundError, OSError) as exc:
                    print(f"[Error] {exc}")
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="BTL1.1 E2EE chat CLI")
    parser.add_argument("--name", required=True, help="Client identity, e.g. alice")
    parser.add_argument("--mssvs", required=True, help="Comma-separated 2..4 MSSVs in stable team order")
    parser.add_argument("--identity", type=Path, help="Directory containing private.pem")
    parser.add_argument("--trust", type=Path, help="Directory containing <peer>.pem public keys")
    parser.add_argument("--downloads", type=Path, help="Directory for received files")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9009)
    args = parser.parse_args()
    root = Path(".local")
    app = ChatClient(args.name, args.mssvs.split(","),
                     args.identity or root / "identities" / args.name,
                     args.trust or root / "trusted" / args.name,
                     args.downloads or root / "received" / args.name,
                     args.host, args.port)
    app.run()


if __name__ == "__main__":
    main()
