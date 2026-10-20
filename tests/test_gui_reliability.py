"""Regressions for idle GUI disconnect and out-of-order E2EE send operations."""
from __future__ import annotations

import queue
import socket
import threading
import time
from pathlib import Path

import pytest

from securechat import crypto, gui_client
from securechat.gui import ChatWindow
from securechat.gui_client import GuiChatClient
from securechat.protocol import recv_packet, send_packet
from securechat.server import RelayServer

MSSVS = ["2312345", "2312346", "2312347", "2312348"]


def test_gui_actions_use_one_fifo_worker_without_display():
    app = object.__new__(ChatWindow)
    app.is_closing = False
    app.operations = queue.Queue()
    app.events = queue.Queue()
    output = []
    worker = threading.Thread(target=app._operation_worker, daemon=True)
    worker.start()
    for i in range(40):
        app._spawn(lambda i=i: output.append(i))
    app.operations.join()
    app.operations.put(None)
    worker.join(2)
    assert not worker.is_alive()
    assert output == list(range(40))
    assert app.events.empty()


def _minimal_adapter():
    adapter = object.__new__(GuiChatClient)
    adapter.name = "alice"
    adapter._operation_lock = threading.RLock()
    adapter._callback = lambda event: None
    return adapter


def test_concurrent_messages_send_in_encryption_sequence():
    adapter = _minimal_adapter()
    encrypted_first = threading.Event()
    class FakeSession:
        def __init__(self):
            self.seq = 0
            self.lock = threading.Lock()
        def has_outgoing(self, peer):
            return True
        def encrypt_payload(self, kind, peer, message):
            with self.lock:
                self.seq += 1
                seq = self.seq
            if seq == 1:
                encrypted_first.set()
                time.sleep(0.07)  # Force sequence-2 attempt while packet 1 is pending.
            return {"type": kind, "seq": seq}
    adapter.session = FakeSession()
    sent = []
    adapter._send = lambda packet: sent.append(packet["seq"])
    first = threading.Thread(target=adapter.send_message, args=("bob", "first"))
    second = threading.Thread(target=adapter.send_message, args=("bob", "second"))
    first.start()
    assert encrypted_first.wait(2)
    second.start()
    first.join(2)
    second.join(2)
    assert not first.is_alive() and not second.is_alive()
    assert sent == [1, 2]


def test_file_transfer_does_not_interleave_chat(monkeypatch, tmp_path):
    adapter = _minimal_adapter()
    class FakeSession:
        def __init__(self):
            self.seq = 0
        def has_outgoing(self, peer):
            return True
        def encrypt_payload(self, kind, peer, message):
            self.seq += 1
            return {"type": kind, "seq": self.seq}
    adapter.session = FakeSession()
    sent = []
    chunk_one = threading.Event()
    adapter._send = lambda packet: sent.append((packet["type"], packet["seq"]))
    def slow_file(session, peer, path, send):
        send(session.encrypt_payload("file_meta", peer, b"a"))
        chunk_one.set()
        time.sleep(0.07)
        send(session.encrypt_payload("file_chunk", peer, b"b"))
        return "demo-id"
    monkeypatch.setattr(gui_client, "send_file", slow_file)
    t1 = threading.Thread(target=adapter.send_encrypted_file, args=("bob", tmp_path / "file"))
    t2 = threading.Thread(target=adapter.send_message, args=("bob", "hello"))
    t1.start()
    assert chunk_one.wait(2)
    t2.start()
    t1.join(2)
    t2.join(2)
    assert [kind for kind, _ in sent] == ["file_meta", "file_chunk", "chat"]
    assert [seq for _, seq in sent] == [1, 2, 3]


def test_server_ping_pong_and_rejects_extra_fields():
    server = RelayServer(("127.0.0.1", 0), idle_timeout=0.3)
    runner = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    runner.start()
    sock = socket.create_connection(server.server_address, timeout=2)
    sock.settimeout(2)
    try:
        send_packet(sock, {"type": "hello", "version": 1, "name": "alice", "mssvs": MSSVS,
                           "handshake": crypto.handshake_text(MSSVS),
                           "group_seed_hash": crypto.group_seed(MSSVS).hex()})
        assert recv_packet(sock)["type"] == "welcome"
        send_packet(sock, {"type": "ping", "extra": "not allowed"})
        assert recv_packet(sock)["type"] == "error"
        send_packet(sock, {"type": "ping"})
        assert recv_packet(sock) == {"type": "pong"}
    finally:
        sock.close()
        server.shutdown()
        server.server_close()
        runner.join(3)
        assert not runner.is_alive()


def test_gui_heartbeat_keeps_short_idle_connection_alive(monkeypatch, paired_sessions):
    monkeypatch.setattr(gui_client, "HEARTBEAT_INTERVAL", 0.05)
    _, _, root = paired_sessions
    server = RelayServer(("127.0.0.1", 0), idle_timeout=0.25)
    runner = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    runner.start()
    events = queue.Queue()
    app = GuiChatClient("alice", MSSVS, root / "identities" / "alice",
                        root / "trusted" / "alice", root / "received" / "alice",
                        *server.server_address, events.put)
    try:
        app.connect()
        assert events.get(timeout=2)["kind"] == "connected"
        time.sleep(0.72)  # Nearly 3x the timeout; pings must prevent disconnect.
        assert server.find("alice") is not None
        app.request_peers()
        deadline = time.monotonic() + 2
        kinds = []
        while time.monotonic() < deadline:
            try:
                event = events.get(timeout=0.1)
                kinds.append(event["kind"])
                if event["kind"] == "peers":
                    break
            except queue.Empty:
                continue
        assert "peers" in kinds
        assert "disconnected" not in kinds
    finally:
        app.close()
        server.shutdown()
        server.server_close()
        runner.join(3)
        assert not runner.is_alive()
