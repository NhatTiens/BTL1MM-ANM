"""Local TCP behavior, lifecycle, concurrency and actual ChatClient integration."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import logging
from pathlib import Path
import socket
import struct
import threading
import time

import pytest

from securechat import crypto
from securechat.client import ChatClient
from securechat.protocol import MAX_FRAME_BYTES, pack_packet, recv_packet, send_packet
from securechat.server import RelayServer

MSSVS = ["2312345", "2312346", "2312347", "2312348"]


def hello(name="alice", **changes):
    return {"type": "hello", "version": 1, "name": name, "mssvs": MSSVS,
            "handshake": crypto.handshake_text(MSSVS),
            "group_seed_hash": crypto.group_seed(MSSVS).hex(), **changes}


def chat(**changes):
    return {"type": "chat", "sender": "alice", "recipient": "bob", "seq": 1,
            "session_id": "a" * 32, "nonce": "opaque_nonce",
            "ciphertext": "opaque_ciphertext", **changes}


def eventually(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "Condition was not reached before deadline"


@contextmanager
def running(**options):
    server = RelayServer(("127.0.0.1", 0), **options)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    sockets = []
    def connect(name=None):
        sock = socket.create_connection(server.server_address, timeout=2)
        sock.settimeout(3)
        sockets.append(sock)
        if name:
            send_packet(sock, hello(name))
            assert recv_packet(sock)["type"] == "welcome"
        return sock
    try:
        yield server, connect
    finally:
        for sock in sockets:
            sock.close()
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
        assert server.list_names() == []
        assert not server._connections


@pytest.fixture
def relay():
    with running() as value:
        yield value


def test_register_list_duplicate_and_identity_safe_cleanup(relay):
    server, connect = relay
    alice, bob = connect("alice"), connect("bob")
    duplicate = connect()
    send_packet(duplicate, hello())
    assert recv_packet(duplicate)["type"] == "error"
    old = server.find("alice")
    send_packet(alice, {"type": "list_peers"})
    assert recv_packet(alice)["names"] == ["alice", "bob"]
    alice.close()
    eventually(lambda: server.find("alice") is None)
    connect("alice")
    server.unregister("alice", old)
    assert server.find("alice") is not None


@pytest.mark.parametrize("change", [{"name": ""}, {"name": "a" * 25}, {"name": "../a"},
    {"name": "alice\nforged"}, {"name": []}, {"name": "Việt"},
    {"version": True}, {"version": 2}, {"version": "1"}, {"type": "chat"},
    {"mssvs": []}, {"mssvs": [2312345, 2312346]}, {"mssvs": ["1", " 2"]},
    {"mssvs": ["１", "２"]}, {"mssvs": [None, {}]},
    {"handshake": "Hello"}, {"group_seed_hash": "0" * 64}])
def test_invalid_hello_does_not_damage_server(relay, change):
    server, connect = relay
    bad = connect()
    send_packet(bad, hello(**change))
    assert recv_packet(bad)["type"] == "error"
    with pytest.raises((EOFError, OSError)):
        recv_packet(bad)
    connect("healthy")
    assert server.list_names() == ["healthy"]


@pytest.mark.parametrize("kind", ["session_init", "chat", "file_meta", "file_chunk", "file_done"])
def test_forward_all_kinds_unchanged_without_crypto(relay, monkeypatch, kind):
    _, connect = relay
    alice, bob = connect("alice"), connect("bob")
    def forbidden(*args, **kwargs):
        raise AssertionError("Relay attempted to use private cryptography")
    for name in ("decrypt", "unwrap_key", "load_private"):
        monkeypatch.setattr(crypto, name, forbidden)
    packet = chat(type=kind, transfer_id="b" * 32, index=0,
                  wrapped_key="opaque_wrapped", signature="opaque_signature",
                  group_seed_hash="c" * 64, extra="Unicode Tiếng Việt 🌸")
    send_packet(alice, packet)
    assert recv_packet(bob) == packet


@pytest.mark.parametrize("change", [{"sender": "bob"}, {"recipient": []},
    {"recipient": "missing"}, {"ciphertext": None}, {"seq": True}, {"seq": -1},
    {"session_id": "bad"}, {"nonce": ""}, {"plaintext": "must_reject"},
    {"type": "file_chunk", "index": -1}, {"type": "session_init"}])
def test_invalid_routes_recover(relay, change):
    _, connect = relay
    alice, bob = connect("alice"), connect("bob")
    send_packet(alice, chat(**change))
    assert recv_packet(alice)["type"] == "error"
    send_packet(alice, chat())
    assert recv_packet(bob) == chat()


@pytest.mark.parametrize("field", ["sender", "recipient", "ciphertext", "seq", "nonce", "session_id"])
def test_missing_route_field(relay, field):
    _, connect = relay
    alice = connect("alice")
    packet = chat()
    del packet[field]
    send_packet(alice, packet)
    assert recv_packet(alice)["type"] == "error"


@pytest.mark.parametrize("wire", [struct.pack("!I", MAX_FRAME_BYTES + 1),
    struct.pack("!I", 5) + b'{bad}', struct.pack("!I", 2) + b'[]'])
def test_broken_frames_closed_and_other_client_survives(relay, wire):
    _, connect = relay
    bad, healthy = connect("bad"), connect("healthy")
    bad.sendall(wire)
    assert recv_packet(bad)["type"] == "error"
    with pytest.raises((EOFError, OSError)):
        recv_packet(bad)
    send_packet(healthy, {"type": "list_peers"})
    assert recv_packet(healthy)["type"] == "peers"


def test_reset_and_truncated_input_clean_registry(relay):
    server, connect = relay
    for name in ("reset", "truncated"):
        sock = connect(name)
        if name == "reset":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        else:
            sock.sendall(struct.pack("!I", 100) + b'{')
        sock.close()
        eventually(lambda: server.find(name) is None)
    connect("healthy")


def test_concurrent_senders_preserve_frames(relay):
    _, connect = relay
    bob = connect("bob")
    with ThreadPoolExecutor(max_workers=8) as pool:
        senders = list(pool.map(connect, [f"peer{i}" for i in range(8)]))
        def send_many(item):
            i, sock = item
            for seq in range(1, 21):
                send_packet(sock, chat(sender=f"peer{i}", seq=seq, ciphertext="x" * 2048))
        futures = [pool.submit(send_many, item) for item in enumerate(senders)]
        received = [recv_packet(bob) for _ in range(160)]
        for future in futures:
            future.result(timeout=3)
    for i in range(8):
        assert [p["seq"] for p in received if p["sender"] == f"peer{i}"] == list(range(1, 21))


@pytest.mark.parametrize("error", [BrokenPipeError, ConnectionResetError, TimeoutError])
def test_recipient_failure_unregisters_only_target(relay, monkeypatch, error):
    server, connect = relay
    alice, bob = connect("alice"), connect("bob")
    target = server.find("bob")
    def broken(packet):
        raise error("do not log this payload")
    monkeypatch.setattr(target, "reply", broken)
    send_packet(alice, chat())
    assert recv_packet(alice)["type"] == "error"
    eventually(lambda: server.find("bob") is None)
    assert server.find("alice") is not None


def test_handshake_idle_timeouts_and_capacity():
    with running(max_connections=1, handshake_timeout=0.15, idle_timeout=0.2) as (server, connect):
        silent = connect()
        eventually(lambda: len(server._connections) == 1)
        refused = connect()
        with pytest.raises((EOFError, OSError)):
            recv_packet(refused)
        with pytest.raises((EOFError, OSError)):
            recv_packet(silent)
        eventually(lambda: not server._connections)
        alice = connect("alice")
        with pytest.raises((EOFError, OSError)):
            recv_packet(alice)
        eventually(lambda: server.list_names() == [])


def test_close_wakes_live_handlers():
    server = RelayServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    sock = socket.create_connection(server.server_address, timeout=2)
    try:
        send_packet(sock, hello())
        assert recv_packet(sock)["type"] == "welcome"
        server.shutdown()
        closer = threading.Thread(target=server.server_close)
        closer.start()
        closer.join(3)
        assert not closer.is_alive()
        assert not server._connections
        assert server.list_names() == []
    finally:
        sock.close()
        server.shutdown()
        server.server_close()
        thread.join(3)


def test_logs_do_not_include_payload_or_mssv(relay, caplog):
    _, connect = relay
    caplog.set_level(logging.DEBUG, logger="securechat.server")
    alice, bob = connect("alice"), connect("bob")
    marker = "PRIVATE_PAYLOAD_MARKER"
    send_packet(alice, chat(ciphertext=marker))
    assert recv_packet(bob)["ciphertext"] == marker
    assert marker not in caplog.text
    assert MSSVS[0] not in caplog.text
    assert "Client joined" in caplog.text
    eventually(lambda: "Routed" in caplog.text)


def test_actual_chatclients_two_way_chat_files(relay, paired_sessions, monkeypatch):
    """Exercise real connect(), command(), receive loop, crypto and FileReceiver."""
    server, _ = relay
    _, _, root = paired_sessions
    clients, threads, received, wire_packets = [], [], [], []
    from securechat.server import RelayHandler
    original_reply = RelayHandler.reply
    def observe_reply(self, packet):
        if packet["type"] in {"chat", "file_meta", "file_chunk", "file_done", "session_init"}:
            wire_packets.append(packet.copy())
        return original_reply(self, packet)
    monkeypatch.setattr(RelayHandler, "reply", observe_reply)
    try:
        for name in ("alice", "bob"):
            client = ChatClient(name, MSSVS, root / "identities" / name,
                                root / "trusted" / name, root / "received" / name,
                                *server.server_address)
            clients.append(client)
            loop = client._receive_loop
            def tracked_loop(loop=loop):
                threads.append(threading.current_thread())
                loop()
            monkeypatch.setattr(client, "_receive_loop", tracked_loop)
            decrypt = client.session.decrypt_payload
            def observed(packet, decrypt=decrypt, name=name):
                data = decrypt(packet)
                if packet["type"] == "chat":
                    received.append((name, data))
                return data
            monkeypatch.setattr(client.session, "decrypt_payload", observed)
            client.connect()
        for sender, receiver in ((clients[0], clients[1]), (clients[1], clients[0])):
            sender.command(f"/connect {receiver.name}")
            message = f"Bí mật 🌸 từ {sender.name}"
            sender.command(f"/msg {receiver.name} {message}")
            eventually(lambda: (receiver.name, message.encode()) in received)
            for size in (0, 1024, 70000):
                source = root / f"dữ_liệu_{sender.name}_{size}.txt"
                marker = b"PRIVATE_FILE_MARKER"
                source.write_bytes((marker * (size // len(marker) + 1))[:size])
                sender.command(f"/file {receiver.name} {source}")
                folder = root / "received" / receiver.name
                eventually(lambda: bool(list(folder.glob(f"*_{source.name}"))))
                saved = next(folder.glob(f"*_{source.name}"))
                assert saved.read_bytes() == source.read_bytes()
                assert hashlib.sha256(saved.read_bytes()).digest() == hashlib.sha256(source.read_bytes()).digest()
        wire = b"".join(pack_packet(p) for p in wire_packets)
        assert "Bí mật".encode() not in wire
        assert b"PRIVATE_FILE_MARKER" not in wire
        assert "dữ_liệu".encode() not in wire
        assert not hasattr(server, "private_key")
        assert len(received) == 2
        assert not list((root / "received").rglob("*.part"))
    finally:
        for client in clients:
            client.close()
        for thread in threads:
            thread.join(3)
            assert not thread.is_alive()


def test_atomic_duplicate_registration(relay):
    server, connect = relay
    barrier = threading.Barrier(8)
    def register(_):
        sock = connect()
        barrier.wait(timeout=3)
        send_packet(sock, hello("same_name"))
        return recv_packet(sock)["type"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(register, range(8)))
    assert results.count("welcome") == 1
    assert results.count("error") == 7
    assert server.list_names() == ["same_name"]


def test_welcome_precedes_racing_route(relay, monkeypatch):
    server, connect = relay
    alice, bob = connect("alice"), connect()
    published, release = threading.Event(), threading.Event()
    original = server.register
    def paused_register(name, handler):
        result = original(name, handler)
        if name == "bob":
            published.set()
            assert release.wait(3)
        return result
    monkeypatch.setattr(server, "register", paused_register)
    try:
        send_packet(bob, hello("bob"))
        assert published.wait(3)
        send_packet(alice, chat())
    finally:
        release.set()
    assert recv_packet(bob)["type"] == "welcome"
    assert recv_packet(bob) == chat()


def test_cli_sigint_exits_with_open_client():
    import os
    import signal
    import subprocess
    import sys
    if os.name != "posix":
        pytest.skip("SIGINT subprocess test requires POSIX; lifecycle tests remain portable")
    process = subprocess.Popen([sys.executable, "-u", "-m", "securechat.server", "--port", "0"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = []
    reader = threading.Thread(target=lambda: lines.extend(iter(process.stderr.readline, "")))
    reader.start()
    client = None
    try:
        eventually(lambda: any("Relay listening at" in line for line in lines))
        line = next(line for line in lines if "Relay listening at" in line)
        port = int(line.rsplit(":", 1)[1])
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        send_packet(client, hello())
        assert recv_packet(client)["type"] == "welcome"
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=3) == 0
    finally:
        if client is not None:
            client.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        reader.join(3)
        process.stdout.close()
        process.stderr.close()
        assert not reader.is_alive()


@pytest.mark.parametrize("phase", ["silent", "partial_header", "partial_body", "registered"])
def test_close_without_cross_thread_shutdown_wakeup(monkeypatch, phase):
    """Closing must not rely on OS shutdown waking a read in another thread."""
    server = RelayServer(("127.0.0.1", 0), handshake_timeout=30, idle_timeout=30)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    sock = socket.create_connection(server.server_address, timeout=2)
    closer = None
    try:
        wire = pack_packet(hello())
        if phase == "partial_header":
            sock.sendall(wire[:2])
        elif phase == "partial_body":
            sock.sendall(wire[:12])
        elif phase == "registered":
            sock.sendall(wire)
            assert recv_packet(sock)["type"] == "welcome"
        eventually(lambda: len(server._connections) == 1)
        # Simulate an OS where shutdown fails to wake the waiting reader.
        monkeypatch.setattr(socket.socket, "shutdown", lambda *args: None)
        server.shutdown()
        closer = threading.Thread(target=server.server_close)
        closer.start()
        closer.join(2)
        assert not closer.is_alive()
        assert server.list_names() == []
        assert not server._connections
    finally:
        sock.close()
        server.shutdown()
        if closer is not None:
            closer.join(3)
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


def test_fragmented_hello_survives_multiple_poll_intervals(relay):
    _, connect = relay
    sock = connect()
    wire = pack_packet(hello())
    sock.sendall(wire[:2])
    time.sleep(0.15)
    sock.sendall(wire[2:12])
    time.sleep(0.15)
    sock.sendall(wire[12:])
    assert recv_packet(sock)["type"] == "welcome"
    send_packet(sock, {"type": "list_peers"})
    assert recv_packet(sock)["names"] == ["alice"]
