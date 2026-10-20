import socket
import threading

from securechat.crypto import group_seed, handshake_text
from securechat.protocol import VERSION, recv_packet, send_packet
from securechat.server import RelayServer


def _hello(sock, name):
    mssvs = ["2312345", "2312346"]
    send_packet(sock, {"type": "hello", "version": VERSION, "name": name,
                       "mssvs": mssvs, "handshake": handshake_text(mssvs),
                       "group_seed_hash": group_seed(mssvs).hex()})
    return recv_packet(sock)


def test_server_forwards_ciphertext_without_decrypting():
    server = RelayServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    a = b = None
    try:
        a = socket.create_connection(server.server_address, timeout=2)
        b = socket.create_connection(server.server_address, timeout=2)
        a.settimeout(3)
        b.settimeout(3)
        assert _hello(a, "alice")["type"] == "welcome"
        assert _hello(b, "bob")["type"] == "welcome"
        frame = {"type": "chat", "sender": "alice", "recipient": "bob",
                 "ciphertext": "opaque_data_only", "seq": 1}
        send_packet(a, frame)
        assert recv_packet(b) == frame
        send_packet(a, {**frame, "sender": "bob"})
        assert recv_packet(a)["type"] == "error"
    finally:
        if a is not None:
            a.close()
        if b is not None:
            b.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
