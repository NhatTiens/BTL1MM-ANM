import json

import pytest
from cryptography.exceptions import InvalidTag

from securechat.transfer import FileReceiver, send_file


def test_end_to_end_encrypted_file(paired_sessions, tmp_path):
    alice, bob, _ = paired_sessions
    bob.accept_session_init(alice.create_session_init("bob"))
    source = tmp_path / "report.txt"
    source.write_bytes(b"confidential" * 7000)
    packets = []
    transfer_id = send_file(alice, "bob", source, packets.append)
    assert transfer_id and len(packets) >= 4
    assert all("confidential" not in json.dumps(p) for p in packets)
    receiver = FileReceiver(tmp_path / "downloads")
    final = None
    for packet in packets:
        result = receiver.handle(packet, bob)
        if result is not None:
            final = result
    assert final is not None
    assert open(final, "rb").read() == source.read_bytes()


def test_transfer_tamper_is_rejected(paired_sessions, tmp_path):
    alice, bob, _ = paired_sessions
    bob.accept_session_init(alice.create_session_init("bob"))
    source = tmp_path / "file.bin"
    source.write_bytes(b"my file")
    packets = []
    send_file(alice, "bob", source, packets.append)
    receiver = FileReceiver(tmp_path / "downloads")
    receiver.handle(packets[0], bob)
    with pytest.raises(InvalidTag):
        receiver.handle({**packets[1], "index": 99}, bob)


def test_empty_file(paired_sessions, tmp_path):
    alice, bob, _ = paired_sessions
    bob.accept_session_init(alice.create_session_init("bob"))
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")
    packets = []
    send_file(alice, "bob", source, packets.append)
    receiver = FileReceiver(tmp_path / "downloads")
    last = None
    for packet in packets:
        last = receiver.handle(packet, bob)
    assert last is not None
    assert open(last, "rb").read() == b""
