import shutil

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from securechat.session import SecureSessionError


def test_signed_handshake_and_e2ee_chat(paired_sessions):
    alice, bob, _ = paired_sessions
    init = alice.create_session_init("bob")
    assert bob.accept_session_init(init) == "alice"
    packet = alice.encrypt_payload("chat", "bob", "Vietnamese: xin chào".encode())
    assert "xin chào" not in str(packet)
    assert bob.decrypt_payload(packet).decode() == "Vietnamese: xin chào"
    with pytest.raises(SecureSessionError, match="Replay"):
        bob.decrypt_payload(packet)
    with pytest.raises(SecureSessionError, match="Replay"):
        bob.accept_session_init(init)


def test_no_unverified_peer_allowed(paired_sessions):
    alice, _, _ = paired_sessions
    with pytest.raises(SecureSessionError, match="No pinned key"):
        alice.create_session_init("unknown")


def test_mitm_swap_of_pinned_public_key_fails(paired_sessions):
    alice, bob, root = paired_sessions
    init = alice.create_session_init("bob")
    # An attacker replaces Bob's pinned copy of Alice's public key.
    shutil.copyfile(root / "identities" / "mallory" / "public.pem",
                    root / "trusted" / "bob" / "alice.pem")
    with pytest.raises(InvalidSignature):
        bob.accept_session_init(init)


def test_tampering_aad_detected(paired_sessions):
    alice, bob, _ = paired_sessions
    bob.accept_session_init(alice.create_session_init("bob"))
    packet = alice.encrypt_payload("chat", "bob", b"private")
    with pytest.raises(InvalidTag):
        bob.decrypt_payload({**packet, "seq": packet["seq"] + 1})
