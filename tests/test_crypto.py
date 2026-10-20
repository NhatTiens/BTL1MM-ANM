import hashlib

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from securechat import crypto


def test_required_mssv_sha256():
    ids = ["2312345", "2312346"]
    assert crypto.group_seed(ids) == hashlib.sha256(b"23123452312346").digest()
    assert crypto.handshake_text(ids) == "Hello, We are 2312345, 2312346"


def test_aesgcm_rejects_modified_ciphertext():
    key = crypto.make_session_key(["2312345", "2312346"])
    nonce, ciphertext = crypto.encrypt(key, b"sensitive message", b"fixed aad")
    assert crypto.decrypt(key, nonce, ciphertext, b"fixed aad") == b"sensitive message"
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, nonce, ciphertext, b"altered aad")


def test_rsa_signature_and_key_exchange(tmp_path):
    crypto.generate_identity(tmp_path)
    priv = crypto.load_private(tmp_path / "private.pem")
    pub = crypto.load_public(tmp_path / "public.pem")
    session_key = crypto.make_session_key(["2312345", "2312346"])
    assert crypto.unwrap_key(priv, crypto.wrap_key(pub, session_key)) == session_key
    signed = {"type": "session_init", "sender": "alice"}
    signature = crypto.sign_object(priv, signed)
    crypto.verify_object(pub, signed, signature)
    with pytest.raises(InvalidSignature):
        crypto.verify_object(pub, {**signed, "sender": "mallory"}, signature)
