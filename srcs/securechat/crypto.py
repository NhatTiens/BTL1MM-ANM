"""Owner 2 - Cryptographic primitives and the MSSV-based HKDF context.

Security note: MSSVs are public. SHA256(MSSV1 || MSSV2 || ...) is NEVER
used as the sole secret encryption key: a fresh random secret is required.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .protocol import canonical_json


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def validate_mssvs(mssvs: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(str(value).strip() for value in mssvs)
    if not (2 <= len(normalized) <= 4) or not all(v.isascii() and v.isdigit() for v in normalized):
        raise ValueError("Supply 2 to 4 numeric MSSVs, in the same order on each client")
    return normalized


def group_seed(mssvs: Sequence[str]) -> bytes:
    """Assignment rule: SHA256(MSSV_1 || MSSV_2 || ...), no separators."""
    mssvs = validate_mssvs(mssvs)
    return hashlib.sha256("".join(mssvs).encode("ascii")).digest()


def handshake_text(mssvs: Sequence[str]) -> str:
    return "Hello, We are " + ", ".join(validate_mssvs(mssvs))


def generate_identity(folder: Path) -> None:
    """Generate one local RSA identity. MUST NOT run on tracked source folders."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    private_path = folder / "private.pem"
    public_path = folder / "public.pem"
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"Identity already exists in {folder}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    private_path.write_bytes(data)
    if os.name == "posix":
        private_path.chmod(0o600)
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private(path: Path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public(path: Path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def make_session_key(mssvs: Sequence[str]) -> bytes:
    """HKDF(random 32-byte secret, salt=SHA256(MSSV concatenation)).

    TODO[OWNER-2]: document key rotation and session expiry policy.
    """
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=group_seed(mssvs),
                info=b"btl1-e2ee-chat/session-key/v1").derive(os.urandom(32))


def wrap_key(peer_public, key: bytes) -> str:
    return b64(peer_public.encrypt(key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))


def unwrap_key(my_private, wrapped: str) -> bytes:
    value = my_private.decrypt(unb64(wrapped), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    if len(value) != 32:
        raise ValueError("Invalid AES-256 session key")
    return value


def sign_object(my_private, obj: dict[str, Any]) -> str:
    signature = my_private.sign(canonical_json(obj), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return b64(signature)


def verify_object(peer_public, obj: dict[str, Any], signature: str) -> None:
    peer_public.verify(unb64(signature), canonical_json(obj), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[str, str]:
    nonce = os.urandom(12)
    return b64(nonce), b64(AESGCM(key).encrypt(nonce, plaintext, aad))


def decrypt(key: bytes, nonce: str, ciphertext: str, aad: bytes) -> bytes:
    nonce_bytes = unb64(nonce)
    if len(nonce_bytes) != 12:
        raise ValueError("Invalid AES-GCM nonce")
    return AESGCM(key).decrypt(nonce_bytes, unb64(ciphertext), aad)
