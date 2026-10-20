"""Owner 4 - Shared test fixtures for team security and regression tests."""
import shutil
from pathlib import Path

import pytest

from securechat.crypto import generate_identity
from securechat.session import SessionManager

MSSVS = ["2312345", "2312346", "2312347", "2312348"]


@pytest.fixture
def paired_sessions(tmp_path: Path):
    for name in ("alice", "bob", "mallory"):
        generate_identity(tmp_path / "identities" / name)
    for name, peer in (("alice", "bob"), ("bob", "alice")):
        trust = tmp_path / "trusted" / name
        trust.mkdir(parents=True)
        shutil.copyfile(tmp_path / "identities" / peer / "public.pem", trust / f"{peer}.pem")

    def make(name: str) -> SessionManager:
        return SessionManager(name, MSSVS, tmp_path / "identities" / name,
                              tmp_path / "trusted" / name)
    return make("alice"), make("bob"), tmp_path
