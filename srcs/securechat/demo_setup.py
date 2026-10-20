"""Create local, throwaway Alice/Bob key material under .local/ (ignored by Git).

Local demo autotrust MUST NOT be used to assert real-world MitM protection:
verify peer public-key fingerprints over a separate authenticated channel.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from .crypto import fingerprint, generate_identity, load_public


def setup(root: Path) -> None:
    root = Path(root)
    for user in ("alice", "bob"):
        generate_identity(root / "identities" / user)
    for owner, peer in (("alice", "bob"), ("bob", "alice")):
        destination = root / "trusted" / owner
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / "identities" / peer / "public.pem", destination / f"{peer}.pem")
    for user in ("alice", "bob"):
        fp = fingerprint(load_public(root / "identities" / user / "public.pem"))
        print(f"{user}: SHA256 fingerprint {fp}")
    print("Local demo keys ready. Never commit .local/ or assume automatic trust is safe outside a demo.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate local demo identity and trust files")
    parser.add_argument("--root", type=Path, default=Path(".local"))
    args = parser.parse_args()
    setup(args.root)


if __name__ == "__main__":
    main()
