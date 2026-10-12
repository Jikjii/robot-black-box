"""Ed25519 signing keys for the black box.

Private keys are stored as unencrypted PKCS#8 PEM files with owner-only permissions.
Public keys are stored as one line of hex (the raw 32-byte key), which is what the log's
genesis record carries and what `blackbox verify --pubkey` pins against.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    """Return the raw 32-byte public key as lowercase hex."""
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def public_from_hex(value: str) -> Ed25519PublicKey:
    raw = bytes.fromhex(value.strip())
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes (64 hex characters)")
    return Ed25519PublicKey.from_public_bytes(raw)


def save_private(key: Ed25519PrivateKey, path: str | Path) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Write a brand-new owner-only file and move it into place, so an existing file's looser
    # permissions can never carry over to the new secret.
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_private(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def save_public(key: Ed25519PrivateKey | Ed25519PublicKey, path: str | Path) -> None:
    Path(path).write_text(public_hex(key) + "\n", encoding="ascii")


def load_public_hex(path: str | Path) -> str:
    value = Path(path).read_text(encoding="ascii").strip().lower()
    public_from_hex(value)  # validate
    return value
