"""Ed25519 signing keys live outside the report directory and outside the repo."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a3p.env import setting


def key_dir() -> Path:
    raw = setting("KEY_DIR")
    path = Path(raw).expanduser() if raw else Path.home() / ".a3p" / "keys"
    path.mkdir(parents=True, exist_ok=True)
    return path


def generate(directory: Path | None = None) -> Path:
    directory = directory or key_dir()
    directory.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = directory / "current.pem"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    (directory / "current.pub").write_text(public.hex() + "\n", encoding="utf-8")
    return path


def rotate(directory: Path | None = None) -> Path:
    directory = directory or key_dir()
    directory.mkdir(parents=True, exist_ok=True)
    current = directory / "current.pem"
    public = directory / "current.pub"
    if current.exists():
        archive = directory / "archive"
        archive.mkdir(exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        current.replace(archive / f"{stamp}.pem")
        if public.exists():
            with (directory / "trusted.pub").open("a", encoding="utf-8") as handle:
                handle.write(public.read_text(encoding="utf-8").strip() + "\n")
    return generate(directory)


def load_private(directory: Path | None = None) -> tuple[Ed25519PrivateKey, Path]:
    directory = directory or key_dir()
    path = directory / "current.pem"
    if not path.exists():
        generate(directory)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key, path
