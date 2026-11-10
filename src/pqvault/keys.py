"""Key files.

Public key:  one line, "pqv1pub:" + base64 of the hybrid public key. Safe to share.
Private key: text file whose body is the raw private key encrypted with a
             passphrase using the regular .pqv format (Argon2id + AES-256-GCM).
"""

from __future__ import annotations

import base64
import binascii
import io
import os
import textwrap
from pathlib import Path

from . import DecryptionError, PQVaultError, format, kem
from .password import Argon2Params

PUBLIC_PREFIX = "pqv1pub:"
_BEGIN = "-----BEGIN PQVAULT PRIVATE KEY-----"
_END = "-----END PQVAULT PRIVATE KEY-----"


def encode_public(pk: kem.PublicKey) -> str:
    return PUBLIC_PREFIX + base64.b64encode(pk.raw).decode()


def decode_public(text: str) -> kem.PublicKey:
    text = text.strip()
    if not text.startswith(PUBLIC_PREFIX):
        raise PQVaultError("not a pqvault public key")
    try:
        raw = base64.b64decode(text[len(PUBLIC_PREFIX) :], validate=True)
    except binascii.Error:
        raise PQVaultError("public key is not valid base64") from None
    return kem.PublicKey(raw)


def encode_private(sk: kem.PrivateKey, passphrase: bytes, argon_params: Argon2Params | None = None) -> str:
    out = io.BytesIO()
    format.encrypt(io.BytesIO(sk.raw), out, passwords=[passphrase], argon_params=argon_params)
    body = textwrap.fill(base64.b64encode(out.getvalue()).decode(), 64)
    return (
        "# pqvault private key - KEEP SECRET, never share this file\n"
        f"# public key: {encode_public(sk.public_key)}\n"
        f"{_BEGIN}\n{body}\n{_END}\n"
    )


def decode_private(text: str, passphrase: bytes) -> kem.PrivateKey:
    try:
        start = text.index(_BEGIN) + len(_BEGIN)
        end = text.index(_END)
        blob = base64.b64decode("".join(text[start:end].split()), validate=True)
    except (ValueError, binascii.Error):
        raise PQVaultError("not a valid pqvault private key file") from None
    out = io.BytesIO()
    try:
        format.decrypt(io.BytesIO(blob), out, password=passphrase)
    except DecryptionError:
        raise DecryptionError("wrong passphrase for private key") from None
    return kem.PrivateKey(out.getvalue())


def write_keypair(base: Path, passphrase: bytes, argon_params: Argon2Params | None = None) -> tuple[Path, Path]:
    pub_path, key_path = base.with_name(base.name + ".pub"), base.with_name(base.name + ".key")
    for p in (pub_path, key_path):
        if p.exists():
            raise PQVaultError(f"{p} already exists; refusing to overwrite")
    sk = kem.PrivateKey.generate()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(encode_private(sk, passphrase, argon_params))
    pub_path.write_text(encode_public(sk.public_key) + "\n")
    return pub_path, key_path
