"""Key files.

Public key:  one line, safe to share.
  "pqv2pub:" + base64(kem_public || verify_key)     current
  "pqv1pub:" + base64(kem_public)                   v0.1 keys: encryption only
Private key: text file whose body is the raw private key material encrypted
  with a passphrase using the regular .pqv format (Argon2id + AES-256-GCM).
"""

from __future__ import annotations

import base64
import binascii
import io
import os
import textwrap
from pathlib import Path

from . import DecryptionError, PQVaultError, format, kem
from .identity import PUBLIC_SIZE, Identity, PublicIdentity
from .password import Argon2Params

PUBLIC_PREFIX_V1 = "pqv1pub:"
PUBLIC_PREFIX = "pqv2pub:"
_BEGIN = "-----BEGIN PQVAULT PRIVATE KEY-----"
_END = "-----END PQVAULT PRIVATE KEY-----"


def encode_public(pub: PublicIdentity) -> str:
    prefix = PUBLIC_PREFIX if pub.verify else PUBLIC_PREFIX_V1
    return prefix + base64.b64encode(pub.raw).decode()


def decode_public(text: str) -> PublicIdentity:
    text = text.strip()
    if text.startswith(PUBLIC_PREFIX):
        prefix, size = PUBLIC_PREFIX, PUBLIC_SIZE
    elif text.startswith(PUBLIC_PREFIX_V1):
        prefix, size = PUBLIC_PREFIX_V1, kem.PUBLIC_KEY_SIZE
    else:
        raise PQVaultError("not a pqvault public key")
    try:
        raw = base64.b64decode(text[len(prefix):], validate=True)
    except binascii.Error:
        raise PQVaultError("public key is not valid base64") from None
    if len(raw) != size:
        raise PQVaultError("public key has the wrong length")
    return PublicIdentity.from_raw(raw)


def encode_private(identity: Identity, passphrase: bytes, argon_params: Argon2Params | None = None) -> str:
    out = io.BytesIO()
    format.encrypt(io.BytesIO(identity.raw), out, passwords=[passphrase], argon_params=argon_params)
    body = textwrap.fill(base64.b64encode(out.getvalue()).decode(), 64)
    return (
        "# pqvault private key - KEEP SECRET, never share this file\n"
        f"# fingerprint: {identity.public.fingerprint}\n"
        f"{_BEGIN}\n{body}\n{_END}\n"
    )


def decode_private(text: str, passphrase: bytes) -> Identity:
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
    return Identity.from_raw(out.getvalue())


def write_keypair(base: Path, passphrase: bytes, argon_params: Argon2Params | None = None) -> tuple[Path, Path, Identity]:
    pub_path, key_path = base.with_name(base.name + ".pub"), base.with_name(base.name + ".key")
    for p in (pub_path, key_path):
        if p.exists():
            raise PQVaultError(f"{p} already exists; refusing to overwrite")
    identity = Identity.generate()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(encode_private(identity, passphrase, argon_params))
    pub_path.write_text(encode_public(identity.public) + "\n")
    return pub_path, key_path, identity
