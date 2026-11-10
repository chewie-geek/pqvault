"""The .pqv container format.

    "PQV1" | version (u8) | header_len (u32) | header | header_mac (32) | payload

    header  = flags (u8) | payload_salt (16) | n_stanzas (u16) | stanzas
    stanza  = type (u8) | body_len (u32) | body

Every stanza wraps the same random 256-bit file key, so a file can be opened
by a password or by any of several recipients. The header MAC (keyed from the
file key) authenticates the whole header; the payload key is derived from the
file key and the per-file payload salt.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterable, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import DecryptionError, PQVaultError, kem, stream
from .password import DEFAULT_PARAMS, SALT_SIZE, Argon2Params, derive_key

MAGIC = b"PQV1"
VERSION = 1
FILE_KEY_SIZE = 32
MAC_SIZE = 32
PAYLOAD_SALT_SIZE = 16
MAX_HEADER_SIZE = 1 << 20
WRAPPED_KEY_SIZE = FILE_KEY_SIZE + 16

FLAG_DIRECTORY = 0x01  # payload is a tar archive of a folder
_KNOWN_FLAGS = FLAG_DIRECTORY

STANZA_PASSWORD = 1
STANZA_RECIPIENT = 2

_PREFIX = struct.Struct(">4sBI")
_ZERO_NONCE = bytes(12)  # safe: every wrap key is used exactly once


@dataclass
class Header:
    flags: int
    payload_salt: bytes
    stanzas: list[tuple[int, bytes]] = field(default_factory=list)
    authenticated: bytes = b""  # prefix + header bytes, covered by the MAC
    mac: bytes = b""

    @property
    def has_password(self) -> bool:
        return any(t == STANZA_PASSWORD for t, _ in self.stanzas)

    @property
    def has_recipients(self) -> bool:
        return any(t == STANZA_RECIPIENT for t, _ in self.stanzas)


def _hkdf(key: bytes, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(key)


def _mac(file_key: bytes, data: bytes) -> bytes:
    return hmac.new(_hkdf(file_key, None, b"pqvault-v1 header"), data, hashlib.sha256).digest()


def _wrap(key: bytes, file_key: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(_ZERO_NONCE, file_key, aad)


def _unwrap(key: bytes, wrapped: bytes, aad: bytes) -> bytes | None:
    try:
        return AESGCM(key).decrypt(_ZERO_NONCE, wrapped, aad)
    except InvalidTag:
        return None


_PW_FIXED = struct.Struct(">16sIIB")
_PW_AAD = b"pqvault-v1 password stanza"
_RCPT_AAD = b"pqvault-v1 recipient stanza"


def _password_stanza(file_key: bytes, password: bytes, params: Argon2Params) -> bytes:
    salt = os.urandom(SALT_SIZE)
    fixed = _PW_FIXED.pack(salt, params.memory_kib, params.iterations, params.lanes)
    wrap_key = derive_key(password, salt, params)
    return fixed + _wrap(wrap_key, file_key, _PW_AAD + fixed)


def _recipient_stanza(file_key: bytes, pk: kem.PublicKey) -> bytes:
    ss, enc = kem.encapsulate(pk)
    return enc + _wrap(ss, file_key, _RCPT_AAD + enc)


def encrypt(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    passwords: Sequence[bytes] = (),
    recipients: Sequence[kem.PublicKey] = (),
    flags: int = 0,
    argon_params: Argon2Params | None = None,
) -> None:
    if not passwords and not recipients:
        raise PQVaultError("need at least one password or recipient")
    if len(passwords) > 1:
        raise PQVaultError("at most one password per file")
    params = argon_params or DEFAULT_PARAMS

    file_key = os.urandom(FILE_KEY_SIZE)
    payload_salt = os.urandom(PAYLOAD_SALT_SIZE)
    stanzas = [(STANZA_PASSWORD, _password_stanza(file_key, p, params)) for p in passwords]
    stanzas += [(STANZA_RECIPIENT, _recipient_stanza(file_key, r)) for r in recipients]

    body = bytearray(struct.pack(">B", flags) + payload_salt + struct.pack(">H", len(stanzas)))
    for stype, sbody in stanzas:
        body += struct.pack(">BI", stype, len(sbody)) + sbody
    authenticated = _PREFIX.pack(MAGIC, VERSION, len(body)) + bytes(body)

    dst.write(authenticated + _mac(file_key, authenticated))
    stream.encrypt(_payload_key(file_key, payload_salt), src, dst)


def read_header(src: BinaryIO) -> Header:
    prefix = src.read(_PREFIX.size)
    if len(prefix) < _PREFIX.size:
        raise PQVaultError("not a pqvault file (too short)")
    magic, version, length = _PREFIX.unpack(prefix)
    if magic != MAGIC:
        raise PQVaultError("not a pqvault file")
    if version != VERSION:
        raise PQVaultError(f"unsupported pqvault format version {version}")
    if length > MAX_HEADER_SIZE:
        raise PQVaultError("header too large")
    body = src.read(length)
    mac = src.read(MAC_SIZE)
    if len(body) != length or len(mac) != MAC_SIZE:
        raise PQVaultError("file is truncated")

    r = io.BytesIO(body)

    def take(n: int) -> bytes:
        b = r.read(n)
        if len(b) != n:
            raise PQVaultError("malformed header")
        return b

    flags = take(1)[0]
    if flags & ~_KNOWN_FLAGS:
        raise PQVaultError("file uses unknown features")
    payload_salt = take(PAYLOAD_SALT_SIZE)
    (count,) = struct.unpack(">H", take(2))
    stanzas = []
    for _ in range(count):
        stype, slen = struct.unpack(">BI", take(5))
        stanzas.append((stype, take(slen)))
    if r.read(1):
        raise PQVaultError("malformed header (trailing data)")
    return Header(flags, payload_salt, stanzas, prefix + body, mac)


def unlock(
    header: Header,
    *,
    password: bytes | None = None,
    identities: Iterable[kem.PrivateKey] = (),
) -> bytes:
    """Recover and verify the file key, or raise DecryptionError."""
    identities = list(identities)
    for stype, body in header.stanzas:
        file_key = None
        if stype == STANZA_PASSWORD and password is not None:
            if len(body) != _PW_FIXED.size + WRAPPED_KEY_SIZE:
                raise PQVaultError("malformed password stanza")
            fixed = body[: _PW_FIXED.size]
            salt, mem, iters, lanes = _PW_FIXED.unpack(fixed)
            key = derive_key(password, salt, Argon2Params(mem, iters, lanes))
            file_key = _unwrap(key, body[_PW_FIXED.size :], _PW_AAD + fixed)
        elif stype == STANZA_RECIPIENT and identities:
            if len(body) != kem.ENCAPSULATION_SIZE + WRAPPED_KEY_SIZE:
                raise PQVaultError("malformed recipient stanza")
            enc = body[: kem.ENCAPSULATION_SIZE]
            for ident in identities:
                file_key = _unwrap(kem.decapsulate(ident, enc), body[kem.ENCAPSULATION_SIZE :], _RCPT_AAD + enc)
                if file_key:
                    break
        if file_key is not None:
            if not hmac.compare_digest(_mac(file_key, header.authenticated), header.mac):
                raise DecryptionError("header authentication failed (file tampered with)")
            return file_key
    if password is not None:
        raise DecryptionError("wrong password, or the file was not encrypted with a password")
    raise DecryptionError("none of the given keys can decrypt this file")


def _payload_key(file_key: bytes, payload_salt: bytes) -> bytes:
    return _hkdf(file_key, payload_salt, b"pqvault-v1 payload")


def decrypt_payload(header: Header, file_key: bytes, src: BinaryIO, dst: BinaryIO) -> None:
    stream.decrypt(_payload_key(file_key, header.payload_salt), src, dst)


def decrypt(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    password: bytes | None = None,
    identities: Iterable[kem.PrivateKey] = (),
) -> Header:
    header = read_header(src)
    file_key = unlock(header, password=password, identities=identities)
    decrypt_payload(header, file_key, src, dst)
    return header
