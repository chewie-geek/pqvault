"""The .pqv container format.

    "PQV1" | version (u8) | header_len (u32) | header | header_mac (32) | payload

    header  = flags (u8) | payload_salt (16) | n_stanzas (u16) | stanzas
    stanza  = type (u8) | body_len (u32) | body

Every stanza wraps the same random 256-bit file key, so a file can be opened
by a password or by any of several recipients. The header MAC (keyed from the
file key) authenticates the whole header; the payload key is derived from the
file key and the per-file payload salt.

Signed files (flag FLAG_SIGNED) carry a fixed-size trailer at the END OF THE
PLAINTEXT, so it is encrypted along with the data (only recipients learn who
signed):

    trailer = signed_at u64 | signer_public_identity (3200) | hybrid signature (3373)
    signed message = domain | signed_at | SHA-512(header) | SHA-512(signer) | SHA-512(data)

Binding the header means the signature covers this exact set of recipients:
a recipient cannot strip the encryption and re-send the signed content to
someone else under the original sender's name.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import struct
import time
from dataclasses import dataclass, field
from typing import BinaryIO, Iterable, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import DecryptionError, PQVaultError, kem, signing, stream
from .identity import (PUBLIC_SIZE, TIMESTAMP, Identity, PublicIdentity, SignatureInfo,
                       require_fresh, require_signer, signable)
from .password import DEFAULT_PARAMS, SALT_SIZE, Argon2Params, derive_key

MAGIC = b"PQV1"
VERSION = 1
FILE_KEY_SIZE = 32
MAC_SIZE = 32
PAYLOAD_SALT_SIZE = 16
MAX_HEADER_SIZE = 1 << 20
WRAPPED_KEY_SIZE = FILE_KEY_SIZE + 16

FLAG_DIRECTORY = 0x01  # payload is a tar archive of a folder
FLAG_SIGNED = 0x02  # plaintext ends with a signature trailer
_KNOWN_FLAGS = FLAG_DIRECTORY | FLAG_SIGNED

TRAILER_SIZE = TIMESTAMP.size + PUBLIC_SIZE + signing.SIGNATURE_SIZE
_SIG_CONTEXT = b"pqvault-v1 file"

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
    signer: Identity | None = None,
    signed_at: int | None = None,
) -> None:
    if not passwords and not recipients:
        raise PQVaultError("need at least one password or recipient")
    if len(passwords) > 1:
        raise PQVaultError("at most one password per file")
    params = argon_params or DEFAULT_PARAMS

    file_key = os.urandom(FILE_KEY_SIZE)
    payload_salt = os.urandom(PAYLOAD_SALT_SIZE)
    if signer is not None:
        signable(signer.public)
        flags |= FLAG_SIGNED
    stanzas = [(STANZA_PASSWORD, _password_stanza(file_key, p, params)) for p in passwords]
    stanzas += [(STANZA_RECIPIENT, _recipient_stanza(file_key, r)) for r in recipients]

    body = bytearray(struct.pack(">B", flags) + payload_salt + struct.pack(">H", len(stanzas)))
    for stype, sbody in stanzas:
        body += struct.pack(">BI", stype, len(sbody)) + sbody
    authenticated = _PREFIX.pack(MAGIC, VERSION, len(body)) + bytes(body)

    dst.write(authenticated + _mac(file_key, authenticated))
    if signer is not None:
        when = int(time.time()) if signed_at is None else signed_at
        src = _SigningReader(src, signer, authenticated, when)
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


def _signed_message(header_bytes: bytes, signer: PublicIdentity, data_digest: bytes, signed_at: int) -> bytes:
    return (
        b"pqvault-v1 file signature\x00"
        + TIMESTAMP.pack(signed_at)
        + hashlib.sha512(header_bytes).digest()
        + hashlib.sha512(signer.raw).digest()
        + data_digest
    )


class _SigningReader:
    """Passes data through while hashing it; at EOF, emits the signature trailer."""

    def __init__(self, src: BinaryIO, signer: Identity, header_bytes: bytes, signed_at: int):
        self._src, self._signer, self._header, self._when = src, signer, header_bytes, signed_at
        self._hash = hashlib.sha512()
        self._tail: bytes | None = None

    def read(self, n: int) -> bytes:
        if self._tail is None:
            data = self._src.read(n)
            if data:
                self._hash.update(data)
                return data
            pub = self._signer.public
            msg = _signed_message(self._header, pub, self._hash.digest(), self._when)
            sig = signing.sign(self._signer.signing, msg, _SIG_CONTEXT)
            self._tail = TIMESTAMP.pack(self._when) + pub.raw + sig
        out, self._tail = self._tail[:n], self._tail[n:]
        return out


class _VerifyingWriter:
    """Writes all but the last TRAILER_SIZE bytes through, hashing them."""

    def __init__(self, dst: BinaryIO):
        self._dst = dst
        self._buf = bytearray()
        self._hash = hashlib.sha512()

    def write(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > TRAILER_SIZE:
            cut = len(self._buf) - TRAILER_SIZE
            out = bytes(self._buf[:cut])
            self._hash.update(out)
            self._dst.write(out)
            del self._buf[:cut]

    def finish(self, header_bytes: bytes) -> SignatureInfo:
        if len(self._buf) != TRAILER_SIZE:
            raise signing.SignatureError("signed file is missing its signature")
        trailer = bytes(self._buf)
        (signed_at,) = TIMESTAMP.unpack_from(trailer)
        key_end = TIMESTAMP.size + PUBLIC_SIZE
        signer = PublicIdentity.from_raw(trailer[TIMESTAMP.size : key_end])
        if signer.verify is None:
            raise signing.SignatureError("malformed signer key")
        msg = _signed_message(header_bytes, signer, self._hash.digest(), signed_at)
        signing.verify(signer.verify, trailer[key_end:], msg, _SIG_CONTEXT)
        return SignatureInfo(signer, signed_at)


def decrypt_payload(header: Header, file_key: bytes, src: BinaryIO, dst: BinaryIO) -> SignatureInfo | None:
    """Decrypt the payload; for signed files, verify the signature and return the signer.

    The caller must treat output as untrusted until this returns (the CLI
    writes to a temp file and discards it on any error)."""
    key = _payload_key(file_key, header.payload_salt)
    if not header.flags & FLAG_SIGNED:
        stream.decrypt(key, src, dst)
        return None
    writer = _VerifyingWriter(dst)
    stream.decrypt(key, src, writer)
    return writer.finish(header.authenticated)


def decrypt(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    password: bytes | None = None,
    identities: Iterable[kem.PrivateKey] = (),
    trusted: Sequence[PublicIdentity] | None = None,
    max_age: int | None = None,
) -> SignatureInfo | None:
    """Decrypt a whole file. If `trusted` is given, the file must be signed by
    one of them; if `max_age` (seconds) is given, the signature must be that recent."""
    header = read_header(src)
    file_key = unlock(header, password=password, identities=identities)
    info = decrypt_payload(header, file_key, src, dst)
    if trusted is not None:
        require_signer(info, list(trusted))
    if max_age is not None:
        require_fresh(info, max_age)
    return info
