"""Chunked AES-256-GCM payload encryption (the STREAM construction).

The plaintext is split into 64 KiB chunks. Each chunk's 96-bit nonce is an
11-byte big-endian chunk counter followed by a 1-byte "last chunk" flag, so
reordering, dropping, duplicating or truncating chunks is detected. The key
must be unique per file (callers derive it from a fresh random file key).
"""

from __future__ import annotations

from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import DecryptionError

CHUNK_SIZE = 64 * 1024
TAG_SIZE = 16
_MAX_COUNTER = (1 << 88) - 1


def _nonce(counter: int, last: bool) -> bytes:
    if counter > _MAX_COUNTER:
        raise OverflowError("stream too long")
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _read_full(src: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes unless EOF is reached first."""
    buf = bytearray()
    while len(buf) < n:
        piece = src.read(n - len(buf))
        if not piece:
            break
        buf += piece
    return bytes(buf)


def encrypt(key: bytes, src: BinaryIO, dst: BinaryIO) -> None:
    aead = AESGCM(key)
    counter = 0
    chunk = _read_full(src, CHUNK_SIZE)
    while True:
        nxt = _read_full(src, CHUNK_SIZE) if len(chunk) == CHUNK_SIZE else b""
        last = not nxt
        dst.write(aead.encrypt(_nonce(counter, last), chunk, None))
        if last:
            return
        chunk = nxt
        counter += 1


def decrypt(key: bytes, src: BinaryIO, dst: BinaryIO) -> None:
    aead = AESGCM(key)
    size = CHUNK_SIZE + TAG_SIZE
    counter = 0
    chunk = _read_full(src, size)
    if len(chunk) < TAG_SIZE:
        raise DecryptionError("encrypted payload is truncated")
    while True:
        nxt = _read_full(src, size) if len(chunk) == size else b""
        last = not nxt
        try:
            plain = aead.decrypt(_nonce(counter, last), chunk, None)
        except InvalidTag:
            raise DecryptionError("payload authentication failed (file corrupted, truncated or tampered with)") from None
        if last:
            # Only an entirely empty file may end in an empty chunk.
            if not plain and counter > 0:
                raise DecryptionError("payload has an invalid trailing chunk")
            dst.write(plain)
            return
        if len(nxt) < TAG_SIZE:
            raise DecryptionError("encrypted payload is truncated")
        dst.write(plain)
        chunk = nxt
        counter += 1
