import io
import os

import pytest

from pqvault import DecryptionError, stream

C = stream.CHUNK_SIZE
CT = C + stream.TAG_SIZE
KEY = os.urandom(32)


def enc(data: bytes) -> bytes:
    out = io.BytesIO()
    stream.encrypt(KEY, io.BytesIO(data), out)
    return out.getvalue()


def dec(blob: bytes) -> bytes:
    out = io.BytesIO()
    stream.decrypt(KEY, io.BytesIO(blob), out)
    return out.getvalue()


@pytest.mark.parametrize("size", [0, 1, C - 1, C, C + 1, 2 * C, 3 * C + 7])
def test_roundtrip(size):
    data = os.urandom(size)
    assert dec(enc(data)) == data


def test_ciphertext_length():
    assert len(enc(b"")) == stream.TAG_SIZE
    assert len(enc(os.urandom(2 * C))) == 2 * CT  # no extra empty chunk


@pytest.mark.parametrize("cut", [0, 5, CT, 2 * CT, 2 * CT + 100])
def test_truncation_detected(cut):
    blob = enc(os.urandom(3 * C))
    with pytest.raises(DecryptionError):
        dec(blob[:cut])


def test_reordered_chunks_detected():
    blob = enc(os.urandom(3 * C))
    a, b, rest = blob[:CT], blob[CT : 2 * CT], blob[2 * CT :]
    with pytest.raises(DecryptionError):
        dec(b + a + rest)


def test_appended_data_detected():
    with pytest.raises(DecryptionError):
        dec(enc(os.urandom(C)) + b"x" * 20)


def test_trailing_empty_chunk_rejected():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = os.urandom(C)
    a = AESGCM(KEY)
    forged = a.encrypt(stream._nonce(0, False), data, None) + a.encrypt(stream._nonce(1, True), b"", None)
    with pytest.raises(DecryptionError):
        dec(forged)


@pytest.mark.parametrize("pos", [0, C // 2, CT - 1, CT, CT + C + 15])
def test_bitflip_detected(pos):
    blob = bytearray(enc(os.urandom(2 * C)))
    blob[pos] ^= 1
    with pytest.raises(DecryptionError):
        dec(bytes(blob))


def test_wrong_key():
    blob = enc(b"secret")
    out = io.BytesIO()
    with pytest.raises(DecryptionError):
        stream.decrypt(os.urandom(32), io.BytesIO(blob), out)
