import io
import os

import pytest

from pqvault import DecryptionError, PQVaultError, format, kem
from pqvault.password import Argon2Params


def enc(data=b"hello quantum world", **kw) -> bytes:
    out = io.BytesIO()
    format.encrypt(io.BytesIO(data), out, **kw)
    return out.getvalue()


def dec(blob: bytes, **kw) -> bytes:
    out = io.BytesIO()
    format.decrypt(io.BytesIO(blob), out, **kw)
    return out.getvalue()


def test_password_roundtrip():
    assert dec(enc(passwords=[b"pw"]), password=b"pw") == b"hello quantum world"


def test_wrong_password():
    with pytest.raises(DecryptionError):
        dec(enc(passwords=[b"pw"]), password=b"nope")


def test_multiple_recipients_and_password():
    a, b, c = (kem.PrivateKey.generate() for _ in range(3))
    blob = enc(passwords=[b"pw"], recipients=[a.public_key, b.public_key])
    assert dec(blob, identities=[a]) == b"hello quantum world"
    assert dec(blob, identities=[b]) == b"hello quantum world"
    assert dec(blob, identities=[c, b]) == b"hello quantum world"
    assert dec(blob, password=b"pw") == b"hello quantum world"
    with pytest.raises(DecryptionError):
        dec(blob, identities=[c])


def test_needs_a_lock():
    with pytest.raises(PQVaultError):
        enc()


def test_every_header_byte_is_protected():
    sk = kem.PrivateKey.generate()
    blob = enc(passwords=[b"pw"], recipients=[sk.public_key])
    header_end = len(blob) - (len(b"hello quantum world") + 16)
    for pos in range(header_end):
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        for kw in ({"password": b"pw"}, {"identities": [sk]}):
            with pytest.raises(PQVaultError):
                dec(bytes(bad), **kw)


def test_payload_tamper_detected():
    blob = bytearray(enc(passwords=[b"pw"]))
    blob[-1] ^= 1
    with pytest.raises(DecryptionError):
        dec(bytes(blob), password=b"pw")


def test_not_a_pqv_file():
    with pytest.raises(PQVaultError):
        dec(b"this is not encrypted", password=b"pw")


def test_dos_argon2_params_rejected():
    blob = bytearray(enc(passwords=[b"pw"]))
    # Locate the password stanza's memory field and set it to an absurd value.
    header = format.read_header(io.BytesIO(bytes(blob)))
    body = header.stanzas[0][1]
    start = bytes(blob).index(body)
    blob[start + 16 : start + 20] = (0xFFFFFFFF).to_bytes(4, "big")
    with pytest.raises(PQVaultError, match="out of allowed range"):
        dec(bytes(blob), password=b"pw")


def test_custom_argon_params_are_used():
    params = Argon2Params(memory_kib=128, iterations=2, lanes=2)
    blob = enc(passwords=[b"pw"], argon_params=params)
    assert dec(blob, password=b"pw") == b"hello quantum world"


def test_large_file_roundtrip(tmp_path):
    size = 100 * 1024 * 1024 + 12345
    src, mid, out = tmp_path / "in", tmp_path / "mid", tmp_path / "out"
    with open(src, "wb") as f:
        for _ in range(size // (1 << 20)):
            f.write(os.urandom(1 << 20))
        f.write(os.urandom(size % (1 << 20)))
    sk = kem.PrivateKey.generate()
    with open(src, "rb") as s, open(mid, "wb") as d:
        format.encrypt(s, d, recipients=[sk.public_key])
    with open(mid, "rb") as s, open(out, "wb") as d:
        format.decrypt(s, d, identities=[sk])
    assert out.stat().st_size == size
    with open(src, "rb") as a, open(out, "rb") as b:
        while True:
            x, y = a.read(1 << 20), b.read(1 << 20)
            assert x == y
            if not x:
                break
