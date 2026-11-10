import os

import pytest

from pqvault import PQVaultError, kem


def test_roundtrip():
    sk = kem.PrivateKey.generate()
    ss, enc = kem.encapsulate(sk.public_key)
    assert len(ss) == 32 and len(enc) == kem.ENCAPSULATION_SIZE
    assert kem.decapsulate(sk, enc) == ss


def test_fresh_secret_each_time():
    pk = kem.PrivateKey.generate().public_key
    assert kem.encapsulate(pk)[0] != kem.encapsulate(pk)[0]


def test_wrong_key_gives_different_secret():
    sk, other = kem.PrivateKey.generate(), kem.PrivateKey.generate()
    ss, enc = kem.encapsulate(sk.public_key)
    assert kem.decapsulate(other, enc) != ss


@pytest.mark.parametrize("pos", [0, kem.MLKEM_CT_SIZE - 1, kem.MLKEM_CT_SIZE, kem.ENCAPSULATION_SIZE - 1])
def test_tampered_encapsulation_changes_secret(pos):
    # Covers both halves: changing either the ML-KEM or X25519 part breaks it.
    sk = kem.PrivateKey.generate()
    ss, enc = kem.encapsulate(sk.public_key)
    bad = bytearray(enc)
    bad[pos] ^= 1
    try:
        assert kem.decapsulate(sk, bytes(bad)) != ss
    except PQVaultError:
        pass  # e.g. low-order X25519 point rejected


def test_private_key_serialization_is_deterministic():
    sk = kem.PrivateKey.generate()
    again = kem.PrivateKey(sk.raw)
    assert again.public_key.raw == sk.public_key.raw


def test_bad_lengths():
    with pytest.raises(PQVaultError):
        kem.PublicKey(os.urandom(10))
    with pytest.raises(PQVaultError):
        kem.PrivateKey(os.urandom(10))
    with pytest.raises(PQVaultError):
        kem.decapsulate(kem.PrivateKey.generate(), b"short")
