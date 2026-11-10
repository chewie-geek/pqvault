import stat

import pytest

from pqvault import DecryptionError, PQVaultError, kem, keys


def test_public_roundtrip():
    pk = kem.PrivateKey.generate().public_key
    assert keys.decode_public(keys.encode_public(pk)).raw == pk.raw


def test_bad_public():
    with pytest.raises(PQVaultError):
        keys.decode_public("ssh-rsa AAAA")
    with pytest.raises(PQVaultError):
        keys.decode_public("pqv1pub:!!!")


def test_private_roundtrip_and_wrong_passphrase():
    sk = kem.PrivateKey.generate()
    text = keys.encode_private(sk, b"correct horse")
    assert keys.decode_private(text, b"correct horse").raw == sk.raw
    assert sk.raw.hex() not in text
    with pytest.raises(DecryptionError):
        keys.decode_private(text, b"wrong")


def test_write_keypair(tmp_path):
    pub, key = keys.write_keypair(tmp_path / "me", b"pass")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    sk = keys.decode_private(key.read_text(), b"pass")
    assert keys.decode_public(pub.read_text()).raw == sk.public_key.raw
    with pytest.raises(PQVaultError, match="already exists"):
        keys.write_keypair(tmp_path / "me", b"pass")
