import base64
import stat

import pytest

from pqvault import DecryptionError, PQVaultError, kem, keys
from pqvault.identity import Identity, PublicIdentity


def test_public_roundtrip():
    pub = Identity.generate().public
    text = keys.encode_public(pub)
    assert text.startswith("pqv2pub:")
    assert keys.decode_public(text) == pub


def test_v1_public_key_still_loads():
    k = kem.PrivateKey.generate().public_key
    pub = keys.decode_public("pqv1pub:" + base64.b64encode(k.raw).decode())
    assert pub.kem.raw == k.raw and pub.verify is None


def test_bad_public():
    with pytest.raises(PQVaultError):
        keys.decode_public("ssh-rsa AAAA")
    with pytest.raises(PQVaultError):
        keys.decode_public("pqv2pub:!!!")
    with pytest.raises(PQVaultError):  # v1 payload under a v2 prefix
        keys.decode_public("pqv2pub:" + base64.b64encode(kem.PrivateKey.generate().public_key.raw).decode())


def test_private_roundtrip_and_wrong_passphrase():
    ident = Identity.generate()
    text = keys.encode_private(ident, b"correct horse")
    back = keys.decode_private(text, b"correct horse")
    assert back.raw == ident.raw
    assert ident.public.fingerprint in text
    with pytest.raises(DecryptionError):
        keys.decode_private(text, b"wrong")


def test_v1_private_key_still_loads():
    old = Identity(kem.PrivateKey.generate(), None)
    back = keys.decode_private(keys.encode_private(old, b"pw"), b"pw")
    assert back.signing is None and back.kem.raw == old.kem.raw


def test_fingerprint_covers_both_halves():
    a, b = Identity.generate(), Identity.generate()
    spliced = PublicIdentity(b.public.kem, a.public.verify)  # attacker's KEM + Alice's signing key
    assert spliced.fingerprint != a.public.fingerprint


def test_write_keypair(tmp_path):
    pub, key, ident = keys.write_keypair(tmp_path / "me", b"pass")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert keys.decode_private(key.read_text(), b"pass").raw == ident.raw
    assert keys.decode_public(pub.read_text()) == ident.public
    with pytest.raises(PQVaultError, match="already exists"):
        keys.write_keypair(tmp_path / "me", b"pass")
