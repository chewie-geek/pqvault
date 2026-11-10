"""Hybrid post-quantum key encapsulation: ML-KEM-768 (FIPS 203) + X25519.

An attacker must break BOTH ML-KEM and X25519 to recover the shared secret,
so files stay protected even if a flaw is later found in either one.
The combiner hashes both shared secrets together with every public value
of the exchange (in the spirit of the X-Wing construction).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import PQVaultError

MLKEM_PK_SIZE = 1184
MLKEM_CT_SIZE = 1088
MLKEM_SEED_SIZE = 64
X25519_SIZE = 32

PUBLIC_KEY_SIZE = MLKEM_PK_SIZE + X25519_SIZE
PRIVATE_KEY_SIZE = MLKEM_SEED_SIZE + X25519_SIZE
ENCAPSULATION_SIZE = MLKEM_CT_SIZE + X25519_SIZE
SHARED_SECRET_SIZE = 32

_LABEL = b"pqvault-v1 hybrid ML-KEM-768+X25519"


class PublicKey:
    def __init__(self, data: bytes):
        if len(data) != PUBLIC_KEY_SIZE:
            raise PQVaultError("invalid public key length")
        try:
            self._mlkem = mlkem.MLKEM768PublicKey.from_public_bytes(data[:MLKEM_PK_SIZE])
            self._x = x25519.X25519PublicKey.from_public_bytes(data[MLKEM_PK_SIZE:])
        except ValueError as e:
            raise PQVaultError(f"invalid public key: {e}") from None
        self.raw = bytes(data)


class PrivateKey:
    def __init__(self, data: bytes):
        if len(data) != PRIVATE_KEY_SIZE:
            raise PQVaultError("invalid private key length")
        self._mlkem = mlkem.MLKEM768PrivateKey.from_seed_bytes(data[:MLKEM_SEED_SIZE])
        self._x = x25519.X25519PrivateKey.from_private_bytes(data[MLKEM_SEED_SIZE:])
        self.raw = bytes(data)
        self.public_key = PublicKey(
            self._mlkem.public_key().public_bytes_raw() + self._x.public_key().public_bytes_raw()
        )

    @classmethod
    def generate(cls) -> "PrivateKey":
        m = mlkem.MLKEM768PrivateKey.generate()
        x = x25519.X25519PrivateKey.generate()
        return cls(m.private_bytes_raw() + x.private_bytes_raw())


def _combine(ss_m: bytes, ss_x: bytes, enc: bytes, recipient_pk: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SHARED_SECRET_SIZE,
        salt=None,
        info=_LABEL + enc + recipient_pk,
    ).derive(ss_m + ss_x)


def encapsulate(pk: PublicKey) -> tuple[bytes, bytes]:
    """Return (shared_secret, encapsulation) for the given recipient."""
    ss_m, ct_m = pk._mlkem.encapsulate()
    eph = x25519.X25519PrivateKey.generate()
    try:
        ss_x = eph.exchange(pk._x)
    except ValueError:
        raise PQVaultError("recipient X25519 key is invalid") from None
    enc = ct_m + eph.public_key().public_bytes_raw()
    return _combine(ss_m, ss_x, enc, pk.raw), enc


def decapsulate(sk: PrivateKey, enc: bytes) -> bytes:
    """Recover the shared secret. A wrong key yields an unrelated secret
    (ML-KEM implicit rejection) which then fails authentication upstream."""
    if len(enc) != ENCAPSULATION_SIZE:
        raise PQVaultError("invalid encapsulation length")
    ss_m = sk._mlkem.decapsulate(enc[:MLKEM_CT_SIZE])
    try:
        ss_x = sk._x.exchange(x25519.X25519PublicKey.from_public_bytes(enc[MLKEM_CT_SIZE:]))
    except ValueError:
        raise PQVaultError("invalid ephemeral X25519 key in file") from None
    return _combine(ss_m, ss_x, enc, sk.public_key.raw)
