"""Hybrid post-quantum signatures: ML-DSA-65 (FIPS 204) + Ed25519.

A signature is valid only if BOTH component signatures verify, so forging one
requires breaking ML-DSA *and* Ed25519. Ed25519 has no native context string,
so the context is length-prefixed into its message for domain separation.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from . import PQVaultError

MLDSA_PK_SIZE = 1952
MLDSA_SEED_SIZE = 32
MLDSA_SIG_SIZE = 3309
ED_SIZE = 32
ED_SIG_SIZE = 64

VERIFY_KEY_SIZE = MLDSA_PK_SIZE + ED_SIZE
SIGNING_KEY_SIZE = MLDSA_SEED_SIZE + ED_SIZE
SIGNATURE_SIZE = MLDSA_SIG_SIZE + ED_SIG_SIZE


class SignatureError(PQVaultError):
    """A signature is missing, malformed, invalid, or from the wrong signer."""


class VerifyKey:
    def __init__(self, data: bytes):
        if len(data) != VERIFY_KEY_SIZE:
            raise PQVaultError("invalid signature verification key length")
        try:
            self._mldsa = mldsa.MLDSA65PublicKey.from_public_bytes(data[:MLDSA_PK_SIZE])
            self._ed = ed25519.Ed25519PublicKey.from_public_bytes(data[MLDSA_PK_SIZE:])
        except ValueError as e:
            raise PQVaultError(f"invalid signature verification key: {e}") from None
        self.raw = bytes(data)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VerifyKey) and other.raw == self.raw

    def __hash__(self) -> int:
        return hash(self.raw)


class SigningKey:
    def __init__(self, data: bytes):
        if len(data) != SIGNING_KEY_SIZE:
            raise PQVaultError("invalid signing key length")
        self._mldsa = mldsa.MLDSA65PrivateKey.from_seed_bytes(data[:MLDSA_SEED_SIZE])
        self._ed = ed25519.Ed25519PrivateKey.from_private_bytes(data[MLDSA_SEED_SIZE:])
        self.raw = bytes(data)
        self.verify_key = VerifyKey(
            self._mldsa.public_key().public_bytes_raw() + self._ed.public_key().public_bytes_raw()
        )

    @classmethod
    def generate(cls) -> "SigningKey":
        m = mldsa.MLDSA65PrivateKey.generate()
        e = ed25519.Ed25519PrivateKey.generate()
        return cls(m.private_bytes_raw() + e.private_bytes_raw())


def _ed_message(context: bytes, message: bytes) -> bytes:
    return len(context).to_bytes(1, "big") + context + message


def sign(sk: SigningKey, message: bytes, context: bytes) -> bytes:
    return sk._mldsa.sign(message, context) + sk._ed.sign(_ed_message(context, message))


def verify(vk: VerifyKey, signature: bytes, message: bytes, context: bytes) -> None:
    if len(signature) != SIGNATURE_SIZE:
        raise SignatureError("malformed signature")
    try:
        vk._mldsa.verify(signature[:MLDSA_SIG_SIZE], message, context)
        vk._ed.verify(signature[MLDSA_SIG_SIZE:], _ed_message(context, message))
    except InvalidSignature:
        raise SignatureError("signature is invalid (file altered or not signed by this key)") from None
