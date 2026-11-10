"""Public and private identities, and fingerprints.

An identity bundles an encryption keypair (ML-KEM-768 + X25519) with a signing
keypair (ML-DSA-65 + Ed25519). The fingerprint covers BOTH public halves, so
nobody can splice someone else's signing key onto their own encryption key.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass

from . import PQVaultError, kem, signing
from .signing import SignatureError

PUBLIC_SIZE = kem.PUBLIC_KEY_SIZE + signing.VERIFY_KEY_SIZE


@dataclass(frozen=True)
class PublicIdentity:
    kem: kem.PublicKey
    verify: signing.VerifyKey | None  # None for v0.1 (encryption-only) keys

    @property
    def raw(self) -> bytes:
        return self.kem.raw + (self.verify.raw if self.verify else b"")

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(b"pqvault fingerprint\x00" + self.raw).hexdigest()[:32].upper()
        return " ".join(digest[i : i + 4] for i in range(0, 32, 4))

    @classmethod
    def from_raw(cls, raw: bytes) -> "PublicIdentity":
        if len(raw) == kem.PUBLIC_KEY_SIZE:
            return cls(kem.PublicKey(raw), None)
        if len(raw) == PUBLIC_SIZE:
            return cls(kem.PublicKey(raw[: kem.PUBLIC_KEY_SIZE]), signing.VerifyKey(raw[kem.PUBLIC_KEY_SIZE :]))
        raise PQVaultError("public key has the wrong length")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicIdentity) and other.raw == self.raw

    def __hash__(self) -> int:
        return hash(self.raw)


@dataclass(frozen=True)
class Identity:
    kem: kem.PrivateKey
    signing: signing.SigningKey | None  # None for v0.1 keys

    @classmethod
    def generate(cls) -> "Identity":
        return cls(kem.PrivateKey.generate(), signing.SigningKey.generate())

    @property
    def public(self) -> PublicIdentity:
        return PublicIdentity(self.kem.public_key, self.signing.verify_key if self.signing else None)

    @property
    def raw(self) -> bytes:
        return self.kem.raw + (self.signing.raw if self.signing else b"")

    @classmethod
    def from_raw(cls, raw: bytes) -> "Identity":
        if len(raw) == kem.PRIVATE_KEY_SIZE:
            return cls(kem.PrivateKey(raw), None)
        if len(raw) == kem.PRIVATE_KEY_SIZE + signing.SIGNING_KEY_SIZE:
            return cls(kem.PrivateKey(raw[: kem.PRIVATE_KEY_SIZE]), signing.SigningKey(raw[kem.PRIVATE_KEY_SIZE :]))
        raise PQVaultError("private key has unexpected contents")


@dataclass(frozen=True)
class SignatureInfo:
    """A verified signature: who signed, and when they say they signed.

    `signed_at` (Unix seconds, UTC) comes from the SIGNER's clock. It is
    covered by the signature, so nobody else can change it, but a signer
    with a wrong clock (or who lies) can put any time they like."""

    signer: PublicIdentity
    signed_at: int


TIMESTAMP = struct.Struct(">Q")
CLOCK_SKEW = 5 * 60  # tolerance for signatures that appear slightly in the future


def require_signer(info: SignatureInfo | None, trusted: list[PublicIdentity]) -> None:
    """Raise unless the file was signed by one of the trusted identities."""
    if info is None:
        raise SignatureError("file is not signed, but you required a signer (--from)")
    if info.signer not in trusted:
        raise SignatureError(f"file was signed by an untrusted key ({info.signer.fingerprint})")


def require_fresh(info: SignatureInfo | None, max_age: int, now: float | None = None) -> None:
    """Raise unless the signature was made within the last `max_age` seconds."""
    if info is None:
        raise SignatureError("file is not signed, so its age can't be checked (--max-age)")
    now = time.time() if now is None else now
    if info.signed_at > now + CLOCK_SKEW:
        raise SignatureError("signature is dated in the future (signer's clock is wrong?)")
    if now - info.signed_at > max_age:
        raise SignatureError("signature is older than the allowed --max-age")


def signable(identity: PublicIdentity) -> PublicIdentity:
    if identity.verify is None:
        raise PQVaultError("this key has no signing key (made by pqvault 0.1); run keygen to make a new one")
    return identity
