"""Detached signatures: prove who published a file without encrypting it.

    pqvault sign report.pdf -i me.key      -> report.pdf.sig
    pqvault verify report.pdf --from me.pub
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import textwrap
import time
from typing import BinaryIO

from . import signing
from .identity import (PUBLIC_SIZE, TIMESTAMP, Identity, PublicIdentity, SignatureInfo,
                       require_fresh, require_signer, signable)
from .signing import SignatureError

_CONTEXT = b"pqvault-v1 detached"
_VERSION = b"\x01"
_BEGIN = "-----BEGIN PQVAULT SIGNATURE-----"
_END = "-----END PQVAULT SIGNATURE-----"


# blob = version | signed_at u64 | signer public identity | signature
_KEY_START = 1 + TIMESTAMP.size
_SIG_START = _KEY_START + PUBLIC_SIZE


def _message(signer: PublicIdentity, signed_at: int, src: BinaryIO) -> bytes:
    h = hashlib.sha512()
    for block in iter(lambda: src.read(1 << 20), b""):
        h.update(block)
    return (b"pqvault-v1 detached signature\x00" + TIMESTAMP.pack(signed_at)
            + hashlib.sha512(signer.raw).digest() + h.digest())


def sign(identity: Identity, src: BinaryIO, signed_at: int | None = None) -> str:
    pub = signable(identity.public)
    when = int(time.time()) if signed_at is None else signed_at
    sig = signing.sign(identity.signing, _message(pub, when, src), _CONTEXT)
    blob = base64.b64encode(_VERSION + TIMESTAMP.pack(when) + pub.raw + sig).decode()
    return f"{_BEGIN}\n{textwrap.fill(blob, 64)}\n{_END}\n"


def verify(text: str, src: BinaryIO, trusted: list[PublicIdentity], max_age: int | None = None) -> SignatureInfo:
    """Verify a detached signature. The returned signer is always one of `trusted`."""
    try:
        start = text.index(_BEGIN) + len(_BEGIN)
        blob = base64.b64decode("".join(text[start : text.index(_END)].split()), validate=True)
    except (ValueError, binascii.Error):
        raise SignatureError("not a valid pqvault signature file") from None
    if len(blob) != _SIG_START + signing.SIGNATURE_SIZE or blob[:1] != _VERSION:
        raise SignatureError("unsupported or malformed signature file")
    (signed_at,) = TIMESTAMP.unpack_from(blob, 1)
    info = SignatureInfo(PublicIdentity.from_raw(blob[_KEY_START:_SIG_START]), signed_at)
    require_signer(info, trusted)
    signing.verify(info.signer.verify, blob[_SIG_START:], _message(info.signer, signed_at, src), _CONTEXT)
    if max_age is not None:
        require_fresh(info, max_age)
    return info
