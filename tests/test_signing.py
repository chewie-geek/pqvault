import base64
import io
import os
import time

import pytest

from pqvault import PQVaultError, detached, format, kem, signing
from pqvault.identity import Identity, SignatureInfo, require_fresh
from pqvault.signing import SignatureError

ALICE, BOB, MALLORY = Identity.generate(), Identity.generate(), Identity.generate()
DATA = os.urandom(150_000)  # spans several chunks


# --- primitives ---

def test_hybrid_sign_verify():
    sk = signing.SigningKey.generate()
    sig = signing.sign(sk, b"msg", b"ctx")
    assert len(sig) == signing.SIGNATURE_SIZE
    signing.verify(sk.verify_key, sig, b"msg", b"ctx")
    for msg, ctx in ((b"msg2", b"ctx"), (b"msg", b"other")):
        with pytest.raises(SignatureError):
            signing.verify(sk.verify_key, sig, msg, ctx)


@pytest.mark.parametrize("pos", [0, signing.MLDSA_SIG_SIZE - 1, signing.MLDSA_SIG_SIZE, signing.SIGNATURE_SIZE - 1])
def test_both_halves_required(pos):
    # Corrupting either the ML-DSA or the Ed25519 half must fail.
    sk = signing.SigningKey.generate()
    sig = bytearray(signing.sign(sk, b"m", b"c"))
    sig[pos] ^= 1
    with pytest.raises(SignatureError):
        signing.verify(sk.verify_key, bytes(sig), b"m", b"c")


# --- signatures inside encrypted files ---

def enc(data=DATA, **kw) -> bytes:
    out = io.BytesIO()
    format.encrypt(io.BytesIO(data), out, **kw)
    return out.getvalue()


def dec(blob, **kw):
    out = io.BytesIO()
    signer = format.decrypt(io.BytesIO(blob), out, **kw)
    return out.getvalue(), signer


@pytest.mark.parametrize("size", [0, 1, 64 * 1024 - 1, 64 * 1024, 150_000])
def test_signed_roundtrip(size):
    data = os.urandom(size)
    blob = enc(data, recipients=[BOB.kem.public_key], signer=ALICE)
    before = int(time.time())
    out, info = dec(blob, identities=[BOB.kem], trusted=[ALICE.public])
    assert out == data and info.signer == ALICE.public
    assert before - 5 <= info.signed_at <= time.time()


def test_signed_with_password():
    out, info = dec(enc(passwords=[b"pw"], signer=ALICE), password=b"pw")
    assert out == DATA and info.signer == ALICE.public


def test_unsigned_reports_none():
    _, signer = dec(enc(passwords=[b"pw"]), password=b"pw")
    assert signer is None


def test_trusted_required_but_unsigned():
    with pytest.raises(SignatureError, match="not signed"):
        dec(enc(passwords=[b"pw"]), password=b"pw", trusted=[ALICE.public])


def test_wrong_signer_rejected():
    blob = enc(recipients=[BOB.kem.public_key], signer=MALLORY)
    with pytest.raises(SignatureError, match="untrusted"):
        dec(blob, identities=[BOB.kem], trusted=[ALICE.public])


def test_signer_is_hidden_from_non_recipients():
    blob = enc(recipients=[BOB.kem.public_key], signer=ALICE)
    assert ALICE.public.verify.raw[:64] not in blob


def test_signature_cannot_be_moved_to_new_recipients():
    """Bob decrypts Alice's signed file and re-encrypts the plaintext *with the
    trailer* to Carol, hoping Carol sees "signed by Alice". The signature binds
    the original header, so it must fail."""
    carol = Identity.generate()
    blob = enc(recipients=[BOB.kem.public_key], signer=ALICE)
    src = io.BytesIO(blob)
    header = format.read_header(src)
    key = format.unlock(header, identities=[BOB.kem])
    raw_plain = io.BytesIO()
    format.stream.decrypt(format._payload_key(key, header.payload_salt), src, raw_plain)

    forged = io.BytesIO()
    format.encrypt(io.BytesIO(raw_plain.getvalue()), forged, recipients=[carol.kem.public_key],
                   flags=format.FLAG_SIGNED)
    with pytest.raises(SignatureError, match="signature is invalid"):
        dec(forged.getvalue(), identities=[carol.kem], trusted=[ALICE.public])


def test_signing_needs_signing_key():
    old = Identity(kem.PrivateKey.generate(), None)
    with pytest.raises(PQVaultError, match="no signing key"):
        enc(passwords=[b"pw"], signer=old)


# --- detached signatures ---

def test_detached_roundtrip():
    sig = detached.sign(ALICE, io.BytesIO(DATA))
    info = detached.verify(sig, io.BytesIO(DATA), [BOB.public, ALICE.public])
    assert info.signer == ALICE.public and abs(info.signed_at - time.time()) < 5


def test_detached_modified_file():
    sig = detached.sign(ALICE, io.BytesIO(DATA))
    with pytest.raises(SignatureError):
        detached.verify(sig, io.BytesIO(DATA + b"!"), [ALICE.public])


def test_detached_untrusted_signer():
    sig = detached.sign(MALLORY, io.BytesIO(DATA))
    with pytest.raises(SignatureError, match="untrusted"):
        detached.verify(sig, io.BytesIO(DATA), [ALICE.public])


def test_detached_garbage():
    with pytest.raises(SignatureError):
        detached.verify("hello", io.BytesIO(DATA), [ALICE.public])


# --- timestamps ---

DAY = 86400


def test_embedded_timestamp_is_what_signer_set():
    blob = enc(passwords=[b"pw"], signer=ALICE, signed_at=1_700_000_000)
    _, info = dec(blob, password=b"pw")
    assert info.signed_at == 1_700_000_000


def test_max_age_accepts_recent_rejects_old():
    fresh = enc(passwords=[b"pw"], signer=ALICE)
    dec(fresh, password=b"pw", max_age=60)
    old = enc(passwords=[b"pw"], signer=ALICE, signed_at=int(time.time()) - 2 * DAY)
    with pytest.raises(SignatureError, match="older than"):
        dec(old, password=b"pw", max_age=DAY)


def test_max_age_requires_a_signature():
    with pytest.raises(SignatureError, match="not signed"):
        dec(enc(passwords=[b"pw"]), password=b"pw", max_age=DAY)


def test_future_timestamp_rejected_by_max_age():
    info = SignatureInfo(ALICE.public, int(time.time()) + DAY)
    with pytest.raises(SignatureError, match="future"):
        require_fresh(info, max_age=7 * DAY)
    # small clock skew is tolerated
    require_fresh(SignatureInfo(ALICE.public, int(time.time()) + 60), max_age=DAY)


def test_detached_timestamp_cannot_be_changed():
    """Rewrite the time inside a .sig to make an old signature look fresh."""
    old = int(time.time()) - 30 * DAY
    sig = detached.sign(ALICE, io.BytesIO(DATA), signed_at=old)
    lines = sig.strip().splitlines()
    blob = bytearray(base64.b64decode("".join(lines[1:-1])))
    blob[1:9] = int(time.time()).to_bytes(8, "big")
    forged = f"{lines[0]}\n{base64.b64encode(bytes(blob)).decode()}\n{lines[-1]}\n"
    with pytest.raises(SignatureError, match="invalid"):
        detached.verify(forged, io.BytesIO(DATA), [ALICE.public])


def test_detached_max_age():
    sig = detached.sign(ALICE, io.BytesIO(DATA), signed_at=int(time.time()) - 2 * DAY)
    assert detached.verify(sig, io.BytesIO(DATA), [ALICE.public], max_age=7 * DAY).signer == ALICE.public
    with pytest.raises(SignatureError, match="older than"):
        detached.verify(sig, io.BytesIO(DATA), [ALICE.public], max_age=DAY)
