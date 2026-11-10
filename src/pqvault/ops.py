"""File-level operations shared by the command line and the interactive app.

Everything here raises PQVaultError on failure and never leaves partial
output behind: results go to a temp file next to the target and are moved
into place only after everything (decryption, signature, signer checks)
has succeeded.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Sequence

from . import PQVaultError, detached, format, kem
from .identity import Identity, PublicIdentity, SignatureInfo, require_fresh, require_signer

SUFFIX = ".pqv"
SIG_SUFFIX = ".sig"


def default_encrypt_output(path: Path) -> Path:
    return path.with_name(path.name + SUFFIX)


def default_decrypt_output(path: Path) -> Path:
    if path.suffix != SUFFIX:
        raise PQVaultError("file does not end in .pqv; choose an output name")
    return path.with_suffix("")


@contextmanager
def atomic_output(target: Path, force: bool) -> Iterator[Path]:
    """Yield a temp path next to target; move it into place only on success."""
    if target.exists() and not force:
        raise PQVaultError(f"{target} already exists (choose overwrite to replace it)")
    fd, tmp = tempfile.mkstemp(prefix=".pqvault-", dir=target.parent or ".")
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        yield tmp_path
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    if target.is_dir():
        shutil.rmtree(target)
    os.replace(tmp_path, target)


def encrypt_path(
    path: Path,
    output: Path | None = None,
    *,
    passwords: Sequence[bytes] = (),
    recipients: Sequence[PublicIdentity] = (),
    signer: Identity | None = None,
    force: bool = False,
) -> Path:
    """Encrypt a file or folder. Returns the output path."""
    if not path.exists():
        raise PQVaultError(f"{path} does not exist")
    target = output or default_encrypt_output(path)
    opts = dict(passwords=passwords, recipients=[r.kem for r in recipients], signer=signer)
    with atomic_output(target, force) as tmp, open(tmp, "wb") as dst:
        if path.is_dir():
            with tempfile.TemporaryFile() as spool:
                with tarfile.open(fileobj=spool, mode="w") as tar:
                    tar.add(path, arcname=path.name)
                spool.seek(0)
                format.encrypt(spool, dst, flags=format.FLAG_DIRECTORY, **opts)
        else:
            with open(path, "rb") as src:
                format.encrypt(src, dst, **opts)
    return target


def make_check(trusted: Sequence[PublicIdentity] | None, max_age: int | None) -> Callable[[SignatureInfo | None], None]:
    def check(info: SignatureInfo | None) -> None:
        if trusted:
            require_signer(info, list(trusted))
        if max_age is not None:
            require_fresh(info, max_age)
    return check


def needs_password(path: Path) -> bool:
    """True if the file can be opened with a password."""
    with open(path, "rb") as src:
        return format.read_header(src).has_password


def decrypt_path(
    path: Path,
    output: Path | None = None,
    *,
    password: bytes | None = None,
    identities: Sequence[kem.PrivateKey] = (),
    trusted: Sequence[PublicIdentity] | None = None,
    max_age: int | None = None,
    force: bool = False,
) -> tuple[Path, SignatureInfo | None]:
    """Decrypt a .pqv file (or folder archive). Returns (output path, signature info)."""
    target = output or default_decrypt_output(path)
    check = make_check(trusted, max_age)
    with open(path, "rb") as src:
        header = format.read_header(src)
        file_key = format.unlock(header, password=password, identities=identities)
        if header.flags & format.FLAG_DIRECTORY:
            info = _decrypt_folder(header, file_key, src, target, force, check)
        else:
            with atomic_output(target, force) as tmp, open(tmp, "wb") as dst:
                info = format.decrypt_payload(header, file_key, src, dst)
                check(info)  # raising here discards the temp file
    return target, info


def _decrypt_folder(header, file_key: bytes, src, output: Path, force: bool,
                    check: Callable[[SignatureInfo | None], None]) -> SignatureInfo | None:
    """Authenticate (and verify) the whole archive first, then extract and move into place."""
    if output.exists() and not force:
        raise PQVaultError(f"{output} already exists (choose overwrite to replace it)")
    staging = Path(tempfile.mkdtemp(prefix=".pqvault-", dir=output.parent or "."))
    try:
        with tempfile.TemporaryFile() as spool:
            info = format.decrypt_payload(header, file_key, src, spool)
            check(info)
            spool.seek(0)
            with tarfile.open(fileobj=spool, mode="r") as tar:
                tar.extractall(staging, filter="data")  # blocks ../ and absolute paths
        entries = list(staging.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise PQVaultError("encrypted folder archive has an unexpected layout")
        if output.exists():
            shutil.rmtree(output) if output.is_dir() else output.unlink()
        os.replace(entries[0], output)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return info


def sign_path(path: Path, identity: Identity, output: Path | None = None, force: bool = False) -> Path:
    if not path.is_file():
        raise PQVaultError(f"{path} is not a file")
    target = output or path.with_name(path.name + SIG_SUFFIX)
    with open(path, "rb") as src:
        text = detached.sign(identity, src)
    with atomic_output(target, force) as tmp:
        tmp.write_text(text)
        tmp.chmod(0o644)  # signatures are public, unlike decrypted files
    return target


def verify_path(path: Path, trusted: Sequence[PublicIdentity], sig: Path | None = None,
                max_age: int | None = None) -> SignatureInfo:
    sig = sig or path.with_name(path.name + SIG_SUFFIX)
    if not sig.exists():
        raise PQVaultError(f"signature file {sig} not found")
    if not trusted:
        raise PQVaultError("no trusted keys to check against")
    with open(path, "rb") as src:
        return detached.verify(sig.read_text(), src, list(trusted), max_age=max_age)
