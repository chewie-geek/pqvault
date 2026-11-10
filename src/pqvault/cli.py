"""Command-line interface: pqvault keygen | encrypt | decrypt | sign | verify | fingerprint."""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
import shutil
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

import click

from . import PQVaultError, __version__, detached, format, keys
from .identity import CLOCK_SKEW, Identity, PublicIdentity, SignatureInfo, require_fresh, require_signer

SUFFIX = ".pqv"


def _prompt_secret(label: str, confirm: bool) -> bytes:
    value = click.prompt(label, hide_input=True, confirmation_prompt=confirm)
    if not value:
        raise click.UsageError(f"{label} must not be empty")
    return value.encode()


@contextmanager
def _atomic_output(target: Path, force: bool) -> Iterator[Path]:
    """Yield a temp path next to target; move it into place only on success."""
    if target.exists() and not force:
        raise click.ClickException(f"{target} already exists (use --force to overwrite)")
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


def _load_identity(path: Path) -> Identity:
    return keys.decode_private(path.read_text(), _prompt_secret(f"Passphrase for {path}", confirm=False))


def _load_publics(paths: tuple[Path, ...]) -> list[PublicIdentity]:
    return [keys.decode_public(p.read_text()) for p in paths]


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class Duration(click.ParamType):
    """A length of time like 90s, 30m, 12h, 7d or 2w, converted to seconds."""

    name = "duration"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", str(value).lower())
        if not m:
            self.fail(f"{value!r} is not a duration like 30m, 12h, 7d or 2w", param, ctx)
        return int(m.group(1)) * _UNITS[m.group(2)]


def _ago(seconds: float) -> str:
    future = seconds < 0
    seconds = abs(seconds)
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = int(seconds // size)
            text = f"{n} {unit}{'s' if n != 1 else ''}"
            break
    else:
        text = "just now" if not future else "a few seconds"
        return text if not future else f"in {text}"
    return f"in {text}" if future else f"{text} ago"


def _when(signed_at: int) -> str:
    local = datetime.fromtimestamp(signed_at, tz=timezone.utc).astimezone()
    return f"{local:%Y-%m-%d %H:%M:%S %Z} ({_ago(time.time() - signed_at)})"


def _describe_signature(info: SignatureInfo | None, trusted: list[PublicIdentity] | None) -> None:
    if info is None:
        click.echo("Not signed: this file does not prove who created it.")
        return
    if trusted:
        click.echo(f"Good signature from trusted key {info.signer.fingerprint}")
    else:
        click.echo(f"Signed by key {info.signer.fingerprint}")
        click.echo("  (not checked against a key you trust: compare this fingerprint with the sender,")
        click.echo("   or pass --from THEIR.pub to require it)")
    click.echo(f"Signed at {_when(info.signed_at)}, according to the signer's clock")
    if info.signed_at > time.time() + CLOCK_SKEW:
        click.echo("  Warning: this time is in the future; the signer's clock may be wrong.")


def _decrypt_folder(header, file_key: bytes, src, output: Path, force: bool,
                    check: Callable[[SignatureInfo | None], None]) -> SignatureInfo | None:
    """Authenticate (and verify) the whole archive first, then extract and move into place."""
    if output.exists() and not force:
        raise click.ClickException(f"{output} already exists (use --force to overwrite)")
    staging = Path(tempfile.mkdtemp(prefix=".pqvault-", dir=output.parent or "."))
    try:
        with tempfile.TemporaryFile() as spool:
            signer = format.decrypt_payload(header, file_key, src, spool)
            check(signer)
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
    return signer


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="pqvault")
def main() -> None:
    """Encrypt files so they stay secret even against quantum computers."""


@main.command()
@click.option("-o", "--output", "base", required=True, type=click.Path(path_type=Path),
              help="Base name: writes BASE.pub and BASE.key")
def keygen(base: Path) -> None:
    """Create a post-quantum identity: encryption (ML-KEM-768 + X25519)
    and signing (ML-DSA-65 + Ed25519) keys."""
    passphrase = _prompt_secret("Passphrase to protect the private key", confirm=True)
    try:
        pub, key, identity = keys.write_keypair(base, passphrase)
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(f"Public key (share this):   {pub}")
    click.echo(f"Private key (keep secret): {key}")
    click.echo(f"Fingerprint: {identity.public.fingerprint}")


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-p", "--password", "use_password", is_flag=True, help="Lock with a password.")
@click.option("-r", "--recipient", "recipients", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Recipient public key file (repeatable).")
@click.option("-s", "--sign", "sign_with", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Sign with your private key so recipients can prove it came from you.")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file (default: PATH.pqv).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def encrypt(path: Path, use_password: bool, recipients: tuple[Path, ...], sign_with: Path | None,
            output: Path | None, force: bool) -> None:
    """Encrypt a file or folder."""
    if not use_password and not recipients:
        raise click.UsageError("choose --password and/or at least one --recipient")
    target = output or path.with_name(path.name + SUFFIX)
    try:
        pubs = [r.kem for r in _load_publics(recipients)]
        signer = _load_identity(sign_with) if sign_with else None
        passwords = [_prompt_secret("Password", confirm=True)] if use_password else []
        with _atomic_output(target, force) as tmp, open(tmp, "wb") as dst:
            opts = dict(passwords=passwords, recipients=pubs, signer=signer)
            if path.is_dir():
                with tempfile.TemporaryFile() as spool:
                    with tarfile.open(fileobj=spool, mode="w") as tar:
                        tar.add(path, arcname=path.name)
                    spool.seek(0)
                    format.encrypt(spool, dst, flags=format.FLAG_DIRECTORY, **opts)
            else:
                with open(path, "rb") as src:
                    format.encrypt(src, dst, **opts)
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(f"Encrypted{' and signed' if signer else ''} -> {target}")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-i", "--identity", "identities", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Your private key file (repeatable).")
@click.option("--from", "senders", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Require a valid signature from this public key (repeatable: any one is accepted).")
@click.option("--max-age", type=Duration(), metavar="DURATION",
              help="Reject signatures older than this, e.g. 30m, 12h, 7d (blocks replayed old files).")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output path (default: PATH without .pqv).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def decrypt(path: Path, identities: tuple[Path, ...], senders: tuple[Path, ...], max_age: int | None,
            output: Path | None, force: bool) -> None:
    """Decrypt a .pqv file."""
    if output is None:
        if path.suffix != SUFFIX:
            raise click.UsageError("input does not end in .pqv; give --output")
        output = path.with_suffix("")
    try:
        trusted = _load_publics(senders) or None
        with open(path, "rb") as src:
            header = format.read_header(src)
            idents, password = [], None
            if identities:
                idents = [_load_identity(i).kem for i in identities]
            elif header.has_password:
                password = _prompt_secret("Password", confirm=False)
            else:
                raise click.UsageError("this file needs a private key; pass --identity")
            file_key = format.unlock(header, password=password, identities=idents)

            def check(info: SignatureInfo | None) -> None:
                if trusted:
                    require_signer(info, trusted)
                if max_age is not None:
                    require_fresh(info, max_age)

            if header.flags & format.FLAG_DIRECTORY:
                signer = _decrypt_folder(header, file_key, src, output, force, check)
            else:
                with _atomic_output(output, force) as tmp, open(tmp, "wb") as dst:
                    signer = format.decrypt_payload(header, file_key, src, dst)
                    check(signer)  # raising here discards the temp file
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(f"Decrypted -> {output}")
    _describe_signature(signer, trusted)


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-i", "--identity", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Your private key file.")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Signature file (default: PATH.sig).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def sign(path: Path, identity: Path, output: Path | None, force: bool) -> None:
    """Sign a file without encrypting it (writes a detached .sig file)."""
    target = output or path.with_name(path.name + ".sig")
    try:
        ident = _load_identity(identity)
        with open(path, "rb") as src:
            text = detached.sign(ident, src)
        with _atomic_output(target, force) as tmp:
            tmp.write_text(text)
            tmp.chmod(0o644)  # signatures are public, unlike decrypted files
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(f"Signed -> {target}")
    click.echo(f"Fingerprint: {ident.public.fingerprint}")
    click.echo(f"Signed at {_when(int(time.time()))}")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--from", "senders", required=True, multiple=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Public key you expect the signature to come from (repeatable).")
@click.option("--sig", "sig_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Signature file (default: PATH.sig).")
@click.option("--max-age", type=Duration(), metavar="DURATION",
              help="Reject signatures older than this, e.g. 30m, 12h, 7d.")
def verify(path: Path, senders: tuple[Path, ...], sig_path: Path | None, max_age: int | None) -> None:
    """Check that a file was signed by someone you trust and hasn't changed."""
    sig_path = sig_path or path.with_name(path.name + ".sig")
    if not sig_path.exists():
        raise click.UsageError(f"signature file {sig_path} not found; pass --sig")
    try:
        trusted = _load_publics(senders)
        with open(path, "rb") as src:
            info = detached.verify(sig_path.read_text(), src, trusted, max_age=max_age)
    except PQVaultError as e:
        raise click.ClickException(str(e))
    _describe_signature(info, trusted)


@main.command()
@click.argument("pubkey", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def fingerprint(pubkey: Path) -> None:
    """Show a public key's fingerprint (compare it with its owner in person or by phone)."""
    try:
        pub = keys.decode_public(pubkey.read_text())
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(pub.fingerprint)
    if pub.verify is None:
        click.echo("(old v0.1 key: encryption only, cannot sign)")


if __name__ == "__main__":
    main()
