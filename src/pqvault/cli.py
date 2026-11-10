"""Command-line interface: pqvault keygen | encrypt | decrypt."""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import click

from . import PQVaultError, __version__, format, keys

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


def _decrypt_folder(header, file_key: bytes, src, output: Path, force: bool) -> None:
    """Authenticate the whole archive first, then extract and move into place."""
    if output.exists() and not force:
        raise click.ClickException(f"{output} already exists (use --force to overwrite)")
    staging = Path(tempfile.mkdtemp(prefix=".pqvault-", dir=output.parent or "."))
    try:
        with tempfile.TemporaryFile() as spool:
            format.decrypt_payload(header, file_key, src, spool)
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


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="pqvault")
def main() -> None:
    """Encrypt files so they stay secret even against quantum computers."""


@main.command()
@click.option("-o", "--output", "base", required=True, type=click.Path(path_type=Path),
              help="Base name: writes BASE.pub and BASE.key")
def keygen(base: Path) -> None:
    """Create a post-quantum keypair (ML-KEM-768 + X25519)."""
    passphrase = _prompt_secret("Passphrase to protect the private key", confirm=True)
    try:
        pub, key = keys.write_keypair(base, passphrase)
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(f"Public key (share this):   {pub}")
    click.echo(f"Private key (keep secret): {key}")


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-p", "--password", "use_password", is_flag=True, help="Lock with a password.")
@click.option("-r", "--recipient", "recipients", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Recipient public key file (repeatable).")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file (default: PATH.pqv).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def encrypt(path: Path, use_password: bool, recipients: tuple[Path, ...], output: Path | None, force: bool) -> None:
    """Encrypt a file or folder."""
    if not use_password and not recipients:
        raise click.UsageError("choose --password and/or at least one --recipient")
    try:
        pubs = [keys.decode_public(r.read_text()) for r in recipients]
    except PQVaultError as e:
        raise click.ClickException(str(e))
    passwords = [_prompt_secret("Password", confirm=True)] if use_password else []
    target = output or path.with_name(path.name + SUFFIX)

    with _atomic_output(target, force) as tmp, open(tmp, "wb") as dst:
        if path.is_dir():
            with tempfile.TemporaryFile() as spool:
                with tarfile.open(fileobj=spool, mode="w") as tar:
                    tar.add(path, arcname=path.name)
                spool.seek(0)
                format.encrypt(spool, dst, passwords=passwords, recipients=pubs, flags=format.FLAG_DIRECTORY)
        else:
            with open(path, "rb") as src:
                format.encrypt(src, dst, passwords=passwords, recipients=pubs)
    click.echo(f"Encrypted -> {target}")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-i", "--identity", "identities", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Your private key file (repeatable).")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output path (default: PATH without .pqv).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def decrypt(path: Path, identities: tuple[Path, ...], output: Path | None, force: bool) -> None:
    """Decrypt a .pqv file."""
    if output is None:
        if path.suffix != SUFFIX:
            raise click.UsageError("input does not end in .pqv; give --output")
        output = path.with_suffix("")
    try:
        with open(path, "rb") as src:
            header = format.read_header(src)
            idents, password = [], None
            if identities:
                for ident in identities:
                    idents.append(keys.decode_private(ident.read_text(), _prompt_secret(f"Passphrase for {ident}", confirm=False)))
            elif header.has_password:
                password = _prompt_secret("Password", confirm=False)
            else:
                raise click.UsageError("this file needs a private key; pass --identity")
            file_key = format.unlock(header, password=password, identities=idents)

            if header.flags & format.FLAG_DIRECTORY:
                _decrypt_folder(header, file_key, src, output, force)
            else:
                with _atomic_output(output, force) as tmp, open(tmp, "wb") as dst:
                    format.decrypt_payload(header, file_key, src, dst)
    except PQVaultError as e:
        raise click.ClickException(str(e))
    click.echo(f"Decrypted -> {output}")


if __name__ == "__main__":
    main()
