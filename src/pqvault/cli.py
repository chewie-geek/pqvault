"""Command line. `pqvault` alone opens the interactive app; subcommands are for scripts.

Anywhere a key is expected you can give either a file path or the name of a
key saved in your keyring (see `pqvault keys`).
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from functools import cache
from pathlib import Path

import click

from . import PQVaultError, __version__, keys, ops
from .identity import CLOCK_SKEW, Identity, PublicIdentity, SignatureInfo
from .keyring import Keyring

# ---------------------------------------------------------------- helpers


@cache
def _keyring() -> Keyring:
    return Keyring()


def _prompt_secret(label: str, confirm: bool) -> bytes:
    value = click.prompt(label, hide_input=True, confirmation_prompt=confirm)
    if not value:
        raise click.UsageError(f"{label} must not be empty")
    return value.encode()


def _resolve_public(ref: str) -> PublicIdentity:
    p = Path(ref)
    return keys.decode_public(p.read_text()) if p.is_file() else _keyring().public(ref)


def _resolve_identity(ref: str) -> Identity:
    p = Path(ref)
    passphrase = _prompt_secret(f"Passphrase for {ref}", confirm=False)
    if p.is_file():
        return keys.decode_private(p.read_text(), passphrase)
    return _keyring().load_identity(ref, passphrase)


def _default_identity_name() -> str:
    name = _keyring().default
    if not name:
        raise PQVaultError("no key given and no default key saved (use -i, or `pqvault keys create NAME`)")
    return name


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", str(text).lower())
    if not m:
        raise ValueError(f"{text!r} is not a duration like 30m, 12h, 7d or 2w")
    return int(m.group(1)) * _UNITS[m.group(2)]


class Duration(click.ParamType):
    """A length of time like 90s, 30m, 12h, 7d or 2w, converted to seconds."""

    name = "duration"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        try:
            return parse_duration(value)
        except ValueError as e:
            self.fail(str(e), param, ctx)


def ago(seconds: float) -> str:
    future = seconds < 0
    seconds = abs(seconds)
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = int(seconds // size)
            text = f"{n} {unit}{'s' if n != 1 else ''}"
            return f"in {text}" if future else f"{text} ago"
    return "in a few seconds" if future else "just now"


def when(signed_at: int) -> str:
    local = datetime.fromtimestamp(signed_at, tz=timezone.utc).astimezone()
    return f"{local:%Y-%m-%d %H:%M:%S %Z} ({ago(time.time() - signed_at)})"


def describe_signature(info: SignatureInfo | None, trusted: bool, keyring: Keyring | None) -> list[str]:
    """Human-readable lines about a verified signature (shared with the app)."""
    if info is None:
        return ["Not signed: this file does not prove who created it."]
    saved = keyring.lookup(info.signer) if keyring else None
    who = f"{saved.label} [{info.signer.fingerprint}]" if saved else info.signer.fingerprint
    if trusted:
        lines = [f"Good signature from trusted key {who}"]
    elif saved:
        lines = [f"Good signature from {who} (a key in your keyring)"]
    else:
        lines = [f"Signed by unknown key {who}",
                 "  (not in your keyring: compare this fingerprint with the sender,",
                 "   or import their key / pass --from to require it)"]
    lines.append(f"Signed at {when(info.signed_at)}, according to the signer's clock")
    if info.signed_at > time.time() + CLOCK_SKEW:
        lines.append("  Warning: this time is in the future; the signer's clock may be wrong.")
    return lines


def _fail(e: PQVaultError):
    raise click.ClickException(str(e))


# ---------------------------------------------------------------- commands


@click.group(context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.version_option(__version__, prog_name="pqvault")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Encrypt and sign files so they stay secure even against quantum computers.

    Run with no command to open the interactive app."""
    if ctx.invoked_subcommand is None:
        from .app import run_app
        run_app()


@main.command()
@click.option("-o", "--output", "base", required=True, type=click.Path(path_type=Path),
              help="Base name: writes BASE.pub and BASE.key")
def keygen(base: Path) -> None:
    """Create a keypair as loose files (see `pqvault keys create` to save one in your keyring)."""
    passphrase = _prompt_secret("Passphrase to protect the private key", confirm=True)
    try:
        pub, key, identity = keys.write_keypair(base, passphrase)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Public key (share this):   {pub}")
    click.echo(f"Private key (keep secret): {key}")
    click.echo(f"Fingerprint: {identity.public.fingerprint}")


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-p", "--password", "use_password", is_flag=True, help="Lock with a password.")
@click.option("-r", "--recipient", "recipients", multiple=True, metavar="KEY",
              help="Recipient: public key file or saved key name (repeatable).")
@click.option("-s", "--sign", "sign_with", metavar="KEY",
              help="Sign with your private key (file or saved name) so recipients can prove it came from you.")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file (default: PATH.pqv).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def encrypt(path: Path, use_password: bool, recipients: tuple[str, ...], sign_with: str | None,
            output: Path | None, force: bool) -> None:
    """Encrypt a file or folder."""
    if not use_password and not recipients:
        raise click.UsageError("choose --password and/or at least one --recipient")
    try:
        pubs = [_resolve_public(r) for r in recipients]
        signer = _resolve_identity(sign_with) if sign_with else None
        passwords = [_prompt_secret("Password", confirm=True)] if use_password else []
        target = ops.encrypt_path(path, output, passwords=passwords, recipients=pubs, signer=signer, force=force)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Encrypted{' and signed' if signer else ''} -> {target}")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-i", "--identity", "identities", multiple=True, metavar="KEY",
              help="Your private key: file or saved name (repeatable). Default: password, else your default key.")
@click.option("--from", "senders", multiple=True, metavar="KEY",
              help="Require a valid signature from this public key: file or saved name (repeatable).")
@click.option("--max-age", type=Duration(), metavar="DURATION",
              help="Reject signatures older than this, e.g. 30m, 12h, 7d (blocks replayed old files).")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output path (default: PATH without .pqv).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def decrypt(path: Path, identities: tuple[str, ...], senders: tuple[str, ...], max_age: int | None,
            output: Path | None, force: bool) -> None:
    """Decrypt a .pqv file."""
    try:
        if output is None:
            output = ops.default_decrypt_output(path)
        trusted = [_resolve_public(s) for s in senders] or None
        password, idents = None, []
        if identities:
            idents = [_resolve_identity(i).kem for i in identities]
        elif ops.needs_password(path):
            password = _prompt_secret("Password", confirm=False)
        else:
            idents = [_resolve_identity(_default_identity_name()).kem]
        target, info = ops.decrypt_path(path, output, password=password, identities=idents,
                                        trusted=trusted, max_age=max_age, force=force)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Decrypted -> {target}")
    for line in describe_signature(info, bool(trusted), _keyring()):
        click.echo(line)


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-i", "--identity", metavar="KEY", help="Your private key: file or saved name (default: your default key).")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Signature file (default: PATH.sig).")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output if it exists.")
def sign(path: Path, identity: str | None, output: Path | None, force: bool) -> None:
    """Sign a file without encrypting it (writes a detached .sig file)."""
    try:
        ident = _resolve_identity(identity or _default_identity_name())
        target = ops.sign_path(path, ident, output, force)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Signed -> {target}")
    click.echo(f"Fingerprint: {ident.public.fingerprint}")
    click.echo(f"Signed at {when(int(time.time()))}")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--from", "senders", required=True, multiple=True, metavar="KEY",
              help="Public key you expect the signature from: file or saved name (repeatable).")
@click.option("--sig", "sig_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Signature file (default: PATH.sig).")
@click.option("--max-age", type=Duration(), metavar="DURATION",
              help="Reject signatures older than this, e.g. 30m, 12h, 7d.")
def verify(path: Path, senders: tuple[str, ...], sig_path: Path | None, max_age: int | None) -> None:
    """Check that a file was signed by someone you trust and hasn't changed."""
    try:
        trusted = [_resolve_public(s) for s in senders]
        info = ops.verify_path(path, trusted, sig_path, max_age)
    except PQVaultError as e:
        _fail(e)
    for line in describe_signature(info, True, _keyring()):
        click.echo(line)


@main.command()
@click.argument("key", metavar="KEY")
def fingerprint(key: str) -> None:
    """Show a public key's fingerprint (file or saved name). Compare it with its owner in person or by phone."""
    try:
        pub = _resolve_public(key)
    except PQVaultError as e:
        _fail(e)
    click.echo(pub.fingerprint)
    if pub.verify is None:
        click.echo("(old v0.1 key: encryption only, cannot sign)")


# ---------------------------------------------------------------- keyring


@main.group("keys")
def keys_group() -> None:
    """Manage saved keys (stored in ~/.pqvault, or $PQVAULT_HOME)."""


@keys_group.command("list")
def keys_list() -> None:
    """List your keys and your contacts' keys."""
    kr = _keyring()
    default = kr.default
    entries = kr.all()
    if not entries:
        click.echo("No saved keys. Create one with `pqvault keys create NAME`.")
    for e in entries:
        star = "*" if e.mine and e.name == default else " "
        kind = "mine   " if e.mine else "contact"
        click.echo(f"{star} {kind}  {e.name:<20} {e.public.fingerprint}")


@keys_group.command("create")
@click.argument("name")
def keys_create(name: str) -> None:
    """Create a new keypair of your own and save it."""
    try:
        passphrase = _prompt_secret("Passphrase to protect the private key", confirm=True)
        entry = _keyring().create_identity(name, passphrase)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Created {entry.name}: {entry.public.fingerprint}")
    click.echo(f"Share your public key file: {_keyring().public_path(name)}")


@keys_group.command("import")
@click.argument("name")
@click.argument("pubfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-y", "--yes", is_flag=True, help="Skip the fingerprint confirmation.")
def keys_import(name: str, pubfile: Path, yes: bool) -> None:
    """Save someone's public key under NAME."""
    try:
        text = pubfile.read_text()
        pub = _keyring().preview_contact(text)
        click.echo(f"Fingerprint: {pub.fingerprint}")
        if not yes:
            click.confirm(f"Did you confirm this fingerprint with {name} in person or over a trusted call?", abort=True)
        _keyring().import_contact(name, text)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Saved {name}.")


@keys_group.command("export")
@click.argument("name")
def keys_export(name: str) -> None:
    """Print one of your public keys, to share."""
    try:
        click.echo(_keyring().public_path(name).read_text().strip())
    except PQVaultError as e:
        _fail(e)


@keys_group.command("remove")
@click.argument("name")
def keys_remove(name: str) -> None:
    """Remove a contact's key."""
    try:
        _keyring().remove_contact(name)
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Removed {name}.")


@keys_group.command("default")
@click.argument("name")
def keys_default(name: str) -> None:
    """Choose which of your keys is used when none is given."""
    try:
        _keyring().default = name
    except PQVaultError as e:
        _fail(e)
    click.echo(f"Default key is now {name}.")


if __name__ == "__main__":
    main()
