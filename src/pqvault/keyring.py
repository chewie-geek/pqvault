"""Saved keys, stored in ~/.pqvault (or $PQVAULT_HOME).

    identities/NAME.key  NAME.pub   your own keypairs (private key passphrase-protected)
    contacts/NAME.pub               other people's public keys you have imported
    config.json                     {"default": NAME, "theme": NAME, ...}

Importing a contact means "I trust that this key belongs to NAME", so the
app asks you to confirm the fingerprint with its owner first.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import PQVaultError, keys
from .identity import Identity, PublicIdentity
from .password import Argon2Params

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


@dataclass(frozen=True)
class Entry:
    name: str
    public: PublicIdentity
    mine: bool  # True: one of your identities (you hold the private key)

    @property
    def label(self) -> str:
        return f"{self.name} (me)" if self.mine else self.name


def default_home() -> Path:
    return Path(os.environ.get("PQVAULT_HOME") or Path.home() / ".pqvault")


def check_name(name: str) -> str:
    if not _NAME.fullmatch(name or ""):
        raise PQVaultError("names may use letters, digits, '.', '_' and '-' (max 64, no leading symbol)")
    return name


class Keyring:
    def __init__(self, home: Path | None = None):
        self.home = Path(home) if home else default_home()
        self.identities_dir = self.home / "identities"
        self.contacts_dir = self.home / "contacts"
        for d in (self.home, self.identities_dir, self.contacts_dir):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)

    # --- listing ---

    def identities(self) -> list[Entry]:
        return [Entry(p.stem, keys.decode_public(p.read_text()), True)
                for p in sorted(self.identities_dir.glob("*.pub"))]

    def contacts(self) -> list[Entry]:
        return [Entry(p.stem, keys.decode_public(p.read_text()), False)
                for p in sorted(self.contacts_dir.glob("*.pub"))]

    def all(self) -> list[Entry]:
        return self.identities() + self.contacts()

    def lookup(self, public: PublicIdentity) -> Entry | None:
        """Find which saved name (if any) a public key belongs to."""
        return next((e for e in self.all() if e.public == public), None)

    def public(self, name: str) -> PublicIdentity:
        for d in (self.contacts_dir, self.identities_dir):
            p = d / f"{check_name(name)}.pub"
            if p.exists():
                return keys.decode_public(p.read_text())
        raise PQVaultError(f"no saved key named {name!r}")

    def public_path(self, name: str) -> Path:
        p = self.identities_dir / f"{check_name(name)}.pub"
        if not p.exists():
            raise PQVaultError(f"no identity named {name!r}")
        return p

    # --- your identities ---

    def create_identity(self, name: str, passphrase: bytes, argon_params: Argon2Params | None = None) -> Entry:
        self._ensure_free(check_name(name))
        _, _, ident = keys.write_keypair(self.identities_dir / name, passphrase, argon_params)
        if self.default is None:
            self.default = name
        return Entry(name, ident.public, True)

    def load_identity(self, name: str, passphrase: bytes) -> Identity:
        p = self.identities_dir / f"{check_name(name)}.key"
        if not p.exists():
            raise PQVaultError(f"no identity named {name!r}")
        return keys.decode_private(p.read_text(), passphrase)

    @property
    def default(self) -> str | None:
        name = self._config().get("default")
        return name if name and (self.identities_dir / f"{name}.key").exists() else None

    @default.setter
    def default(self, name: str) -> None:
        if not (self.identities_dir / f"{check_name(name)}.key").exists():
            raise PQVaultError(f"no identity named {name!r}")
        self.set_setting("default", name)

    # --- app settings (stored alongside the default key in config.json) ---

    def setting(self, key: str, fallback=None):
        return self._config().get(key, fallback)

    def set_setting(self, key: str, value) -> None:
        cfg = self._config()
        cfg[key] = value
        (self.home / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")

    # --- contacts ---

    def preview_contact(self, text: str) -> PublicIdentity:
        """Parse a public key so its fingerprint can be confirmed before importing."""
        pub = keys.decode_public(text)
        existing = self.lookup(pub)
        if existing:
            raise PQVaultError(f"this key is already saved as {existing.label!r}")
        return pub

    def import_contact(self, name: str, text: str) -> Entry:
        self._ensure_free(check_name(name))
        pub = self.preview_contact(text)
        (self.contacts_dir / f"{name}.pub").write_text(keys.encode_public(pub) + "\n")
        return Entry(name, pub, False)

    def remove_contact(self, name: str) -> None:
        p = self.contacts_dir / f"{check_name(name)}.pub"
        if not p.exists():
            raise PQVaultError(f"no contact named {name!r}")
        p.unlink()

    # --- helpers ---

    def _ensure_free(self, name: str) -> None:
        taken = [p for p in (self.identities_dir / f"{name}.key", self.identities_dir / f"{name}.pub",
                             self.contacts_dir / f"{name}.pub") if p.exists()]
        if taken:
            raise PQVaultError(f"the name {name!r} is already used")

    def _config(self) -> dict:
        try:
            return json.loads((self.home / "config.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
