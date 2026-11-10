import os
import stat

import pytest

from pqvault import PQVaultError, keys
from pqvault.identity import Identity
from pqvault.keyring import Keyring, check_name


@pytest.fixture
def kr(tmp_path):
    return Keyring(tmp_path / "home")


def test_dirs_are_private(kr):
    for d in (kr.home, kr.identities_dir, kr.contacts_dir):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_create_identity_sets_default(kr):
    me = kr.create_identity("me", b"pw")
    kr.create_identity("work", b"pw")
    assert kr.default == "me"
    assert [e.name for e in kr.identities()] == ["me", "work"]
    assert kr.load_identity("me", b"pw").public == me.public
    kr.default = "work"
    assert kr.default == "work"


def test_import_contact_and_lookup(kr):
    alice = Identity.generate()
    text = keys.encode_public(alice.public)
    assert kr.preview_contact(text) == alice.public
    kr.import_contact("alice", text)
    assert kr.public("alice") == alice.public
    assert kr.lookup(alice.public).name == "alice"
    assert kr.lookup(Identity.generate().public) is None


def test_duplicate_key_or_name_rejected(kr):
    kr.create_identity("me", b"pw")
    alice = keys.encode_public(Identity.generate().public)
    kr.import_contact("alice", alice)
    with pytest.raises(PQVaultError, match="already saved"):
        kr.import_contact("alice2", alice)
    with pytest.raises(PQVaultError, match="already used"):
        kr.import_contact("me", keys.encode_public(Identity.generate().public))
    with pytest.raises(PQVaultError, match="already saved"):  # your own key as a contact
        kr.import_contact("me2", kr.public_path("me").read_text())


@pytest.mark.parametrize("bad", ["", "../evil", "a/b", ".hidden", "x" * 65, "sp ace"])
def test_bad_names(bad):
    with pytest.raises(PQVaultError):
        check_name(bad)


def test_remove_contact(kr):
    kr.import_contact("bob", keys.encode_public(Identity.generate().public))
    kr.remove_contact("bob")
    assert kr.contacts() == []
    with pytest.raises(PQVaultError):
        kr.remove_contact("bob")


def test_env_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PQVAULT_HOME", str(tmp_path / "custom"))
    assert Keyring().home == tmp_path / "custom"
    assert os.path.isdir(tmp_path / "custom" / "contacts")
