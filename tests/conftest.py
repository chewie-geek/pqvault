import pytest

from pqvault import format
from pqvault.password import Argon2Params

FAST = Argon2Params(memory_kib=64, iterations=1, lanes=1)


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    """Real Argon2id, but with tiny cost so the suite runs quickly."""
    monkeypatch.setattr(format, "DEFAULT_PARAMS", FAST)


@pytest.fixture(autouse=True)
def isolated_keyring(tmp_path_factory, monkeypatch):
    """Never touch the real ~/.pqvault during tests."""
    from pqvault import cli

    monkeypatch.setenv("PQVAULT_HOME", str(tmp_path_factory.mktemp("pqvault-home")))
    cli._keyring.cache_clear()
    yield
    cli._keyring.cache_clear()
