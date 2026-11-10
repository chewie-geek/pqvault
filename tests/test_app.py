"""Drive the full-screen app headlessly, the way a user would."""

import asyncio
import time

import pytest
from textual.widgets import Checkbox, Input, RadioButton, RichLog, Select, SelectionList

from pqvault import keys
from pqvault.app import (CreateKeyScreen, DecryptScreen, EncryptScreen, FingerprintScreen, ImportKeyScreen,
                         KeysScreen, PqvaultApp, SignScreen, VerifyScreen)
from pqvault.identity import Identity
from pqvault.keyring import Keyring


def run(coro):
    return asyncio.run(coro)


def log_text(app) -> str:
    return "\n".join(str(line.text) for line in app.main_screen.query_one("#log", RichLog).lines)


async def wait_for(pilot, predicate, timeout=10.0):
    """Wait for background crypto jobs to finish."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        await pilot.pause(0.05)
        if predicate():
            return
    status = ""
    try:
        status = str(pilot.app.screen.query_one("#status").render())
    except Exception:
        pass
    raise AssertionError(f"timed out; screen={type(pilot.app.screen).__name__} status={status!r}")


async def press_go(pilot):
    """Click the dialog's main button. Buttons ignore clicks during their
    0.2 s press animation, so wait that out first (as a human would)."""
    await pilot.pause(0.25)
    assert await pilot.click("#go")
    await pilot.pause()


async def fill(screen, **fields):
    for field, value in fields.items():
        screen.query_one(f"#{field}", Input).value = value


@pytest.fixture
def setup(tmp_path):
    kr = Keyring(tmp_path / "home")
    work = tmp_path / "work"
    work.mkdir()
    return kr, work


def test_menu_layout_and_exit(setup):
    kr, work = setup

    async def go():
        app = PqvaultApp(kr, work)
        async with app.run_test(size=(120, 40)) as pilot:
            menu = [str(o.prompt) for o in app.query_one("#menu").options]
            assert [m.split()[0] for m in menu] == ["Encrypt", "Decrypt", "Sign", "Verify", "Keys", "Show", "Exit"]
            assert "no key yet" in log_text(app)
            await pilot.press("q")
            await pilot.pause()
        assert app.return_code == 0 or app.return_code is None
    run(go())


def test_full_key_flow(setup):
    """Create my key, import alice, alice signs a file to me, I decrypt requiring alice."""
    kr, work = setup
    alice = Identity.generate()
    (work / "alice.pub").write_text(keys.encode_public(alice.public))
    secret = work / "plan.txt"
    secret.write_text("top secret plan")

    async def go():
        app = PqvaultApp(kr, work)
        async with app.run_test(size=(120, 50)) as pilot:
            # Keys -> Create key
            await pilot.press("k")
            await pilot.pause()
            assert isinstance(app.screen, KeysScreen)
            await pilot.click("#create")
            await pilot.pause()
            await fill(app.screen, name="me", pw="pp", pw2="pp")
            await press_go(pilot)
            await wait_for(pilot, lambda: isinstance(app.screen, KeysScreen))
            assert [e.name for e in kr.identities()] == ["me"] and kr.default == "me"

            # Keys -> Import contact key: refused until fingerprint confirmed
            await pilot.click("#import")
            await pilot.pause()
            await fill(app.screen, source=str(work / "alice.pub"), name="alice")
            await pilot.pause()
            assert alice.public.fingerprint in str(app.screen.query_one("#fp").render())
            await press_go(pilot)
            await pilot.pause()
            assert "confirm the fingerprint" in str(app.screen.query_one("#status").render())
            app.screen.query_one("#confirmed", Checkbox).value = True
            await press_go(pilot)
            await wait_for(pilot, lambda: isinstance(app.screen, KeysScreen))
            assert [e.name for e in kr.contacts()] == ["alice"]
            await pilot.press("escape")

            # Encrypt with key, to me, signed by me
            await pilot.press("e")
            await pilot.pause()
            s = app.screen
            assert isinstance(s, EncryptScreen)
            await fill(s, path=str(secret))
            s.query_one("#recipients", SelectionList).select("me")
            s.query_one("#do-sign", Checkbox).value = True
            await pilot.pause()
            await fill(s, **{"sign-pass": "pp"})
            await press_go(pilot)
            await wait_for(pilot, lambda: not isinstance(app.screen, EncryptScreen))
            assert (work / "plan.txt.pqv").exists()
            assert "Encrypted plan.txt" in log_text(app)

            # Decrypt with key, requiring a signature from me
            await pilot.press("d")
            await pilot.pause()
            s = app.screen
            await fill(s, path=str(work / "plan.txt.pqv"), **{"key-pass": "pp", "out": str(work / "back.txt")})
            s.query_one("#from", Select).value = "me"
            await press_go(pilot)
            await wait_for(pilot, lambda: not isinstance(app.screen, DecryptScreen))
            assert (work / "back.txt").read_text() == "top secret plan"
            assert "trusted key me (me)" in log_text(app)

            # Decrypt again requiring alice: must fail, dialog stays open, nothing written
            await pilot.press("d")
            await pilot.pause()
            s = app.screen
            await fill(s, path=str(work / "plan.txt.pqv"), **{"key-pass": "pp", "out": str(work / "nope.txt")})
            s.query_one("#from", Select).value = "alice"
            await press_go(pilot)
            await wait_for(pilot, lambda: "untrusted" in str(s.query_one("#status").render()))
            assert isinstance(app.screen, DecryptScreen)
            assert not (work / "nope.txt").exists()
            await pilot.press("escape")
    run(go())


def test_password_flow_and_wrong_password(setup):
    kr, work = setup
    f = work / "notes.txt"
    f.write_text("pw notes")

    async def go():
        app = PqvaultApp(kr, work)
        async with app.run_test(size=(120, 50)) as pilot:
            await pilot.press("e")
            await pilot.pause()
            s = app.screen
            s.query_one("#mode-pw", RadioButton).value = True
            await pilot.pause()
            assert s.query_one("#pw-section").display and not s.query_one("#key-section").display
            await fill(s, path=str(f), pw="hunter2", pw2="hunter3")
            await press_go(pilot)
            await pilot.pause()
            assert "don't match" in str(s.query_one("#status").render())
            await fill(s, pw2="hunter2")
            await press_go(pilot)
            await wait_for(pilot, lambda: not isinstance(app.screen, EncryptScreen))

            await pilot.press("d")

            await pilot.pause()
            s = app.screen
            await fill(s, path=str(work / "notes.txt.pqv"))
            await pilot.pause()
            # mode auto-switches to password for a password-locked file
            assert s.query_one("#mode-pw", RadioButton).value
            await fill(s, pw="wrong", out=str(work / "o.txt"))
            await press_go(pilot)
            await wait_for(pilot, lambda: "wrong password" in str(s.query_one("#status").render()))
            await fill(s, pw="hunter2")
            await press_go(pilot)
            await wait_for(pilot, lambda: not isinstance(app.screen, DecryptScreen))
            assert (work / "o.txt").read_text() == "pw notes"
            assert "Not signed" in log_text(app)
    run(go())


def test_sign_verify_fingerprint(setup):
    kr, work = setup
    kr.create_identity("me", b"pp")
    f = work / "release.zip"
    f.write_bytes(b"release")

    async def go():
        app = PqvaultApp(kr, work)
        async with app.run_test(size=(120, 50)) as pilot:
            await pilot.press("s")
            await pilot.pause()
            await fill(app.screen, path=str(f), **{"key-pass": "pp"})
            await press_go(pilot)
            await wait_for(pilot, lambda: not isinstance(app.screen, SignScreen))
            assert (work / "release.zip.sig").exists()

            await pilot.press("v")

            await pilot.pause()
            s = app.screen
            await fill(s, path=str(f), **{"max-age": "1h"})
            await press_go(pilot)
            await wait_for(pilot, lambda: "Good signature" in str(s.query_one("#status").render()))
            f.write_bytes(b"tampered")
            await press_go(pilot)
            await wait_for(pilot, lambda: "invalid" in str(s.query_one("#status").render()))
            await pilot.press("escape")

            await pilot.press("f")

            await pilot.pause()
            s = app.screen
            assert isinstance(s, FingerprintScreen)
            s.query_one("#which", Select).value = "me"
            await press_go(pilot)
            fp = kr.public("me").fingerprint
            await wait_for(pilot, lambda: fp in str(s.query_one("#status").render()))
    run(go())


def test_sign_without_key_explains(setup):
    kr, work = setup
    f = work / "x"
    f.write_text("x")

    async def go():
        app = PqvaultApp(kr, work)
        async with app.run_test(size=(120, 50)) as pilot:
            await pilot.press("s")
            await pilot.pause()
            await fill(app.screen, path=str(f), **{"key-pass": "pp"})
            await press_go(pilot)
            await pilot.pause()
            assert "create a key first" in str(app.screen.query_one("#status").render())
    run(go())


def test_theme_persists_across_sessions(setup):
    kr, work = setup

    async def first():
        app = PqvaultApp(kr, work)
        async with app.run_test() as pilot:
            assert app.theme != "nord"
            app.theme = "nord"
            await pilot.pause()

    async def second():
        app = PqvaultApp(kr, work)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.theme == "nord"

    run(first())
    assert kr.setting("theme") == "nord"
    run(second())


def test_unknown_saved_theme_is_ignored(setup):
    kr, work = setup
    kr.set_setting("theme", "no-such-theme")

    async def go():
        app = PqvaultApp(kr, work)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.theme in app.available_themes
    run(go())
