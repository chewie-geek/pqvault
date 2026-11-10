"""Interactive full-screen app (run `pqvault` with no arguments).

Layout: a menu on the left (Encrypt, Decrypt, Sign, Verify, Keys, Fingerprint,
Exit), your saved keys and an activity log on the right. Each action opens a
form; the crypto runs in a background thread so the screen never freezes.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable

from rich.markup import escape
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    DirectoryTree,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    RadioButton,
    RadioSet,
    RichLog,
    Select,
    SelectionList,
    Static,
    TextArea,
)
from textual.widgets.option_list import Option
from textual.worker import Worker, WorkerState

from . import PQVaultError, __version__, keys, ops
from .cli import describe_signature, parse_duration
from .identity import PublicIdentity
from .keyring import Keyring

Job = Callable[[], list[str]]

MENU = [
    ("encrypt", "Encrypt", "e"),
    ("decrypt", "Decrypt", "d"),
    ("sign", "Sign file", "s"),
    ("verify", "Verify file", "v"),
    ("keys", "Keys", "k"),
    ("fingerprint", "Show fingerprint", "f"),
    ("exit", "Exit", "q"),
]

ANYONE = "__anyone__"
NONE = "__none__"


def _path(text: str) -> Path:
    text = text.strip()
    if not text:
        raise PQVaultError("choose a file")
    return Path(text).expanduser()


def _optional_path(text: str) -> Path | None:
    return Path(text.strip()).expanduser() if text.strip() else None


def _secret(text: str, what: str) -> bytes:
    if not text:
        raise PQVaultError(f"enter the {what}")
    return text.encode()


def _max_age(text: str) -> int | None:
    if not text.strip():
        return None
    try:
        return parse_duration(text)
    except ValueError as e:
        raise PQVaultError(str(e)) from None


# ====================================================================== pickers


class FilePicker(ModalScreen[Path | None]):
    """Browse for a file (or, with Choose, a highlighted folder)."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

    def __init__(self, start: Path):
        super().__init__()
        self.start = start

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog picker"):
            yield Label("Choose a file or folder", classes="title")
            yield Static(str(self.start), id="where", classes="hint")
            yield DirectoryTree(self.start, id="tree")
            with Horizontal(classes="buttons"):
                yield Button("Choose", variant="primary", id="choose")
                yield Button("Up a folder", id="up")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one(DirectoryTree).focus()

    @on(DirectoryTree.FileSelected)
    def _file(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(event.path)

    @on(Button.Pressed, "#choose")
    def _choose(self) -> None:
        node = self.query_one(DirectoryTree).cursor_node
        self.dismiss(node.data.path if node and node.data else None)

    @on(Button.Pressed, "#up")
    def _up(self) -> None:
        tree = self.query_one(DirectoryTree)
        tree.path = Path(tree.path).resolve().parent
        self.query_one("#where", Static).update(str(tree.path))

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None:
        self.dismiss(None)


# ====================================================================== forms


class FormScreen(ModalScreen[list[str] | None]):
    """A dialog with fields, a status line, and Go / Cancel buttons.

    Subclasses implement fields() and prepare(). prepare() validates input on
    the UI thread and returns a job that runs in a background thread; the job
    returns lines for the activity log. Errors keep the dialog open."""

    TITLE = ""
    GO = "Go"
    KEEP_OPEN = False  # True: show the result in the dialog instead of closing
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    @property
    def keyring(self) -> Keyring:
        return self.app.keyring  # type: ignore[attr-defined]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog"):
            yield Label(self.TITLE, classes="title")
            yield from self.fields()
            yield Static("", id="status")
            with Horizontal(classes="buttons"):
                yield Button(self.GO, variant="primary", id="go")
                yield Button("Cancel" if not self.KEEP_OPEN else "Close", id="cancel")

    def fields(self) -> ComposeResult:
        yield from ()

    def prepare(self) -> Job:
        raise NotImplementedError

    # --- helpers for subclasses ---

    def path_row(self, field_id: str, placeholder: str) -> ComposeResult:
        with Horizontal(classes="path-row"):
            yield Input(placeholder=placeholder, id=field_id)
            yield Button("Browse…", id=f"browse-{field_id}", classes="browse")

    def value(self, selector: str) -> str:
        return self.query_one(selector, Input).value

    def show(self, selector: str, visible: bool) -> None:
        self.query_one(selector).display = visible

    def identity_options(self) -> list[tuple[str, str]]:
        ids = self.keyring.identities()
        if not ids:
            return [("(no keys yet: create one under Keys)", NONE)]
        default = self.keyring.default
        ids.sort(key=lambda e: e.name != default)
        return [(e.label, e.name) for e in ids]

    def status(self, text: str, error: bool = False) -> None:
        widget = self.query_one("#status", Static)
        widget.set_class(error, "error")
        widget.update(escape(text))

    # --- events ---

    @on(Button.Pressed, ".browse")
    def _browse(self, event: Button.Pressed) -> None:
        target = event.button.id.removeprefix("browse-")

        def picked(path: Path | None) -> None:
            if path is not None:
                self.query_one(f"#{target}", Input).value = str(path)

        self.app.push_screen(FilePicker(self.app.start_dir), picked)  # type: ignore[attr-defined]

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#go")
    @on(Input.Submitted)
    def submit(self) -> None:
        try:
            job = self.prepare()
        except (PQVaultError, OSError) as e:
            self.status(str(e), error=True)
            return
        self.query_one("#go", Button).disabled = True
        self.status("Working…")
        self.run_worker(job, thread=True, exit_on_error=False, group="job")

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.group != "job":
            return
        if event.state == WorkerState.SUCCESS:
            if self.KEEP_OPEN:
                self.query_one("#go", Button).disabled = False
                self.status("\n".join(event.worker.result))
            else:
                self.dismiss(event.worker.result)
        elif event.state == WorkerState.ERROR:
            self.query_one("#go", Button).disabled = False
            err = event.worker.error
            msg = str(err) if isinstance(err, (PQVaultError, OSError)) else f"Unexpected error: {err!r}"
            self.status(msg, error=True)


class EncryptScreen(FormScreen):
    TITLE = "Encrypt a file or folder"
    GO = "Encrypt"

    def fields(self) -> ComposeResult:
        yield from self.path_row("path", "File or folder to encrypt")
        with RadioSet(id="mode"):
            yield RadioButton("With key: only chosen people can open it", value=True, id="mode-key")
            yield RadioButton("Without key: anyone with the password can open it", id="mode-pw")
        with Vertical(id="key-section"):
            yield Label("Who can open it? (space to select)")
            yield SelectionList[str](
                *[(f"{e.label:<24} {e.public.fingerprint[:14]}", e.name, False) for e in self.keyring.all()],
                id="recipients",
            )
        with Vertical(id="pw-section"):
            yield Input(placeholder="Password", password=True, id="pw")
            yield Input(placeholder="Repeat password", password=True, id="pw2")
        yield Checkbox("Sign it with my key (proves it came from you)", id="do-sign")
        with Vertical(id="sign-section"):
            yield Select(self.identity_options(), allow_blank=False, id="signer")
            yield Input(placeholder="Passphrase for your key", password=True, id="sign-pass")
        yield Input(placeholder="Save as (default: <name>.pqv next to it)", id="out")
        yield Checkbox("Overwrite if it exists", id="force")

    def on_mount(self) -> None:
        self._sync()

    @on(RadioSet.Changed)
    @on(Checkbox.Changed, "#do-sign")
    def _sync(self) -> None:
        with_key = self.query_one("#mode", RadioSet).pressed_index == 0
        self.show("#key-section", with_key)
        self.show("#pw-section", not with_key)
        self.show("#sign-section", self.query_one("#do-sign", Checkbox).value)

    def prepare(self) -> Job:
        path = _path(self.value("#path"))
        if not path.exists():
            raise PQVaultError(f"{path} does not exist")
        passwords, recipients = [], []
        if self.query_one("#mode", RadioSet).pressed_index == 0:
            names = self.query_one("#recipients", SelectionList).selected
            if not names:
                raise PQVaultError("select at least one person (or use a password)")
            recipients = [self.keyring.public(n) for n in names]
        else:
            pw = _secret(self.value("#pw"), "password")
            if self.value("#pw2") != self.value("#pw"):
                raise PQVaultError("passwords don't match")
            passwords = [pw]
        sign = self.query_one("#do-sign", Checkbox).value
        signer_name = self.query_one("#signer", Select).value
        if sign and signer_name == NONE:
            raise PQVaultError("create a key first (Keys → Create key)")
        sign_pass = _secret(self.value("#sign-pass"), "passphrase for your key") if sign else b""
        out = _optional_path(self.value("#out"))
        force = self.query_one("#force", Checkbox).value
        kr = self.keyring
        who = ", ".join(self.query_one("#recipients", SelectionList).selected) if recipients else "password"

        def job() -> list[str]:
            signer = kr.load_identity(signer_name, sign_pass) if sign else None
            target = ops.encrypt_path(path, out, passwords=passwords, recipients=recipients,
                                      signer=signer, force=force)
            return [f"Encrypted {path.name} -> {target}",
                    f"  opens with: {who}" + (f"; signed by {signer_name}" if sign else "")]
        return job


class DecryptScreen(FormScreen):
    TITLE = "Decrypt a .pqv file"
    GO = "Decrypt"

    def fields(self) -> ComposeResult:
        yield from self.path_row("path", "Encrypted .pqv file")
        with RadioSet(id="mode"):
            yield RadioButton("With key: it was encrypted to me", value=True, id="mode-key")
            yield RadioButton("Without key: I have the password", id="mode-pw")
        with Vertical(id="key-section"):
            yield Select(self.identity_options(), allow_blank=False, id="identity")
            yield Input(placeholder="Passphrase for your key", password=True, id="key-pass")
        with Vertical(id="pw-section"):
            yield Input(placeholder="Password", password=True, id="pw")
        yield Label("Require a signature from:")
        yield Select([("Nobody: just tell me who signed it", ANYONE)]
                     + [(e.label, e.name) for e in self.keyring.all()], allow_blank=False, id="from")
        yield Input(placeholder="Max signature age, e.g. 7d (optional)", id="max-age")
        yield Input(placeholder="Save as (default: name without .pqv)", id="out")
        yield Checkbox("Overwrite if it exists", id="force")

    def on_mount(self) -> None:
        self._sync()

    @on(Input.Changed, "#path")
    def _guess_mode(self, event: Input.Changed) -> None:
        """Pick key/password automatically once a real .pqv file is entered."""
        try:
            path = _path(event.value)
            if path.is_file():
                self.query_one("#mode-pw" if ops.needs_password(path) else "#mode-key", RadioButton).value = True
        except (PQVaultError, OSError):
            pass

    @on(RadioSet.Changed)
    def _sync(self) -> None:
        with_key = self.query_one("#mode", RadioSet).pressed_index == 0
        self.show("#key-section", with_key)
        self.show("#pw-section", not with_key)

    def prepare(self) -> Job:
        path = _path(self.value("#path"))
        if not path.is_file():
            raise PQVaultError(f"{path} is not a file")
        with_key = self.query_one("#mode", RadioSet).pressed_index == 0
        name = self.query_one("#identity", Select).value
        if with_key and name == NONE:
            raise PQVaultError("you have no keys; use the password option or create a key")
        secret = (_secret(self.value("#key-pass"), "passphrase for your key") if with_key
                  else _secret(self.value("#pw"), "password"))
        sender = self.query_one("#from", Select).value
        trusted = [self.keyring.public(sender)] if sender != ANYONE else None
        max_age = _max_age(self.value("#max-age"))
        out = _optional_path(self.value("#out")) or ops.default_decrypt_output(path)
        force = self.query_one("#force", Checkbox).value
        kr = self.keyring

        def job() -> list[str]:
            idents = [kr.load_identity(name, secret).kem] if with_key else []
            target, info = ops.decrypt_path(path, out, password=None if with_key else secret,
                                            identities=idents, trusted=trusted, max_age=max_age, force=force)
            return [f"Decrypted {path.name} -> {target}",
                    *("  " + line for line in describe_signature(info, bool(trusted), kr))]
        return job


class SignScreen(FormScreen):
    TITLE = "Sign a file (without encrypting it)"
    GO = "Sign"

    def fields(self) -> ComposeResult:
        yield from self.path_row("path", "File to sign")
        yield Select(self.identity_options(), allow_blank=False, id="identity")
        yield Input(placeholder="Passphrase for your key", password=True, id="key-pass")
        yield Input(placeholder="Save signature as (default: <name>.sig)", id="out")
        yield Checkbox("Overwrite if it exists", id="force")

    def prepare(self) -> Job:
        path = _path(self.value("#path"))
        name = self.query_one("#identity", Select).value
        if name == NONE:
            raise PQVaultError("create a key first (Keys → Create key)")
        secret = _secret(self.value("#key-pass"), "passphrase for your key")
        out = _optional_path(self.value("#out"))
        force = self.query_one("#force", Checkbox).value
        kr = self.keyring

        def job() -> list[str]:
            target = ops.sign_path(path, kr.load_identity(name, secret), out, force)
            return [f"Signed {path.name} as {name} -> {target}", "  share the .sig file along with the original"]
        return job


class VerifyScreen(FormScreen):
    TITLE = "Verify a signed file"
    GO = "Verify"
    KEEP_OPEN = True

    def fields(self) -> ComposeResult:
        yield from self.path_row("path", "File that was signed")
        yield from self.path_row("sig", "Signature file (default: <name>.sig)")
        yield Label("Expect it to be signed by:")
        yield Select([("Anyone in my keyring", ANYONE)] + [(e.label, e.name) for e in self.keyring.all()],
                     allow_blank=False, id="from")
        yield Input(placeholder="Max signature age, e.g. 7d (optional)", id="max-age")

    def prepare(self) -> Job:
        path = _path(self.value("#path"))
        sig = _optional_path(self.value("#sig"))
        sender = self.query_one("#from", Select).value
        trusted = ([e.public for e in self.keyring.all()] if sender == ANYONE
                   else [self.keyring.public(sender)])
        if not trusted:
            raise PQVaultError("your keyring is empty: import the signer's key first (Keys → Import)")
        max_age = _max_age(self.value("#max-age"))
        kr = self.keyring

        def job() -> list[str]:
            info = ops.verify_path(path, trusted, sig, max_age)
            return [f"Verified {path.name}", *("  " + line for line in describe_signature(info, True, kr))]
        return job


class FingerprintScreen(FormScreen):
    TITLE = "Show a fingerprint"
    GO = "Show"
    KEEP_OPEN = True

    def fields(self) -> ComposeResult:
        yield Static("Read this out to the key's owner (in person or on a call) and check it matches theirs.",
                     classes="hint")
        yield Select([("A key file…", NONE)] + [(e.label, e.name) for e in self.keyring.all()],
                     allow_blank=False, id="which")
        yield from self.path_row("path", "Public key file (.pub)")

    def prepare(self) -> Job:
        which = self.query_one("#which", Select).value
        if which == NONE:
            pub = keys.decode_public(_path(self.value("#path")).read_text())
        else:
            pub = self.keyring.public(which)
        return lambda: [f"{pub.fingerprint}"]


class CreateKeyScreen(FormScreen):
    TITLE = "Create a new key of your own"
    GO = "Create"

    def fields(self) -> ComposeResult:
        yield Static("Your key lets people encrypt files to you, and lets you sign files.\n"
                     "The passphrase protects it if your computer is stolen; it can't be recovered.",
                     classes="hint")
        yield Input(placeholder="Name (e.g. your first name)", id="name")
        yield Input(placeholder="Passphrase", password=True, id="pw")
        yield Input(placeholder="Repeat passphrase", password=True, id="pw2")

    def prepare(self) -> Job:
        name = self.value("#name").strip()
        pw = _secret(self.value("#pw"), "passphrase")
        if self.value("#pw2") != self.value("#pw"):
            raise PQVaultError("passphrases don't match")
        kr = self.keyring

        def job() -> list[str]:
            e = kr.create_identity(name, pw)
            return [f"Created key {e.name}: {e.public.fingerprint}",
                    f"  share your public key: {kr.public_path(e.name)}"]
        return job


class ImportKeyScreen(FormScreen):
    TITLE = "Import a contact's public key"
    GO = "Import"

    def fields(self) -> ComposeResult:
        yield from self.path_row("source", "Their .pub file, or paste their pqv2pub:… key")
        yield Static("", id="fp", classes="fingerprint")
        yield Input(placeholder="Save as name (e.g. alice)", id="name")
        yield Checkbox("I checked this fingerprint with them in person or on a call", id="confirmed")

    def _text(self) -> str:
        raw = self.value("#source").strip()
        if raw.startswith("pqv"):
            return raw
        path = _path(raw)
        if not path.is_file():
            raise PQVaultError(f"{path} is not a file")
        return path.read_text()

    @on(Input.Changed, "#source")
    def _preview(self) -> None:
        fp = self.query_one("#fp", Static)
        try:
            pub = self.keyring.preview_contact(self._text())
            fp.update(f"Fingerprint: {pub.fingerprint}")
        except (PQVaultError, OSError) as e:
            fp.update(f"[dim]{escape(str(e))}[/dim]" if self.value("#source").strip() else "")

    def prepare(self) -> Job:
        text = self._text()
        name = self.value("#name").strip()
        if not self.query_one("#confirmed", Checkbox).value:
            raise PQVaultError("confirm the fingerprint with its owner first; this is what stops impostors")
        kr = self.keyring

        def job() -> list[str]:
            e = kr.import_contact(name, text)
            return [f"Imported {e.name}: {e.public.fingerprint}"]
        return job


class PublicKeyScreen(ModalScreen[None]):
    """Show one of your public keys so it can be copied and shared."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Close")]

    def __init__(self, name: str, path: Path, pub: PublicIdentity):
        super().__init__()
        self.key_name, self.key_path, self.pub = name, path, pub

    def compose(self) -> ComposeResult:
        text = keys.encode_public(self.pub)
        with Vertical(classes="dialog"):
            yield Label(f"Public key: {self.key_name}", classes="title")
            yield Static(f"Fingerprint: {self.pub.fingerprint}\nFile: {self.key_path}\n"
                         "Safe to share: send the file, or copy the text below.", classes="hint")
            yield TextArea(text, read_only=True, soft_wrap=True, id="pubtext")
            with Horizontal(classes="buttons"):
                yield Button("Copy", variant="primary", id="copy")
                yield Button("Close", id="close")

    @on(Button.Pressed, "#copy")
    def _copy(self) -> None:
        self.app.copy_to_clipboard(keys.encode_public(self.pub))
        self.notify("Copied (if your terminal allows clipboard access)")

    @on(Button.Pressed, "#close")
    def _close(self) -> None:
        self.dismiss(None)


class KeysScreen(ModalScreen[None]):
    """Show keys, create a key, import (upload) a contact's key, and manage them."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Close"),
                Binding("c", "create", "Create key"), Binding("i", "import_key", "Import key")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label("Keys", classes="title")
            yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
            with Horizontal(classes="buttons"):
                yield Button("New key", variant="primary", id="create")
                yield Button("Import key", variant="primary", id="import")
                yield Button("Show public", id="show")
                yield Button("Make default", id="default")
                yield Button("Remove", variant="error", id="remove")
                yield Button("Close", id="close")
            yield Static("", id="status")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("", "Name", "Type", "Fingerprint")
        self.reload()

    def reload(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        kr = self.app.keyring  # type: ignore[attr-defined]
        default = kr.default
        for e in kr.all():
            star = "★" if e.mine and e.name == default else ""
            table.add_row(star, e.name, "mine" if e.mine else "contact", e.public.fingerprint,
                          key=f"{'mine' if e.mine else 'contact'}:{e.name}")
        self.app.refresh_keys()  # type: ignore[attr-defined]

    def selected(self) -> tuple[str, str] | None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        kind, name = key.split(":", 1)
        return kind, name

    def status(self, text: str, error: bool = False) -> None:
        w = self.query_one("#status", Static)
        w.set_class(error, "error")
        w.update(text)

    def _after_form(self, lines: list[str] | None) -> None:
        if lines:
            self.app.log_lines(lines)  # type: ignore[attr-defined]
            self.status(lines[0])
        self.reload()

    @on(Button.Pressed, "#create")
    def action_create(self) -> None:
        self.app.push_screen(CreateKeyScreen(), self._after_form)

    @on(Button.Pressed, "#import")
    def action_import_key(self) -> None:
        self.app.push_screen(ImportKeyScreen(), self._after_form)

    @on(Button.Pressed, "#show")
    def _show(self) -> None:
        sel = self.selected()
        if not sel:
            return
        kind, name = sel
        kr = self.app.keyring  # type: ignore[attr-defined]
        path = kr.public_path(name) if kind == "mine" else kr.contacts_dir / f"{name}.pub"
        self.app.push_screen(PublicKeyScreen(name, path, kr.public(name)))

    @on(Button.Pressed, "#default")
    def _default(self) -> None:
        sel = self.selected()
        if not sel or sel[0] != "mine":
            self.status("Select one of your own keys to make it the default.", error=True)
            return
        self.app.keyring.default = sel[1]  # type: ignore[attr-defined]
        self.status(f"{sel[1]} is now your default key.")
        self.reload()

    @on(Button.Pressed, "#remove")
    def _remove(self) -> None:
        sel = self.selected()
        if not sel or sel[0] != "contact":
            self.status("Select a contact to remove (your own keys can't be removed here).", error=True)
            return
        self.app.keyring.remove_contact(sel[1])  # type: ignore[attr-defined]
        self.app.log_lines([f"Removed contact {sel[1]}"])  # type: ignore[attr-defined]
        self.status(f"Removed {sel[1]}.")
        self.reload()

    @on(Button.Pressed, "#close")
    def _close(self) -> None:
        self.dismiss(None)


# ====================================================================== app


class PqvaultApp(App[None]):
    TITLE = "pqvault"
    SUB_TITLE = f"post-quantum encryption · v{__version__}"
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #menu { width: 26; border: round $accent; }
    #side { width: 1fr; }
    #keys { height: auto; max-height: 45%; border: round $primary; }
    #log { height: 1fr; border: round $primary; }
    ModalScreen { align: center middle; }
    .dialog { width: 84; max-width: 95%; height: auto; max-height: 95%;
              border: thick $accent; background: $surface; padding: 0 2; }
    .dialog.wide { width: 100; }
    .picker { height: 80%; }
    .picker DirectoryTree { height: 1fr; }
    .title { text-style: bold; color: $accent; margin: 1 0; }
    .hint { color: $text-muted; margin-bottom: 1; }
    #key-section, #pw-section, #sign-section { height: auto; }
    .fingerprint { color: $success; text-style: bold; }
    .path-row { height: auto; }
    .path-row Input { width: 1fr; }
    .buttons { height: auto; margin-bottom: 1; }
    .buttons Button { margin-right: 1; min-width: 10; }
    #status { margin: 1 0 0 0; }
    #status.error { color: $error; }
    SelectionList { height: 6; }
    KeysScreen DataTable { height: auto; max-height: 15; margin-bottom: 1; }
    RadioSet { width: 100%; }
    TextArea { height: 10; }
    """
    BINDINGS = [Binding(key, f"menu('{action}')", label, show=True) for action, label, key in MENU]

    def __init__(self, keyring: Keyring | None = None, start_dir: Path | None = None):
        super().__init__()
        self.keyring = keyring or Keyring()
        self.start_dir = start_dir or Path.cwd()

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            yield OptionList(*[Option(f"{label}  [dim]({key})[/dim]", id=action) for action, label, key in MENU],
                             id="menu")
            with Vertical(id="side"):
                yield DataTable(id="keys", cursor_type="none", show_cursor=False)
                yield RichLog(id="log", markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#menu").border_title = "Menu"
        keys_table = self.query_one("#keys", DataTable)
        keys_table.border_title = "Saved keys"
        keys_table.add_columns("", "Name", "Type", "Fingerprint")
        self.query_one("#log").border_title = "Activity"
        self.refresh_keys()
        self.log_lines([f"Keys are stored in {self.keyring.home}",
                        f"Working folder: {self.start_dir}"])
        if not self.keyring.identities():
            self.log_lines(["You have no key yet. Press k, then Create key, to make one."])
        self.query_one("#menu").focus()

    @property
    def main_screen(self):
        """The base screen (dialogs are pushed on top of it)."""
        return self.screen_stack[0]

    def refresh_keys(self) -> None:
        table = self.main_screen.query_one("#keys", DataTable)
        table.clear()
        default = self.keyring.default
        for e in self.keyring.all():
            star = "★" if e.mine and e.name == default else ""
            table.add_row(star, e.name, "mine" if e.mine else "contact", e.public.fingerprint)
        if not table.row_count:
            table.add_row("", "[dim]none yet[/dim]", "", "")

    def log_lines(self, lines: list[str], error: bool = False) -> None:
        log = self.main_screen.query_one("#log", RichLog)
        stamp = datetime.now().strftime("%H:%M:%S")
        for i, line in enumerate(lines):
            prefix = f"[dim]{stamp}[/dim] " if i == 0 else "         "
            line = escape(line)
            log.write(f"{prefix}[red]{line}[/red]" if error else prefix + line)

    @on(OptionList.OptionSelected, "#menu")
    def _menu_selected(self, event: OptionList.OptionSelected) -> None:
        self.action_menu(event.option.id)

    def action_menu(self, action: str) -> None:
        if isinstance(self.screen, ModalScreen):
            return  # menu shortcuts only work from the main screen
        if action == "exit":
            self.exit()
            return
        if action == "keys":
            self.push_screen(KeysScreen(), lambda _: self.refresh_keys())
            return
        screen = {"encrypt": EncryptScreen, "decrypt": DecryptScreen, "sign": SignScreen,
                  "verify": VerifyScreen, "fingerprint": FingerprintScreen}[action]()

        def done(lines: list[str] | None) -> None:
            if lines:
                self.log_lines(lines)
            self.refresh_keys()

        self.push_screen(screen, done)


def run_app() -> None:
    PqvaultApp().run()
