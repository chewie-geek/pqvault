import os

from click.testing import CliRunner

from pqvault.cli import main


def run(*args, input=None):
    return CliRunner().invoke(main, list(map(str, args)), input=input)


def test_password_file_roundtrip(tmp_path):
    f = tmp_path / "doc.pdf"
    f.write_bytes(os.urandom(200_000))
    r = run("encrypt", f, "-p", input="pw\npw\n")
    assert r.exit_code == 0, r.output
    enc = tmp_path / "doc.pdf.pqv"
    assert f.read_bytes() not in enc.read_bytes()
    out = tmp_path / "back.pdf"
    r = run("decrypt", enc, "-o", out, input="pw\n")
    assert r.exit_code == 0, r.output
    assert out.read_bytes() == f.read_bytes()


def test_keypair_roundtrip(tmp_path):
    assert run("keygen", "-o", tmp_path / "me", input="kp\nkp\n").exit_code == 0
    f = tmp_path / "note.txt"
    f.write_text("top secret")
    assert run("encrypt", f, "-r", tmp_path / "me.pub").exit_code == 0
    f.unlink()
    r = run("decrypt", tmp_path / "note.txt.pqv", "-i", tmp_path / "me.key", input="kp\n")
    assert r.exit_code == 0, r.output
    assert f.read_text() == "top secret"


def test_folder_roundtrip(tmp_path):
    d = tmp_path / "photos"
    (d / "photos").mkdir(parents=True)  # nested folder with the same name
    (d / "a.txt").write_text("a")
    (d / "photos" / "b.bin").write_bytes(os.urandom(70_000))
    assert run("encrypt", d, "-p", input="pw\npw\n").exit_code == 0
    out = tmp_path / "restored"
    r = run("decrypt", tmp_path / "photos.pqv", "-o", out, input="pw\n")
    assert r.exit_code == 0, r.output
    assert (out / "a.txt").read_text() == "a"
    assert (out / "photos" / "b.bin").read_bytes() == (d / "photos" / "b.bin").read_bytes()


def test_tampered_file_leaves_no_output(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(os.urandom(150_000))
    run("encrypt", f, "-p", input="pw\npw\n")
    enc = tmp_path / "x.txt.pqv"
    data = bytearray(enc.read_bytes())
    data[-100] ^= 1
    enc.write_bytes(bytes(data))
    f.unlink()
    r = run("decrypt", enc, input="pw\n")
    assert r.exit_code != 0
    assert "tampered" in r.output
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.txt.pqv"]


def test_wrong_password_message(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hi")
    run("encrypt", f, "-p", input="pw\npw\n")
    r = run("decrypt", tmp_path / "x.txt.pqv", "-o", tmp_path / "y", input="nope\n")
    assert r.exit_code != 0 and "wrong password" in r.output


def test_refuses_overwrite(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hi")
    run("encrypt", f, "-p", input="pw\npw\n")
    r = run("encrypt", f, "-p", input="pw\npw\n")
    assert r.exit_code != 0 and "already exists" in r.output


def test_requires_a_lock(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hi")
    assert run("encrypt", f).exit_code != 0


def test_signed_encrypt_and_verified_decrypt(tmp_path):
    run("keygen", "-o", tmp_path / "alice", input="a\na\n")
    run("keygen", "-o", tmp_path / "bob", input="b\nb\n")
    f = tmp_path / "msg.txt"
    f.write_text("from alice")
    r = run("encrypt", f, "-r", tmp_path / "bob.pub", "-s", tmp_path / "alice.key", input="a\n")
    assert r.exit_code == 0 and "signed" in r.output, r.output
    out = tmp_path / "got.txt"
    r = run("decrypt", tmp_path / "msg.txt.pqv", "-i", tmp_path / "bob.key",
            "--from", tmp_path / "alice.pub", "-o", out, input="b\n")
    assert r.exit_code == 0, r.output
    assert "Good signature" in r.output and out.read_text() == "from alice"


def test_decrypt_rejects_wrong_sender_and_writes_nothing(tmp_path):
    for who in ("alice", "bob", "mallory"):
        run("keygen", "-o", tmp_path / who, input="x\nx\n")
    f = tmp_path / "msg.txt"
    f.write_text("from mallory")
    run("encrypt", f, "-r", tmp_path / "bob.pub", "-s", tmp_path / "mallory.key", input="x\n")
    out = tmp_path / "got.txt"
    r = run("decrypt", tmp_path / "msg.txt.pqv", "-i", tmp_path / "bob.key",
            "--from", tmp_path / "alice.pub", "-o", out, input="x\n")
    assert r.exit_code != 0 and "untrusted" in r.output
    assert not out.exists()
    assert not list(tmp_path.glob(".pqvault-*"))


def test_signed_folder_wrong_sender_extracts_nothing(tmp_path):
    for who in ("alice", "mallory"):
        run("keygen", "-o", tmp_path / who, input="x\nx\n")
    d = tmp_path / "docs"
    d.mkdir()
    (d / "a.txt").write_text("a")
    run("encrypt", d, "-p", "-s", tmp_path / "mallory.key", input="x\npw\npw\n")
    out = tmp_path / "restored"
    r = run("decrypt", tmp_path / "docs.pqv", "--from", tmp_path / "alice.pub", "-o", out, input="pw\n")
    assert r.exit_code != 0 and not out.exists()


def test_unverified_signature_shows_fingerprint(tmp_path):
    run("keygen", "-o", tmp_path / "alice", input="a\na\n")
    f = tmp_path / "m.txt"
    f.write_text("hi")
    run("encrypt", f, "-p", "-s", tmp_path / "alice.key", input="a\npw\npw\n")
    r = run("decrypt", tmp_path / "m.txt.pqv", "-o", tmp_path / "o.txt", input="pw\n")
    fp = run("fingerprint", tmp_path / "alice.pub").output.strip()
    assert r.exit_code == 0 and fp in r.output and "not checked" in r.output


def test_detached_sign_verify_cli(tmp_path):
    run("keygen", "-o", tmp_path / "alice", input="a\na\n")
    run("keygen", "-o", tmp_path / "eve", input="e\ne\n")
    f = tmp_path / "release.zip"
    f.write_bytes(os.urandom(5000))
    assert run("sign", f, "-i", tmp_path / "alice.key", input="a\n").exit_code == 0
    assert (tmp_path / "release.zip.sig").exists()
    r = run("verify", f, "--from", tmp_path / "alice.pub")
    assert r.exit_code == 0 and "Good signature" in r.output
    assert run("verify", f, "--from", tmp_path / "eve.pub").exit_code != 0
    f.write_bytes(os.urandom(5000))
    assert run("verify", f, "--from", tmp_path / "alice.pub").exit_code != 0


def test_signing_time_shown_and_max_age(tmp_path):
    run("keygen", "-o", tmp_path / "alice", input="a\na\n")
    f = tmp_path / "m.txt"
    f.write_text("hi")
    run("encrypt", f, "-p", "-s", tmp_path / "alice.key", input="a\npw\npw\n")
    r = run("decrypt", tmp_path / "m.txt.pqv", "-o", tmp_path / "o.txt", "--max-age", "10m", input="pw\n")
    assert r.exit_code == 0, r.output
    assert "Signed at" in r.output and "just now" in r.output


def test_max_age_rejects_unsigned_and_bad_duration(tmp_path):
    f = tmp_path / "m.txt"
    f.write_text("hi")
    run("encrypt", f, "-p", input="pw\npw\n")
    r = run("decrypt", tmp_path / "m.txt.pqv", "-o", tmp_path / "o.txt", "--max-age", "1d", input="pw\n")
    assert r.exit_code != 0 and "not signed" in r.output
    assert not (tmp_path / "o.txt").exists()
    r = run("decrypt", tmp_path / "m.txt.pqv", "--max-age", "soon", input="pw\n")
    assert r.exit_code != 0 and "not a duration" in r.output


def test_verify_max_age_cli(tmp_path):
    run("keygen", "-o", tmp_path / "alice", input="a\na\n")
    f = tmp_path / "r.bin"
    f.write_bytes(b"x" * 100)
    run("sign", f, "-i", tmp_path / "alice.key", input="a\n")
    r = run("verify", f, "--from", tmp_path / "alice.pub", "--max-age", "1h")
    assert r.exit_code == 0 and "Signed at" in r.output, r.output
