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
