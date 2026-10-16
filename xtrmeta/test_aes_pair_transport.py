#!/usr/bin/env python3
"""MIT-0. Real AE-1/AE-3 Zip archives carrying the Xtro pair envelope.

Checks archive-index preservation and transport-envelope consistency only.
Does NOT claim the companion payload SHA/auth was verified by the Xtro reader.
"""

from __future__ import annotations
import pathlib
import shutil
import struct
import subprocess
import tempfile
import zipfile
from test_zip_interop import rewrite_headers, run

ROOT = pathlib.Path(__file__).resolve().parent
ZIP = (ROOT / "../zip30/zip").resolve()
SIDECAR = "__XTRO_ZIP__/x/0102030405060708090a0b0c0d0e0f10.xtm"


def invoke(*args, cwd):
    return subprocess.run(
        [str(ZIP), *map(str, args)],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def change_aes_strength(raw, member):
    """Corrupt one central AES strength (without altering encrypted payload)."""
    raw = bytearray(raw)
    e = raw.rfind(b"PK\x05\x06")
    assert e >= 0
    count = struct.unpack_from("<H", raw, e + 10)[0]
    at = struct.unpack_from("<I", raw, e + 16)[0]
    for _ in range(count):
        assert raw[at : at + 4] == b"PK\x01\x02"
        nl, el, cl = struct.unpack_from("<HHH", raw, at + 28)
        name = bytes(raw[at + 46 : at + 46 + nl]).decode()
        if name == member:
            pos = at + 46 + nl
            end = pos + el
            while pos < end:
                tag, ln = struct.unpack_from("<HH", raw, pos)
                assert pos + 4 + ln <= end
                if tag == 0x9901:
                    raw[pos + 8] = 1 if raw[pos + 8] != 1 else 3
                    return bytes(raw)
                pos += ln + 4
            raise AssertionError("AES field absent")
        at += 46 + nl + el + cl
    raise AssertionError("member absent")


def one(mode, root):
    d = root / mode
    d.mkdir()
    run(str(ROOT / "emit_fixture"), str(d), "encrypted")
    name = (d / "companion_name.txt").read_text()
    assert name == SIDECAR
    (d / name).parent.mkdir(parents=True)
    (d / name).write_bytes((d / "manifest.xtm").read_bytes())
    args = ["--aes-strength", "256", "-eP", "test-password"]
    if mode == "ae3":
        args += ["--aes-mode", "quantum"]
    args += ["transport.zip", "owner.dat", name]
    p = invoke(*args, cwd=d)
    assert p.returncode == 0, (mode, p.stdout, p.stderr)
    original = (d / "transport.zip").read_bytes()
    archive = d / "xtro-transport.zip"
    archive.write_bytes(
        rewrite_headers(
            original,
            b"owner.dat",
            name.encode(),
            (d / "local_xtr.bin").read_bytes(),
            (d / "central_xtr.bin").read_bytes(),
            b"test-password",
            skip_fwkcs=True,
        )
    )
    with zipfile.ZipFile(archive) as z:
        aes_fields = [
            data for tag, data in extras(z.getinfo(name).extra) if tag == 0x9901
        ]
        assert len(aes_fields) == 1
        assert struct.unpack_from("<H", aes_fields[0], 0)[0] == (
            3 if mode == "ae3" else 1
        )
        assert len(z.infolist()) == 2 and z.getinfo("owner.dat").compress_type == 99
        assert z.getinfo(name).compress_type == 99
        assert z.getinfo(name).flag_bits & 1
        assert any(extra[0] == 0x9901 for extra in extras(z.getinfo(name).extra))
    original = archive.read_bytes()
    (d / "normal.txt").write_text("unrelated data")
    p = invoke(archive, "normal.txt", cwd=d)
    assert p.returncode == 0, (mode, p.stdout, p.stderr)
    with zipfile.ZipFile(archive) as z:
        assert z.namelist() == ["owner.dat", name, "normal.txt"]
    # Pair deletion must preserve unrelated, and a selected owner copy
    # must include the companion even though both payloads are AES.
    copy = d / "copy.zip"
    p = invoke(archive, "--copy", "owner.dat", "--out", copy, cwd=d)
    assert p.returncode == 0, (mode, p.stdout, p.stderr)
    with zipfile.ZipFile(copy) as z:
        assert z.namelist() == ["owner.dat", name]
    p = invoke("-d", archive, "owner.dat", cwd=d)
    assert p.returncode == 0, (mode, p.stdout, p.stderr)
    with zipfile.ZipFile(archive) as z:
        assert z.namelist() == ["normal.txt"]
    # A change to AES strength on only one member invalidates the pair.
    malformed = d / "bad-aes.zip"
    malformed.write_bytes(change_aes_strength(original, name))
    before = malformed.read_bytes()
    p = invoke(malformed, "normal.txt", cwd=d)
    assert p.returncode != 0 and b"Xtro" in p.stdout + p.stderr, (mode, p)
    assert malformed.read_bytes() == before
    print(mode, "AES transport pair copy/delete/preservation and mismatch passed")


def extras(buf):
    at = 0
    while at < len(buf):
        tag, n = struct.unpack_from("<HH", buf, at)
        yield tag, buf[at + 4 : at + 4 + n]
        at += n + 4


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-aes-transport-") as d:
        root = pathlib.Path(d)
        one("ae1", root)
        one("ae3", root)


if __name__ == "__main__":
    main()
