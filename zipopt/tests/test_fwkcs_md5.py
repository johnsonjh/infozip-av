#!/usr/bin/env python3
"""FWKCS opt-in writer regression against independent hashlib (MIT-0)."""

import hashlib
import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = pathlib.Path(os.environ.get("ZO_TEST_TOOL", str(ROOT / "zipopt/zipopt")))
UNZIP = pathlib.Path(os.environ.get("ZO_TEST_UNZIP", str(ROOT / "unzip60/unzip")))
checks = 0


def run(*args, rc=0):
    global checks
    r = subprocess.run([str(a) for a in args], capture_output=True, timeout=35)
    assert r.returncode == rc, (args, r.returncode, r.stdout[-400:], r.stderr[-800:])
    checks += 1


def extras(data):
    i = 0
    fields = []
    while i < len(data):
        tag, length = struct.unpack_from("<HH", data, i)
        assert length <= len(data) - i - 4
        fields.append((tag, data[i + 4 : i + 4 + length]))
        i += length + 4
    return fields


with tempfile.TemporaryDirectory() as t:
    t = pathlib.Path(t)
    src, opt, stripped, retained = [
        t / x for x in ("in.zip", "md.zip", "plain.zip", "md2.zip")
    ]
    with zipfile.ZipFile(src, "w") as z:
        for name, data, method in [
            ("folder/", b"", 0),
            ("folder/empty", b"", 0),
            ("folder/a", b"A" * 3500, 8),
            ("folder/b", b"hello world" * 9, 0),
        ] + [
            ("boundary-%d" % n, bytes(range(n)), 0)
            for n in (55, 56, 63, 64, 65, 119, 120, 127, 128)
        ]:
            z.writestr(name, data, compress_type=method)
    run(TOOL, "--methods=store", "--fwkcs-md5", src, opt)
    run(UNZIP, "-tqq", opt)
    with zipfile.ZipFile(opt) as z:
        for e in z.infolist():
            fw = [data for tag, data in extras(e.extra) if tag == 0x4B46]
            assert fw == (
                [] if e.is_dir() else [b"MD5" + hashlib.md5(z.read(e)).digest()]
            ), (e.filename, fw)
    run(TOOL, "--methods=store", opt, stripped)
    with zipfile.ZipFile(stripped) as z:
        assert all(
            not any(tag == 0x4B46 for tag, _ in extras(e.extra)) for e in z.infolist()
        )
    run(TOOL, "--methods=store", opt, retained)
    run(TOOL, "--methods=store", "--fwkcs-md5", opt, t / "again.zip")
    with zipfile.ZipFile(t / "again.zip") as z:
        for e in z.infolist():
            fw = [data for tag, data in extras(e.extra) if tag == 0x4B46]
            assert len(fw) == (0 if e.is_dir() else 1)
    # Central-only FWKCS on a directory is verified and retained when
    # requested, but no directory field is added when originally absent.
    directory_input = t / "directory-existing.zip"
    b = bytearray(src.read_bytes())
    end = b.rfind(b"PK\x05\x06")
    cd_size, cd_start = struct.unpack_from("<II", b, end + 12)
    nlen, xlen = struct.unpack_from("<HH", b, cd_start + 28)
    field = b"FK\x13\x00MD5" + hashlib.md5(b"").digest()
    b[cd_start + 46 + nlen + xlen : cd_start + 46 + nlen + xlen] = field
    struct.pack_into("<H", b, cd_start + 30, xlen + len(field))
    struct.pack_into("<I", b, end + len(field) + 12, cd_size + len(field))
    directory_input.write_bytes(b)
    directory_output = t / "directory-existing-out.zip"
    run(TOOL, "--fwkcs-md5", "--methods=store", directory_input, directory_output)
    with zipfile.ZipFile(directory_output) as z:
        assert [v for k, v in extras(z.infolist()[0].extra) if k == 0x4B46] == [
            field[4:]
        ]
    run(UNZIP, "-tqq", directory_output)
    b[cd_start + 46 + nlen + xlen + 7] ^= 0x51
    corrupted_directory = t / "directory-bad.zip"
    corrupted_directory.write_bytes(b)
    run(
        TOOL,
        "--fwkcs-md5",
        "--methods=store",
        corrupted_directory,
        t / "directory-bad-out.zip",
        rc=1,
    )
    assert not (t / "directory-bad-out.zip").exists()

    # A failed validation must not publish an output.
    bad = t / "bad.zip"
    b = bytearray(opt.read_bytes())
    loc = b.find(b"FK\x13\x00MD5")
    assert loc != -1
    b[loc + 7] ^= 0x55
    bad.write_bytes(b)
    run(TOOL, "--fwkcs-md5", "--methods=store", bad, t / "bad.out.zip", rc=1)
    assert not (t / "bad.out.zip").exists()
print("FWKCS zipopt tests passed:", checks, "command invocations")
