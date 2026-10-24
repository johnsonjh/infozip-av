#!/usr/bin/env python3
"""Cross-platform, information-only Xtro owner/companion reporting tests.

Run after building UnZip: python3 tests/test_xtro_assoc_reporting.py
--unzip unzip60/unzip. No native EA support or password is needed for the
synthetic fixtures. The supplied OS/2 AES archive can be tested separately.
"""

import argparse
import pathlib
import struct
import subprocess
import tempfile
import zipfile

OWNER = bytes.fromhex("0123456789abcdef0123456789abcdef")
PSEUDO = "__XTRO_ZIP__/x/" + OWNER.hex() + ".xtm"
NAME = "SOURCE/ONE.TXT"


def owner_extra(valid=True):
    body = (
        b"XTRO"
        + (b"\x01\x00" if valid else b"\x02\x00")
        + b"\x02\x00"
        + OWNER
        + struct.pack("<IQI", 1, 0, 0)
        + bytes(32)
    )
    assert len(body) == 72
    return struct.pack("<HH", 0x5854, len(body)) + body


def inline_extra():
    body = b"XTRO\x01\x00\x01\x00" + OWNER + struct.pack("<IQI", 0, 36, 0)
    body += b"XTMD\x01\x00\x00\x00" + OWNER + struct.pack("<IQ", 0, 0)
    assert len(body) == 76
    return struct.pack("<HH", 0x5854, len(body)) + body


def make_archive(path, reverse=False, duplicate=False, valid=True, fillers=0):
    with zipfile.ZipFile(path, "w") as out:

        def member(name, data, metadata=False):
            info = zipfile.ZipInfo(name)
            if metadata:
                info.extra = owner_extra(valid=valid)
            out.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)

        if reverse:
            member(PSEUDO, b"placeholder metadata payload")
        for i in range(fillers):
            member(f"junk/{i:05d}", b"")
        member(NAME, b"file data", metadata=True)
        member("README.TXT", b"unrelated file")
        if duplicate:
            member("OTHER.TXT", b"other data", metadata=True)
        if not reverse:
            member(PSEUDO, b"placeholder metadata payload")


def run(binary, *args):
    proc = subprocess.run(
        [str(binary), *map(str, args)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode:
        raise AssertionError(f"UnZip returned {proc.returncode}: {proc.stdout}")
    return proc.stdout


def test(binary, work):
    forward = work / "forward.zip"
    reverse = work / "reverse.zip"
    duplicate = work / "duplicate.zip"
    malformed = work / "malformed.zip"
    late = work / "late.zip"
    inline = work / "inline.zip"
    make_archive(forward)
    make_archive(reverse, reverse=True)
    make_archive(duplicate, duplicate=True)
    make_archive(malformed, valid=False)
    make_archive(late, reverse=True, fillers=16420)
    with zipfile.ZipFile(inline, "w") as out:
        info = zipfile.ZipInfo(NAME)
        info.extra = inline_extra()
        out.writestr(info, b"file data")

    for archive in (forward, reverse):
        listing = run(binary, "-l", archive)
        verbose_unzip = run(binary, "-v", archive)
        script_zipinfo = run(binary, "-Z", "-s", archive)
        for output in (listing, verbose_unzip, script_zipinfo):
            assert PSEUDO in output, output
            assert "[Xtro:" not in output, output
        details = run(binary, "-Z", "-v", archive)
        assert "Xtro metadata: stored in linked companion" in details, details
        assert "Xtro metadata companion associations:" in details, details
        assert f"[Xtro: {NAME}]" in details, details
        result = run(binary, "-t", archive)
        assert f"[Xtro: {NAME}]" in result, result
        assert "No errors detected" in result, result

    assert "Xtro late association" in run(binary, "-t", late)
    assert f"[Xtro: {NAME}]" in run(binary, "-t", late)
    assert "Xtro late association" not in run(binary, "-t", reverse)
    assert "Xtro metadata companion associations:" not in run(
        binary, "-Z", "-v", forward, "README.TXT"
    )
    assert f"[Xtro: {NAME}]" in run(binary, "-Z", "-v", forward, NAME)
    assert "Xtro late association" not in run(binary, "-t", forward)
    result = run(binary, "-Z", "-v", duplicate)
    assert "owner unavailable or ambiguous" in result, result
    result = run(binary, "-Z", "-v", malformed)
    assert "owner unavailable or ambiguous" in result, result
    assert f"[Xtro: {NAME}]" not in result, result
    result = run(binary, "-Z", "-v", inline)
    assert "Xtro metadata: stored inline for this member" in result, result
    assert "Xtro metadata companion associations:" not in result, result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--unzip", type=pathlib.Path, default="unzip60/unzip")
    args = parser.parse_args()
    binary = args.unzip.resolve()
    with tempfile.TemporaryDirectory(prefix="xtro-assoc-") as scratch:
        test(binary, pathlib.Path(scratch))
    print("PASS: portable Xtro association reporting")
