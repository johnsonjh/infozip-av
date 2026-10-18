#!/usr/bin/env python3
"""Regression tests for Info-ZIP 2.x's modulo-65536 EOCD entry counts.

Usage: python3 tests/test_legacy_entry_count.py --zip build/bin/zip
Use --zipnote path to test the ZipNote rewrite path as well.
"""

import argparse
import hashlib
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

EOCD = b"PK\x05\x06"
Z64LOC = b"PK\x06\x07"
Z64END = b"PK\x06\x06"
CD = b"PK\x01\x02"


def get_eocd(data):
    off = data.rfind(EOCD)
    assert off >= 0
    assert len(data) == off + 22, "test generator requires no archive comment"
    return off


def build_valid(path, count):
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        for i in range(count):
            payload = (
                ("payload-%d" % i).encode() if i in (0, count // 2, count - 1) else b""
            )
            z.writestr("f%06d.txt" % i, payload, compress_type=zipfile.ZIP_STORED)


def make_legacy(raw, count):
    end = get_eocd(raw)
    if count <= 65535:
        return raw
    assert raw[end - 20 : end - 16] == Z64LOC
    z64off = struct.unpack_from("<Q", raw, end - 12)[0]
    assert raw[z64off : z64off + 4] == Z64END
    eocd = bytearray(raw[end:])
    struct.pack_into("<HH", eocd, 8, count & 0xFFFF, count & 0xFFFF)
    return raw[:z64off] + eocd


def run(command, cwd=None, stdin=None):
    return subprocess.run(
        command, cwd=cwd, input=stdin, capture_output=True, timeout=150
    )


def check_members(path, count, removed=False):
    with zipfile.ZipFile(path) as z:
        assert len(z.infolist()) == count - int(removed), (
            path,
            len(z.infolist()),
            count,
        )
        names = set(z.namelist())
        assert ("f000000.txt" in names) != removed
        assert "f%06d.txt" % (count - 1) in names
        assert (
            z.read("f%06d.txt" % (count - 1)) == ("payload-%d" % (count - 1)).encode()
        )
        assert z.testzip() is None


def check_delete(zipbin, path, count, expect_legacy):
    data = path.read_bytes()
    result = run([str(zipbin), "-d", str(path), "f000000.txt"])
    assert result.returncode == 0, (count, result.returncode, result.stderr[-1200:])
    diagnostics = (result.stdout + result.stderr).lower()
    assert (b"legacy archive" in diagnostics) == expect_legacy, (
        count,
        diagnostics[-500:],
    )
    assert path.read_bytes() != data
    check_members(path, count, removed=True)
    end = get_eocd(path.read_bytes())
    if count - 1 > 65535:
        assert path.read_bytes()[end - 20 : end - 16] == Z64LOC


def check_reject(zipbin, path, raw, label):
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).digest()
    result = run([str(zipbin), "-d", str(path), "f000000.txt"])
    assert result.returncode != 0, (label, result.stdout[-500:], result.stderr[-500:])
    assert hashlib.sha256(path.read_bytes()).digest() == digest, label


def run_tests(zipbin, zipnote, sanitizer_fast=False):
    checks = 0
    counts = (
        (65536, 65537)
        if sanitizer_fast
        else (65534, 65535, 65536, 65537, 70000, 131071, 131072)
    )
    with tempfile.TemporaryDirectory(prefix="xtro-527388-") as root:
        root = Path(root)
        for count in counts:
            valid = root / ("valid-%d.zip" % count)
            legacy = root / ("legacy-%d.zip" % count)
            build_valid(valid, count)
            raw = valid.read_bytes()
            legacy_raw = make_legacy(raw, count)
            legacy.write_bytes(legacy_raw)
            check_members(legacy, count)
            checks += 1

            native = root / ("native-delete-%d.zip" % count)
            shutil.copyfile(valid, native)
            check_delete(zipbin, native, count, False)
            checks += 1

            old = root / ("legacy-delete-%d.zip" % count)
            shutil.copyfile(legacy, old)
            check_delete(zipbin, old, count, count > 65535)
            checks += 1

            if count != 65537:
                continue

            to_update = root / "legacy-update.zip"
            to_update.write_bytes(legacy_raw)
            (root / "new-member.txt").write_text("new content")
            updated = run(
                [str(zipbin), "-u", str(to_update), "new-member.txt"], cwd=root
            )
            assert updated.returncode == 0, updated.stderr[-500:]
            with zipfile.ZipFile(to_update) as z:
                assert len(z.infolist()) == count + 1
                assert z.read("new-member.txt") == b"new content"
                assert z.testzip() is None
            checks += 1

            end = get_eocd(legacy_raw)
            wrong = bytearray(legacy_raw)
            struct.pack_into("<HH", wrong, end + 8, 2, 2)
            check_reject(zipbin, root / "bad-count.zip", bytes(wrong), "bad count")
            checks += 1

            for delta in (-1, 1):
                wrong = bytearray(legacy_raw)
                cdsize = struct.unpack_from("<I", wrong, end + 12)[0]
                struct.pack_into("<I", wrong, end + 12, cdsize + delta)
                check_reject(
                    zipbin, root / "bad-cdsize.zip", bytes(wrong), "bad cdsize"
                )
                checks += 1

            wrong = bytearray(legacy_raw)
            cdoff = struct.unpack_from("<I", wrong, end + 16)[0]
            struct.pack_into("<I", wrong, end + 16, cdoff + 1)
            check_reject(zipbin, root / "bad-cdoff.zip", bytes(wrong), "bad offset")
            checks += 1

            check_reject(
                zipbin,
                root / "gap-before-eocd.zip",
                legacy_raw[:end] + b"JUNK" + legacy_raw[end:],
                "gap before end",
            )
            checks += 1

            cdstart = struct.unpack_from("<I", legacy_raw, end + 16)[0]
            first_cd_end = (
                cdstart + 46 + struct.unpack_from("<H", legacy_raw, cdstart + 28)[0]
            )
            assert legacy_raw[first_cd_end : first_cd_end + 4] == CD
            wrong = bytearray(
                legacy_raw[:first_cd_end] + b"JUNK" + legacy_raw[first_cd_end:]
            )
            new_end = end + 4
            cdsize = struct.unpack_from("<I", wrong, new_end + 12)[0]
            struct.pack_into("<I", wrong, new_end + 12, cdsize + 4)
            check_reject(
                zipbin, root / "gap-inside-cd.zip", bytes(wrong), "gap inside CD"
            )
            checks += 1

            z64end = get_eocd(raw)
            locator = z64end - 20
            z64off = struct.unpack_from("<Q", raw, locator + 8)[0]
            assert raw[z64off : z64off + 4] == Z64END
            bad_zip64 = bytearray(raw)
            struct.pack_into("<Q", bad_zip64, z64off + 32, count + 1)
            check_reject(
                zipbin,
                root / "bad-zip64-count.zip",
                bytes(bad_zip64),
                "bad ZIP64 count",
            )
            checks += 1

            if zipnote:
                note_path = root / "legacy-note.zip"
                note_path.write_bytes(legacy_raw)
                note = run([str(zipnote), str(note_path)])
                assert note.returncode == 0, note.stderr[-500:]
                edited = run([str(zipnote), "-w", str(note_path)], stdin=note.stdout)
                assert edited.returncode == 0, edited.stderr[-500:]
                check_members(note_path, count)
                checks += 1

        empty_zip = root / "false-empty.zip"
        small = root / "small.zip"
        build_valid(small, 3)
        raw = bytearray(small.read_bytes())
        end = get_eocd(raw)
        struct.pack_into("<HH", raw, end + 8, 0, 0)
        check_reject(zipbin, empty_zip, bytes(raw), "false empty")
        checks += 1

        empty_valid = root / "empty-valid.zip"
        with zipfile.ZipFile(empty_valid, "w"):
            pass
        before = empty_valid.read_bytes()
        result = run([str(zipbin), "-d", str(empty_valid), "f000000.txt"])
        assert result.returncode != 0 and empty_valid.read_bytes() == before
        checks += 1
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--zipnote", type=Path)
    parser.add_argument("--sanitizer-fast", action="store_true")
    args = parser.parse_args()
    zipbin = args.zip.resolve()
    zipnote = args.zipnote.resolve() if args.zipnote else None
    assert zipbin.is_file()
    if zipnote:
        assert zipnote.is_file()
    print(
        "PASS:",
        run_tests(zipbin, zipnote, args.sanitizer_fast),
        "large entry-count regression checks",
    )
