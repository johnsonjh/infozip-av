#!/usr/bin/env python3
"""W2B2B native NTFS Zip->UnZip encrypted companion acceptance (MIT-0).

Requires real Windows, working NT EAs, W2B2B-enabled Zip/UnZip, and a
writable NTFS directory. Wine native EA stubs are not acceptance evidence.
Only disposable files under --workdir are modified. Test password is public.
"""

import argparse
import ctypes
import os
from pathlib import Path
import sys
import tempfile
import zipfile

from test_win_zip_native import DATA, NAME, XID, field, seed_native_ea
from test_win_unzip_native import snapshot, run

PASSWORD = "xtro-test-only"
CONTENTS = b"Windows EA companion test contents\0\xfe"


def zip_command(program, archive, source, mode):
    """Select ZipCrypto (-P) or AES (-eP), never both."""
    cmd = [str(program), "-q", "--xattrs", "-j", "-0"]
    if mode == "zipcrypto":
        cmd.extend(["-P", PASSWORD])
    elif mode in ("standard", "quantum"):
        cmd.extend(["-eP", PASSWORD, "--aes-mode", mode, "--aes-strength", "256"])
    else:
        raise ValueError("unrecognized encryption mode: " + str(mode))
    cmd.extend([str(archive), str(source)])
    return cmd


def cli_selftest():
    base = ["zip.exe", "-q", "--xattrs", "-j", "-0"]
    for mode, arguments in (
        ("zipcrypto", ["-P", PASSWORD]),
        (
            "standard",
            ["-eP", PASSWORD, "--aes-mode", "standard", "--aes-strength", "256"],
        ),
        (
            "quantum",
            ["-eP", PASSWORD, "--aes-mode", "quantum", "--aes-strength", "256"],
        ),
    ):
        actual = zip_command("zip.exe", "archive.zip", "owner.bin", mode)
        assert actual == base + arguments + ["archive.zip", "owner.bin"], mode
    try:
        zip_command("zip.exe", "archive.zip", "owner.bin", "unknown")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown encryption mode accepted")
    print("PASS: W2B2B companion acceptance CLI; 4 cases")


def inspect(archive, encrypted):
    with zipfile.ZipFile(archive) as zf:
        owners = [
            e for e in zf.infolist() if not e.filename.startswith("__XTRO_ZIP__/")
        ]
        companions = [
            e for e in zf.infolist() if e.filename.startswith("__XTRO_ZIP__/")
        ]
        assert (
            len(owners) == len(companions) == 1
        ), "missing/duplicate owner or companion"
        owner, companion = owners[0], companions[0]
        payload = field(owner.extra, XID)
        assert payload is not None and len(payload) >= 40
        assert payload[:6] == b"XTRO\x01\x00" and payload[6] == 2
        assert payload[7] == int(encrypted), "encrypted companion flag mismatch"
        assert companion.filename == "__XTRO_ZIP__/x/" + payload[8:24].hex() + ".xtm"
        assert bool(owner.flag_bits & 1) == encrypted
        assert bool(companion.flag_bits & 1) == encrypted
        if encrypted:
            assert len(payload) == 40, "encrypted owner leaks public SHA/manifest"
        return owner.filename


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip")
    ap.add_argument("--unzip")
    ap.add_argument("--workdir")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="verify encryption argument selection without Windows",
    )
    args = ap.parse_args()
    if args.self_test:
        cli_selftest()
        return 0
    if not args.zip or not args.unzip or not args.workdir:
        ap.error("--zip, --unzip and --workdir are required")
    if os.name != "nt":
        print("SKIP: real Windows NTFS required")
        return 77
    root = Path(args.workdir).resolve()
    zp, uz = Path(args.zip).resolve(), Path(args.unzip).resolve()
    if not root.is_dir() or not zp.is_file() or not uz.is_file():
        ap.error("workdir, zip.exe and unzip.exe must exist")
    count = 0
    with tempfile.TemporaryDirectory(prefix="xtro-win-comp-", dir=str(root)) as temp:
        temp = Path(temp)
        src = temp / "owner.bin"
        src.write_bytes(CONTENTS)
        status = seed_native_ea(src, DATA)
        if status:
            if hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
                print("SKIP: Wine native EA syscall unavailable: 0x%08x" % status)
                return 77
            raise RuntimeError("native EA seed failed: 0x%08x" % status)
        for mode in ("zipcrypto", "standard", "quantum"):
            archive = temp / (mode + ".zip")
            run(zip_command(zp, archive, src, mode))
            owner = inspect(archive, True)
            good = temp / (mode + "-good")
            good.mkdir()
            run(
                [
                    str(uz),
                    "-q",
                    "-P",
                    PASSWORD,
                    "--xattrs",
                    "-o",
                    str(archive),
                    "-d",
                    str(good),
                ]
            )
            target = good / owner
            if (
                target.read_bytes() != CONTENTS
                or snapshot(target).get(NAME, (None, None))[1] != DATA
            ):
                raise RuntimeError("%s native encrypted metadata mismatch" % mode)
            if (good / "__XTRO_ZIP__").exists():
                raise RuntimeError("private companion materialized as ordinary file")
            count += 1
            wrong = temp / (mode + "-wrong")
            wrong.mkdir()
            result = run(
                [
                    str(uz),
                    "-q",
                    "-P",
                    "wrong-password",
                    "--xattrs",
                    str(archive),
                    "-d",
                    str(wrong),
                ],
                False,
            )
            if result.returncode == 0:
                raise RuntimeError("wrong-password archive unexpectedly succeeded")
            other = wrong / owner
            if other.exists() and NAME in snapshot(other):
                raise RuntimeError("%s wrote native EA despite wrong password" % mode)
            count += 1
        # A large public manifest must use the same deferred companion path.
        # If NTFS refuses the test attribute, report a precise skip separately.
        large = b"L" * 60500
        large_src = temp / "large.bin"
        large_src.write_bytes(CONTENTS)
        status = seed_native_ea(large_src, large)
        if status:
            print("SKIP: public large-companion native seed: NTSTATUS 0x%08x" % status)
        else:
            archive = temp / "public-large.zip"
            run([str(zp), "-q", "--xattrs", "-0", "-j", str(archive), str(large_src)])
            owner = inspect(archive, False)
            out = temp / "large-out"
            out.mkdir()
            run([str(uz), "-q", "--xattrs", str(archive), "-d", str(out)])
            if snapshot(out / owner).get(NAME, (None, None))[1] != large:
                raise RuntimeError("public companion exact native value mismatch")
            count += 1
    print("PASS: NATIVE WINDOWS W2B2B companion restoration; %d cases" % count)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, AssertionError, RuntimeError, zipfile.BadZipFile) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
