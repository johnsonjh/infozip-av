#!/usr/bin/env python3
"""W3C2B/C native Windows ADS + EA restoration acceptance (MIT-0).

Use disposable NTFS files. Wine EA support is not native acceptance evidence.
This tests Zip/UnZip behavior, not the portable C89 transaction mock.
Overwrites also verify that the original NTFS file identity survives.
"""

import argparse
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from test_win_stream_archive_native import STREAM_NAME, STREAM_BYTES, PASSWORD
from test_win_zip_native import NAME, DATA, seed_native_ea
from test_win_unzip_native import snapshot, mutate_local

CONTENTS = b"W3C2B/C named stream owner\x00\xff"
STALE = "stale-old"


def run(command, succeeds=True):
    cp = subprocess.run([str(a) for a in command], capture_output=True, text=True)
    if bool(cp.returncode == 0) != bool(succeeds):
        raise RuntimeError(
            "unexpected exit for %r\nstdout=%s\nstderr=%s\nrc=%d"
            % (command, cp.stdout, cp.stderr, cp.returncode)
        )
    return cp


def ads_path(owner, name):
    return str(owner) + ":" + name + ":$DATA"


def write_ads(owner, name, data):
    with open(ads_path(owner, name), "wb") as out:
        out.write(data)


def read_ads(owner, name):
    try:
        with open(ads_path(owner, name), "rb") as stream:
            return stream.read()
    except FileNotFoundError:
        return None


def win_file_id(path):
    """Read the real NTFS file identity, not merely the pathname."""
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class Info(ctypes.Structure):
        _fields_ = [
            ("attrs", wintypes.DWORD),
            ("created", FileTime),
            ("accessed", FileTime),
            ("modified", FileTime),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = k32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    query = k32.GetFileInformationByHandle
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
    query.restype = wintypes.BOOL
    close = k32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    h = create(str(path), 0x80, 1 | 2 | 4, None, 3, 0x00200000, None)
    if h == ctypes.c_void_p(-1).value:
        raise RuntimeError("file identity open failed: %d" % ctypes.get_last_error())
    try:
        info = Info()
        if not query(h, ctypes.byref(info)):
            raise RuntimeError(
                "file identity query failed: %d" % ctypes.get_last_error()
            )
        return info.volume, info.index_high, info.index_low
    finally:
        close(h)


def assert_ads(owner, desired, present=True):
    data = read_ads(owner, STREAM_NAME)
    if (data == STREAM_BYTES) != present:
        raise RuntimeError(
            "ADS stream restored incorrectly: %s; value %r"
            % (owner, None if data is None else len(data))
        )
    if desired is not None and data != desired:
        raise RuntimeError("ADS byte-for-byte mismatch")


def self_test():
    assert STREAM_NAME.encode("utf-8") == b"\xe9\x9b\xaa"
    assert len(STREAM_BYTES) == 2 * 1024 * 1024
    assert ["--streams", "--no-xattrs"][-1] == "--no-xattrs"
    print("PASS: W3C2B/C native acceptance harness self-test; 3 checks")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip")
    parser.add_argument("--unzip")
    parser.add_argument("--workdir")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if os.name != "nt":
        print("SKIP: Windows NTFS required")
        return 77
    if hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        print("SKIP: Wine NT native EA operations not supported")
        return 77
    if not args.zip or not args.unzip or not args.workdir:
        parser.error("--zip --unzip --workdir are required")
    zip_exe, unzip_exe = Path(args.zip).resolve(), Path(args.unzip).resolve()
    root = Path(args.workdir).resolve()
    if not zip_exe.is_file() or not unzip_exe.is_file() or not root.is_dir():
        parser.error("Zip, UnZip and workdir must exist")
    tests = 0
    with tempfile.TemporaryDirectory(prefix="xtro-w3c2-", dir=root) as folder:
        base = Path(folder)
        src = base / "owner.bin"
        src.write_bytes(CONTENTS)
        write_ads(src, STREAM_NAME, STREAM_BYTES)
        if seed_native_ea(src, DATA, flags=0x80):
            raise RuntimeError("native NT EA seed failed")
        mixed = base / "mixed.zip"
        run([zip_exe, "-q", "-j", "-0", "--xattrs", "--streams", mixed, src])
        tests += 1

        def extract(archive, name, *flags, success=True, seed=False):
            out = base / name
            out.mkdir()
            dst = out / "owner.bin"
            if seed:
                dst.write_bytes(b"preexisting")
                write_ads(dst, STREAM_NAME, b"old-stream-contents")
                write_ads(dst, STALE, b"this should be removed")
                if seed_native_ea(dst, b"old-attribute"):
                    raise RuntimeError("native destination EA seed failed")
            previous_id = win_file_id(dst) if seed else None
            run(
                [unzip_exe, "-q", "-o"] + list(flags) + [archive, "-d", out],
                succeeds=success,
            )
            if previous_id is not None and win_file_id(dst) != previous_id:
                raise RuntimeError("metadata overwrite replaced the NTFS owner file")
            return dst, out

        # Keep each metadata selection truly independent.
        dst, out = extract(mixed, "ads-only", "--streams", "--no-xattrs")
        assert_ads(dst, STREAM_BYTES)
        if NAME in snapshot(dst):
            raise RuntimeError("--no-xattrs nonetheless restored EA")
        if (out / "__XTRO_ZIP__").exists():
            raise RuntimeError("metadata companion exposed")
        tests += 1

        dst, _ = extract(mixed, "ea-only", "--xattrs", "--no-streams")
        if snapshot(dst).get(NAME) != (0x80, DATA):
            raise RuntimeError("EA flags/value not restored")
        if read_ads(dst, STREAM_NAME) is not None:
            raise RuntimeError("--no-streams nonetheless restored ADS")
        tests += 1

        dst, _ = extract(mixed, "both", "--xattrs", "--streams")
        assert_ads(dst, STREAM_BYTES)
        if snapshot(dst).get(NAME) != (0x80, DATA):
            raise RuntimeError("combined native EA missing")
        tests += 1

        # Existing streams require EXACT replacement and stale named stream removal.
        dst, _ = extract(mixed, "replacement", "--streams", "--xattrs", seed=True)
        assert_ads(dst, STREAM_BYTES)
        if read_ads(dst, STALE) is not None:
            raise RuntimeError("stale destination ADS not removed")
        if snapshot(dst).get(NAME) != (0x80, DATA):
            raise RuntimeError("stale destination EA not replaced")
        tests += 1

        # A selected ADS operation must preserve EAs that were already on
        # the destination. In particular, EA absence from the invocation is
        # not permission to replace the preexisting user EA namespace.
        dst, _ = extract(
            mixed, "ads-preserve-ea", "--streams", "--no-xattrs", seed=True
        )
        assert_ads(dst, STREAM_BYTES)
        if snapshot(dst).get(NAME) != (0, b"old-attribute"):
            raise RuntimeError("--streams replaced an unselected native EA")
        tests += 1

        # Likewise, EA replacement must leave both named streams alone.
        dst, _ = extract(
            mixed, "ea-preserve-ads", "--xattrs", "--no-streams", seed=True
        )
        if (
            snapshot(dst).get(NAME) != (0x80, DATA)
            or read_ads(dst, STREAM_NAME) != b"old-stream-contents"
            or read_ads(dst, STALE) != b"this should be removed"
        ):
            raise RuntimeError("--xattrs replaced unselected named streams")
        tests += 1

        # Last occurrence of each selector wins; neither class is implicit.
        dst, _ = extract(
            mixed, "disabled", "--streams", "--no-streams", "--xattrs", "--no-xattrs"
        )
        if NAME in snapshot(dst) or read_ads(dst, STREAM_NAME) is not None:
            raise RuntimeError("disabled metadata restoration changed target")
        tests += 1

        for mode, encryption in (
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
            arc = base / (mode + ".zip")
            run(
                [zip_exe, "-q", "-j", "-0", "--xattrs", "--streams"]
                + encryption
                + [arc, src]
            )
            dst, out = extract(
                arc, mode + "-good", "-P", PASSWORD, "--streams", "--xattrs"
            )
            assert_ads(dst, STREAM_BYTES)
            if (
                snapshot(dst).get(NAME) != (0x80, DATA)
                or (out / "__XTRO_ZIP__").exists()
            ):
                raise RuntimeError("encrypted companion metadata loss/exposure")
            tests += 1
            dst, _ = extract(
                arc,
                mode + "-wrong",
                "-P",
                "wrong-password",
                "--streams",
                "--xattrs",
                success=False,
            )
            if dst.exists() and (
                NAME in snapshot(dst) or read_ads(dst, STREAM_NAME) is not None
            ):
                raise RuntimeError("wrong password published metadata")
            tests += 1

        corrupted = base / "bad-local.zip"
        mutate_local(mixed, corrupted)
        dst, _ = extract(corrupted, "corrupt", "--streams", "--xattrs", success=False)
        if dst.exists() and (
            NAME in snapshot(dst) or read_ads(dst, STREAM_NAME) is not None
        ):
            raise RuntimeError("invalid local/central association wrote metadata")
        tests += 1
    print("PASS: NATIVE WINDOWS W3C2B/C ADS restore; %d archive cases" % tests)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, AssertionError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
