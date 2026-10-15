#!/usr/bin/env python3
"""Opt-in Unicode Win32 EA Zip/UnZip path acceptance (real Windows only).

This tests the ACP-representable subset of Unicode names; it intentionally
cannot certify non-ACP names until UnZip's extraction path uses UTF-16.
MIT-0.
"""

import argparse
import ctypes
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import zipfile
from test_win_zip_native import DATA, NAME, seed_native_ea
from test_win_unzip_native import snapshot


def run(args):
    p = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    if p.returncode:
        raise RuntimeError(
            "%s: rc=%d\n%s\n%s" % (args, p.returncode, p.stdout, p.stderr)
        )


def roundtrippable_acp(name):
    """Do not allow an ACP best-fit fallback to disguise a Unicode failure."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    func = k32.WideCharToMultiByte
    func.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    func.restype = ctypes.c_int
    k32.GetACP.restype = ctypes.c_uint
    cp = k32.GetACP()
    used = ctypes.c_int(0)
    flags = 0 if cp == 65001 else 0x400
    n = func(
        cp, flags, name, -1, None, 0, None, None if cp == 65001 else ctypes.byref(used)
    )
    return bool(n and not used.value)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True)
    ap.add_argument("--unzip", required=True)
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args()
    if os.name != "nt":
        print("SKIP: Windows native EA test requires NTFS")
        return 77
    if hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        print("SKIP: Wine does not support NtSetEaFile")
        return 77
    z, uz, root = (
        Path(args.zip).resolve(),
        Path(args.unzip).resolve(),
        Path(args.workdir).resolve(),
    )
    count, skipped = 0, 0
    with tempfile.TemporaryDirectory(prefix="xtro-unicode-", dir=root) as temp:
        base = Path(temp)
        for filename in ("caf\u00e9.bin", "\u96ea.bin"):
            if not roundtrippable_acp(filename):
                print(
                    "SKIP: Unicode name not representable in active ANSI code page: %s"
                    % filename
                )
                skipped += 1
                continue
            src = base / filename
            src.write_bytes(b"unicode owner bytes\0")
            status = seed_native_ea(src, DATA)
            if status:
                raise RuntimeError("NT EA creation failed: %08x" % status)
            archive = base / ("case-%d.zip" % count)
            run([str(z), "-q", "-j", "-0", "--xattrs", str(archive), str(src)])
            with zipfile.ZipFile(archive) as a:
                ordinary = [
                    x.filename
                    for x in a.infolist()
                    if not x.filename.startswith("__XTRO_ZIP__/")
                ]
                if ordinary != [filename]:
                    raise RuntimeError("Unicode archive name changed: %r" % ordinary)
            out = base / ("out-%d" % count)
            out.mkdir()
            run([str(uz), "-q", "-o", "--xattrs", str(archive), "-d", str(out)])
            restored = out / filename
            if not restored.exists() or restored.read_bytes() != src.read_bytes():
                raise RuntimeError(
                    "Unicode extraction name or contents changed: %s" % filename
                )
            if snapshot(restored).get(NAME, (None, None))[1] != DATA:
                raise RuntimeError("Unicode owner EA missing: %s" % filename)
            count += 1
    print(
        "RESULT: WINDOWS Unicode ACP-representable EA paths; %d passed; %d skipped"
        % (count, skipped)
    )
    return 0 if count else 77


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, AssertionError, zipfile.BadZipFile) as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        sys.exit(1)
