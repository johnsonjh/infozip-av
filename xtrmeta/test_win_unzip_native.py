#!/usr/bin/env python3
"""W2B2A experimental native-Windows NT EA UnZip acceptance. MIT-0.

Requires real Windows with working NtSetEaFile/NtQueryEaFile. Wine's
STATUS_ACCESS_DENIED EA stub must not be counted as a passing test.
"""

import argparse
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

from test_win_zip_native import (
    DATA,
    NAME,
    XID,
    EA_READ_ACCESS,
    EA_OPEN_FLAGS,
    field,
    seed_native_ea,
    verify_archive,
)

STALE = b"XTROSTALE"


class IOSB(ctypes.Structure):
    _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]


def snapshot(path):
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    op = k32.CreateFileW
    op.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    op.restype = wintypes.HANDLE
    close = k32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    h = op(str(path), EA_READ_ACCESS, 1 | 2 | 4, None, 3, EA_OPEN_FLAGS, None)
    if h == ctypes.c_void_p(-1).value:
        raise RuntimeError("EA query open failed: %d" % ctypes.get_last_error())
    try:
        query = ntdll.NtQueryEaFile
        query.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(IOSB),
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.c_ubyte,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
            ctypes.c_ubyte,
        ]
        query.restype = ctypes.c_long
        buf = ctypes.create_string_buffer(1048576)
        io = IOSB()
        status = (
            query(h, ctypes.byref(io), buf, len(buf), 0, None, 0, None, 1) & 0xFFFFFFFF
        )
        if status in (0xC0000052, 0x80000012):
            return {}
        if status:
            raise RuntimeError("NtQueryEaFile returned 0x%08x" % status)
        p = bytes(buf)[: io.information]
        result = {}
        offset = 0
        while offset < len(p):
            if len(p) - offset < 9:
                raise RuntimeError("truncated EA header")
            next_offset, flags, nlen, vlen = struct.unpack_from("<IBBH", p, offset)
            if offset + 9 + nlen + vlen > len(p) or p[offset + 8 + nlen] != 0:
                raise RuntimeError("truncated EA body")
            name = p[offset + 8 : offset + 8 + nlen]
            value = p[offset + 9 + nlen : offset + 9 + nlen + vlen]
            if name in result:
                raise RuntimeError("duplicate native EA")
            result[name] = (flags, value)
            if not next_offset:
                break
            if next_offset % 4 or next_offset < 9 + nlen + vlen:
                raise RuntimeError("invalid native EA next offset")
            offset += next_offset
        return result
    finally:
        close(h)


def run(args, success=True):
    p = subprocess.run(args, capture_output=True, text=True)
    if success and p.returncode:
        raise RuntimeError(
            "%s\n%s\n%s\nrc=%s" % (args, p.stdout, p.stderr, p.returncode)
        )
    if not success and p.returncode == 0:
        raise RuntimeError("corrupt archive unexpectedly succeeded: %s" % args)
    return p


def mutate_local(archive, destination):
    b = bytearray(archive.read_bytes())
    with zipfile.ZipFile(archive) as zf:
        info = next(
            i for i in zf.infolist() if not i.filename.startswith("__XTRO_ZIP__/")
        )
        off = info.header_offset
    if b[off : off + 4] != b"PK\x03\x04":
        raise RuntimeError("missing local header")
    fn, ef = struct.unpack_from("<HH", b, off + 26)
    pos, stop = off + 30 + fn, off + 30 + fn + ef
    while pos < stop:
        ident, count = struct.unpack_from("<HH", b, pos)
        if ident == XID:
            if count < 40:
                raise RuntimeError("invalid inline Xtro")
            b[pos + 4 + 8] ^= 0x80  # mutate the local owner identity only
            destination.write_bytes(b)
            return
        pos += 4 + count
    raise RuntimeError("missing local Xtro field")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True)
    ap.add_argument("--unzip", required=True)
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args()
    if os.name != "nt":
        print("SKIP: requires real Windows native NT EAs")
        return 77
    if hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        print("SKIP: Wine native EA operations are not implemented")
        return 77
    root = Path(args.workdir).resolve()
    z = Path(args.zip).resolve()
    uz = Path(args.unzip).resolve()
    for path in (root, z, uz):
        if not path.exists():
            ap.error("missing path: %s" % path)
    count = 0
    with tempfile.TemporaryDirectory(prefix="xtro-unzip-w2b2a-", dir=root) as directory:
        base = Path(directory)
        src = base / "owner.bin"
        src.write_bytes(b"ordinary owner contents\0\xfe")
        status = seed_native_ea(src, DATA)
        if status:
            raise RuntimeError("NT EA seed unavailable 0x%08x" % status)
        arc = base / "owner.zip"
        run([str(z), "--xattrs", "-0", "-j", str(arc), str(src)])
        if verify_archive(arc, src.name, DATA) != 1:
            raise RuntimeError("W2B2A requires the public inline test case")
        count += 1
        restored = base / "restore"
        restored.mkdir()
        run([str(uz), "--xattrs", "-o", str(arc), "-d", str(restored)])
        result = restored / src.name
        if (
            result.read_bytes() != src.read_bytes()
            or snapshot(result).get(NAME, (None, None))[1] != DATA
        ):
            raise RuntimeError("inline native restoration did not preserve EA and data")
        count += 1
        disabled = base / "disabled"
        disabled.mkdir()
        run([str(uz), "--xattrs", "--no-xattrs", "-o", str(arc), "-d", str(disabled)])
        if NAME in snapshot(disabled / src.name):
            raise RuntimeError("--no-xattrs wrote native EA")
        count += 1
        # -n must leave both file contents and existing EAs unchanged.
        status = seed_native_ea(result, b"WRONG")
        if status:
            raise RuntimeError("cannot seed preexisting native EA")
        run([str(uz), "--xattrs", "-n", str(arc), "-d", str(restored)])
        if snapshot(result).get(NAME, (None, None))[1] != b"WRONG":
            raise RuntimeError("skip modified an existing EA")
        count += 1
        precedence = base / "precedence"
        precedence.mkdir()
        run([str(uz), "--no-xattrs", "--xattrs", "-o", str(arc), "-d", str(precedence)])
        if snapshot(precedence / src.name).get(NAME, (None, None))[1] != DATA:
            raise RuntimeError("last --xattrs did not enable restoration")
        count += 1
        # Create a stale EA with a different name by changing only the name
        # in the seeding helper's module-level constant (restore afterward).
        import test_win_zip_native as helper

        original = helper.NAME
        try:
            helper.NAME = STALE
            status = helper.seed_native_ea(result, b"STALE")
        finally:
            helper.NAME = original
        if status:
            raise RuntimeError("cannot seed stale native EA")
        run([str(uz), "--xattrs", "-o", str(arc), "-d", str(restored)])
        values = snapshot(result)
        if values.get(NAME, (None, None))[1] != DATA or STALE in values:
            raise RuntimeError("exact native EA replacement failed: %r" % values)
        count += 1
        corrupt = base / "corrupt.zip"
        mutate_local(arc, corrupt)
        bad = base / "bad"
        bad.mkdir()
        run([str(uz), "--xattrs", "-o", str(corrupt), "-d", str(bad)], False)
        if (bad / src.name).exists() and NAME in snapshot(bad / src.name):
            raise RuntimeError("local/central mismatch wrote native metadata")
        count += 1
    print("PASS: NATIVE WINDOWS W2B2A UnZip inline EAs; %d cases" % count)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, AssertionError, zipfile.BadZipFile) as error:
        print("FAIL: %s" % error, file=sys.stderr)
        sys.exit(1)
