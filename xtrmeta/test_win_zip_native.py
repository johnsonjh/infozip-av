#!/usr/bin/env python3
"""Xtro-ZIP W2B1 native Windows Zip EA *capture* acceptance.

Uses a real NTFS EA on a disposable ordinary file and examines both ZIP
headers and the decoded metadata payload. Does not test UnZip restoration.
Wine may return exit 77 when NtSetEaFile is stubbed. MIT-0.
"""

import argparse
import ctypes
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

XID = 0x5854
DATA = b"EA\x00\x01\xfe\xff\r\nW2B1"
NAME = b"XTRODATA"

# Open native EAs with only the rights NtQueryEaFile/NtSetEaFile need.
# Directory opens require BACKUP_SEMANTICS even without backup privileges;
# OPEN_REPARSE_POINT prevents following the final path component.
EA_READ_ACCESS = 0x0008  # FILE_READ_EA
EA_WRITE_ACCESS = 0x0010  # FILE_WRITE_EA
EA_OPEN_FLAGS = 0x02000000 | 0x00200000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT


def field(extra, tag):
    pos = 0
    found = None
    while pos < len(extra):
        if len(extra) - pos < 4:
            raise AssertionError("truncated ZIP extra header")
        ident, n = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if n > len(extra) - pos:
            raise AssertionError("truncated ZIP extra payload")
        if ident == tag:
            if found is not None:
                raise AssertionError("duplicated Xtro extra")
            found = extra[pos : pos + n]
        pos += n
    return found


def verify_archive(path, expected_name, value):
    with zipfile.ZipFile(path) as zf:
        ordinary = [
            x for x in zf.infolist() if not x.filename.startswith("__XTRO_ZIP__/")
        ]
        assert len(ordinary) == 1, "unexpected ordinary ZIP members"
        info = ordinary[0]
        assert info.filename == expected_name, info.filename
        assert zf.read(info) == b"ordinary owner contents\x00\xfe"
        cen = field(info.extra, XID)
        assert cen is not None and len(cen) >= 40 and cen[:6] == b"XTRO\x01\x00"
        assert cen[6] in (1, 2) and cen[7] == 0, "expected public Xtro metadata"
        owner = cen[8:24]
        assert owner != bytes(16)
        with open(path, "rb") as stream:
            stream.seek(info.header_offset)
            hdr = stream.read(30)
            assert hdr[:4] == b"PK\x03\x04"
            flen, xlen = struct.unpack_from("<HH", hdr, 26)
            stream.seek(flen, os.SEEK_CUR)
            loc = field(stream.read(xlen), XID)
        assert loc == cen[:40], "Xtro local/central mismatch"
        if cen[6] == 1:
            manifest = cen[40:]
            assert len(manifest) == struct.unpack_from("<Q", cen, 28)[0]
            assert (
                zlib.crc32(manifest) & 0xFFFFFFFF
                == struct.unpack_from("<I", cen, 36)[0]
            )
        else:
            companions = [
                x for x in zf.infolist() if x.filename.startswith("__XTRO_ZIP__/")
            ]
            assert len(companions) == 1, "missing/multiple Xtro companions"
            assert companions[0].filename == "__XTRO_ZIP__/x/" + owner.hex() + ".xtm"
            manifest = zf.read(companions[0])
            import hashlib

            assert hashlib.sha256(manifest).digest() == cen[40:72], "SHA mismatch"
        assert manifest[:8] == b"XTMD\x01\x00\x00\x00"
        assert manifest[8:24] == owner
        assert NAME in manifest and value in manifest, "captured EA bytes absent"
    return cen[6]


def seed_native_ea(path, value, flags=0):
    """Set one native EA; default retains behavior of earlier test suites."""
    if flags not in (0, 0x80):
        raise ValueError("EA flags must be 0 or FILE_NEED_EA (0x80)")
    from ctypes import wintypes

    class IOSB(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    openfile = k32.CreateFileW
    openfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    openfile.restype = wintypes.HANDLE
    close = k32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    h = openfile(
        str(path),
        EA_READ_ACCESS | EA_WRITE_ACCESS,
        1 | 2 | 4,
        None,
        3,
        EA_OPEN_FLAGS,
        None,
    )
    if h == ctypes.c_void_p(-1).value:
        raise RuntimeError("CreateFileW: %d" % ctypes.get_last_error())
    try:
        ntset = ntdll.NtSetEaFile
        ntset.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(IOSB),
            ctypes.c_void_p,
            wintypes.ULONG,
        ]
        ntset.restype = ctypes.c_long
        assert value and len(value) <= 65535
        rec = (
            struct.pack("<IBBH", 0, flags, len(NAME), len(value)) + NAME + b"\0" + value
        )
        buf = ctypes.create_string_buffer(rec)
        status = ntset(h, ctypes.byref(IOSB()), buf, len(rec)) & 0xFFFFFFFF
        return status
    finally:
        close(h)


def synthetic_selftest():
    import hashlib

    value = DATA
    owner = bytes(range(1, 17))
    # Only a structural fixture: not a substitute for native Windows calls.
    manifest = b"XTMD\x01\x00\x00\x00" + owner + struct.pack("<IQ", 1, 0)
    record = b"W2B1" + NAME + value
    manifest = manifest[:28] + struct.pack("<Q", len(record)) + record
    cen = (
        b"XTRO\x01\x00\x01\x00"
        + owner
        + struct.pack("<IQI", 1, len(manifest), zlib.crc32(manifest))
        + manifest
    )
    local = cen[:40]
    assert len(local) == 40
    assert field(struct.pack("<HH", XID, len(cen)) + cen, XID) == cen
    assert hashlib.sha256(manifest).digest() != bytes(32)
    try:
        field(
            struct.pack("<HH", XID, 40) + local + struct.pack("<HH", XID, 40) + local,
            XID,
        )
    except AssertionError:
        pass
    else:
        raise AssertionError("duplicate field accepted")
    print("PASS: standalone ZIP Xtro parser self-tests (not native integration)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", help="path to Zip's native Windows zip.exe")
    ap.add_argument("--workdir", help="writable local NTFS directory")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        synthetic_selftest()
        return 0
    if os.name != "nt":
        print("SKIP: native Windows required")
        return 77
    if not args.zip or not args.workdir:
        ap.error("--zip and --workdir are required")
    root = pathlib.Path(args.workdir).resolve()
    if not root.is_dir():
        ap.error("--workdir must be a directory")
    zip_binary = pathlib.Path(args.zip).resolve()
    if not zip_binary.is_file():
        ap.error("zip.exe not found")
    with tempfile.TemporaryDirectory(prefix="xtro-w2b-", dir=root) as tmp:
        tmp = pathlib.Path(tmp)
        sample = tmp / "ea-owner.bin"
        sample.write_bytes(b"ordinary owner contents\x00\xfe")
        status = seed_native_ea(sample, DATA)
        if status:
            wine = hasattr(ctypes.WinDLL("ntdll"), "wine_get_version")
            if wine or status in (0xC00000BB,):
                print("SKIP: native EA set unavailable; NTSTATUS 0x%08x" % status)
                return 77
            raise RuntimeError(
                "native Windows EA seed failed: NTSTATUS 0x%08x" % status
            )
        archive = tmp / "capture.zip"
        command = [str(zip_binary), "--xattrs", "-0", "-j", str(archive), str(sample)]
        p = subprocess.run(command, capture_output=True, text=True)
        if p.returncode:
            print(p.stdout, p.stderr, sep="\n")
            raise AssertionError("zip --xattrs failed (%d)" % p.returncode)
        mode = verify_archive(archive, sample.name, DATA)
        print(
            "PASS: NATIVE WINDOWS EA Zip capture; %s manifest"
            % ("inline" if mode == 1 else "companion")
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, RuntimeError) as err:
        print("FAIL:", err, file=sys.stderr)
        sys.exit(1)
