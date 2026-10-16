#!/usr/bin/env python3
"""Native Windows W2B2C1 directory EA acceptance (MIT-0).

Runs on disposable NTFS directories, requires real Windows and native NT EA
syscalls. Wine and Linux-hosted mocks are not acceptance evidence.
"""

import argparse
import ctypes
import os
from pathlib import Path
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
    EA_WRITE_ACCESS,
    EA_OPEN_FLAGS,
    field,
    seed_native_ea,
)
from test_win_unzip_native import snapshot, mutate_local


def run(args, success=True, cwd=None):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if success and p.returncode:
        raise RuntimeError(
            "command failed %s\n%s\n%s\nrc=%s"
            % (args, p.stdout, p.stderr, p.returncode)
        )
    if not success and p.returncode == 0:
        raise RuntimeError("corrupt archive unexpectedly succeeded")
    return p


def inspect_directory(archive, expected, want_companion=False):
    with zipfile.ZipFile(archive) as zf:
        dirs = [i for i in zf.infolist() if i.filename == expected]
        if len(dirs) != 1 or not dirs[0].is_dir():
            raise RuntimeError("missing single directory ZIP member")
        info = dirs[0]
        raw = field(info.extra, XID)
        if raw is None or len(raw) < 40 or raw[:6] != b"XTRO\x01\x00":
            raise RuntimeError("missing central Xtro directory metadata")
        if info.compress_size or info.file_size or info.CRC or info.flag_bits & 1:
            raise RuntimeError("directory owner must be empty, STORE, public")
        if want_companion and raw[6] != 2:
            raise RuntimeError("large directory EA did not use companion")
        with open(archive, "rb") as stream:
            stream.seek(info.header_offset)
            header = stream.read(30)
            if header[:4] != b"PK\x03\x04":
                raise RuntimeError("missing local directory header")
            nlen, elen = struct.unpack_from("<HH", header, 26)
            name = stream.read(nlen)
            if name != expected.encode("ascii"):
                raise RuntimeError("local/central directory name mismatch")
            local = field(stream.read(elen), XID)
            if local != raw[:40]:
                raise RuntimeError("local/central Xtro directory mismatch")
        return raw[6]


def self_test_directory_ea_handle_flags():
    """Exercise the actual Win32 helper call arguments without NTFS/Wine.

    A fake kernel32/ntdll validates that our test code requests the EA
    rights and BACKUP_SEMANTICS rather than unnecessary generic file rights.
    This is not evidence of native Windows directory EA support.
    """

    class FakeCall:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    calls = []

    def create(path, access, share, security, disposition, flags, template):
        calls.append((path, access, share, disposition, flags))
        return 1234

    def query(*unused):
        return 0x80000012  # STATUS_NO_MORE_EAS

    class FakeDLL:
        pass

    kernel = FakeDLL()
    kernel.CreateFileW = FakeCall(create)
    kernel.CloseHandle = FakeCall(lambda h: 1)
    native = FakeDLL()
    native.NtSetEaFile = FakeCall(lambda *a: 0)
    native.NtQueryEaFile = FakeCall(query)
    old = getattr(ctypes, "WinDLL", None)
    ctypes.WinDLL = lambda name, **kw: kernel if name == "kernel32" else native
    try:
        assert seed_native_ea(Path("synthetic-directory"), b"EA") == 0
        assert snapshot(Path("synthetic-directory")) == {}
    finally:
        if old is None:
            del ctypes.WinDLL
        else:
            ctypes.WinDLL = old

    assert len(calls) == 2, calls
    assert calls[0][1] == EA_READ_ACCESS | EA_WRITE_ACCESS, calls
    assert calls[1][1] == EA_READ_ACCESS, calls
    assert all(c[2] == 7 and c[3] == 3 and c[4] == EA_OPEN_FLAGS for c in calls), calls
    assert EA_OPEN_FLAGS == 0x02200000
    print("PASS: Windows directory EA handle flags; 2 mocked opens")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip")
    parser.add_argument("--unzip")
    parser.add_argument("--workdir")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test_directory_ea_handle_flags()
        return 0
    if not args.zip or not args.unzip or not args.workdir:
        parser.error("--zip, --unzip and --workdir are required")
    if os.name != "nt":
        print("SKIP: requires native Windows NT EA support")
        return 77
    if hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        print("SKIP: Wine NT EA operations are not native Windows")
        return 77
    zp = Path(args.zip).resolve()
    uz = Path(args.unzip).resolve()
    root = Path(args.workdir).resolve()
    if not zp.is_file() or not uz.is_file() or not root.is_dir():
        parser.error("zip/unzip binary and writable test directory are required")
    tests = 0
    skips = 0
    with tempfile.TemporaryDirectory(prefix="xtro-win-dir-", dir=root) as tmp:
        base = Path(tmp)
        src = base / "dirname"
        src.mkdir()
        (src / "item.bin").write_bytes(b"directory owner member")
        status = seed_native_ea(src, DATA)
        if status:
            raise RuntimeError(
                "directory NtSetEaFile refused seed: NTSTATUS 0x%08x" % status
            )
        arc = base / "directory.zip"
        run([str(zp), "-q", "--xattrs", "-0", "-r", str(arc), "dirname"], cwd=base)
        inspect_directory(arc, "dirname/")
        tests += 1
        out = base / "out"
        out.mkdir()
        run([str(uz), "-q", "--xattrs", str(arc), "-d", str(out)])
        if (out / "dirname" / "item.bin").read_bytes() != b"directory owner member":
            raise RuntimeError("directory contents missing")
        if snapshot(out / "dirname").get(NAME, (None, None))[1] != DATA:
            raise RuntimeError("directory EA did not restore")
        tests += 1
        disabled = base / "disabled"
        disabled.mkdir()
        run([str(uz), "-q", "--xattrs", "--no-xattrs", str(arc), "-d", str(disabled)])
        if NAME in snapshot(disabled / "dirname"):
            raise RuntimeError("disabled restoration changed native directory EAs")
        tests += 1
        # Existing directories are not newly created; their EAs must survive.
        changed = b"preexisting"
        status = seed_native_ea(out / "dirname", changed)
        if status:
            raise RuntimeError("cannot seed preexisting directory EA")
        run([str(uz), "-q", "--xattrs", "-o", str(arc), "-d", str(out)])
        if snapshot(out / "dirname").get(NAME, (None, None))[1] != changed:
            raise RuntimeError("existing directory EA was overwritten")
        tests += 1
        # Corrupt only the local Xtro owner ID; no metadata should be written.
        tampered = base / "tampered.zip"
        mutate_local(arc, tampered)
        rejected = base / "rejected"
        rejected.mkdir()
        run([str(uz), "-q", "--xattrs", str(tampered), "-d", str(rejected)], False)
        if (rejected / "dirname").is_dir() and NAME in snapshot(rejected / "dirname"):
            raise RuntimeError("corrupt local Xtro wrote directory EAs")
        tests += 1
        # Large *public* EA should use the verified companion lifecycle where
        # supported; skip explicitly on NTFS volumes that refuse this size.
        large = b"L" * 60500
        status = seed_native_ea(src, large)
        if status:
            skips += 1
            print("SKIP: directory large EA native seed: NTSTATUS 0x%08x" % status)
        else:
            big = base / "large.zip"
            run([str(zp), "-q", "--xattrs", "-0", "-r", str(big), "dirname"], cwd=base)
            inspect_directory(big, "dirname/", want_companion=True)
            dest = base / "bigout"
            dest.mkdir()
            run([str(uz), "-q", "--xattrs", str(big), "-d", str(dest)])
            if snapshot(dest / "dirname").get(NAME, (None, None))[1] != large:
                raise RuntimeError("directory companion did not restore full EA")
            if (dest / "__XTRO_ZIP__").exists():
                raise RuntimeError("internal companion exposed on filesystem")
            tests += 1
    print(
        "PASS: NATIVE WINDOWS W2B2C1 directory EAs; %d cases; %d skipped"
        % (tests, skips)
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, AssertionError, RuntimeError, zipfile.BadZipFile) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
