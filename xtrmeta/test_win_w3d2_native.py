#!/usr/bin/env python3
"""W3D2 real-Windows acceptance: Unicode argv, NTFS metadata and path safety.

Needs the native opt-in UTF-8 UnZip, and an NTFS scratch directory.
It does not change any permanent destination data. MIT-0.
"""

import argparse
import binascii
import struct
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from test_win_zip_native import DATA, NAME, seed_native_ea
from test_win_unzip_native import snapshot
from test_win_stream_restore_native import write_ads, read_ads, win_file_id
from test_win_stream_archive_native import STREAM_NAME, STREAM_BYTES

UNICODE = ("雪.bin", "目录/雪.bin", "🧪.bin", "plain/é-雪.bin")
BANNED = (
    "NUL.txt",
    "nested/CON.log",
    "nested/COM¹.txt",
    "nested/aux.txt",
    "nested/a|b.bin",
    "nested/trailing.",
)


def run(cmd, must_succeed=True):
    result = subprocess.run(
        [str(x) for x in cmd], capture_output=True, text=True, errors="replace"
    )
    if must_succeed != (result.returncode == 0):
        raise RuntimeError(
            "command %r returned %d\n%s\n%s"
            % (cmd, result.returncode, result.stdout, result.stderr)
        )
    return result


def unicode_fixture(path):
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        for i, name in enumerate(UNICODE):
            payload = bytes(((k * 31 + i) & 255) for k in range(40001 + i))
            z.writestr(name, payload, compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(path) as z:
        if z.namelist() != list(UNICODE):
            raise AssertionError("Unicode fixture records differ")


def extra_field_fixture(path):
    # Info-ZIP Unicode Path (0x7075): old ASCII filename with verified CRC
    # and a UTF-8 replacement, without ZIP's general-purpose UTF-8 flag.
    source = b"legacy-name.bin"
    target = "传统-雪.bin"
    name = target.encode("utf-8")
    data = b"W3D2 verified Unicode-path extra field"
    payload = b"\x01" + struct.pack("<I", binascii.crc32(source) & 0xFFFFFFFF) + name
    field = struct.pack("<HH", 0x7075, len(payload)) + payload
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        entry = zipfile.ZipInfo(source.decode("ascii"))
        entry.extra = field
        z.writestr(entry, data)
    with zipfile.ZipFile(path) as z:
        if z.infolist()[0].flag_bits & 0x800:
            raise AssertionError("Unicode path extra fixture unexpectedly has GPBF EFS")
    return target, data


def zip64_fixture(path):
    # Force the ZIP64 local record even though the member is small enough
    # to keep this test quick and independent of free disk capacity.
    name = "ZIP64-雪.bin"
    data = b"W3D2 forced ZIP64 local header" * 117
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        entry = zipfile.ZipInfo(name)
        with z.open(entry, "w", force_zip64=True) as out:
            out.write(data)
    return name, data


def test(args):
    if args.self_test:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.zip"
            unicode_fixture(path)
            with zipfile.ZipFile(path) as z:
                for name in UNICODE:
                    if not z.getinfo(name).flag_bits & 0x800:
                        raise AssertionError("missing UTF-8 flag")
            extra_field_fixture(Path(tmp) / "extra.zip")
            zip64_fixture(Path(tmp) / "zip64.zip")
            with zipfile.ZipFile(Path(tmp) / "bad.zip", "w") as z:
                for name in BANNED:
                    z.writestr(name, b"device-test")
        print(
            "PASS: W3D2 fixture self-test; 4 Unicode + 1 0x7075 + 1 ZIP64 + 6 rejected paths"
        )
        return 0
    if os.name != "nt":
        print("SKIP: W3D2 native acceptance requires real Windows NTFS")
        return 77
    if hasattr(ctypes.WinDLL("ntdll"), "wine_get_version"):
        print("SKIP: Wine cannot certify native Windows NT EAs")
        return 77
    if not args.zip or not args.unzip:
        raise RuntimeError("--zip and --unzip are required")
    zipexe, unzipexe = Path(args.zip).resolve(), Path(args.unzip).resolve()
    root = Path(args.workdir).resolve()
    if not zipexe.is_file() or not unzipexe.is_file() or not root.is_dir():
        raise RuntimeError("binary/workdir missing")
    count = 0
    with tempfile.TemporaryDirectory(prefix="xtro-w3d2-", dir=root) as scratch:
        base = Path(scratch)
        # The archive and -d arguments themselves contain characters absent
        # from a western ACP: GetCommandLineW -> UTF-8 -> wide filesystem I/O.
        archive = base / "归档-雪-🧪.zip"
        target = base / "目标-雪-🧪"
        target.mkdir()
        unicode_fixture(archive)
        run([unzipexe, "-q", "-o", str(archive), "-d", str(target)])
        with zipfile.ZipFile(archive) as za:
            for name in UNICODE:
                restored = target.joinpath(*name.split("/"))
                if not restored.is_file() or restored.read_bytes() != za.read(name):
                    raise AssertionError(
                        "Unicode archive or destination path: %s" % name
                    )
                count += 1

        extra_archive = base / "extra-归档.zip"
        extra_name, extra_data = extra_field_fixture(extra_archive)
        extra_out = base / "extra-输出"
        extra_out.mkdir()
        run([unzipexe, "-q", "-o", str(extra_archive), "-d", str(extra_out)])
        if (extra_out / extra_name).read_bytes() != extra_data:
            raise AssertionError("0x7075 Unicode Path extra field not honored")
        count += 1

        zip64_archive = base / "ZIP64-归档.zip"
        zip64_name, zip64_data = zip64_fixture(zip64_archive)
        zip64_out = base / "ZIP64-输出"
        zip64_out.mkdir()
        run([unzipexe, "-q", "-o", str(zip64_archive), "-d", str(zip64_out)])
        if (zip64_out / zip64_name).read_bytes() != zip64_data:
            raise AssertionError("forced ZIP64 with Unicode output failed")
        count += 1

        # Existing Unicode owner, EAs and ADS must survive an ordinary
        # overwrite with both metadata classes deselected. The file identity
        # must remain stable, not delete/recreate in order to hide the loss.
        dst = target / "雪.bin"
        dst.write_bytes(b"old-content")
        write_ads(dst, STREAM_NAME, b"unselected Unicode ADS")
        if seed_native_ea(dst, b"unselected Unicode EA"):
            raise AssertionError("native EA seed failed")
        before = win_file_id(dst)
        run(
            [
                unzipexe,
                "-q",
                "-o",
                "--no-xattrs",
                "--no-streams",
                str(archive),
                "-d",
                str(target),
            ]
        )
        if (
            win_file_id(dst) != before
            or snapshot(dst).get(NAME) != (0, b"unselected Unicode EA")
            or read_ads(dst, STREAM_NAME) != b"unselected Unicode ADS"
        ):
            raise AssertionError("Unicode overwrite lost unselected native metadata")
        count += 1

        # Mixed EA+ADS archive restored under a Unicode destination directory:
        # combines wide CLI output path and existing independently selected
        # verified/transactional metadata restoration, including large ADS.
        src = base / "owner.bin"
        src.write_bytes(b"W3D2 mixed metadata owner")
        write_ads(src, STREAM_NAME, STREAM_BYTES)
        if seed_native_ea(src, DATA, flags=0x80):
            raise AssertionError("native NEED_EA seed failed")
        mixarc = base / "元数据-🧪.zip"
        run([zipexe, "-q", "-j", "-0", "--xattrs", "--streams", mixarc, src])
        out = base / "恢复-雪"
        out.mkdir()
        run([unzipexe, "-q", "--xattrs", "--streams", mixarc, "-d", out])
        extracted = out / "owner.bin"
        if (
            extracted.read_bytes() != src.read_bytes()
            or snapshot(extracted).get(NAME) != (0x80, DATA)
            or read_ads(extracted, STREAM_NAME) != STREAM_BYTES
        ):
            raise AssertionError("mixed metadata under Unicode output path")
        count += 1

        # Rejected filesystem names must not escape to a Win32 device, ADS,
        # or a normalized output filename. Each malformed entry is isolated.
        for index, name in enumerate(BANNED):
            arc = base / ("bad-%d.zip" % index)
            dest = base / ("bad-out-%d" % index)
            dest.mkdir()
            with zipfile.ZipFile(arc, "w") as za:
                za.writestr(name, b"device-test")
            run([unzipexe, "-q", "-o", arc, "-d", dest], must_succeed=False)
            files = [f for f in dest.rglob("*") if f.is_file()]
            if files:
                raise AssertionError("unsafe path published files: %r" % files)
            count += 1

        # Hard-link overwrite changes all aliases, so it must be rejected.
        src_arc = base / "hardlink.zip"
        with zipfile.ZipFile(src_arc, "w") as za:
            za.writestr("owner.bin", b"new-data")
        dest = base / "hardlink-dest"
        dest.mkdir()
        owner = dest / "owner.bin"
        owner.write_bytes(b"original")
        alias = dest / "alias.bin"
        try:
            os.link(owner, alias)
        except OSError:
            print("SKIP: hard-link rejection (filesystem disallows hardlinks)")
        else:
            run(
                [
                    unzipexe,
                    "-q",
                    "-o",
                    "--no-xattrs",
                    "--no-streams",
                    src_arc,
                    "-d",
                    dest,
                ],
                must_succeed=False,
            )
            if owner.read_bytes() != b"original" or alias.read_bytes() != b"original":
                raise AssertionError("hard-link overwrite changed another name")
            count += 1
    print("PASS: NATIVE WINDOWS W3D2 Unicode CLI/EA/ADS safety; %d cases" % count)
    return 0


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--zip")
    a.add_argument("--unzip")
    a.add_argument("--workdir", default=".")
    a.add_argument("--self-test", action="store_true")
    try:
        sys.exit(test(a.parse_args()))
    except (OSError, AssertionError, RuntimeError, zipfile.BadZipFile) as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        sys.exit(1)
