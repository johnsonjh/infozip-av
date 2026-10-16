#!/usr/bin/env python3
"""M7D W3C1 Zip --streams native NTFS capture acceptance (MIT-0).

Uses disposable named $DATA streams and optional NT EA. Inspects exact Xtro
manifest records and companion authentication (without writing any ADS).
Not an UnZip --streams restoration test. Native Windows NTFS required.
"""

import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

from test_win_zip_native import DATA, NAME, field, seed_native_ea, XID

PASSWORD = "xtro-test-only"
CONTENTS = b"Xtro Windows ADS owner contents\x00"
STREAM_NAME = "雪"
STREAM_BYTES = bytes(range(256)) * 8192  # 2 MiB, deliberately >64 KiB


def run(command):
    result = subprocess.run([str(v) for v in command], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            "command failed %r\n%s\n%s\nrc=%d"
            % (command, result.stdout, result.stderr, result.returncode)
        )


def decode_records(body, expect_ea, ea_flags=0):
    assert body[:8] == b"XTMD\x01\x00\x00\x00", "invalid XTMD header"
    count = struct.unpack_from("<I", body, 24)[0]
    size = struct.unpack_from("<Q", body, 28)[0]
    assert size == len(body) - 36, "invalid records size"
    assert count == (2 if expect_ea else 1), "wrong manifest record count"
    assert ea_flags in (0, 0x80), "invalid expected native EA flag"
    pos, records = 36, []
    for _ in range(count):
        typ, flags, origin, encoding, ns_size, name_size, native_size, value_size = (
            struct.unpack_from("<HHHHIIIQ", body, pos)
        )
        pos += 28
        assert origin == 7 and flags == 0 and encoding == 0
        end = pos + ns_size + name_size + native_size + value_size
        assert end <= len(body), "truncated record"
        ns = body[pos : pos + ns_size]
        pos += ns_size
        name = body[pos : pos + name_size]
        pos += name_size
        native = body[pos : pos + native_size]
        pos += native_size
        val = body[pos : pos + value_size]
        pos += value_size
        records.append((typ, ns, name, native, val))
    assert pos == len(body), "extra trailing manifest bytes"
    if expect_ea:
        assert records[0][0:3] == (1, b"nt", NAME)
        assert records[0][4] == DATA
        expected_native = bytes.fromhex("010000000200000008000300000001000000") + bytes(
            (ea_flags,)
        )
        assert (
            records[0][3] == expected_native
        ), "EA flags not preserved: " "seeded 0x%02x, captured %s" % (
            ea_flags,
            records[0][3].hex(),
        )
    ads = records[-1]
    assert ads[0:3] == (3, b"ntfs", STREAM_NAME.encode("utf-8"))
    assert ads[3] == bytes.fromhex(
        "010000000200000009000b0000000400000080000000"
    ), "ADS TLV mismatch"
    assert ads[4] == STREAM_BYTES, "stream bytes corrupted or truncated"
    return count


def inspect(archive, with_ea, encrypted=False, zipcrypto=False, ea_flags=0):
    with zipfile.ZipFile(archive) as zf:
        files = [e for e in zf.infolist() if not e.filename.startswith("__XTRO_ZIP__/")]
        meta = [e for e in zf.infolist() if e.filename.startswith("__XTRO_ZIP__/")]
        assert len(files) == 1, "expected exactly one ordinary owner"
        owner = files[0]
        assert owner.filename == "owner.bin"
        ex = field(owner.extra, XID)
        assert ex is not None and ex[:6] == b"XTRO\x01\x00"
        assert bool(ex[7] & 1) == encrypted
        oid = ex[8:24]
        assert oid != bytes(16)
        if encrypted:
            assert ex[6] == 2 and len(ex) == 40, "encrypted metadata leaked publicly"
            assert len(meta) == 1 and (meta[0].flag_bits & 1) != 0
            assert meta[0].filename == "__XTRO_ZIP__/x/" + oid.hex() + ".xtm"
            # ZipCrypto is readable by Python's stdlib. WinZip AES needs the
            # production UnZip decoder; only test confidential graph here.
            if zipcrypto:
                body = zf.read(meta[0], pwd=PASSWORD.encode("ascii"))
                assert len(body) >= 36 and body[-36:-32] == b"XTCS"
                assert hashlib.sha256(body[:-36]).digest() == body[-32:]
                decode_records(body[:-36], with_ea, ea_flags)
        else:
            if ex[6] == 1:
                body = ex[40:]
                assert not meta
            else:
                assert ex[6] == 2 and len(meta) == 1
                assert meta[0].filename == "__XTRO_ZIP__/x/" + oid.hex() + ".xtm"
                body = zf.read(meta[0])
                assert hashlib.sha256(body).digest() == ex[40:72]
            assert struct.unpack_from("<Q", ex, 28)[0] == len(body)
            assert struct.unpack_from("<I", ex, 36)[0] == zlib.crc32(body)
            decode_records(body, with_ea, ea_flags)
        with open(archive, "rb") as fp:
            fp.seek(owner.header_offset)
            hdr = fp.read(30)
            assert hdr[:4] == b"PK\x03\x04"
            namelen, extralen = struct.unpack_from("<HH", hdr, 26)
            fp.seek(namelen, os.SEEK_CUR)
            local = field(fp.read(extralen), XID)
        assert local == ex[:40], "local/central XTRO identity mismatch"


def self_test():
    body = b"XTMD\x01\x00\x00\x00" + bytes(range(1, 17)) + struct.pack("<IQ", 1, 0)
    native = bytes.fromhex("010000000200000009000b0000000400000080000000")
    record = (
        struct.pack(
            "<HHHHIIIQ",
            3,
            0,
            7,
            0,
            4,
            len(STREAM_NAME.encode("utf-8")),
            len(native),
            len(STREAM_BYTES),
        )
        + b"ntfs"
        + STREAM_NAME.encode("utf-8")
        + native
        + STREAM_BYTES
    )
    body = body[:28] + struct.pack("<Q", len(record)) + record
    assert decode_records(body, False) == 1
    # Exercise both permitted native EA flag states; this must match the
    # flags actually submitted by seed_native_ea(), not a hardcoded 0x80.
    for flag in (0, 0x80):
        ea_native = bytes.fromhex("010000000200000008000300000001000000") + bytes(
            (flag,)
        )
        ea_record = (
            struct.pack(
                "<HHHHIIIQ", 1, 0, 7, 0, 2, len(NAME), len(ea_native), len(DATA)
            )
            + b"nt"
            + NAME
            + ea_native
            + DATA
        )
        mixed_body = (
            body[:24]
            + struct.pack("<IQ", 2, len(ea_record) + len(record))
            + ea_record
            + record
        )
        assert decode_records(mixed_body, True, flag) == 2
        try:
            decode_records(mixed_body, True, flag ^ 0x80)
        except AssertionError:
            pass
        else:
            raise AssertionError("EA flag mismatch went undetected")
    print("PASS: W3C1 mixed stream Xtro parser self-test; 0x00/0x80 flags")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip")
    ap.add_argument("--workdir")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if os.name != "nt":
        print("SKIP: native Windows NTFS required")
        return 77
    if not args.zip or not args.workdir:
        ap.error("--zip and --workdir required")
    root, zip_bin = Path(args.workdir).resolve(), Path(args.zip).resolve()
    if not root.is_dir() or not zip_bin.is_file():
        ap.error("missing workdir or Zip binary")
    count = 0
    with tempfile.TemporaryDirectory(prefix="xtro-w3c1-", dir=str(root)) as tmp:
        tmp = Path(tmp)
        src = tmp / "owner.bin"
        src.write_bytes(CONTENTS)
        try:
            with open(str(src) + ":" + STREAM_NAME + ":$DATA", "wb") as stream:
                stream.write(STREAM_BYTES)
        except OSError as exc:
            raise RuntimeError("native NTFS ADS creation failed: %s" % exc)
        # Test both native flag values. An earlier harness always seeded
        # flags=0 but incorrectly asserted FILE_NEED_EA (0x80) in the ZIP.
        # Verify the source NTFS attribute independently before invoking Zip.
        from test_win_unzip_native import snapshot

        for eas, flag, filename in (
            (False, 0, "ads-only.zip"),
            (True, 0, "mixed-ordinary-ea.zip"),
            (True, 0x80, "mixed-need-ea.zip"),
        ):
            if eas:
                status = seed_native_ea(src, DATA, flags=flag)
                if status:
                    raise RuntimeError("native NT EA seed failed: 0x%08x" % status)
                actual = snapshot(src).get(NAME)
                if actual != (flag, DATA):
                    raise RuntimeError(
                        "native NTFS did not retain EA flags: "
                        "expected 0x%02x, observed %r" % (flag, actual)
                    )
            archive = tmp / filename
            command = [zip_bin, "-q", "-j", "-0", "--streams"]
            if eas:
                command.append("--xattrs")
            run(command + [archive, src])
            inspect(archive, eas, ea_flags=flag)
            count += 1
        # Encrypted graph: preserve the requested ZIP encryption type.
        for kind, args in (
            ("zipcrypto", ["-P", PASSWORD]),
            (
                "aes-standard",
                ["-eP", PASSWORD, "--aes-mode", "standard", "--aes-strength", "256"],
            ),
            (
                "aes-quantum",
                ["-eP", PASSWORD, "--aes-mode", "quantum", "--aes-strength", "256"],
            ),
        ):
            archive = tmp / (kind + ".zip")
            run(
                [zip_bin, "-q", "-j", "-0", "--xattrs", "--streams"]
                + args
                + [archive, src]
            )
            inspect(
                archive,
                True,
                encrypted=True,
                zipcrypto=(kind == "zipcrypto"),
                ea_flags=0x80,
            )
            count += 1
    print("PASS: NATIVE WINDOWS W3C1 Zip ADS capture; %d archive cases" % count)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, AssertionError, zipfile.BadZipFile) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
