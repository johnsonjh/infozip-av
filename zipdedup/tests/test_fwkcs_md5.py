#!/usr/bin/env python3
"""FWKCS writer and compatibility cases, pure Python stdlib fixtures (MIT-0)."""

import hashlib
import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = pathlib.Path(os.environ.get("ZD_TEST_TOOL", str(ROOT / "zipdedup/zipdedup")))
UNZIP = pathlib.Path(os.environ.get("ZD_TEST_UNZIP", str(ROOT / "unzip60/unzip")))
CHECKS = 0


def run(*args, rc=0, msg=None):
    global CHECKS
    r = subprocess.run([str(x) for x in args], capture_output=True, timeout=30)
    assert r.returncode == rc, (args, r.returncode, r.stdout[-500:], r.stderr[-1000:])
    if msg:
        assert msg.encode() in r.stderr, (args, r.stderr)
    CHECKS += 1
    return r


def fields(extra):
    out = []
    pos = 0
    while pos < len(extra):
        assert len(extra) - pos >= 4
        tag, length = struct.unpack_from("<HH", extra, pos)
        assert length <= len(extra) - pos - 4
        out.append((tag, extra[pos + 4 : pos + 4 + length]))
        pos += length + 4
    return out


def verify(path, expected_dirs=True):
    with zipfile.ZipFile(path) as z:
        for f in z.infolist():
            md5 = [v for k, v in fields(f.extra) if k == 0x4B46]
            assert len(md5) == (0 if f.is_dir() and expected_dirs else 1), (
                f.filename,
                md5,
            )
            if md5:
                assert md5[0] == b"MD5" + hashlib.md5(z.read(f)).digest()
    run(UNZIP, "-tqq", path)


def add_central_field(source, dest, records):
    b = source.read_bytes()
    end = b.rfind(b"PK\x05\x06")
    assert end >= 0
    size, start = struct.unpack_from("<II", b, end + 12)
    pos, stop = start, start + size
    out = bytearray()
    index = 0
    while pos < stop:
        assert b[pos : pos + 4] == b"PK\x01\x02"
        name, ex, comment = struct.unpack_from("<HHH", b, pos + 28)
        length = 46 + name + ex + comment
        row = bytearray(b[pos : pos + length])
        tail = records.get(index, b"")
        struct.pack_into("<H", row, 30, ex + len(tail))
        out.extend(row[: 46 + name + ex] + tail + row[46 + name + ex :])
        pos += length
        index += 1
    assert pos == stop
    b = bytearray(b[:start]) + out + bytearray(b[end:])
    end += len(out) - size
    struct.pack_into("<I", b, end + 12, len(out))
    dest.write_bytes(b)


def make_archive(path, pairs):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in pairs:
            z.writestr(
                name,
                data,
                compress_type=(
                    zipfile.ZIP_STORED if not name.endswith("/") else zipfile.ZIP_STORED
                ),
            )


with tempfile.TemporaryDirectory() as t:
    base = pathlib.Path(t)
    original, md, second = [base / x for x in ("ordinary.zip", "md.zip", "repeat.zip")]
    make_archive(
        original,
        [("folder/", b""), ("folder/empty", b""), ("folder/hello", b"hello" * 300)]
        + [
            ("boundary-%d" % n, bytes(range(n)))
            for n in (55, 56, 63, 64, 65, 119, 120, 127, 128)
        ],
    )
    run(TOOL, "--fwkcs-md5", original, md)
    verify(md)
    assert original.read_bytes() != md.read_bytes()
    run(TOOL, "--fwkcs-md5", md, second)
    assert second.read_bytes() == md.read_bytes(), "repeated opt-in must be no-op"
    run(TOOL, original, base / "plain.zip")
    assert (
        original.read_bytes() == (base / "plain.zip").read_bytes()
    ), "default no-op identity"

    # Input with a pre-existing *correct* central-only field is retained.
    partial = base / "partial.zip"
    ext = b"FK\x13\x00MD5" + hashlib.md5(b"").digest()
    add_central_field(original, partial, {1: ext})
    preserved = base / "preserved.zip"
    run(TOOL, "--fwkcs-md5", partial, preserved)
    verify(preserved)
    assert [
        v
        for k, v in fields(zipfile.ZipFile(preserved).infolist()[1].extra)
        if k == 0x4B46
    ] == [b"MD5" + hashlib.md5(b"").digest()]
    directory_existing = base / "directory-existing.zip"
    add_central_field(original, directory_existing, {0: ext, 1: ext})
    run(TOOL, "--fwkcs-md5", directory_existing, base / "directory-existing-out.zip")
    verify(base / "directory-existing-out.zip", expected_dirs=False)

    bad = base / "bad.zip"
    add_central_field(original, bad, {1: b"FK\x13\x00MD5" + b"\xff" * 16})
    run(TOOL, "--fwkcs-md5", bad, base / "bad.out.zip", rc=1)
    assert not (base / "bad.out.zip").exists()
    duplicate = base / "duplicate.zip"
    add_central_field(original, duplicate, {1: ext + ext})
    run(TOOL, "--fwkcs-md5", duplicate, base / "duplicate.out.zip", rc=1)
    malformed = base / "malformed.zip"
    add_central_field(original, malformed, {1: b"FK\x12\x00MD5" + b"\0" * 15})
    run(TOOL, "--fwkcs-md5", malformed, base / "malformed.out.zip", rc=1)

    # An undecodable member remains a default no-op, but fails opt-in.
    unsupported = base / "unsupported.zip"
    make_archive(unsupported, [("unknown", b"")])
    data = bytearray(unsupported.read_bytes())
    lh = data.index(b"PK\x03\x04")
    cd = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, lh + 8, 200)
    struct.pack_into("<H", data, cd + 10, 200)
    unsupported.write_bytes(data)
    run(TOOL, unsupported, base / "unsupported.copy.zip")
    assert unsupported.read_bytes() == (base / "unsupported.copy.zip").read_bytes()
    run(TOOL, "--fwkcs-md5", unsupported, base / "unsupported.out.zip", rc=1)

    # A metadata-only rewrite must still respect existing APK safeguards.
    signed = base / "signed.zip"
    signed_bytes = bytearray(original.read_bytes())
    eocd = signed_bytes.rfind(b"PK\x05\x06")
    cdstart = struct.unpack_from("<I", signed_bytes, eocd + 16)[0]
    pair = struct.pack("<QI", 6, 0x7109871A) + b"AB"
    blocksize = 24 + len(pair)
    block = (
        struct.pack("<Q", blocksize)
        + pair
        + struct.pack("<Q", blocksize)
        + b"APK Sig Block 42"
    )
    signed_bytes[cdstart:cdstart] = block
    struct.pack_into("<I", signed_bytes, eocd + len(block) + 16, cdstart + len(block))
    signed.write_bytes(signed_bytes)
    run(
        TOOL,
        "--fwkcs-md5",
        signed,
        base / "signed.no.zip",
        rc=1,
        msg="APK Signing Block",
    )
    run(
        TOOL,
        "--fwkcs-md5",
        "--force",
        signed,
        base / "signed.yes.zip",
        msg="APK Signing Block",
    )
    verify(base / "signed.yes.zip")
    run(TOOL, signed, base / "signed.copy.zip", msg="APK Signing Block")
    assert signed.read_bytes() == (base / "signed.copy.zip").read_bytes()

    # Method 92 RefPtr must hash referenced plaintext, not 20-byte SHA-1.
    data = bytes((i * 37 + (i >> 8)) % 256 for i in range(110000))
    refs = base / "refs.zip"
    make_archive(refs, [("one.dat", data), ("two.dat", data)])
    dedup = base / "refs.dedup.zip"
    run(TOOL, refs, dedup)
    with zipfile.ZipFile(dedup) as z:
        assert any(e.compress_type == 92 for e in z.infolist())
    run(TOOL, "--fwkcs-md5", dedup, base / "refs.fwkcs.zip")
    with zipfile.ZipFile(base / "refs.fwkcs.zip") as z:
        for f in z.infolist():
            tags = [v for k, v in fields(f.extra) if k == 0x4B46]
            assert tags == [b"MD5" + hashlib.md5(data).digest()], (f.filename, tags)
    run(UNZIP, "-tqq", base / "refs.fwkcs.zip")

    # Combined deduplication and FWKCS must annotate the physical source and
    # the newly generated method-92 reference in a single output pass.
    run(TOOL, "--fwkcs-md5", refs, base / "refs.combined.zip")
    with zipfile.ZipFile(base / "refs.combined.zip") as z:
        assert any(e.compress_type == 92 for e in z.infolist())
        assert all(
            [v for k, v in fields(e.extra) if k == 0x4B46]
            == [b"MD5" + hashlib.md5(data).digest()]
            for e in z.infolist()
        )
    run(UNZIP, "-tqq", base / "refs.combined.zip")

    # ZIP64 local size fields, streamed descriptor and central FWKCS metadata.
    zip64 = base / "zip64.zip"
    with zipfile.ZipFile(zip64, "w") as z:
        with z.open("streamed", "w", force_zip64=True) as writer:
            writer.write(b"Zip64 small payload" * 300)
    run(TOOL, "--fwkcs-md5", zip64, base / "zip64.fwkcs.zip")
    verify(base / "zip64.fwkcs.zip")

    # Record capacity is checked; never truncate an existing central extra.
    too_big = base / "largeextra.zip"
    ext = struct.pack("<HH", 0xAABB, 65510) + b"\0" * 65510
    with zipfile.ZipFile(too_big, "w") as z:
        zi = zipfile.ZipInfo("empty")
        zi.extra = ext
        z.writestr(zi, b"")
    run(TOOL, "--fwkcs-md5", too_big, base / "largeextra.out.zip", rc=1)
    assert not (base / "largeextra.out.zip").exists()

print("FWKCS zipdedup tests passed:", CHECKS, "command invocations")
