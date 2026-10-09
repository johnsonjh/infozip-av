#!/usr/bin/env python3
"""End-to-end regression suite for the MIT-0 standalone Method 92 writer.

Needs stdlib Python 3 for the test harness; production zipdedup is ANSI C89.
This suite deliberately tests the independent Info-ZIP decoder, not just ZIP
structure according to Python's zipfile (which cannot extract Method 92).
"""

import hashlib
import io
import os
import pathlib
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "zipdedup" / "zipdedup"
ZIP = ROOT / "zip30" / "zip"
UNZIP = ROOT / "unzip60" / "unzip"


def run(*args, rc=0):
    p = subprocess.run(
        [str(a) for a in args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode == rc if isinstance(rc, int) else p.returncode in rc:
        return p
    raise AssertionError(
        f"{p.args}: exit {p.returncode}, stdout={p.stdout}, stderr={p.stderr}"
    )


def raw(zipname, info):
    with open(zipname, "rb") as f:
        f.seek(info.header_offset)
        hdr = f.read(30)
        assert hdr[:4] == b"PK\x03\x04"
        nl, xl = struct.unpack_from("<HH", hdr, 26)
        f.seek(info.header_offset + 30 + nl + xl)
        return f.read(info.compress_size), hdr


def check_rewrite(inputname, output, same, refs):
    before = zipfile.ZipFile(inputname)
    after = zipfile.ZipFile(output)
    assert before.namelist() == after.namelist()
    for name in same:
        a, b = before.getinfo(name), after.getinfo(name)
        assert (a.compress_type, a.CRC, a.file_size) == (
            b.compress_type,
            b.CRC,
            b.file_size,
        )
        assert raw(inputname, a)[0] == raw(output, b)[0]
    for name, srcname in refs.items():
        e, source = after.getinfo(name), before.getinfo(srcname)
        assert e.compress_type == 92 and e.compress_size == 20
        assert e.CRC == source.CRC and e.file_size == source.file_size
        try:
            decoded = before.read(srcname)
        except NotImplementedError:
            decoded = subprocess.run(
                [str(UNZIP), "-p", str(inputname), srcname],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
        assert raw(output, e)[0] == hashlib.sha1(decoded).digest()
        assert e.extract_version >= 20
        ef = e.extra
        assert b"\x03\x99\x14\x00" in ef
    run(UNZIP, "-t", output)
    before.close()
    after.close()


def make_test_zip(path):
    r = random.Random(475)
    incompressible = r.randbytes(90000)
    repeated = b"C89 Info-ZIP Method 92\n" * 6000
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        for name, data, method in (
            ("source.bin", incompressible, 0),
            ("dup-deflate.bin", incompressible, 8),
            ("dup-store.bin", incompressible, 0),
            ("source.txt", repeated, 8),
            ("dup.txt", repeated, 8),
            ("tiny-1", b"x", 0),
            ("tiny-2", b"x", 0),
        ):
            zi = zipfile.ZipInfo(name, (2026, 10, 8, 4, 8, 2))
            zi.compress_type = method
            zi.comment = b"original entry comment"
            zi.extra = b"\x0a\x00\x01\x00X"
            z.writestr(zi, data)
        z.comment = b"archive comment survives"
    return incompressible


def test_normal(base):
    source = base / "ordinary.zip"
    out = base / "dedup.zip"
    make_test_zip(source)
    run(TOOL, "--dry-run", source, out)
    assert not out.exists()
    run(TOOL, "-v", source, out)
    check_rewrite(
        source,
        out,
        ["source.bin", "source.txt", "tiny-1", "tiny-2"],
        {
            "dup-deflate.bin": "source.bin",
            "dup-store.bin": "source.bin",
            "dup.txt": "source.txt",
        },
    )
    assert zipfile.ZipFile(out).comment == b"archive comment survives"
    assert zipfile.ZipFile(out).getinfo("dup.txt").comment == b"original entry comment"
    again = base / "again.zip"
    run(TOOL, out, again)
    assert out.read_bytes() == again.read_bytes(), "not byte-idempotent"
    run(TOOL, source, out, rc=1)
    assert out.read_bytes() == again.read_bytes(), "overwrote existing output"

    before = out.read_bytes()
    run(ZIP, "-d", out, "source.bin", rc=16)
    assert out.read_bytes() == before, "invalid deletion altered input"
    run(ZIP, "-d", out, "dup-deflate.bin")
    run(UNZIP, "-t", out)
    run(ZIP, "-d", out, "tiny-1")
    run(UNZIP, "-t", out)


def test_legacy(base):
    src = base / "legacy_src"
    src.mkdir()
    data = (b"ABCDE FGH IJK\n" * 8000) + bytes(range(256)) * 16
    (src / "source.bin").write_bytes(data)
    (src / "dup.bin").write_bytes(data)
    for cm, lvl, expected in [
        ("shrink", 9, 1),
        ("reduce", 1, 2),
        ("reduce", 3, 3),
        ("reduce", 5, 4),
        ("reduce", 9, 5),
        ("implode", 9, 6),
        ("dcl-implode", 9, 10),
    ]:
        archive = base / f"{cm}-{lvl}.zip"
        out = base / f"{cm}-{lvl}-dedup.zip"
        run(
            ZIP,
            "-q",
            "-Z",
            cm,
            "-" + str(lvl),
            archive,
            src / "source.bin",
        )
        # Avoid path-prefix differences: use cwd relative paths in ZIP.
        # The archive has a single source; its exact name is read back.
        run(ZIP, "-q", "-0", archive, src / "dup.bin")
        with zipfile.ZipFile(archive) as z:
            orig = z.infolist()
            assert orig[0].compress_type == expected
            one, two = orig[0].filename, orig[1].filename
        run(TOOL, archive, out)
        check_rewrite(archive, out, [one], {two: one})


def test_zip64_and_fwkcs(base):
    src = base / "force-local-zip64.zip"
    out = base / "zip64-refptr.zip"
    data = bytes(random.Random(50).randbytes(48000))
    # Intentionally force 64-bit local sizes for small files; their compressed
    # data are still ordinary Stored data and must remain bit-exact.
    extra = struct.pack("<HH", 0x4B46, 19) + b"MD5" + hashlib.md5(data).digest()
    with zipfile.ZipFile(src, "w", allowZip64=True) as z:
        for name in ("z64-source.bin", "z64-reference.bin"):
            zi = zipfile.ZipInfo(name)
            zi.extra = extra
            with z.open(zi, "w", force_zip64=True) as f:
                f.write(data)
    run(TOOL, src, out)
    check_rewrite(src, out, ["z64-source.bin"], {"z64-reference.bin": "z64-source.bin"})
    for name in ("z64-source.bin", "z64-reference.bin"):
        assert zipfile.ZipFile(out).getinfo(name).extract_version >= 45


def test_zip64_end(base):
    original = base / "plain.zip"
    make_test_zip(original)
    src = original.read_bytes()
    at = src.rfind(b"PK\x05\x06")
    assert at > 0
    entries = struct.unpack_from("<H", src, at + 10)[0]
    cdsize = struct.unpack_from("<I", src, at + 12)[0]
    cdoff = struct.unpack_from("<I", src, at + 16)[0]
    end = bytearray(src[at:])
    z64 = b"PK\x06\x06" + struct.pack(
        "<QHHIIQQQQ", 44, 45, 45, 0, 0, entries, entries, cdsize, cdoff
    )
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, at, 1)
    struct.pack_into("<HHII", end, 8, 65535, 65535, 0xFFFFFFFF, 0xFFFFFFFF)
    inputname = base / "eocd64.zip"
    output = base / "eocd64-out.zip"
    inputname.write_bytes(src[:at] + z64 + locator + end)
    assert len(zipfile.ZipFile(inputname).infolist()) == entries
    run(TOOL, inputname, output)
    check_rewrite(
        inputname,
        output,
        ["source.bin", "source.txt"],
        {
            "dup-deflate.bin": "source.bin",
            "dup-store.bin": "source.bin",
            "dup.txt": "source.txt",
        },
    )


def test_add_to_winzip_group(base):
    src = ROOT.parent / "1.zip"
    if not src.exists():
        return
    local = base / "wzexisting.zip"
    shutil.copyfile(src, local)
    data = zipfile.ZipFile(src).read("Group-A/00_source.bin")
    new = base / "thirdcopy.bin"
    new.write_bytes(data)
    run(ZIP, "-q", "-j", "-0", local, new)
    out = base / "wzextended.zip"
    run(TOOL, local, out)
    check_rewrite(
        local,
        out,
        ["Group-A/00_source.bin", "Group-B/00_source.txt"],
        {"thirdcopy.bin": "Group-A/00_source.bin"},
    )


def test_more_codecs(base):
    src = base / "morecodecs"
    src.mkdir()
    data = b"New ZIP codec compatibility\n" * 16000
    (src / "source.bin").write_bytes(data)
    (src / "duplicate.bin").write_bytes(data)
    for cm, method in [
        ("deflate64", 9),
        ("bzip2", 12),
        ("lzma", 14),
        ("zstd", 93),
        ("xz", 95),
        ("ppmd", 98),
    ]:
        inp = base / (cm + "-source.zip")
        out = base / (cm + "-out.zip")
        run(ZIP, "-q", "-Z", cm, "-9", inp, src / "source.bin")
        run(ZIP, "-q", "-0", inp, src / "duplicate.bin")
        with zipfile.ZipFile(inp) as z:
            one, two = z.infolist()
            assert one.compress_type == method
        run(TOOL, inp, out)
        check_rewrite(inp, out, [one.filename], {two.filename: one.filename})


def test_descriptor(base):
    class Nonseek(io.BytesIO):
        def seek(self, *args):
            raise OSError("no seek")

    data = b"descriptor: example\n" * 6000
    sink = Nonseek()
    with zipfile.ZipFile(sink, "w") as z:
        for name in ("a", "b"):
            z.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
    src = base / "descriptor.zip"
    out = base / "descriptor-out.zip"
    src.write_bytes(sink.getvalue())
    with zipfile.ZipFile(src) as z:
        assert z.infolist()[0].flag_bits & 8
        assert z.infolist()[1].flag_bits & 8
    run(TOOL, src, out)
    check_rewrite(src, out, ["a"], {"b": "a"})
    with zipfile.ZipFile(out) as z:
        assert (z.getinfo("b").flag_bits & 8) == 0


def test_rejections(base):
    src = base / "bad.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("x", "abcdefgh" * 200)
        z.writestr("y", "abcdefgh" * 200)
    ordinary = src.read_bytes()
    for typ in ["encrypted", "pkav", "digital", "split"]:
        b = bytearray(ordinary)
        if typ == "encrypted":
            # Both local and central flags changed. Must reject before hash.
            pos = b.find(b"PK\x03\x04")
            struct.pack_into("<H", b, pos + 6, 1)
            pos = b.find(b"PK\x01\x02")
            struct.pack_into("<H", b, pos + 8, 1)
        elif typ == "pkav":
            with zipfile.ZipFile(src, "w") as z:
                info = zipfile.ZipInfo("bad")
                info.extra = b"\x07\x00\x00\x00"
                z.writestr(info, "test")
            b = bytearray(src.read_bytes())
            src.write_bytes(ordinary)
        elif typ == "split":
            pos = b.rfind(b"PK\x05\x06")
            struct.pack_into("<H", b, pos + 4, 1)
        else:
            pos = b.rfind(b"PK\x05\x06")
            sig = b"PK\x05\x05\x00\x00"
            csize = struct.unpack_from("<I", b, pos + 12)[0]
            b[pos + 12 : pos + 16] = struct.pack("<I", csize + len(sig))
            b[pos:pos] = sig
        file = base / (typ + ".zip")
        file.write_bytes(b)
        out = base / (typ + "-out.zip")
        run(TOOL, file, out, rc=1)
        assert not out.exists() and file.read_bytes() == bytes(b)


def test_real_winzip(base):
    for name in ("1.zip", "2.zip", "testwv(1).zip"):
        p = ROOT.parent / name
        if p.exists():
            out = base / (name + ".copy")
            run(TOOL, p, out)
            assert p.read_bytes() == out.read_bytes(), name


def main():
    assert TOOL.exists() and ZIP.exists() and UNZIP.exists()
    with tempfile.TemporaryDirectory(prefix="zipdedup-regression-") as td:
        base = pathlib.Path(td)
        test_normal(base)
        print(
            "PASS: Store/Deflate, SHA-1, metadata, net savings, idempotence, Zip guard"
        )
        test_zip64_and_fwkcs(base)
        print("PASS: ZIP64 local sizes and FWKCS MD5")
        test_zip64_end(base)
        print("PASS: ZIP64 EOCD/locator")
        test_descriptor(base)
        print("PASS: data descriptors")
        test_legacy(base)
        print("PASS: Shrink, Reduce 2-5, Implode, DCL Implode")
        test_more_codecs(base)
        print("PASS: Deflate64, BZip2, LZMA, Zstandard, XZ, PPMd")
        test_add_to_winzip_group(base)
        print("PASS: extending existing WinZip RefPtr groups")
        test_rejections(base)
        print("PASS: authentication/encryption/split input rejection")
        test_real_winzip(base)
        print("PASS: authentic WinZip archive idempotence (when fixtures supplied)")
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
