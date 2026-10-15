#!/usr/bin/env python3
"""MIT-0. Independent ZIP container, Deflate, ZipCrypto, FWKCS regression.

Standalone M1 test only: this script rewrites small fixture archive headers,
NOT production Xtro-ZIP integration, and NOT an archive transformer.
"""

from __future__ import annotations
import hashlib
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
assert shutil.which("zip") and shutil.which("unzip")


def run(*args, cwd=None):
    result = subprocess.run(
        args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode:
        raise AssertionError((args, result.returncode, result.stdout, result.stderr))
    return result


def extra(field_id: int, payload: bytes):
    return struct.pack("<HH", field_id, len(payload)) + payload


def rewrite_headers(
    raw: bytes,
    owner_name: bytes,
    companion_name: bytes,
    local_extra: bytes,
    central_extra: bytes,
    password: bytes | None,
    skip_fwkcs: bool = False,
):
    """Fixture-only byte preserving ZIP header rewriter; no payload recompression.

    Preserves encrypted compressed member bytes and data descriptors. Only
    supports simple seekable 2-member non-ZIP64 archives for test purposes.
    """
    end = raw.rfind(b"PK\x05\x06")
    assert end >= 0
    signature, disk, disk_cd, here, count, cdlen, cdoff, cmt = struct.unpack_from(
        "<IHHHHIIH", raw, end
    )
    assert (
        signature == 0x06054B50
        and disk == disk_cd == 0
        and here == count == 2
        and cmt == 0
    )
    central_entries = []
    at = cdoff
    for _ in range(count):
        prefix = raw[at : at + 46]
        assert len(prefix) == 46 and prefix[:4] == b"PK\x01\x02"
        nl, el, cl = struct.unpack_from("<HHH", prefix, 28)
        name = raw[at + 46 : at + 46 + nl]
        old_extra = raw[at + 46 + nl : at + 46 + nl + el]
        comment = raw[at + 46 + nl + el : at + 46 + nl + el + cl]
        offset = struct.unpack_from("<I", prefix, 42)[0]
        central_entries.append((prefix, name, old_extra, comment, offset))
        at += 46 + nl + el + cl
    assert at == cdoff + cdlen
    names = [row[1] for row in central_entries]
    assert set(names) == {owner_name, companion_name}
    offsets = sorted(row[4] for row in central_entries)
    out = bytearray()
    new_offsets = {}
    for offset in offsets:
        row = next(row for row in central_entries if row[4] == offset)
        name = row[1]
        local_prefix = raw[offset : offset + 30]
        assert local_prefix[:4] == b"PK\x03\x04"
        nl, el = struct.unpack_from("<HH", local_prefix, 26)
        local_name = raw[offset + 30 : offset + 30 + nl]
        assert name == local_name
        old_local_extra = raw[offset + 30 + nl : offset + 30 + nl + el]
        data_start = offset + 30 + nl + el
        next_offset = next((x for x in offsets if x > offset), cdoff)
        data = raw[data_start:next_offset]
        new_local_extra = old_local_extra + (
            extra(0x5854, local_extra) if name == owner_name else b""
        )
        assert len(new_local_extra) <= 65535
        new_offsets[name] = len(out)
        out += local_prefix[:28] + struct.pack("<H", len(new_local_extra))
        out += name + new_local_extra + data
    new_cd_off = len(out)
    for prefix, name, old_central_extra, comment, _ in central_entries:
        more = extra(0x5854, central_extra) if name == owner_name else b""
        # The independent AES transport tests do not need FWKCS values;
        # their payload hashes are checked by the ZIP layer separately.
        if not skip_fwkcs:
            payload = read_member(raw, name, password)
            # FWKCS generated for the owner regardless of encryption; for
            # a companion only when its metadata is publicly stored.
            if name == owner_name or password is None:
                more += extra(0x4B46, b"MD5" + hashlib.md5(payload).digest())
        new_extra = old_central_extra + more
        assert len(new_extra) <= 65535
        fixed = bytearray(prefix)
        struct.pack_into("<H", fixed, 30, len(new_extra))
        struct.pack_into("<I", fixed, 42, new_offsets[name])
        out += fixed + name + new_extra + comment
    new_cd_len = len(out) - new_cd_off
    out += struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, count, count, new_cd_len, new_cd_off, 0
    )
    return bytes(out)


def read_member(zip_bytes: bytes, name: bytes, password: bytes | None):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        return z.read(name.decode("ascii"), pwd=password)


def extras(data: bytes):
    at = 0
    while at < len(data):
        assert len(data) - at >= 4
        tag, n = struct.unpack_from("<HH", data, at)
        at += 4
        assert at + n <= len(data)
        yield tag, data[at : at + n]
        at += n


def fixture(encrypted: bool, base: Path):
    work = base / ("crypt" if encrypted else "plain")
    work.mkdir()
    mode = "encrypted" if encrypted else "plain"
    run(str(ROOT / "emit_fixture"), str(work), mode)
    original_owner = (work / "owner.dat").read_bytes()
    original_manifest = (work / "manifest.xtm").read_bytes()
    expected_name = (work / "companion_name.txt").read_text()
    (work / expected_name).parent.mkdir(parents=True)
    (work / expected_name).write_bytes(original_manifest)
    local = (work / "local_xtr.bin").read_bytes()
    central = (work / "central_xtr.bin").read_bytes()
    args = ["zip", "-q", "-9", "-D"]
    if encrypted:
        args.extend(["-P", "test-password"])
    args.extend(["input.zip", "owner.dat", expected_name])
    run(*args, cwd=work)
    before = (work / "input.zip").read_bytes()
    pwd = b"test-password" if encrypted else None
    after = rewrite_headers(
        before, b"owner.dat", expected_name.encode(), local, central, pwd
    )
    archive = work / "xtro-fixture.zip"
    archive.write_bytes(after)
    run("unzip", "-P", "test-password", "-tqq", str(archive))
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None if not encrypted else True
        assert z.namelist() == ["owner.dat", expected_name]
        assert z.read("owner.dat", pwd=pwd) == original_owner
        assert z.read(expected_name, pwd=pwd) == original_manifest
        assert all(
            z.getinfo(item).flag_bits & 1 == int(encrypted) for item in z.namelist()
        )
        assert z.getinfo(expected_name).compress_type == zipfile.ZIP_DEFLATED
        assert any(
            t == 0x5854 and v == central
            for t, v in extras(z.getinfo("owner.dat").extra)
        )
        owner_fw = [v for t, v in extras(z.getinfo("owner.dat").extra) if t == 0x4B46]
        assert owner_fw == [b"MD5" + hashlib.md5(original_owner).digest()]
        companion_fw = [
            v for t, v in extras(z.getinfo(expected_name).extra) if t == 0x4B46
        ]
        assert companion_fw == (
            [] if encrypted else [b"MD5" + hashlib.md5(original_manifest).digest()]
        )
        assert b"XTRO" not in z.getinfo(expected_name).extra
        assert b"MD5" not in local
        if encrypted:
            assert central == local and central[24:40] == b"\x00" * 16
            assert original_manifest[-36:-32] == b"XTCS"
            assert (
                original_manifest[-32:]
                == hashlib.sha256(original_manifest[:-36]).digest()
            )
            assert (
                original_manifest[72 : 72 + 12] not in after
            )  # value segment isn't stored plaintext
        else:
            assert central[-32:] == hashlib.sha256(original_manifest).digest()
            assert z.getinfo(expected_name).CRC == zlib.crc32(original_manifest)
        # Both modes verify independently in the new C89 parser after ZIP decoding.
        check = run(
            str(ROOT / "verify_fixture"),
            str(work / "manifest.xtm"),
            str(work / "local_xtr.bin"),
            str(work / "central_xtr.bin"),
        )
        print(mode, len(after), "bytes", check.stdout.decode().strip())
    return archive


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-v1-") as d:
        folder = Path(d)
        p = fixture(False, folder)
        e = fixture(True, folder)
        # Plain ZIP can be rewritten using a *generic* third-party library,
        # but generic rewrites do not promise to preserve Xtro associations.
        with zipfile.ZipFile(p) as inp, zipfile.ZipFile(
            folder / "foreign-rewrite.zip", "w"
        ) as out:
            for info in inp.infolist():
                out.writestr(info, inp.read(info), compress_type=info.compress_type)
        with zipfile.ZipFile(folder / "foreign-rewrite.zip") as z:
            assert z.read("owner.dat") == (folder / "plain" / "owner.dat").read_bytes()
            assert (
                z.read((folder / "plain" / "companion_name.txt").read_text())
                == (folder / "plain" / "manifest.xtm").read_bytes()
            )
            owner = z.getinfo("owner.dat")
            raw = (folder / "foreign-rewrite.zip").read_bytes()
            local_pos = owner.header_offset
            ln, el = struct.unpack_from("<HH", raw, local_pos + 26)
            local_fields = list(
                extras(raw[local_pos + 30 + ln : local_pos + 30 + ln + el])
            )
            local_xtro = [v for typ, v in local_fields if typ == 0x5854]
            central_xtro = [v for typ, v in extras(owner.extra) if typ == 0x5854]
            # Generic rewriters can copy the longer central field into the
            # local header. The M1 strict checker must reject that mismatch.
            assert local_xtro == central_xtro and len(local_xtro[0]) == 72
            assert len((folder / "plain" / "local_xtr.bin").read_bytes()) == 40
        assert e.exists()
    print("ZIP Deflate, ZipCrypto, FWKCS, header-interoperability fixtures passed")


if __name__ == "__main__":
    main()
