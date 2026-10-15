#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""End-to-end narrow ZipCloak public STORE companion -> ZipCrypto transition."""

import os, pathlib, tempfile, struct, zlib, zipfile, subprocess, hashlib
from test_zipcloak_xattrs import cloak

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
CLOAK = ROOT / "zip30/zipcloak"
UNZIP = ROOT / "unzip60/unzip"
checks = 0


def ck(ok, msg):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(msg)


def put16(x):
    return struct.pack("<H", x)


def put32(x):
    return struct.pack("<I", x)


def fields(extra):
    i = 0
    while i < len(extra):
        tag, n = struct.unpack_from("<HH", extra, i)
        yield tag, extra[i + 4 : i + 4 + n]
        i += 4 + n
    assert i == len(extra)


def make_store_fixture(raw, new, fwkcs=False):
    """Build a minimal standards-compliant ZIP, with Xtro's required distinct
    local and central extra fields. The archive contains two STORE members."""
    with zipfile.ZipFile(raw) as z:
        owner, side = z.infolist()
        assert owner.filename == "owner.bin" and side.filename.startswith(
            "__XTRO_ZIP__/"
        )
        payload = z.read(owner)
        manifest = z.read(side)
        cx = next(v for k, v in fields(owner.extra) if k == 0x5854)
        assert len(cx) == 72 and cx[:4] == b"XTRO"
        localx = put16(0x5854) + put16(40) + cx[:40]
        centralx = put16(0x5854) + put16(72) + cx
    out = bytearray()
    cen = bytearray()
    if fwkcs:
        side_fwkcs = put16(0x4B46) + put16(19) + b"MD5" + hashlib.md5(manifest).digest()
        owner_fwkcs = put16(0x4B46) + put16(19) + b"MD5" + hashlib.md5(payload).digest()
    else:
        side_fwkcs = b""
        owner_fwkcs = b""
    for name, content, lex, cex in (
        (b"owner.bin", payload, localx, centralx + owner_fwkcs),
        (side.filename.encode(), manifest, b"", side_fwkcs),
    ):
        crc = zlib.crc32(content) & 0xFFFFFFFF
        at = len(out)
        out += b"PK\x03\x04" + struct.pack(
            "<HHHHHIIIHH",
            20,
            0,
            0,
            0,
            0,
            crc,
            len(content),
            len(content),
            len(name),
            len(lex),
        )
        out += name + lex + content
        cen += b"PK\x01\x02" + struct.pack(
            "<HHHHHHIIIHHHHHII",
            0x0314,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(content),
            len(content),
            len(name),
            len(cex),
            0,
            0,
            0,
            0o100644 << 16,
            at,
        )
        cen += name + cex
    start = len(out)
    out += cen
    out += b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 2, 2, len(cen), start, 0)
    new.write_bytes(out)
    with zipfile.ZipFile(new) as z:
        ck(len(z.infolist()) == 2, "fixture members")
        ck(z.testzip() is None, "fixture crc")
        ck(z.read(z.infolist()[1]) == manifest, "fixture manifest")
    return manifest


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-cloak-store-", dir="/dev/shm") as t:
        d = pathlib.Path(t)
        (d / "owner.bin").write_bytes(b"owner data\x00" * 190)
        os.setxattr(d / "owner.bin", b"user.marker", b"\x00binary\xff")
        os.setxattr(d / "owner.bin", b"user.big", b"A" * 35000)
        os.setxattr(d / "owner.bin", b"user.big2", b"B" * 35000)
        p = subprocess.run(
            [str(ZIP), "--xattrs", "source.zip", "owner.bin"],
            cwd=d,
            capture_output=True,
        )
        ck(p.returncode == 0, "source writer " + repr(p.stderr[-300:]))
        manifest = make_store_fixture(d / "source.zip", d / "store.zip")
        ck(len(manifest) > 65535, "fixture large metadata")
        p = subprocess.run([str(UNZIP), "-tq", "store.zip"], cwd=d, capture_output=True)
        ck(p.returncode == 0, "source extractability " + repr(p.stderr[-300:]))
        original = (d / "store.zip").read_bytes()
        rc, log = cloak(d, ["-O", "encrypted.zip", "store.zip"], 2)
        ck(rc == 0, "zipcloak success %r" % log[-900:])
        ck((d / "store.zip").read_bytes() == original, "source not modified")
        with zipfile.ZipFile(d / "encrypted.zip") as z:
            own, side = z.infolist()
            ck(own.flag_bits & 1, "owner encryption bit")
            ck(side.flag_bits & 1, "side encryption bit")
            ck(side.compress_type == 0, "STORE preserved")
            field = next(v for k, v in fields(own.extra) if k == 0x5854)
            ck(len(field) == 40 and field[7] & 1, "central encrypted no SHA")
            ck(not any(k == 0x4B46 for k, v in fields(side.extra)), "no FWKCS")
            m = z.read(side, pwd=b"secret")
            ck(m[:-36] == manifest, "manifest preserved")
            ck(m[-36:-32] == b"XTCS", "encrypted footer")
            ck(m[-32:] == hashlib.sha256(manifest).digest(), "encrypted SHA")
            ck(
                z.read(own, pwd=b"secret") == (d / "owner.bin").read_bytes(),
                "owner content",
            )
        p = subprocess.run(
            [str(UNZIP), "-tq", "-P", "secret", "encrypted.zip"],
            cwd=d,
            capture_output=True,
        )
        ck(
            p.returncode == 0,
            "UnZip integrity " + repr(p.stderr[-600:]) + repr(p.stdout[-400:]),
        )
        (d / "out").mkdir()
        p = subprocess.run(
            [
                str(UNZIP),
                "-o",
                "--xattrs",
                "-P",
                "secret",
                "encrypted.zip",
                "-d",
                "out",
            ],
            cwd=d,
            capture_output=True,
        )
        ck(
            p.returncode == 0,
            "UnZip native metadata restore "
            + repr(p.stderr[-600:])
            + repr(p.stdout[-400:]),
        )
        for attr in (b"user.marker", b"user.big", b"user.big2"):
            ck(
                os.getxattr(d / "out/owner.bin", attr)
                == os.getxattr(d / "owner.bin", attr),
                "xattr equality " + str(attr),
            )
        # The FWKCS extra field of a public metadata companion must not
        # disclose an MD5 fingerprint after it becomes encrypted.
        # In-place ZipCloak publication must also yield a valid complete pair.
        (d / "inplace.zip").write_bytes(original)
        rc, log = cloak(d, ["inplace.zip"], 2)
        ck(rc == 0, "in-place archive encryption succeeds " + repr(log[-400:]))
        with zipfile.ZipFile(d / "inplace.zip") as iz:
            own, side = iz.infolist()
            ck(
                (own.flag_bits & 1) != 0 and (side.flag_bits & 1) != 0,
                "in-place owner/companion both encrypted",
            )
            ck(
                iz.read(side, pwd=b"secret")[:-36] == manifest,
                "in-place encrypted metadata exact",
            )
        make_store_fixture(d / "source.zip", d / "store-md5.zip", fwkcs=True)
        rc, log = cloak(d, ["-O", "encrypted-md5.zip", "store-md5.zip"], 2)
        ck(rc == 0, "public FWKCS companion transformed %r" % log[-600:])
        with zipfile.ZipFile(d / "encrypted-md5.zip") as z:
            own, side = z.infolist()
            ck(
                any(
                    k == 0x4B46
                    and v
                    == b"MD5" + hashlib.md5((d / "owner.bin").read_bytes()).digest()
                    for k, v in fields(own.extra)
                ),
                "owner FWKCS remains correct",
            )
            ck(
                not any(k == 0x4B46 for k, v in fields(side.extra)),
                "companion FWKCS removed after encryption",
            )
            ck(
                z.read(z.infolist()[1], pwd=b"secret")[-32:]
                == hashlib.sha256(manifest).digest(),
                "encrypted companion digest unchanged with old FWKCS",
            )
        # Corrupt the central-directory SHA without changing ZIP CRCs.
        # The two-pass C89 verifier must reject it before publication.
        corrupted = bytearray(original)
        offset = corrupted.rfind(b"XTRO\x01\0\x02\0")
        ck(offset >= 0, "central Xtro found for negative test")
        corrupted[offset + 40] ^= 1
        (d / "bad-sha.zip").write_bytes(corrupted)
        before = (d / "bad-sha.zip").read_bytes()
        rc, log = cloak(d, ["-O", "bad-output.zip", "bad-sha.zip"], 2)
        ck(rc != 0, "corrupt SHA rejected before publication " + repr(log[-500:]))
        ck(not (d / "bad-output.zip").exists(), "no bad SHA archive published")
        ck((d / "bad-sha.zip").read_bytes() == before, "bad SHA source preserved")
        # A local name-length mismatch must be rejected before readlocal(),
        # because the legacy parser otherwise uses the central name length
        # to terminate a buffer allocated for the local name.
        bad = bytearray(original)
        struct.pack_into("<H", bad, 26, 1)
        (d / "bad-local-name.zip").write_bytes(bad)
        rc, log = cloak(d, ["-O", "bad-local-output.zip", "bad-local-name.zip"], 2)
        ck(rc != 0, "local/central name-length mismatch rejected")
        ck(not (d / "bad-local-output.zip").exists(), "no bad local output")
        # The normal Deflate companion is now supported as well; test its
        # end-to-end transition here rather than expecting preflight denial.
        rc, log = cloak(d, ["-O", "deflate-encrypted.zip", "source.zip"], 2)
        ck(rc == 0, "Deflate companion transition now succeeds " + repr(log[-500:]))
        with zipfile.ZipFile(d / "deflate-encrypted.zip") as f:
            owner, companion = f.infolist()
            ck(
                owner.flag_bits & 1 and companion.flag_bits & 1,
                "Deflate owner and companion encrypted",
            )
            ck(companion.compress_type == 8, "Deflate method preserved")
            ck(
                f.read(companion, pwd=b"secret")[:-36] == manifest,
                "Deflate companion manifest preserved",
            )
        (d / "little.bin").write_bytes(b"little")
        os.setxattr(d / "little.bin", b"user.small", b"small")
        p = subprocess.run(
            [str(ZIP), "--xattrs", "inline.zip", "little.bin"],
            cwd=d,
            capture_output=True,
            timeout=20,
        )
        ck(p.returncode == 0, "inline negative fixture created")
        with zipfile.ZipFile(d / "inline.zip") as iz:
            ck(
                len(iz.infolist()) == 1
                and any(
                    k == 0x5854 and v[6] == 1 for k, v in fields(iz.infolist()[0].extra)
                ),
                "fixture really contains an inline Xtro manifest",
            )
        rc, log = cloak(d, ["-O", "inline-encrypted.zip", "inline.zip"], 2)
        ck(rc == 0, "inline transition now supported " + repr(log[-500:]))
        with zipfile.ZipFile(d / "inline-encrypted.zip") as iz:
            ck(len(iz.infolist()) == 2, "inline conversion adds companion")
            owner, companion = iz.infolist()
            ck(
                bool(owner.flag_bits & 1 and companion.flag_bits & 1),
                "inline owner and new companion encrypted",
            )
            ck(
                iz.read(owner, pwd=b"secret") == b"little",
                "inline owner content intact",
            )
            ck(
                iz.read(companion, pwd=b"secret")[-36:-32] == b"XTCS",
                "inline companion protected checksum trailer",
            )
    print("M6E2C live ZipCloak STORE transition: %d checks passed" % checks)


if __name__ == "__main__":
    main()
