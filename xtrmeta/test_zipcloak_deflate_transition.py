#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""M6E2D: live Deflate-to-ZipCrypto companion transition regression."""

import os, pathlib, tempfile, subprocess, zipfile, hashlib, zlib, struct
from test_zipcloak_xattrs import cloak

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
CLOAK = ROOT / "zip30/zipcloak"
UNZIP = ROOT / "unzip60/unzip"
checks = 0


def ck(value, description):
    global checks
    checks += 1
    if not value:
        raise AssertionError(description)


def run(argv, cwd, success=True):
    r = subprocess.run([str(s) for s in argv], cwd=cwd, capture_output=True, timeout=30)
    ck(
        (r.returncode == 0) == success,
        repr(argv) + repr(r.stderr[-800:]) + repr(r.stdout[-300:]),
    )
    return r


def fields(extras):
    pos = 0
    while pos < len(extras):
        if pos + 4 > len(extras):
            raise ValueError("truncated extra")
        k, n = struct.unpack_from("<HH", extras, pos)
        pos += 4
        if pos + n > len(extras):
            raise ValueError("truncated value")
        yield k, extras[pos : pos + n]
        pos += n


def trial(root, tag, store_owner=False):
    d = root / tag
    d.mkdir()
    content = (b"correlated-data" * 300) if not store_owner else b"content test" * 210
    (d / "owner.bin").write_bytes(content)
    attrs = {
        b"user.note": b"\0binary\xff",
        b"user.alpha": b"A" * 34000,
        b"user.beta": b"B" * 34000,
    }
    for k, v in attrs.items():
        os.setxattr(d / "owner.bin", k, v)
    argv = (
        [ZIP, "--xattrs"] + (["-0"] if store_owner else []) + ["input.zip", "owner.bin"]
    )
    run(argv, d)
    with zipfile.ZipFile(d / "input.zip") as f:
        own, side = f.infolist()
        ck(side.compress_type == 8, "source Deflate companion")
        ck(own.compress_type == (0 if store_owner else 8), "source owner mode")
        manifest = f.read(side)
        digest = hashlib.sha256(manifest).digest()
        src_extras = (own.extra, side.extra)
    rc, log = cloak(d, ["-O", "encrypted.zip", "input.zip"], 2)
    ck(rc == 0, "ZipCloak Deflate transition " + repr(log[-700:]))
    with zipfile.ZipFile(d / "encrypted.zip") as f:
        own, side = f.infolist()
        ck(own.flag_bits & 1 and side.flag_bits & 1, "both entries encrypted")
        ck(side.compress_type == 8, "Deflate method retained")
        ck(own.compress_type == (0 if store_owner else 8), "owner method retained")
        ck(f.read(own, pwd=b"secret") == content, "owner content")
        framed = f.read(side, pwd=b"secret")
        ck(framed[:-36] == manifest, "manifest byte exact")
        ck(framed[-36:-32] == b"XTCS", "protected trailer magic")
        ck(framed[-32:] == digest, "protected SHA-256 digest")
        ck(
            not any(tag == 0x4B46 for tag, val in fields(side.extra)),
            "no plaintext companion FWKCS",
        )
    run([UNZIP, "-tq", "-P", "secret", "encrypted.zip"], d)
    (d / "restored").mkdir()
    run([UNZIP, "-o", "--xattrs", "-P", "secret", "encrypted.zip", "-d", "restored"], d)
    for key, value in attrs.items():
        ck(
            os.getxattr(d / "restored/owner.bin", key) == value,
            "attribute restored " + repr(key),
        )
    ck((d / "restored/owner.bin").read_bytes() == content, "extracted owner content")
    ck((d / "input.zip").exists(), "original archive retained")
    # In-place publication preserves a valid complete association.
    (d / "inplace.zip").write_bytes((d / "input.zip").read_bytes())
    rc, log = cloak(d, ["inplace.zip"], 2)
    ck(rc == 0, "in-place Deflate transition " + repr(log[-600:]))
    with zipfile.ZipFile(d / "inplace.zip") as f:
        own, side = f.infolist()
        ck(own.flag_bits & 1 and side.flag_bits & 1, "in-place encrypted pair")
        ck(side.compress_type == 8, "in-place Deflate companion")
        ck(f.read(side, pwd=b"secret")[:-36] == manifest, "in-place manifest")
    # Public FWKCS is preserved on the owner, removed from encrypted sidecar.
    # This uses the source FWKCS writer instead of synthetic metadata fields.
    run([ZIP, "--xattrs", "--fwkcs", "fwkcs.zip", "owner.bin"], d)
    with zipfile.ZipFile(d / "fwkcs.zip") as f:
        old_owner, old_side = f.infolist()
        ck(any(t == 0x4B46 for t, v in fields(old_owner.extra)), "FWKCS owner fixture")
        ck(any(t == 0x4B46 for t, v in fields(old_side.extra)), "FWKCS side fixture")
        digest_fw = hashlib.sha256(f.read(old_side)).digest()
    rc, log = cloak(d, ["-O", "fwkcs-encrypted.zip", "fwkcs.zip"], 2)
    ck(rc == 0, "Deflate FWKCS transition " + repr(log[-600:]))
    with zipfile.ZipFile(d / "fwkcs-encrypted.zip") as f:
        new_owner, new_side = f.infolist()
        ck(
            any(t == 0x4B46 for t, v in fields(new_owner.extra)),
            "owner FWKCS preserved",
        )
        ck(
            not any(t == 0x4B46 for t, v in fields(new_side.extra)),
            "side FWKCS removed",
        )
        ck(f.read(new_side, pwd=b"secret")[-32:] == digest_fw, "FWKCS companion SHA")
    # A broken compressed stream must never be published as encrypted Xtro.
    original = (d / "input.zip").read_bytes()
    with zipfile.ZipFile(d / "input.zip") as f:
        side = f.infolist()[1]
        hdr = side.header_offset
        n, e = struct.unpack_from("<HH", original, hdr + 26)
        payload_offset = hdr + 30 + n + e
    damaged = bytearray(original)
    damaged[payload_offset + side.compress_size // 2] ^= 0x80
    (d / "corrupted.zip").write_bytes(damaged)
    rc, log = cloak(d, ["-O", "bad-out.zip", "corrupted.zip"], 2)
    ck(rc != 0, "compressed-data corruption rejected")
    ck(not (d / "bad-out.zip").exists(), "no corrupted metadata publication")
    ck((d / "corrupted.zip").read_bytes() == damaged, "corrupted input preserved")
    # The source ZIP CRC must be checked before accepting the new footer.
    damaged = bytearray(original)
    cpos = damaged.rfind(b"PK\x01\x02")
    ck(cpos >= 0, "central directory found")
    struct.pack_into("<I", damaged, cpos + 16, (side.CRC + 1) & 0xFFFFFFFF)
    (d / "bad-crc.zip").write_bytes(damaged)
    rc, log = cloak(d, ["-O", "bad-crc-out.zip", "bad-crc.zip"], 2)
    ck(rc != 0, "source CRC mismatch rejected")
    ck(not (d / "bad-crc-out.zip").exists(), "CRC failure no publication")
    # Supplying an incorrect decoded size must also fail before publication.
    damaged = bytearray(original)
    struct.pack_into("<I", damaged, cpos + 24, side.file_size + 1)
    (d / "bad-size.zip").write_bytes(damaged)
    rc, log = cloak(d, ["-O", "bad-size-out.zip", "bad-size.zip"], 2)
    ck(rc != 0, "decoded-size mismatch rejected")
    ck(not (d / "bad-size-out.zip").exists(), "size failure no publication")
    # Mismatch the Xtro digest while leaving the ordinary ZIP CRCs valid.
    damaged = bytearray(original)
    marker = damaged.rfind(b"XTRO\x01\x00\x02\x00")
    ck(marker >= 0, "central Xtro companion envelope")
    damaged[marker + 40] ^= 0x08
    (d / "bad-sha.zip").write_bytes(damaged)
    rc, log = cloak(d, ["-O", "bad-sha-out.zip", "bad-sha.zip"], 2)
    ck(rc != 0, "Xtro SHA mismatch rejected")
    ck(not (d / "bad-sha-out.zip").exists(), "SHA mismatch no publication")
    # A valid raw Deflate stream with trailing garbage must be rejected.
    raw = zlib.compressobj(level=9, wbits=-15)
    tight = raw.compress(manifest) + raw.flush()
    if len(tight) < side.compress_size:
        damaged = bytearray(original)
        damaged[payload_offset : payload_offset + side.compress_size] = tight + b"X" * (
            side.compress_size - len(tight)
        )
        ck(len(damaged) == len(original), "trailing test length unchanged")
        (d / "trailing.zip").write_bytes(damaged)
        rc, log = cloak(d, ["-O", "trailing-out.zip", "trailing.zip"], 2)
        ck(rc != 0, "Deflate trailing data rejected")
        ck(not (d / "trailing-out.zip").exists(), "trailing data no publication")


def multi_owner(root):
    d = root / "two-owners"
    d.mkdir()
    contents = b"same-owner-data\0" * 120
    for name, value in (("one.bin", b"ONE"), ("two.bin", b"TWO")):
        (d / name).write_bytes(contents)
        os.setxattr(d / name, b"user.identity", value)
        os.setxattr(d / name, b"user.first", value * 11000)
        os.setxattr(d / name, b"user.second", value * 11000)
    run([ZIP, "--xattrs", "multiple.zip", "one.bin", "two.bin"], d)
    with zipfile.ZipFile(d / "multiple.zip") as z:
        ck(len(z.infolist()) == 4, "two owners and two companions")
        ck(
            sum(i.filename.startswith("__XTRO_ZIP__/") for i in z.infolist()) == 2,
            "two independent companions",
        )
        ck(
            all(
                i.compress_type == 8
                for i in z.infolist()
                if i.filename.startswith("__XTRO_ZIP__/")
            ),
            "two Deflate companions",
        )
    rc, log = cloak(d, ["-O", "encrypted.zip", "multiple.zip"], 2)
    ck(rc == 0, "two-owner transition " + repr(log[-700:]))
    with zipfile.ZipFile(d / "encrypted.zip") as z:
        ck(len(z.namelist()) == 4, "two-owner encrypted count")
        for name in z.namelist():
            info = z.getinfo(name)
            ck(info.flag_bits & 1, "two-owner member encrypted " + name)
            ck(bool(z.read(info, pwd=b"secret")), "two-owner payload present")
    (d / "out").mkdir()
    run([UNZIP, "-o", "--xattrs", "-P", "secret", "encrypted.zip", "-d", "out"], d)
    for name, value in (("one.bin", b"ONE"), ("two.bin", b"TWO")):
        ck((d / "out" / name).read_bytes() == contents, "two-owner contents " + name)
        for attr, expected in (
            (b"user.identity", value),
            (b"user.first", value * 11000),
            (b"user.second", value * 11000),
        ):
            ck(
                os.getxattr(d / "out" / name, attr) == expected,
                "two-owner metadata " + name + repr(attr),
            )


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-m6e2d-", dir="/dev/shm") as root:
        root = pathlib.Path(root)
        trial(root, "normal", False)
        trial(root, "store-owner", True)
        multi_owner(root)
    print("M6E2D Deflate ZipCloak live: %d checks passed" % checks)


if __name__ == "__main__":
    main()
