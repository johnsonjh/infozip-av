#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Real ZIP plaintext-inline -> ZipCrypto companion end-to-end regression."""

import hashlib
import os
import pathlib
import struct
import subprocess
import tempfile
import shutil
import zipfile
from test_zipcloak_xattrs import cloak

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
UNZIP = ROOT / "unzip60/unzip"
checks = 0


def ck(ok, msg):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(msg)


def run(args, cwd, success=True):
    p = subprocess.run(list(map(str, args)), cwd=cwd, capture_output=True, timeout=50)
    ck(
        (p.returncode == 0) == success,
        "%r: %s %s" % (args, p.stdout[-250:], p.stderr[-400:]),
    )
    return p


def xfields(blob):
    at = 0
    while at < len(blob):
        ck(len(blob) - at >= 4, "extra field header valid")
        kind, length = struct.unpack_from("<HH", blob, at)
        ck(at + 4 + length <= len(blob), "extra field length valid")
        yield kind, blob[at + 4 : at + 4 + length]
        at += 4 + length


def case(root, tag, fw=False, count=1):
    d = root / tag
    d.mkdir()
    expected = {}
    for i in range(count):
        name = "owner%d.bin" % i
        (d / name).write_bytes((b"owner-binary-%d\x00" % i) * 120)
        value = bytes([i + 1, 0, 255]) + b"XYZ" * (400 + i)
        os.setxattr(d / name, "user.identity", value)
        os.setxattr(d / name, "user.empty", b"")
        expected[name] = value
    argv = (
        [ZIP, "--xattrs"]
        + (["--fwkcs"] if fw else [])
        + ["source.zip"]
        + list(expected)
    )
    run(argv, d)
    with zipfile.ZipFile(d / "source.zip") as z:
        ck(len(z.namelist()) == count, "inline archives only have owners")
        manifests = {}
        owners = {}
        for item in z.infolist():
            ext = dict(xfields(item.extra))[0x5854]
            ck(ext[6] == 1, "owner inline representation")
            manifests[item.filename] = ext[40:]
            owners[item.filename] = ext[8:24]
    before = (d / "source.zip").read_bytes()
    rc, log = cloak(d, ["-O", "encrypted.zip", "source.zip"], 2)
    ck(rc == 0, "ZipCloak encrypt inline " + repr(log[-900:]))
    ck((d / "source.zip").read_bytes() == before, "source unchanged")
    with zipfile.ZipFile(d / "encrypted.zip") as z:
        ck(len(z.infolist()) == count * 2, "generated companion per owner")
        comp = {}
        for item in z.infolist():
            ck(item.flag_bits & 1, "all members encrypted")
            if item.filename.startswith("__XTRO_ZIP__/"):
                ck(item.compress_type == 0, "new STORE companion")
                ck(
                    not any(k == 0x4B46 for k, _ in xfields(item.extra)),
                    "no plaintext FWKCS on new encrypted companion",
                )
                comp[item.filename] = z.read(item, pwd=b"secret")
            else:
                ck(
                    z.read(item, pwd=b"secret") == (d / item.filename).read_bytes(),
                    "owner content",
                )
                ext = dict(xfields(item.extra))[0x5854]
                ck(ext[6] == 2 and ext[7] & 1, "encrypted companion envelope")
                ck(len(ext) == 40, "encrypted digest absent from extra")
                if fw:
                    ck(
                        any(k == 0x4B46 for k, _ in xfields(item.extra)),
                        "FWKCS owner preserved",
                    )
        ck(len(comp) == count, "companion count")
        for name, manifest in manifests.items():
            sid = owners[name].hex()
            cname = "__XTRO_ZIP__/x/" + sid + ".xtm"
            ck(cname in comp, "companion association")
            framed = comp[cname]
            ck(framed[:-36] == manifest, "manifest byte exact")
            ck(framed[-36:-32] == b"XTCS", "trailer identifier")
            ck(framed[-32:] == hashlib.sha256(manifest).digest(), "encrypted SHA-256")
    run([UNZIP, "-tq", "-P", "secret", "encrypted.zip"], d)
    (d / "out").mkdir()
    run([UNZIP, "--xattrs", "-o", "-P", "secret", "encrypted.zip", "-d", "out"], d)
    for name, val in expected.items():
        ck(os.getxattr(d / "out" / name, "user.identity") == val, "xattr round trip")
        ck(os.getxattr(d / "out" / name, "user.empty") == b"", "empty xattr round trip")
    ck(not (d / "out/__XTRO_ZIP__").exists(), "companion not extracted")
    # In-place publication must be as coherent as the separate -O path.
    shutil.copyfile(d / "source.zip", d / "inplace.zip")
    rc, log = cloak(d, ["inplace.zip"], 2)
    ck(rc == 0, "in-place inline transition " + repr(log[-350:]))
    with zipfile.ZipFile(d / "inplace.zip") as z:
        ck(len(z.infolist()) == count * 2, "in-place entry count")
        for member in z.infolist():
            ck(member.flag_bits & 1, "in-place encryption flags")
            z.read(member, pwd=b"secret")
    # Corrupt central inline data: no incomplete output may be published.
    bad = bytearray(before)
    marker = bad.rfind(b"XTRO\x01\x00\x01\x00")
    ck(marker >= 0, "central inline envelope found")
    bad[marker + 41] ^= 1
    (d / "corrupted.zip").write_bytes(bad)
    rc, log = cloak(d, ["-O", "corrupt-out.zip", "corrupted.zip"], 2)
    ck(rc != 0, "malformed central inline rejected")
    ck(not (d / "corrupt-out.zip").exists(), "malformed central has no output")
    ck((d / "corrupted.zip").read_bytes() == bad, "corrupt source remains unchanged")
    # Corrupt local-only owner identity: local/central disagreement fails.
    bad = bytearray(before)
    marker = bad.find(b"XTRO\x01\x00\x01\x00")
    ck(marker >= 0, "local inline envelope found")
    bad[marker + 8] ^= 1
    (d / "bad-local.zip").write_bytes(bad)
    rc, log = cloak(d, ["-O", "bad-local-out.zip", "bad-local.zip"], 2)
    ck(rc != 0, "local/central owner mismatch rejected")
    ck(not (d / "bad-local-out.zip").exists(), "local mismatch has no output")


def mixed_case(root):
    d = root / "mixed"
    d.mkdir()
    (d / "small.bin").write_bytes(b"small" * 200)
    (d / "large.bin").write_bytes(b"large" * 200)
    os.setxattr(d / "small.bin", "user.small", b"\x00xyz\xff")
    os.setxattr(d / "large.bin", "user.bigA", b"A" * 34000)
    os.setxattr(d / "large.bin", "user.bigB", b"B" * 34000)
    run([ZIP, "--xattrs", "mixed.zip", "small.bin", "large.bin"], d)
    with zipfile.ZipFile(d / "mixed.zip") as z:
        ck(len(z.infolist()) == 3, "two owners with one existing sidecar")
    rc, log = cloak(d, ["-O", "encrypted.zip", "mixed.zip"], 2)
    ck(rc == 0, "mixed inline/companion transition " + repr(log[-500:]))
    with zipfile.ZipFile(d / "encrypted.zip") as z:
        ck(len(z.infolist()) == 4, "two owners with two encrypted sidecars")
        ck(all(x.flag_bits & 1 for x in z.infolist()), "all mixed members encrypted")
        ck(
            all(
                x.filename.startswith("__XTRO_ZIP__/")
                or dict(xfields(x.extra))[0x5854][6] == 2
                for x in z.infolist()
            ),
            "both owners companion-backed",
        )
    (d / "out").mkdir()
    run([UNZIP, "--xattrs", "-o", "-P", "secret", "encrypted.zip", "-d", "out"], d)
    ck(
        os.getxattr(d / "out/small.bin", "user.small") == b"\x00xyz\xff",
        "small metadata restored",
    )
    ck(
        os.getxattr(d / "out/large.bin", "user.bigA") == b"A" * 34000,
        "first large attribute restored",
    )
    ck(
        os.getxattr(d / "out/large.bin", "user.bigB") == b"B" * 34000,
        "second large attribute restored",
    )


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-inline-", dir="/dev/shm") as root:
        root = pathlib.Path(root)
        case(root, "single")
        case(root, "fwkcs", True)
        case(root, "multi", False, 2)
        mixed_case(root)
    print("ZipCloak inline-to-encrypted companion: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
