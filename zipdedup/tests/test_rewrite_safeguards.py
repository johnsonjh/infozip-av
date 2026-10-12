#!/usr/bin/env python3
"""Standalone regression checks for the new zipdedup safeguarding policy."""

import hashlib
import os
import pathlib
import random
import struct
import subprocess
import tempfile
import zipfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = pathlib.Path(os.environ.get("ZD_TEST_TOOL", str(ROOT / "zipdedup/zipdedup")))
UNZIP = pathlib.Path(os.environ.get("ZD_TEST_UNZIP", str(ROOT / "unzip60/unzip")))
assert TOOL.exists() and UNZIP.exists()
checks = 0


def run(*args, expected=0, contains=None):
    global checks
    p = subprocess.run([str(a) for a in args], capture_output=True, timeout=20)
    assert p.returncode == expected, (
        args,
        p.returncode,
        p.stdout[-1000:],
        p.stderr[-2000:],
    )
    if contains is not None:
        assert contains.encode() in p.stderr, (args, contains, p.stderr)
    checks += 1
    return p


rnd = random.Random(1234)
DATA = rnd.randbytes(38000)


def make_zip(
    p,
    alignment=None,
    target="source.bin",
    no_dup=False,
    malformed=False,
    apache_flag=False,
):
    with zipfile.ZipFile(p, "w", allowZip64=True) as z:
        for name, data in (
            [("source.bin", DATA)]
            + ([] if no_dup else [("duplicate.bin", DATA)])
            + [("tail.bin", b"other" * 100)]
        ):
            zi = zipfile.ZipInfo(name, (2026, 10, 12, 10, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            if alignment is not None and name == target:
                tag, multiple = alignment
                if malformed:
                    payload = b"\x01"
                else:
                    val = multiple | (0x8000 if tag == 0xA11E and apache_flag else 0)
                    x = 2 + ((-z.fp.tell() - 30 - len(name) - 6) % multiple)
                    payload = struct.pack("<H", val) + b"\0" * (x - 2)
                zi.extra = struct.pack("<HH", tag, len(payload)) + payload
            z.writestr(zi, data)


def add_apk(p, malformed=False, bad_pair=False):
    b = bytearray(p.read_bytes())
    off = b.rfind(b"PK\x05\x06")
    assert off >= 0
    old = struct.unpack_from("<I", b, off + 16)[0]
    pair = struct.pack("<QI", 100000 if bad_pair else 6, 0x7109871A) + b"AB"
    size = 24 + len(pair)
    block = (
        struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    )
    if malformed:
        block = b"\0" * 8 + block[8:]
    b[old:old] = block
    struct.pack_into("<I", b, off + len(block) + 16, old + len(block))
    p.write_bytes(b)


with tempfile.TemporaryDirectory() as t:
    base = pathlib.Path(t)
    ordinary = base / "ordinary.zip"
    make_zip(ordinary)
    run(TOOL, "--dry-run", ordinary, base / "invalid.zip", expected=2)
    run(TOOL, ordinary, base / "ordinary.out.zip")
    run(UNZIP, "-tqq", base / "ordinary.out.zip")
    run(TOOL, "--force", ordinary, base / "force.out.zip")
    assert (base / "ordinary.out.zip").read_bytes() != ordinary.read_bytes()
    run(UNZIP, "-tqq", base / "force.out.zip")

    signed = base / "signed.zip"
    make_zip(signed)
    add_apk(signed)
    run(UNZIP, "-tqq", signed)
    run(
        TOOL,
        signed,
        base / "signed.reject.zip",
        expected=1,
        contains="APK Signing Block",
    )
    assert not (base / "signed.reject.zip").exists()
    run(
        TOOL,
        "--quiet",
        "--force",
        signed,
        base / "signed.force.zip",
        contains="APK Signing Block",
    )
    run(UNZIP, "-tqq", base / "signed.force.zip")
    malformed = base / "malformed.apk"
    make_zip(malformed)
    add_apk(malformed, True)
    run(
        TOOL,
        malformed,
        base / "malformed.reject.zip",
        expected=1,
        contains="malformed envelope",
    )
    run(
        TOOL,
        "--force",
        malformed,
        base / "malformed.force.zip",
        contains="malformed envelope",
    )
    badpair = base / "bad-pair.apk"
    make_zip(badpair)
    add_apk(badpair, bad_pair=True)
    run(
        TOOL,
        badpair,
        base / "bad-pair.reject.zip",
        expected=1,
        contains="malformed envelope",
    )
    run(
        TOOL,
        "--force",
        badpair,
        base / "bad-pair.force.zip",
        contains="malformed envelope",
    )

    for key in [(0xD935, 8), (0xA11E, 8)]:
        # Only first member constrained: the data start never changes.
        q = base / f"first-{key[0]}.zip"
        make_zip(q, key)
        run(TOOL, q, base / f"first-{key[0]}.out.zip")
        run(UNZIP, "-tqq", base / f"first-{key[0]}.out.zip")
        # Third member shifts if second (duplicate) is de-duplicated.
        q = base / f"tail-{key[0]}.zip"
        make_zip(q, key, target="tail.bin")
        r = run(
            TOOL, q, base / f"tail-{key[0]}.out.zip", expected=1, contains="alignment"
        )
        assert not (base / f"tail-{key[0]}.out.zip").exists()
        run(
            TOOL,
            "--force",
            "--quiet",
            q,
            base / f"tail-{key[0]}.forced.zip",
            contains="alignment",
        )
        run(UNZIP, "-tqq", base / f"tail-{key[0]}.forced.zip")
        q = base / f"malformed-{key[0]}.zip"
        make_zip(q, key, target="tail.bin", malformed=True)
        run(
            TOOL,
            q,
            base / f"malformed-{key[0]}.out.zip",
            expected=1,
            contains="alignment",
        )
        run(
            TOOL,
            "--force",
            q,
            base / f"malformed-{key[0]}.forced.zip",
            contains="alignment",
        )
        # No-op always copies exact bytes.
        q = base / f"noop-{key[0]}.zip"
        make_zip(q, key, target="tail.bin", no_dup=True, malformed=True)
        run(TOOL, q, base / f"noop-{key[0]}.out.zip")
        assert q.read_bytes() == (base / f"noop-{key[0]}.out.zip").read_bytes()

    # Apache's allow-method-change flag is stored in bit 15 and does not
    # change the requested power-of-two alignment.
    flagged = base / "apache-flag.zip"
    make_zip(flagged, (0xA11E, 16), apache_flag=True)
    run(TOOL, flagged, base / "apache-flag.out.zip")
    run(UNZIP, "-tqq", base / "apache-flag.out.zip")

    # Android's format allows a positive non-power-of-two multiple.
    nonpower = base / "android-nonpower.zip"
    make_zip(nonpower, (0xD935, 3))
    run(TOOL, nonpower, base / "android-nonpower.out.zip")
    run(UNZIP, "-tqq", base / "android-nonpower.out.zip")

    noop = base / "signed-noop.zip"
    make_zip(noop, no_dup=True)
    add_apk(noop)
    run(TOOL, noop, base / "signed-noop.out.zip", contains="APK Signing Block")
    assert noop.read_bytes() == (base / "signed-noop.out.zip").read_bytes()
    both = base / "both.zip"
    make_zip(both, (0xD935, 8), target="tail.bin")
    add_apk(both)
    run(TOOL, both, base / "both.fail.zip", expected=1, contains="Signing Block")
    run(TOOL, "--force", both, base / "both.forced.zip", contains="alignment")

    # Force must not override existing encrypted-member refusal.
    enc = bytearray(ordinary.read_bytes())
    for sig, position in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = enc.find(sig)
        assert pos >= 0
        val = struct.unpack_from("<H", enc, pos + position)[0]
        struct.pack_into("<H", enc, pos + position, val | 1)
    encrypted = base / "encrypted.zip"
    encrypted.write_bytes(enc)
    run(
        TOOL,
        "--force",
        encrypted,
        base / "encrypted.out.zip",
        expected=1,
        contains="encrypted",
    )
    assert not (base / "encrypted.out.zip").exists()

print(f"PASS {checks} focused zipdedup invocations + byte-exact no-op checks")
