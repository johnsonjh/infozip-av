#!/usr/bin/env python3
"""Zip's internal raw-Deflate adapter: independent zlib format verification."""

import os
import pathlib
import random
import subprocess
import tempfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
CFLAGS = os.environ.get("ZO_PROBE_CFLAGS", "-std=c89 -O2 -Wall -Wextra")
with tempfile.TemporaryDirectory(prefix="zo-internal-deflate-") as tmp:
    tmp = pathlib.Path(tmp)
    exe = tmp / "probe"
    subprocess.run(
        [CC]
        + CFLAGS.split()
        + [
            str(ROOT / "tests/zip_deflate_probe.c"),
            str(ROOT / "zip_deflate.c"),
            "-o",
            str(exe),
        ],
        check=True,
        timeout=60,
    )
    rng = random.Random(100291)
    lengths = [
        0,
        1,
        2,
        3,
        4,
        7,
        16,
        31,
        32,
        63,
        64,
        255,
        256,
        257,
        258,
        259,
        4095,
        4096,
        32767,
        32768,
        32769,
        65535,
        65536,
        65537,
        131072,
    ]
    data_sets = []
    for n in lengths:
        data_sets.append(("random-%d" % n, bytes(rng.getrandbits(8) for _ in range(n))))
        data_sets.append(("repeat-%d" % n, (b"abc123XYZ" * (n // 9 + 1))[:n]))
    data_sets.extend(
        [("zeros-1m", b"\0" * 1048576), ("distinct-256k", bytes(range(256)) * 1024)]
    )
    tests = 0
    for level in range(1, 10):
        for label, data in data_sets:
            source, target = tmp / "input.bin", tmp / "deflated.bin"
            source.write_bytes(data)
            chunk = (1, 7, 257, 4096, 65536)[tests % 5]
            runs = 3 if tests % 13 == 0 else 1
            r = subprocess.run(
                [str(exe), str(level), str(source), str(target), str(chunk), str(runs)],
                capture_output=True,
                timeout=40,
            )
            assert r.returncode == 0, (label, level, r.stderr[-300:])
            raw = target.read_bytes()
            obj = zlib.decompressobj(-15)
            actual = obj.decompress(raw) + obj.flush()
            assert actual == data and obj.eof and not obj.unused_data, (label, level)
            tests += 1
    print("PASS: %d internal Deflate level/size/content/stream tests" % tests)
