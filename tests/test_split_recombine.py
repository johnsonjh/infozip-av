#!/usr/bin/env python3
"""Regression tests for Debian #659535 / #753314 split recombination.

Run from any directory:
    python3 tests/test_split_recombine.py --zip /path/to/zip

Tests exact 16 KiB input-buffer boundaries in all three recombination
modes, streamed and seekable input, stored and deflated data, and a
multi-member archive. Uses no non-standard Python packages.
"""

import argparse
import hashlib
import os
from pathlib import Path
import random
import subprocess
import tempfile
import zipfile


def run(cmd, cwd, data=None):
    p = subprocess.run(
        [str(c) for c in cmd],
        cwd=cwd,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        env=dict(os.environ, LC_ALL="C"),
    )
    if p.returncode != 0:
        raise AssertionError(
            "command %r failed (%s):\n%s"
            % (cmd, p.returncode, p.stdout.decode("utf-8", "replace")[-2500:])
        )
    if b"entry truncated:" in p.stdout or b"zip file empty" in p.stdout:
        raise AssertionError(
            "unexpected truncated or empty archive:\n%s"
            % p.stdout.decode("utf-8", "replace")
        )
    return p


def data_bytes(seed, size):
    r = random.Random(seed)
    return (
        r.randbytes(size)
        if hasattr(r, "randbytes")
        else bytes(r.randrange(256) for _ in range(size))
    )


def verify(archive, expected):
    with zipfile.ZipFile(archive) as z:
        actual = dict((item.filename, z.read(item)) for item in z.infolist())
        assert actual == expected, "contents differ in %s" % archive
        assert z.testzip() is None, "CRC mismatch in %s" % archive


def verify_system_unzip(path):
    try:
        p = subprocess.run(
            ["unzip", "-t", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except FileNotFoundError:
        return
    if p.returncode != 0:
        raise AssertionError(
            "system unzip rejected %s:\n%s"
            % (path, p.stdout.decode("utf-8", "replace"))
        )


def conversions(binary, folder, expected):
    parts = sorted(folder.glob("split.z[0-9]*"))
    assert len(parts) >= 2, "not enough split parts for multi-boundary test"
    original = dict(
        (f.name, hashlib.sha256(f.read_bytes()).digest())
        for f in list(parts) + [folder / "split.zip"]
    )
    count = 0
    for mode in ("-s0", "-F", "-FF"):
        out = folder / (mode.replace("-", "") + ".zip")
        if mode == "-s0":
            cmd = [binary, "-s", "0", "split.zip", "--out", out.name]
        else:
            cmd = [binary, mode, "split.zip", "--out", out.name]
        run(cmd, folder)
        verify(out, expected)
        verify_system_unzip(out)
        count += 1
    new = dict(
        (f.name, hashlib.sha256(f.read_bytes()).digest())
        for f in list(parts) + [folder / "split.zip"]
    )
    assert original == new, "conversion changed source split parts"
    return count


def main(binary):
    total = 0
    with tempfile.TemporaryDirectory(prefix="xtro-split-659535-") as t:
        root = Path(t)
        payload = data_bytes(659535, (1024 * 1024) + 337)
        cases = [
            (size, mode, stream)
            for size in ("64k", "65k", "128k", "256k", "257k", "512k")
            for mode in ("deflate", "store")
            for stream in (True, False)
        ]
        for i, (size, mode, stream) in enumerate(cases):
            work = root / ("case-%02d" % i)
            work.mkdir()
            args = [binary, "-q", "-s", size]
            if mode == "store":
                args.append("-0")
            args += ["split.zip", "-" if stream else "payload.bin"]
            if not stream:
                (work / "payload.bin").write_bytes(payload)
            run(args, work, payload if stream else None)
            total += conversions(
                binary, work, {"-" if stream else "payload.bin": payload}
            )
        multi = root / "multiple"
        multi.mkdir()
        first = data_bytes(12, 800000)
        second = data_bytes(13, 800000)
        (multi / "first.bin").write_bytes(first)
        (multi / "second.bin").write_bytes(second)
        run([binary, "-q", "-s", "256k", "split.zip", "first.bin", "second.bin"], multi)
        total += conversions(binary, multi, {"first.bin": first, "second.bin": second})
    print(
        "PASS: %d split-to-single conversions (24 boundary scenarios and"
        " one multi-member scenario)" % total
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, type=lambda v: Path(v).resolve())
    args = parser.parse_args()
    main(args.zip)
