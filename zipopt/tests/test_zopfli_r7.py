#!/usr/bin/env python3
"""Independent DEFLATE decoder checks for experimental Kraft-capacity R7.

Requires zipopt/tests/test_zopfli_exact_rle.py from the prerequisite patch.
Compile twice from the same source with and without -DZOPFLI_R7_EXPERIMENTAL.
Uses Python's zlib decoder, not the compressor's own decode routines.
"""

import argparse
import ctypes
import pathlib
import random
import shlex
import subprocess
import tempfile

from test_zopfli_exact_rle import compile_lib, load_lib, compress, samples

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "zip30" / "zopfli.c"


def make(compiler, output, r7):
    cmd = shlex.split(compiler) + [
        "-O2",
        "-fPIC",
        "-shared",
        "-std=c89",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DZOPFLI_EXACT_RLE",
    ]
    if r7:
        cmd.append("-DZOPFLI_R7_EXPERIMENTAL")
    cmd.extend([str(SOURCE), "-lm", "-o", str(output)])
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--samples", type=int, default=120)
    parser.add_argument("--iterations", type=int, default=3)
    args = parser.parse_args()
    wins = 0
    total_savings = 0
    changed = 0
    n = 0
    with tempfile.TemporaryDirectory(prefix="xtro-r7-") as temporary:
        temp = pathlib.Path(temporary)
        before, after = temp / "joint.so", temp / "r7.so"
        make(args.cc, before, False)
        make(args.cc, after, True)
        old, new = load_lib(before), load_lib(after)
        for name, contents in samples(args.samples):
            previous, _ = compress(old, contents, args.iterations)
            optimized, _ = compress(new, contents, args.iterations)
            assert len(optimized) <= len(previous), (
                name,
                len(previous),
                len(optimized),
            )
            n += 1
            changed += previous != optimized
            wins += len(optimized) < len(previous)
            total_savings += len(previous) - len(optimized)
        # Non-final first parts, shared bit-position, then final parts.
        for name, contents in (
            ("multipart-binary", bytes(range(256)) * 120),
            ("multipart-repeats", b"ABBCDD" * 4400),
        ):
            previous, _ = compress(old, contents, 1, len(contents) // 2)
            optimized, _ = compress(new, contents, 1, len(contents) // 2)
            assert len(optimized) <= len(previous), name
            n += 1
        # R7 is only allowed to touch dynamic tree headers.
        for blocktype in (0, 1):
            data = b"ABCA" * 1500
            previous, _ = compress(old, data, 1, blocktype=blocktype)
            optimized, _ = compress(new, data, 1, blocktype=blocktype)
            assert previous == optimized, "non-dynamic block modified"
            n += 1
    print(
        "PASS: %d decoded streams, %d altered, %d smaller, %d bytes saved"
        % (n, changed, wins, total_savings)
    )


if __name__ == "__main__":
    main()
