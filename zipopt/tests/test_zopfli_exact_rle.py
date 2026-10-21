#!/usr/bin/env python3
"""Test optional exact-RLE Deflate headers against an unmodified build.

Run from any directory: python3 zipopt/tests/test_zopfli_exact_rle.py
This stand-alone test needs a C89 compiler and Python's zlib module, but no
optional Xtro-ZIP libraries or full Zip/ZipOpt build.
"""

import argparse
import ctypes
import pathlib
import random
import shlex
import subprocess
import tempfile
import time
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "zip30" / "zopfli.c"


class Options(ctypes.Structure):
    _fields_ = [
        ("verbose", ctypes.c_int),
        ("verbose_more", ctypes.c_int),
        ("numiterations", ctypes.c_int),
        ("blocksplitting", ctypes.c_int),
        ("blocksplittinglast", ctypes.c_int),
        ("blocksplittingmax", ctypes.c_int),
    ]


LIBC = ctypes.CDLL(None)
LIBC.free.argtypes = [ctypes.c_void_p]


def compile_lib(compiler, destination, enabled):
    cmd = shlex.split(compiler) + [
        "-O2",
        "-fPIC",
        "-shared",
        "-std=c89",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-Werror",
    ]
    if enabled:
        cmd.append("-DZOPFLI_EXACT_RLE")
    cmd.extend([str(SOURCE), "-lm", "-o", str(destination)])
    subprocess.run(cmd, check=True)


def load_lib(path):
    library = ctypes.CDLL(str(path))
    library.ZopfliInitOptions.argtypes = [ctypes.POINTER(Options)]
    signature = [
        ctypes.POINTER(Options),
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    tail = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.ZopfliDeflate.argtypes = signature + tail
    library.ZopfliDeflate.restype = ctypes.c_int
    library.ZopfliDeflatePart.argtypes = signature + [ctypes.c_size_t] + tail
    library.ZopfliDeflatePart.restype = ctypes.c_int
    return library


def compress(lib, source, iterations, split_at=None, blocktype=2):
    options = Options()
    lib.ZopfliInitOptions(ctypes.byref(options))
    options.numiterations = iterations
    data = ctypes.create_string_buffer(source, len(source) + 1)
    bp = ctypes.c_ubyte(0)
    output = ctypes.c_void_p()
    size = ctypes.c_size_t(0)
    before = time.perf_counter()
    try:
        if split_at is None:
            ok = lib.ZopfliDeflate(
                ctypes.byref(options),
                blocktype,
                1,
                data,
                len(source),
                ctypes.byref(bp),
                ctypes.byref(output),
                ctypes.byref(size),
            )
        else:
            ok = lib.ZopfliDeflatePart(
                ctypes.byref(options),
                blocktype,
                0,
                data,
                0,
                split_at,
                ctypes.byref(bp),
                ctypes.byref(output),
                ctypes.byref(size),
            )
            if ok:
                ok = lib.ZopfliDeflatePart(
                    ctypes.byref(options),
                    blocktype,
                    1,
                    data,
                    split_at,
                    len(source),
                    ctypes.byref(bp),
                    ctypes.byref(output),
                    ctypes.byref(size),
                )
        duration = time.perf_counter() - before
        if not ok:
            raise AssertionError("Zopfli returned allocation failure")
        result = ctypes.string_at(output, size.value)
        try:
            inflated = zlib.decompress(result, -15)
        except zlib.error as exc:
            raise AssertionError(
                "raw Deflate rejected: %s; first bytes %s" % (exc, result[:80].hex())
            ) from exc
        if inflated != source:
            raise AssertionError("raw Deflate round-trip mismatch")
        return result, duration
    finally:
        if output.value:
            LIBC.free(output)


def samples(count):
    yield "empty", b""
    yield "single", b"X"
    yield "zeros", bytes(32768)
    yield "A-repeats", b"A" * 1000
    yield "alternating", b"ABAABABB" * 2000
    yield "all-bytes", bytes(range(256)) * 40
    yield "source-zopfli", SOURCE.read_bytes()[:30000]
    yield "source-codec", (ROOT / "zipopt" / "codec.c").read_bytes()[:30000]
    alpha = b"aaaabbbbccddeefghXYZ-!0123456789\n\x00"
    for seed in range(count):
        rng = random.Random(seed * 127 + 7)
        size = (64, 160, 320, 768, 2048, 8192)[seed % 6]
        kind = seed % 5
        if kind == 0:
            data = bytes(rng.randrange(256) for _ in range(size))
        elif kind == 1:
            data = bytes(rng.choice(alpha) for _ in range(size))
        elif kind == 2:
            data = bytes(rng.randrange(16) for _ in range(size))
        elif kind == 3:
            unit = bytes(rng.choice(alpha) for _ in range(20 + seed % 70))
            data = (unit * (size // len(unit) + 1))[:size]
        else:
            data = bytearray(rng.choice(alpha) for _ in range(size))
            for j in range(20, size - 20, 49):
                data[j : j + 16] = data[j - 16 : j]
            data = bytes(data)
        yield "generated-%04d" % seed, data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc", help="compiler (default: cc)")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--iterations", type=int, default=15)
    args = parser.parse_args()
    if args.samples < 0 or args.iterations < 1:
        parser.error("samples must be >= 0 and iterations must be >= 1")

    wins = []
    changed = 0
    times = [0.0, 0.0]
    total = 0
    with tempfile.TemporaryDirectory(prefix="xtro-zopfli-rle-") as temporary:
        directory = pathlib.Path(temporary)
        plain, candidate = directory / "plain.so", directory / "exact.so"
        compile_lib(args.cc, plain, False)
        compile_lib(args.cc, candidate, True)
        baseline = load_lib(plain)
        optimized = load_lib(candidate)
        for name, source in samples(args.samples):
            original, old_time = compress(baseline, source, args.iterations)
            exact, new_time = compress(optimized, source, args.iterations)
            total += 1
            times[0] += old_time
            times[1] += new_time
            if len(exact) > len(original):
                raise AssertionError(
                    "size regression for %s: %d -> %d"
                    % (name, len(original), len(exact))
                )
            if exact != original:
                changed += 1
            if len(exact) < len(original):
                wins.append((name, len(original), len(exact)))

        # Split, non-final parts exercise the bit-position carry used by Zip
        # when the file is larger than one Zopfli input chunk.
        for name, source in (
            ("part-repetitions", b"A" * 13000 + b"BCD" * 4800),
            ("part-binary", bytes(range(256)) * 121),
        ):
            original, _ = compress(baseline, source, 1, split_at=len(source) // 2)
            exact, _ = compress(optimized, source, 1, split_at=len(source) // 2)
            total += 1
            if len(exact) > len(original):
                raise AssertionError("multipart size regression: " + name)

        # Fixed/stored blocks must never be modified by dynamic header work.
        for blocktype in (0, 1):
            original, _ = compress(baseline, b"ABCA" * 100, 1, blocktype=blocktype)
            exact, _ = compress(optimized, b"ABCA" * 100, 1, blocktype=blocktype)
            total += 1
            if original != exact:
                raise AssertionError("non-dynamic block changed")

    print(
        "PASS: %d round trips; %d different streams; %d smaller; %d bytes saved"
        % (total, changed, len(wins), sum(x - y for _, x, y in wins))
    )
    print("encoder CPU seconds: baseline %.3f, exact %.3f" % tuple(times))
    for name, before, after in wins[:20]:
        print("  %s: %d -> %d" % (name, before, after))


if __name__ == "__main__":
    main()
