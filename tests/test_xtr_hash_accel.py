#!/usr/bin/env python3
"""Portable-Xtro CRC32/SHA256 native A/B regression and optional timing.

Usage: python3 tests/test_xtr_hash_accel.py [--benchmark] [--baseline-tree PATH]
Requires a native C compiler, Python's hashlib/zlib and POSIX shared objects.
"""

import argparse
import ctypes
import hashlib
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class SHAState(ctypes.Structure):
    _fields_ = [
        ("h", ctypes.c_ulong * 8),
        ("bytes_lo", ctypes.c_ulong),
        ("bytes_hi", ctypes.c_ulong),
        ("block", ctypes.c_ubyte * 64),
        ("used", ctypes.c_uint),
    ]


def compile_lib(cc, root, src, output, flags):
    subprocess.run(
        [
            cc,
            "-std=gnu89",
            "-O3",
            "-fPIC",
            "-shared",
            *flags,
            str(root / "xtrmeta" / src),
            "-o",
            str(output),
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return ctypes.CDLL(str(output))


def hash_digest(lib, parts):
    s = SHAState()
    out = (ctypes.c_ubyte * 32)()
    lib.xtr_sha256_init(ctypes.byref(s))
    for p in parts:
        lib.xtr_sha256_update(ctypes.byref(s), ctypes.c_char_p(p), len(p))
    lib.xtr_sha256_final(ctypes.byref(s), out)
    return bytes(out)


def crc_digest(lib, parts):
    crc = 0
    for p in parts:
        crc = lib.xtr_crc32_update(crc, ctypes.c_char_p(p), len(p))
    return crc


def partitions(data, block):
    if not data:
        return [b""]
    return [data[i : i + block] for i in range(0, len(data), block)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--baseline-tree", type=Path)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("native POSIX shared libraries required")
    cc = os.environ.get("CC", "cc")
    if not shutil.which(cc):
        parser.error("native C compiler not found: " + cc)
    roots = {"patched": ROOT}
    if args.baseline_tree:
        roots["original"] = args.baseline_tree.resolve()
    sha, crc = {}, {}
    with tempfile.TemporaryDirectory(prefix="xtro_hash_") as work:
        work = Path(work)
        for label, root in roots.items():
            for flavor in ("cpu", "scalar"):
                suffix = label + "_" + flavor
                shaflags = (
                    [] if flavor == "cpu" else ["-DNO_SHA256_NI", "-DNO_ARM_SHA256"]
                )
                crcflags = (
                    [] if flavor == "cpu" else ["-DNO_PCLMUL_CRC", "-DNO_ARM_CRC32"]
                )
                a = compile_lib(
                    cc, root, "xtrsha.c", work / ("sha_" + suffix + ".so"), shaflags
                )
                a.xtr_sha256_init.argtypes = [ctypes.POINTER(SHAState)]
                a.xtr_sha256_update.argtypes = [
                    ctypes.POINTER(SHAState),
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                ]
                a.xtr_sha256_final.argtypes = [
                    ctypes.POINTER(SHAState),
                    ctypes.c_void_p,
                ]
                sha[suffix] = a
                a = compile_lib(
                    cc, root, "xtrm.c", work / ("crc_" + suffix + ".so"), crcflags
                )
                a.xtr_crc32_update.argtypes = [
                    ctypes.c_ulong,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                ]
                a.xtr_crc32_update.restype = ctypes.c_ulong
                crc[suffix] = a
        rng = random.Random(20261022)
        sizes = list(range(0, 140)) + [
            255,
            256,
            257,
            511,
            512,
            513,
            1023,
            1024,
            4095,
            4096,
            4097,
            65535,
            65536,
            65537,
            1048576,
        ]
        cases = 0
        for n in sizes:
            data = bytes(rng.getrandbits(8) for _ in range(n))
            for chunk in (
                (1, 3, 63, 64, 65, 256, 4096) if n <= 4096 else (4096, 65536)
            ):
                parts = partitions(data, chunk)
                expected_sha = hashlib.sha256(data).digest()
                expected_crc = zlib.crc32(data)
                for name, lib in sha.items():
                    got = hash_digest(lib, parts)
                    if got != expected_sha:
                        raise AssertionError(
                            "SHA256 %s len=%s chunk=%s" % (name, n, chunk)
                        )
                for name, lib in crc.items():
                    got = crc_digest(lib, parts)
                    if got != expected_crc:
                        raise AssertionError(
                            "CRC32 %s len=%s chunk=%s" % (name, n, chunk)
                        )
                cases += 1
        print(
            "PASS: %d size/chunking scenarios, SHA256 and CRC32, %d configurations"
            % (cases, len(sha))
        )
        if args.benchmark:
            data = bytes(rng.getrandbits(8) for _ in range(8 * 1024 * 1024))
            for kind, libs, action in (
                ("SHA256", sha, hash_digest),
                ("CRC32", crc, crc_digest),
            ):
                results = {k: [] for k in libs}
                for _ in range(11):
                    order = list(libs)
                    rng.shuffle(order)
                    for k in order:
                        start = time.process_time_ns()
                        action(libs[k], [data])
                        results[k].append((time.process_time_ns() - start) / 1e6)
                print(
                    kind,
                    "8 MiB CPU-time medians (ms):",
                    ", ".join(
                        "%s %.3f" % (k, statistics.median(v))
                        for k, v in results.items()
                    ),
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
