#!/usr/bin/env python3
"""Reproducible-by-seed native Zip baseline/libdeflate speed and ratio probe.

The program measures one process invocation per archive and prints results
for raw method-8 member sizes, not total ZIP sizes.  This intentionally
includes the process and archiving overhead; it is not a libdeflate-only
microbenchmark.  Use --repeat for steadier medians.
"""

import argparse
import pathlib
import random
import statistics
import subprocess
import tempfile
import time
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def execute(args, cwd):
    begin = time.perf_counter()
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    seconds = time.perf_counter() - begin
    if p.returncode:
        raise RuntimeError(f"{args!r}: {p.returncode}\n{p.stdout}\n{p.stderr}")
    return seconds


def benchmark(zipbin, unzipbin, repeat):
    rng = random.Random(107)
    content = {
        "readme.txt": (ROOT / "README.md").read_bytes(),
        "code.txt": (ROOT / "zip30/zip.c").read_bytes(),
        "syntax.txt": (ROOT / "zipopt/codec.c").read_bytes(),
        "repetitive.bin": (b"abcdef01234567\n" * 8192),
        "pseudorandom.bin": rng.randbytes(131072),
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="xtro-ld-bench-") as dirname:
        directory = pathlib.Path(dirname)
        for filename, raw in content.items():
            (directory / filename).write_bytes(raw)
            for level in (1, 6, 9, 11):
                for backend, extra in (
                    ("builtin", ["--use-libdeflate-"]),
                    ("libdeflate", ["--use-libdeflate"]),
                ):
                    times = []
                    unpack = []
                    member_size = None
                    for n in range(repeat):
                        out = directory / f"{backend}-{level}-{n}.zip"
                        args = [
                            zipbin,
                            "-q",
                            "-X",
                            f"-{level}",
                            *extra,
                            str(out),
                            filename,
                        ]
                        times.append(execute(args, directory))
                        with zipfile.ZipFile(out) as zf:
                            item = zf.getinfo(filename)
                            if zf.read(filename) != raw:
                                raise RuntimeError("bad round-trip: " + str(out))
                            member_size = item.compress_size
                        unpack.append(
                            execute(
                                [unzipbin, "-tq", "--use-libdeflate", str(out)],
                                directory,
                            )
                        )
                    results.append(
                        (
                            filename,
                            len(raw),
                            level,
                            backend,
                            member_size,
                            statistics.median(times),
                            statistics.median(unpack),
                        )
                    )
                    print(f"finished {filename} -{level} {backend}", flush=True)
    print("\nFILE INPUT LEVEL BACKEND DEFLATE_BYTES ZIP_SECONDS TEST_SECONDS")
    for row in results:
        print("%s %d %d %s %d %.6f %.6f" % row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=pathlib.Path, default=ROOT / "zip30/zip")
    parser.add_argument("--unzip", type=pathlib.Path, default=ROOT / "unzip60/unzip")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 20:
        parser.error("--repeat must be 1..20")
    benchmark(str(args.zip.resolve()), str(args.unzip.resolve()), args.repeat)
