#!/usr/bin/env python3
"""Compile and exercise the production OS/2 AES fallback against fake Dos* APIs.

Requires a Linux C89 compiler. This is NOT an entropy-quality certification.
"""

import os
import subprocess
import tempfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    compiler = os.environ.get("CC", "cc")
    flags = [
        "-std=c89",
        "-pedantic",
        "-O1",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-function",
        "-D__OS2__",
        "-D__WATCOMC__",
        "-DNO_AES_NI",
        "-DNO_GHASH_PCLMUL",
        "-DNO_SHA256_NI",
        "-DNO_SHA1_NI",
        "-I" + str(root / "tests/os2mock/entropy"),
    ]
    with tempfile.TemporaryDirectory(prefix="xtro-os2-entropy-") as temp:
        exe = str(Path(temp) / "test_os2_entropy")
        subprocess.run(
            [
                compiler,
                *flags,
                str(root / "zip30/wzaes.c"),
                str(root / "tests/os2mock/test_os2_entropy.c"),
                "-o",
                exe,
            ],
            check=True,
        )
        normal = subprocess.run([exe], check=True, text=True, capture_output=True)
        assert normal.stdout.count("PASS") == 1, normal.stdout
        assert (
            normal.stderr.count("OS/2 AES uses time/memory-derived salts") == 1
        ), normal.stderr
        broken = subprocess.run(
            [exe, "seed_failure"], check=True, text=True, capture_output=True
        )
        assert "PASS" in broken.stdout, broken.stdout
        assert not broken.stderr, broken.stderr
    print(
        "OS/2 entropy regression: PASS (including error zeroization and warning count)"
    )


if __name__ == "__main__":
    main()
