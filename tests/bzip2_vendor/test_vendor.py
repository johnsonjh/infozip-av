#!/usr/bin/env python3
"""Host-side strict-C89 vendored libbzip2 regression (no network)."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "vendor" / "bzip2"
UNITS = (
    "blocksort",
    "huffman",
    "crctable",
    "randtable",
    "compress",
    "decompress",
    "bzlib",
)


def run(args, **kwargs):
    subprocess.run([str(v) for v in args], check=True, **kwargs)


def main():
    cc = os.environ.get("CC", "cc")
    ar = os.environ.get("AR", "ar")
    with tempfile.TemporaryDirectory(prefix="xtro-bzip2-test-") as dirname:
        target = Path(dirname)
        objects = []
        for name in UNITS:
            obj = target / (name + ".o")
            run(
                [
                    cc,
                    "-std=c89",
                    "-pedantic",
                    "-DBZ_STRICT_ANSI",
                    "-O2",
                    "-I" + str(SOURCE),
                    "-c",
                    SOURCE / (name + ".c"),
                    "-o",
                    obj,
                ]
            )
            objects.append(obj)
        library = target / "libbz2.a"
        run([ar, "rcs", library] + objects)
        executable = target / "test-api"
        run(
            [
                cc,
                "-std=c89",
                "-pedantic",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I" + str(SOURCE),
                ROOT / "tests/bzip2_vendor/test_api.c",
                library,
                "-o",
                executable,
            ]
        )
        run([executable])
    print("BZip2 vendored C89 test: PASS")


if __name__ == "__main__":
    main()
