#!/usr/bin/env python3
"""ZIP method-12 interoperability checks for an installed Xtro-ZIP build."""

import argparse
from pathlib import Path
import subprocess
import tempfile
import zipfile


def invoke(*args, cwd=None):
    subprocess.run(
        [str(x) for x in args], cwd=cwd, check=True, stdout=subprocess.DEVNULL
    )


def inspect(path, expected):
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        assert names == ["sample.bin"], names
        assert zf.read("sample.bin") == expected
        assert zf.getinfo("sample.bin").compress_type == zipfile.ZIP_BZIP2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", default="build/bin")
    args = parser.parse_args()
    base = Path(args.bin_dir).resolve()
    programs = {name: base / name for name in ("zip", "unzip", "zipopt", "zipdedup")}
    for name, path in programs.items():
        if not path.is_file():
            parser.error("missing %s: %s" % (name, path))
    payload = (b"Xtro-Bzip2-level-9\x00\xff\n" * 40000) + bytes(range(256)) * 1024
    with tempfile.TemporaryDirectory(prefix="xtro-method12-") as temp:
        root = Path(temp)
        (root / "sample.bin").write_bytes(payload)
        raw = root / "raw.zip"
        opt = root / "opt.zip"
        dedup = root / "dedup.zip"
        invoke(programs["zip"], "-q", "-9", "-Z", "bzip2", raw, "sample.bin", cwd=root)
        invoke(programs["unzip"], "-t", raw)
        inspect(raw, payload)
        invoke(programs["zipopt"], "--methods=bzip2", raw, opt)
        inspect(opt, payload)
        invoke(programs["zipdedup"], raw, dedup)
        inspect(dedup, payload)
    print("ZIP method 12: Zip, UnZip, zipopt, zipdedup, Python: PASS")


if __name__ == "__main__":
    main()
