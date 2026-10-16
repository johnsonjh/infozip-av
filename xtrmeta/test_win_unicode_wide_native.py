#!/usr/bin/env python3
"""Acceptance for the opt-in UTF-8 -> UTF-16 Windows UnZip extraction path.

The expected result is only meaningful on real Windows. This is not a Wine
NTFS/EA acceptance test. MIT-0.
"""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

NAMES = {
    "snow": "\u96ea.bin",
    "nested": "\u76ee\u5f55/\u96ea.bin",
    "supplementary": "\U0001f9ea.bin",
    "mixed": "plain/\u00e9-\u96ea.bin",
}


def create_archive(destination):
    with zipfile.ZipFile(destination, "w", allowZip64=True) as z:
        for index, value in enumerate(NAMES.values()):
            content = bytes([(i * 17 + index) & 255 for i in range(72911 + index)])
            z.writestr(value, content, compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(destination) as z:
        for v in NAMES.values():
            record = z.getinfo(v)
            assert record.flag_bits & 0x800, "UTF-8 member flag missing"


def test(args):
    if args.self_test:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "unicode.zip"
            create_archive(target)
            with zipfile.ZipFile(target) as z:
                assert set(z.namelist()) == set(NAMES.values())
        print("PASS: W3D UTF-8 archive fixture; 4 filenames")
        return
    if os.name != "nt":
        raise SystemExit("ERROR: real Windows required for filesystem acceptance")
    if not args.unzip:
        raise SystemExit("ERROR: --unzip is required")
    unzip = Path(args.unzip).resolve()
    if not unzip.is_file():
        raise SystemExit("ERROR: missing UnZip executable: %s" % unzip)
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xtro-unicode-wide-", dir=workdir) as td:
        root = Path(td)
        archive = root / "unicode.zip"
        out = root / "extracted"
        out.mkdir()
        create_archive(archive)
        cmd = [str(unzip), "-q", "-o", str(archive), "-d", str(out)]
        run = subprocess.run(
            cmd, text=True, encoding="utf-8", errors="replace", capture_output=True
        )
        if run.returncode != 0:
            raise RuntimeError(
                "UnZip exit %d: %s\n%s" % (run.returncode, run.stdout, run.stderr)
            )
        with zipfile.ZipFile(archive) as z:
            for name in NAMES.values():
                path = out.joinpath(*name.split("/"))
                if not path.is_file():
                    raise AssertionError(
                        "missing exact Unicode filename: %r" % str(path)
                    )
                expected = z.read(name)
                actual = path.read_bytes()
                if actual != expected:
                    raise AssertionError("content mismatch for %r" % name)
        # No fallback #Uxxxx escaped names should have been generated.
        actual_files = {
            str(x.relative_to(out)).replace("\\", "/")
            for x in out.rglob("*")
            if x.is_file()
        }
        if actual_files != set(NAMES.values()):
            raise AssertionError("unexpected or escaped files: %r" % actual_files)
    print("PASS: NATIVE WINDOWS W3D Unicode UTF-16 extraction; 4 filenames; 4 contents")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--unzip")
    parser.add_argument("--workdir", default=".")
    test(parser.parse_args())
