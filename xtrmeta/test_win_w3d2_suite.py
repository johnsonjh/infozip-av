#!/usr/bin/env python3
"""Run the complete native Windows Xtro-ZIP acceptance collection. MIT-0.

Each subprocess reports its own case count. A skip is not a pass.
The W3D2 Unicode archive and metadata checks run after established suites.
"""

import argparse
from pathlib import Path
import subprocess
import sys

TESTS = (
    ("test_win_unzip_native.py", True, True),
    ("test_win_companion_native.py", True, True),
    ("test_win_directory_native.py", True, True),
    ("test_win_stream_archive_native.py", True, False),
    ("test_win_stream_restore_native.py", True, True),
    ("test_win_unicode_wide_native.py", False, True),
    ("test_win_w3d2_native.py", True, True),
    ("test_win_zip_unicode_archive_native.py", True, False),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip")
    parser.add_argument("--unzip")
    parser.add_argument("--workdir", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    for name, _, _ in TESTS:
        if not (here / name).is_file():
            raise RuntimeError("missing acceptance test %s" % name)
    if args.self_test:
        print("PASS: W3D2 native suite manifest; %d scripts" % len(TESTS))
        return 0
    if not args.zip or not args.unzip:
        parser.error("--zip and --unzip are required")
    z, uz = Path(args.zip).resolve(), Path(args.unzip).resolve()
    work = Path(args.workdir).resolve()
    if not z.is_file() or not uz.is_file() or not work.is_dir():
        parser.error("Zip/UnZip executables and test directory must exist")
    for name, needs_zip, needs_unzip in TESTS:
        cmd = [sys.executable, str(here / name), "--workdir", str(work)]
        if needs_zip:
            cmd.extend(("--zip", str(z)))
        if needs_unzip:
            cmd.extend(("--unzip", str(uz)))
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="", flush=True)
        if result.returncode != 0:
            print(
                "FAIL: W3D2 native suite %s; return=%d" % (name, result.returncode),
                file=sys.stderr,
            )
            return result.returncode if result.returncode > 0 else 1
        print("SUITE PASS: %s" % name, flush=True)
    print("PASS: W3D2 Windows full native acceptance; %d scripts" % len(TESTS))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        sys.exit(1)
