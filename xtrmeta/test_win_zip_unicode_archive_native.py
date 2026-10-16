#!/usr/bin/env python3
"""Native MinGW Zip Unicode archive publication and update acceptance.

Exercises creation and replacement, not Unicode-named source-file discovery.
The archive and the containing directory use names outside Western ACP.
MIT-0.
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
from test_win_stream_archive_native import CONTENTS, STREAM_NAME, STREAM_BYTES, inspect
from test_win_zip_native import DATA, NAME, seed_native_ea


def source_metadata(path):
    """Read source EAs/ADS independently of Zip before each capture."""
    from test_win_unzip_native import snapshot

    ea = snapshot(path).get(NAME)
    stream_path = str(path) + ":" + STREAM_NAME + ":$DATA"
    try:
        with open(stream_path, "rb") as stream:
            contents = stream.read()
    except FileNotFoundError:
        contents = None
    return ea == (0x80, DATA), contents == STREAM_BYTES


def ensure_source_metadata(path, phase):
    """Restore the *fixture's* EA/ADS when source content editing removed it.

    A source replacement and a ZIP archive replacement are different events.
    Never attribute a metadata loss caused by the fixture's write mode to Zip.
    """
    ea, ads = source_metadata(path)
    print(
        "SOURCE %s: native EA=%s named ADS=%s"
        % (phase, "present" if ea else "absent", "present" if ads else "absent"),
        flush=True,
    )
    if not ea:
        status = seed_native_ea(path, DATA, flags=0x80)
        if status:
            raise RuntimeError(
                "cannot recreate source EA after %s: NTSTATUS 0x%08x" % (phase, status)
            )
    if not ads:
        with open(str(path) + ":" + STREAM_NAME + ":$DATA", "wb") as stream:
            stream.write(STREAM_BYTES)
    if source_metadata(path) != (True, True):
        raise RuntimeError(
            "source fixture metadata is unavailable before Zip %s" % phase
        )


def update_primary_contents(path, contents):
    # Modify the unnamed stream of the *existing* NTFS file. Do not open with
    # Python Path.write_bytes() / 'wb', whose disposition can change native
    # metadata state. Still validate both source metadata classes afterwards.
    with open(path, "r+b") as stream:
        stream.seek(0)
        stream.write(contents)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def run(cmd):
    result = subprocess.run(
        [str(x) for x in cmd], capture_output=True, text=True, errors="replace"
    )
    if result.returncode:
        raise RuntimeError(
            "command %r returned %d\n%s\n%s"
            % (cmd, result.returncode, result.stdout, result.stderr)
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--zip")
    ap.add_argument("--workdir", default=".")
    args = ap.parse_args()
    if args.self_test:
        assert "🧪".encode("utf-8") in "归档-雪-🧪.zip".encode("utf-8")
        assert callable(ensure_source_metadata) and callable(update_primary_contents)
        print("PASS: Unicode Zip output acceptance fixture")
        return 0
    if os.name != "nt":
        print("SKIP: native Windows NTFS is required")
        return 77
    if not args.zip:
        ap.error("--zip is required")
    exe = Path(args.zip).resolve()
    root = Path(args.workdir).resolve()
    if not exe.is_file() or not root.is_dir():
        ap.error("Zip binary or workdir not found")
    with tempfile.TemporaryDirectory(prefix="xtro-zip-u8-", dir=root) as name:
        home = Path(name) / "目录-雪-🧪"
        home.mkdir()
        src = Path(name) / "owner.bin"
        src.write_bytes(CONTENTS)
        with open(str(src) + ":" + STREAM_NAME + ":$DATA", "wb") as fd:
            fd.write(STREAM_BYTES)
        if seed_native_ea(src, DATA, flags=0x80):
            raise RuntimeError("unable to seed native EA on test file")
        ensure_source_metadata(src, "initial capture")
        archive = home / "归档-雪-🧪.zip"
        command = [exe, "-q", "-j", "-0", "--xattrs", "--streams", archive, src]
        run(command)
        inspect(archive, True, ea_flags=0x80)
        with zipfile.ZipFile(archive) as z:
            if z.read("owner.bin") != CONTENTS:
                raise AssertionError("first Unicode archive contents differ")
        # Force a real update/rewrite, including an existing Xtro pair.
        replacement = CONTENTS + b"\x00native-unicode-archive-update"
        update_primary_contents(src, replacement)
        ensure_source_metadata(src, "replacement capture")
        run(command)
        inspect(archive, True, ea_flags=0x80)
        with zipfile.ZipFile(archive) as z:
            if z.read("owner.bin") != replacement:
                raise AssertionError("updated Unicode archive contents differ")
    print(
        "PASS: NATIVE WINDOWS Zip Unicode archive create/update; mixed EA/ADS; 2 cases"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, AssertionError, zipfile.BadZipFile) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
