#!/usr/bin/env python3
"""Diagnose Zip Unicode archive create/update and mixed EA/ADS capture.

Independent destinations per scenario; preserves failed archives. MIT-0.
Does not modify production files, sources, or other archives.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile


def cases():
    return [
        ("ascii-plain", False, False, False),
        ("ascii-mixed", False, False, True),
        ("unicode-file-mixed", False, True, True),
        ("unicode-dir-mixed", True, False, True),
        ("unicode-both-mixed", True, True, True),
        ("unicode-both-plain", True, True, False),
    ]


def inspect(path):
    if not path.exists():
        return "exists=False", False, 0, False
    b = path.read_bytes()
    s = "exists=True bytes=%d sha256=%s first16=%s" % (
        len(b),
        hashlib.sha256(b).hexdigest(),
        b[:16].hex(),
    )
    try:
        with zipfile.ZipFile(path) as z:
            all_entries = z.infolist()
            names = [x.filename for x in all_entries]
            xtro_count = 0
            for info in all_entries:
                p = 0
                extra = info.extra
                while p + 4 <= len(extra):
                    ident = int.from_bytes(extra[p : p + 2], "little")
                    length = int.from_bytes(extra[p + 2 : p + 4], "little")
                    if length > len(extra) - p - 4:
                        break
                    if ident == 0x5854:
                        xtro_count += 1
                    p += length + 4
            bad = z.testzip()
        s += " python_zipfile=%s entries=%d xtro_central_fields=%d names=%r" % (
            "OK" if bad is None else "BAD:" + bad,
            len(names),
            xtro_count,
            names[:6],
        )
        return s, bad is None, len(names), xtro_count > 0
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as e:
        return s + " python_zipfile_error=%s" % str(e), False, 0, False


def attempt(exe, archive, src, label, phase, flags, root):
    cmd = [str(exe), "-q", "-j", "-0"] + flags + [str(archive), str(src)]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    s, structurally_valid, count, has_xtro = inspect(archive)
    print("%s / %s: rc=%d; %s" % (label, phase, proc.returncode, s), flush=True)
    if proc.stdout:
        print("ZIP STDOUT:\n" + proc.stdout, flush=True)
    if proc.stderr:
        print("ZIP STDERR:\n" + proc.stderr, flush=True)
    if proc.returncode or not structurally_valid:
        if archive.exists():
            dst = root / ("xtro-w3d2-diagnostic-" + label + "-" + phase + ".zip")
            shutil.copyfile(archive, dst)
            print("SAVED ARCHIVE:", dst, flush=True)
    return proc.returncode == 0 and structurally_valid, count, has_xtro


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip")
    ap.add_argument("--workdir", default=".")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    test_cases = cases()
    if a.self_test:
        labels = [c[0] for c in test_cases]
        assert len(labels) == len(set(labels))
        assert len(test_cases) == 6
        assert ("unicode-both-mixed", True, True, True) in test_cases
        assert ("unicode-both-plain", True, True, False) in test_cases
        assert ("unicode-both-plain", True, True, False) in test_cases
        print(
            "PASS: Windows Unicode Zip source-preflight diagnostic self-test; 6 scenarios"
        )
        return 0
    if os.name != "nt":
        print("SKIP: native Windows required")
        return 77
    if not a.zip:
        ap.error("--zip is required")
    exe = Path(a.zip).resolve()
    root = Path(a.workdir).resolve()
    if not exe.is_file() or not root.is_dir():
        ap.error("Zip executable or work directory unavailable")
    from test_win_stream_archive_native import CONTENTS, STREAM_NAME, STREAM_BYTES
    from test_win_zip_native import DATA, seed_native_ea
    from test_win_zip_unicode_archive_native import (
        ensure_source_metadata,
        update_primary_contents,
    )

    fail = False
    with tempfile.TemporaryDirectory(prefix="xtro-zip-u8-diag2-", dir=root) as td:
        base = Path(td)
        src = base / "owner.bin"
        for label, unicode_dir, unicode_leaf, mixed in test_cases:
            # Unique directory for every scenario: no accidental preexisting archive.
            directory = base / label / ("目录-雪-🧪" if unicode_dir else "plain")
            directory.mkdir(parents=True)
            archive = directory / ("归档-雪-🧪.zip" if unicode_leaf else "archive.zip")
            assert not archive.exists(), "scenario was not isolated: " + label
            src.write_bytes(CONTENTS)
            with open(str(src) + ":" + STREAM_NAME + ":$DATA", "wb") as stream:
                stream.write(STREAM_BYTES)
            if seed_native_ea(src, DATA, flags=0x80):
                raise RuntimeError("unable to create native Windows EA")
            if mixed:
                ensure_source_metadata(src, label + " initial")
            earlier = time.time() - 20
            os.utime(src, (earlier, earlier))
            opts = ["--xattrs", "--streams"] if mixed else []
            success, count, has_xtro = attempt(
                exe, archive, src, label, "create", opts, root
            )
            if not success:
                fail = True
                continue
            if mixed and not has_xtro:
                print(
                    "WARNING:",
                    label,
                    "mixed metadata requested but no central XTRO field",
                    flush=True,
                )
                fail = True
            if mixed and count < 2 and len(STREAM_BYTES) > 65536:
                print(
                    "WARNING:",
                    label,
                    "large ADS requested but no companion member",
                    flush=True,
                )
                fail = True
            update_primary_contents(src, CONTENTS + b"\x00revised-w3d2-diagnostic")
            os.utime(src, None)
            if mixed:
                ensure_source_metadata(src, label + " before update")
            success, updated_count, updated_xtro = attempt(
                exe, archive, src, label, "update", opts, root
            )
            if not success:
                fail = True
            if mixed and (not updated_xtro or updated_count < 2):
                print(
                    "FAIL:",
                    label,
                    "metadata disappeared from updated archive "
                    "despite verified source metadata",
                    flush=True,
                )
                fail = True
    print(
        "RESULT:",
        (
            "FAIL; inspect per-scenario output"
            if fail
            else "PASS; six independent create/update scenarios"
        ),
    )
    return int(fail)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, AssertionError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
