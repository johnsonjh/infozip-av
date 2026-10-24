#!/usr/bin/env python3
"""Regression tests for per-member codec failure isolation (MIT-0)."""

import os
import pathlib
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTER = ROOT / "zipopt-test-candidate-failure"
CONTENTS = {
    "repeated.bin": b"ABCD" * 8192,
    "small.txt": b"small input\n" * 39,
    "empty.dat": b"",
}


def execute(
    source,
    dest,
    selection,
    *,
    failed=None,
    partial=False,
    fatal=False,
    inapplicable=False,
    ppmd_oom=False
):
    env = os.environ.copy()
    env.pop("ZO_TEST_FAIL_ID", None)
    env.pop("ZO_TEST_WRITE_PARTIAL", None)
    env.pop("ZO_TEST_FATAL", None)
    env.pop("ZO_TEST_INAPPLICABLE", None)
    env.pop("ZO_TEST_PPMD_VERIFY_OOM", None)
    if failed is not None:
        env["ZO_TEST_FAIL_ID"] = str(failed)
    if partial:
        env["ZO_TEST_WRITE_PARTIAL"] = "1"
    if fatal:
        env["ZO_TEST_FATAL"] = "1"
    if inapplicable:
        env["ZO_TEST_INAPPLICABLE"] = "1"
    if ppmd_oom:
        env["ZO_TEST_PPMD_VERIFY_OOM"] = "1"
    args = [str(TESTER)]
    if ppmd_oom:
        args.append("--compress-level=ppmd=3")
    args.extend(["--methods=" + selection, str(source), str(dest)])
    return subprocess.run(
        args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )


def check_archive(p):
    with zipfile.ZipFile(p) as a:
        assert {name: a.read(name) for name in a.namelist()} == CONTENTS
        assert a.testzip() is None
    subprocess.run(
        [str(ROOT / "zipopt-decodecheck"), str(p)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=40,
    )


def main():
    with tempfile.TemporaryDirectory(prefix="zipopt-candidate-failure-") as d:
        base = pathlib.Path(d)
        source = base / "source.zip"
        with zipfile.ZipFile(source, "w") as z:
            for name, content in CONTENTS.items():
                z.writestr(name, content, compress_type=zipfile.ZIP_STORED)

        # PPMd fails after writing partial data; STORE and/or the original
        # must still survive on all three independent members.
        normal = base / "normal.zip"
        skipped = base / "skipped.zip"
        assert execute(source, normal, "store").returncode == 0
        r = execute(source, skipped, "store,ppmd", failed=18, partial=True)
        assert r.returncode == 0, r.stderr
        assert r.stderr.count("skipping failed compressor ppmd") == len(CONTENTS)
        check_archive(skipped)
        assert (
            normal.read_bytes() == skipped.read_bytes()
        ), "partial output from a failed candidate altered final archive"

        # A format-specific codec can decline an unsuitable member without
        # producing the per-file compressor failure message (e.g. WavPack
        # on non-WAV audio or an ordinary document).
        unsupported = base / "inapplicable.zip"
        r = execute(source, unsupported, "store,ppmd", failed=18, inapplicable=True)
        assert r.returncode == 0, r.stderr
        assert "skipping failed compressor" not in r.stderr, r.stderr
        check_archive(unsupported)
        assert normal.read_bytes() == unsupported.read_bytes()

        # Failure of an earlier candidate must not prevent later encoders.
        later = base / "later.zip"
        r = execute(source, later, "store,deflate", failed=0)
        assert r.returncode == 0, r.stderr
        assert r.stderr.count("skipping failed compressor store") == len(CONTENTS)
        check_archive(later)

        # If the only encoder fails, its original is still valid when its
        # method was explicitly selected.
        original = base / "original.zip"
        r = execute(source, original, "store", failed=0)
        assert r.returncode == 0, r.stderr
        check_archive(original)

        # If neither an encoder nor an eligible original remains, the tool
        # must fail and leave no published output.
        none = base / "none.zip"
        r = execute(source, none, "ppmd", failed=18)
        assert r.returncode != 0, "no eligible method must not succeed"
        assert "no eligible encoder" in r.stderr, r.stderr
        assert not none.exists()

        # A forced I/O error is never a candidate-local skip.  Here an
        # earlier STORE result already exists and must still be discarded.
        bad_io = base / "io-failure.zip"
        r = execute(source, bad_io, "store,deflate", failed=10, fatal=True)
        assert r.returncode != 0, "I/O failures must abort"
        assert "I/O failure during compressor deflate" in r.stderr, r.stderr
        assert "skipping failed compressor deflate" not in r.stderr
        assert not bad_io.exists()

        # An encoder may successfully allocate its model while a later
        # independent PPMd decoder cannot.  Never publish that candidate:
        # retry the whole archive with remaining methods and verify it.
        memory_retry = base / "memory-retry.zip"
        r = execute(
            source,
            memory_retry,
            "store,ppmd",
            ppmd_oom=True,
        )
        assert r.returncode == 0, r.stderr
        assert "retrying from scratch without PPMd" in r.stderr, r.stderr
        assert "refusing to publish unverified output" not in r.stderr
        check_archive(memory_retry)
        with zipfile.ZipFile(memory_retry) as z:
            assert all(info.compress_type == 0 for info in z.infolist())

        # If the only permitted compressor cannot be decoded, fail closed.
        memory_only = base / "memory-only.zip"
        r = execute(source, memory_only, "ppmd", ppmd_oom=True)
        assert r.returncode != 0
        assert not memory_only.exists()

    print("candidate failure isolation: PASS")


if __name__ == "__main__":
    main()
