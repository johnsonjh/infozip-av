#!/usr/bin/env python3
"""Regression tests for Debian #1093629 / Ubuntu #2093024 (-T/-TT).

Exercises the Unix subprocess command builder and post-close error cleanup.
Usage: python3 tests/test_zip_test_command.py --zip /path/to/zip
"""

import argparse
import hashlib
import json
import locale
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import zipfile


def available_locales():
    locales = ["C"]
    previous = locale.setlocale(locale.LC_CTYPE)
    for utf8 in ("C.UTF-8", "C.utf8", "en_US.UTF-8"):
        try:
            locale.setlocale(locale.LC_CTYPE, utf8)
        except locale.Error:
            continue
        locales.insert(0, utf8)
        break
    locale.setlocale(locale.LC_CTYPE, previous)
    return locales


def run(binary, work, arguments, loc, success=True):
    env = os.environ.copy()
    env["LC_ALL"] = loc
    result = subprocess.run(
        [str(binary)] + list(map(str, arguments)),
        cwd=work,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=40,
    )
    out = result.stdout
    if (
        result.returncode < 0
        or b"ERROR: AddressSanitizer" in out
        or b"buffer overflow detected" in out
        or b"UndefinedBehaviorSanitizer" in out
    ):
        raise AssertionError("memory safety failure: %r" % out[-3500:])
    if success and result.returncode != 0:
        raise AssertionError(
            "unexpected failure (%d): %r" % (result.returncode, out[-3500:])
        )
    if not success and result.returncode == 0:
        raise AssertionError("expected archive-test failure")
    return result


def assert_good_archive(archive, expected):
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None:
            raise AssertionError("CRC failure in " + str(archive))
        if len(z.namelist()) != 1 or z.read(z.namelist()[0]) != expected:
            raise AssertionError("changed member data in " + str(archive))


def main(zip_binary):
    count = 0
    with tempfile.TemporaryDirectory(prefix="zip-tt-1093629-") as temp:
        root = Path(temp)
        work = root / "work"
        work.mkdir()
        (work / "other").write_bytes(b"untouched payload\n")
        payload = b"untouched payload\n"
        verifier = root / "verify.py"
        verifier.write_text(
            """import json,sys,zipfile\nfrom pathlib import Path\np=Path(sys.argv[1])\nwith zipfile.ZipFile(p) as z:\n assert z.testzip() is None and z.namelist()\nPath(sys.argv[2]).write_text(json.dumps(sys.argv[1:]))\n"""
        )
        # Without {} the archive path is appended after all given arguments.
        # Reverse the two arguments before running the same verifier.
        wrapper = root / "append.py"
        wrapper.write_text(
            """import runpy,sys\nsys.argv=[sys.argv[0],sys.argv[2],sys.argv[1]]\nrunpy.run_path(%r,run_name="__main__")\n"""
            % str(verifier)
        )

        # The original Ubuntu smoke tests, plus representative Unicode names.
        names = [
            "plain.txt",
            "There’s a Baby in the House.flac",
            "Ünicøde",
            "тест.txt",
            "日本語.txt",
            "emoji-😀.dat",
            "sub/" + "é" * 48 + ".txt",
        ]
        for name in names:
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode("utf-8"))
        for loc in available_locales():
            for index, name in enumerate(names):
                output = work / ("unicode-%s-%d.zip" % (loc, index))
                run(zip_binary, work, ["-q", output, name], loc)
                assert_good_archive(output, name.encode("utf-8"))
                count += 1
        smoke = run(
            zip_binary, work, ["ls-verified.zip", "other", "-T", "-TT", "ls"], "C"
        )
        if b"test of ls-verified.zip OK" not in smoke.stdout:
            raise AssertionError("Ubuntu -TT ls smoke test failed")
        count += 1

        # Quote safety and correctness in both substitutions: {} and append.
        # A supplied pathname is never shell syntax, even when a parent
        # directory contains syntax that a shell would otherwise evaluate.
        archive_names = [
            "archive with spaces.zip",
            "archive with 'quotes'.zip",
            "archive$(touch SHOULD_NOT_EXIST).zip",
            "-leading-dash.zip",
            "dir$(touch SHOULD_NOT_EXIST)/archive.zip",
            "dir with 'quote' and $variable/archive.zip",
        ]
        for loc in available_locales():
            for index, name in enumerate(archive_names):
                for mode in ("replace", "append"):
                    target = work / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    result_path = root / ("result-%s-%d-%s.json" % (loc, index, mode))
                    if mode == "replace":
                        command = (
                            "python3 "
                            + shlex.quote(str(verifier))
                            + " {} "
                            + shlex.quote(str(result_path))
                        )
                    else:
                        command = (
                            "python3 "
                            + shlex.quote(str(wrapper))
                            + " "
                            + shlex.quote(str(result_path))
                        )
                    arg = "./" + name if name.startswith("-") else name
                    run(
                        zip_binary,
                        work,
                        ["-q", "-T", "-TT", command, arg, "other"],
                        loc,
                    )
                    passed = json.loads(result_path.read_text())
                    if len(passed) != 2 or passed[1] != str(result_path):
                        raise AssertionError("incorrect -TT argument passing")
                    if "/" in name and not passed[0].startswith(
                        str(Path(name).parent) + "/"
                    ):
                        raise AssertionError("incorrect temporary pathname")
                    assert_good_archive(target, payload)
                    if (work / "SHOULD_NOT_EXIST").exists():
                        raise AssertionError("pathname evaluated as shell code")
                    target.unlink()
                    count += 1

        # Most important regression: the external verifier fails AFTER
        # the completed temporary archive's output stream was closed.
        # The error cleanup must not close a stale FILE * a second time.
        for loc in available_locales():
            original = work / ("existing-%s.zip" % loc)
            run(zip_binary, work, ["-q", original, "other"], loc)
            before = hashlib.sha256(original.read_bytes()).digest()
            run(
                zip_binary,
                work,
                ["-T", "-TT", "false", original, "plain.txt"],
                loc,
                success=False,
            )
            if hashlib.sha256(original.read_bytes()).digest() != before:
                raise AssertionError("existing archive altered on test failure")
            if list(work.glob("zi??????")):
                raise AssertionError("temporary zip left after test failure")
            run(
                zip_binary,
                work,
                ["-T", "-TT", "false", "nonexistent-%s.zip" % loc, "other"],
                loc,
                success=False,
            )
            if (work / ("nonexistent-%s.zip" % loc)).exists():
                raise AssertionError("failed test installed an archive")
            if list(work.glob("zi??????")):
                raise AssertionError("temporary zip left after test failure")
            count += 2
    print("PASS: %d fortified/sanitizer-capable archive-test scenarios" % count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parsed = parser.parse_args()
    main(parsed.zip.resolve())
