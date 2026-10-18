#!/usr/bin/env python3
"""Regression test for Debian #726540: append and prefixed stdout.

Usage: python3 tests/test_stdout_append.py --zip zip30/zip [--baseline old/zip]

The comparator for an append-only destination is a genuinely nonseekable
stdout pipe. These must produce identical ZIP streams. The test also checks
that ordinary seekable stdout does not change relative to the old binary.
"""

import argparse
import io
import os
import pathlib
import random
import subprocess
import tempfile
import zipfile


def reset_atimes(cwd, command):
    # The Unix UT extra field may include access times. Normalize before
    # each invocation so byte comparisons reflect output semantics only.
    for name in command[1:]:
        source = pathlib.Path(cwd) / name
        if name != "-" and source.is_file():
            os.utime(source, (1600000000, 1600000000))


def check(command, cwd, input_data=None, output=None):
    reset_atimes(cwd, command)
    env = os.environ.copy()
    env.update({"TZ": "UTC", "LC_ALL": "C.UTF-8"})
    result = subprocess.run(
        command,
        cwd=cwd,
        input=input_data,
        stdout=output or subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            "zip rc=%s: %r\n%s"
            % (result.returncode, command, result.stderr.decode("utf-8", "replace"))
        )
    return result.stdout or b""


def semantic_name(info):
    # Python's zipfile currently ignores Info-ZIP's Unicode Path extra
    # field (0x7075). Prefer that field where it exists.
    data = info.extra
    pos = 0
    while pos + 4 <= len(data):
        tag = int.from_bytes(data[pos : pos + 2], "little")
        length = int.from_bytes(data[pos + 2 : pos + 4], "little")
        pos += 4
        if pos + length > len(data):
            break
        if tag == 0x7075 and length >= 5 and data[pos] == 1:
            return data[pos + 5 : pos + length].decode("utf-8")
        pos += length
    try:
        return info.filename.encode("cp437").decode("utf-8")
    except (UnicodeError, LookupError):
        return info.filename


def validate(blob, expected):
    with zipfile.ZipFile(io.BytesIO(blob), "r") as z:
        found = {semantic_name(info): info for info in z.infolist()}
        if sorted(found) != sorted(expected):
            raise AssertionError("unexpected filenames: %r" % sorted(found))
        for name, original in expected.items():
            info = found[name]
            extracted = z.read(info)
            if extracted != original:
                raise AssertionError("data mismatch for %r" % name)
            # Descriptor bit is mandatory in a non-rewritable stdout stream.
            if (info.flag_bits & 0x8) == 0:
                raise AssertionError("no data descriptor on %r" % name)


def archive_to_file(
    command,
    cwd,
    path,
    append=False,
    reset_offset=False,
    after_prefix=False,
    input_data=None,
):
    flags = os.O_WRONLY | (
        os.O_APPEND if append else (0 if after_prefix else os.O_TRUNC)
    )
    if not path.exists():
        flags |= os.O_CREAT
    fd = os.open(str(path), flags, 0o600)
    reset_atimes(cwd, command)
    try:
        if reset_offset:
            os.lseek(fd, 0, os.SEEK_SET)
        elif after_prefix:
            os.lseek(fd, 0, os.SEEK_END)
        env = os.environ.copy()
        env.update({"TZ": "UTC", "LC_ALL": "C.UTF-8"})
        p = subprocess.run(
            command,
            cwd=cwd,
            input=input_data,
            stdout=fd,
            stderr=subprocess.PIPE,
            env=env,
            timeout=20,
        )
        if p.returncode != 0:
            raise AssertionError(
                "zip rc=%d: %s" % (p.returncode, p.stderr.decode("utf-8", "replace"))
            )
    finally:
        os.close(fd)
    return path.read_bytes()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True)
    ap.add_argument("--baseline")
    args = ap.parse_args()
    zipbin = str(pathlib.Path(args.zip).resolve())
    baseline = str(pathlib.Path(args.baseline).resolve()) if args.baseline else None
    rng = random.Random(726540)
    cases = [
        ("tiny-deflate", [], {"one.txt": b"small!\n"}, False),
        ("empty-member", [], {"empty.bin": b""}, False),
        ("stored", ["-0"], {"one.txt": b"old zip bytes\n"}, False),
        ("deflate-16k", [], {"one.txt": b"xyzQ" * 4096}, False),
        (
            "deflate-random-128k",
            [],
            {"one.txt": bytes(rng.randrange(256) for _ in range(131072))},
            False,
        ),
        ("bzip2", ["-Z", "bzip2"], {"one.txt": b"compressed " * 3000}, False),
        ("two-members", [], {"one.txt": b"first", "two.txt": b"second" * 2000}, False),
        ("unicode", [], {"тест.txt": b"non-ASCII filename"}, False),
        ("space-name", [], {"some file's name.txt": b"spaces and apostrophe"}, False),
        ("stdin-stream", [], {"-": b"streamed input, with binary\x00" * 20}, True),
    ]
    prefixes = [
        b"",
        b"#!/usr/bin/env escript\n%%!-smp\n",
        b"prefix with nothing special\n",
        b"P" * 16384,
    ]
    total = 0
    with tempfile.TemporaryDirectory(prefix="xtro-append-") as d:
        root = pathlib.Path(d)
        for casename, options, members, from_stdin in cases:
            work = root / casename
            work.mkdir()
            for name, contents in members.items():
                if name != "-":
                    dest = work / name
                    dest.write_bytes(contents)
                    os.utime(dest, (1600000000, 1600000000))
            commands = [zipbin] + options + ["-"] + list(members)
            input_data = members["-"] if from_stdin else None
            refstream = check(commands, work, input_data=input_data)
            validate(refstream, members)
            for i, prefix in enumerate(prefixes):
                file = work / ("append%d.zip" % i)
                file.write_bytes(prefix)
                result = archive_to_file(
                    commands, work, file, append=True, input_data=input_data
                )
                if result != prefix + refstream:
                    raise AssertionError(
                        "append differs from pipe: %s, prefix %d" % (casename, i)
                    )
                validate(result, members)
                total += 1
            # A seekable stdout starting after a prefix is also unsafe to
            # rewrite: re-seeking to member offset zero overwrites the prefix.
            # This is the original Erlang-escript form from Debian #726540.
            for i, prefix in enumerate(prefixes[1:]):
                file = work / ("prefixed%d.zip" % i)
                file.write_bytes(prefix)
                result = archive_to_file(
                    commands, work, file, after_prefix=True, input_data=input_data
                )
                if result != prefix + refstream:
                    raise AssertionError(
                        "prefixed seekable stdout differs: %s, prefix %d"
                        % (casename, i)
                    )
                validate(result, members)
                total += 1
            # O_APPEND still applies even if the inherited file offset is reset.
            file = work / "append-repositioned.zip"
            file.write_bytes(b"start-data\n")
            result = archive_to_file(
                commands,
                work,
                file,
                append=True,
                reset_offset=True,
                input_data=input_data,
            )
            if result != b"start-data\n" + refstream:
                raise AssertionError("append with lseek differs: " + casename)
            validate(result, members)
            total += 1
            # Seekable normal stdout must be unchanged from existing Zip code.
            file = work / "ordinary.zip"
            result = archive_to_file(commands, work, file, input_data=input_data)
            with zipfile.ZipFile(file) as z:
                info = {semantic_name(item): item for item in z.infolist()}
                for name, content in members.items():
                    if z.read(info[name]) != content:
                        raise AssertionError("ordinary seekable stdout data failure")
            if baseline:
                oldcommands = [baseline] + options + ["-"] + list(members)
                oldfile = work / "old.zip"
                oldresult = archive_to_file(
                    oldcommands, work, oldfile, input_data=input_data
                )
                if result != oldresult:
                    raise AssertionError("seekable stdout regression: " + casename)
                if refstream != check(oldcommands, work, input_data=input_data):
                    raise AssertionError("nonseekable stdout regression: " + casename)
            total += 1
    print("PASS: %d stdout output checks across %d input cases" % (total, len(cases)))
    if baseline:
        print(
            "PASS: %d seekable/nonseekable legacy-output comparisons" % (2 * len(cases))
        )


if __name__ == "__main__":
    main()
