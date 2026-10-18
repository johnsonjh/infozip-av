#!/usr/bin/env python3
# Regression test for Debian #918894: effective Unix UTF-8 locale.
# Usage: python3 tests/test_utf8_locale.py [path/to/zip30]
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile

root = Path(sys.argv[1] if len(sys.argv) > 1 else "zip30").resolve()
zip_bin = str(root / "zip")
zipnote = str(root / "zipnote")
zipsplit = str(root / "zipsplit")
zipcloak = str(root / "zipcloak")

cases = (
    ("C.utf8", {}, True),
    ("C", {}, False),
    (None, {"LC_CTYPE": "C.utf8", "LANG": "C"}, True),
    (None, {"LC_CTYPE": "C", "LANG": "C.utf8"}, False),
    ("C", {"LANG": "C.utf8"}, False),
    ("C.utf8", {"LANG": "C"}, True),
    ("missing.UTF-8", {}, False),
)

names = (
    "Adiós.txt",
    "There’s a Baby in the House.flac",
    "тест.txt",
    "中文😀.txt",
    "e\u0301.txt",
    "plain.txt",
)
checks = 0


def invoke(binary, args, work, env, input_data=None):
    done = subprocess.run(
        [binary, *args],
        cwd=work,
        env=env,
        input=input_data,
        capture_output=True,
        timeout=30,
    )
    if done.returncode:
        raise AssertionError(
            f"{binary} {args}: {done.returncode}\n"
            f"stdout={done.stdout!r}\nstderr={done.stderr!r}"
        )
    return done.stdout


def verify(archive, expected):
    global checks
    with zipfile.ZipFile(archive) as zf:
        entries = zf.infolist()
        assert len(entries) == len(names), (archive, entries)
        with open(archive, "rb") as raw:
            for item, name in zip(entries, names):
                expected_bit = expected and not name.isascii()
                assert bool(item.flag_bits & 0x800) == expected_bit, (
                    name,
                    item.flag_bits,
                    expected,
                )
                raw.seek(item.header_offset)
                fixed = raw.read(30)
                assert fixed[:4] == b"PK\x03\x04"
                local_flag = struct.unpack_from("<H", fixed, 6)[0]
                assert bool(local_flag & 0x800) == expected_bit, (
                    name,
                    local_flag,
                    expected,
                )
                namelen = struct.unpack_from("<H", fixed, 26)[0]
                rawname = raw.read(namelen)
                assert rawname == name.encode("utf-8")
                assert zf.read(item) == b"payload"
                if expected:
                    assert item.filename == name, (item.filename, name)
                checks += 1


with tempfile.TemporaryDirectory(prefix="xtro-utf8-locale-") as tmp:
    work = Path(tmp)
    for name in names:
        (work / name).write_bytes(b"payload")

    runtime_cases = list(cases)
    glibc_locale = Path("/usr/lib/locale/C.utf8")
    if glibc_locale.is_dir():
        # Exercise non-US spelling and a locale deliberately forced to C,
        # even though the historical en_US.UTF-8 locale is now available.
        aliases = work / "aliases"
        aliases.mkdir()
        (aliases / "en_GB.utf8").symlink_to(glibc_locale, target_is_directory=True)
        (aliases / "en_US.utf8").symlink_to(glibc_locale, target_is_directory=True)
        (aliases / "en_GB.UTF8").symlink_to(glibc_locale, target_is_directory=True)
        (aliases / "en_GB.UTF_8").symlink_to(glibc_locale, target_is_directory=True)
        runtime_cases.extend(
            [
                ("en_GB.UTF-8", {"LOCPATH": str(aliases)}, True),
                ("C", {"LOCPATH": str(aliases)}, False),
                ("en_US.UTF-8", {"LOCPATH": str(aliases)}, True),
                ("en_GB.UTF8", {"LOCPATH": str(aliases)}, True),
                # glibc does not recognize the spelling UTF_8, even
                # with a corresponding directory present. Merely matching
                # "UTF?8" in the locale name would incorrectly set bit 11.
                ("en_GB.UTF_8", {"LOCPATH": str(aliases)}, False),
            ]
        )

    for index, (lc_all, extra, expected) in enumerate(runtime_cases):
        env = os.environ.copy()
        for key in ("LC_ALL", "LC_CTYPE", "LANG", "LOCPATH"):
            env.pop(key, None)
        if lc_all is not None:
            env["LC_ALL"] = lc_all
        env.update(extra)
        archive = work / f"test{index}.zip"
        invoke(zip_bin, [str(archive), *names], work, env)
        verify(archive, expected)

        # Re-emit an existing archive: existing native UTF-8 flags must survive.
        if expected:
            old_bytes = archive.read_bytes()
            note = invoke(zipnote, [str(archive)], work, env)
            invoke(zipnote, ["-w", str(archive)], work, env, note)
            verify(archive, expected)
            assert zipfile.is_zipfile(archive)
            assert archive.read_bytes() != b""
            checks += 1
            # A no-op ZipNote write may change archive metadata, but not data.
            assert len(old_bytes) > 0

        for tool in (zipnote, zipsplit, zipcloak):
            invoke(tool, ["-h"], work, env)
            checks += 1

    # Exactly the Debian reproduction: the program must not require
    # en_US.UTF-8 as long as C.utf8 is installed and active.
    env = os.environ.copy()
    env["LC_ALL"] = "C.utf8"
    env["LOCPATH"] = str(work / "nonexistent_locale_directory")
    archive = work / "isolated.zip"
    invoke(zip_bin, [str(archive), *names], work, env)
    verify(archive, True)

    # ZipSplit must preserve bit 11 in entries copied into a new archive.
    env = os.environ.copy()
    env["LC_ALL"] = "C.utf8"
    source = work / "test0.zip"
    invoke(zipsplit, ["-n", "65536", str(source)], work, env)
    verify(work / "test01.zip", True)

    print(f"PASS: {checks} UTF-8 locale and ZIP-header checks")
