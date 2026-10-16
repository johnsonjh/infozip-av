#!/usr/bin/env python3
"""Guard Windows UTF-8 feature activation without rewriting LOCAL_* flags.

Host-only checks using C preprocessor and make's command preview; neither
requires MinGW nor claims a native Windows build. SPDX-License-Identifier: MIT-0.
"""

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "unzip60/win32/w32cfg.h"
MAKE = os.environ.get("MAKE", "make")
CC = os.environ.get("CC", "cc")


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def guard_fragment():
    s = HDR.read_text()
    begin = s.index("#if defined(XTR_WIN_UTF8_PATHS) &&")
    end = s.index("/* enable multibyte character set support", begin)
    return s[begin:end]


def cpp(flags):
    command = [CC, "-E", "-dM", "-x", "c", "-"]
    command.extend("-D" + name for name in flags)
    return subprocess.run(
        command,
        input=guard_fragment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_guard():
    common = ["WIN32", "__MINGW32__", "XTR_WIN_NATIVE", "XTR_WIN_UTF8_PATHS"]
    for name in (None, "SFX", "FUNZIP", "DLL", "UNZIPLIB"):
        opts = common + ([] if name is None else [name])
        p = cpp(opts)
        check(
            p.returncode == 0,
            "guard unexpectedly rejected %s: %s" % (name or "console", p.stderr),
        )
        active = "#define XTR_WIN_UTF8_ACTIVE 1" in p.stdout
        check(active == (name is None), "wrong activation in %s" % (name or "console"))
        check(
            (any(line.startswith("#define NO_MBCS") for line in p.stdout.splitlines()))
            == (name is None),
            "incorrect MBCS selection in %s" % (name or "console"),
        )
        check(
            "#define XTR_WIN_UTF8_PATHS 1" in p.stdout,
            "user feature option was stripped in %s" % (name or "console"),
        )
    for invalid in (
        ["WIN32", "__MINGW32__", "XTR_WIN_UTF8_PATHS"],
        ["WIN32", "XTR_WIN_NATIVE", "XTR_WIN_UTF8_PATHS"],
        ["__MINGW32__", "XTR_WIN_NATIVE", "XTR_WIN_UTF8_PATHS"],
    ):
        p = cpp(invalid)
        check(
            p.returncode != 0 and "native MinGW console UnZip" in p.stderr,
            "invalid console configuration was accepted: %s" % invalid,
        )
    p = cpp(["WIN32", "__MINGW32__", "XTR_WIN_NATIVE"])
    check(
        p.returncode == 0 and "XTR_WIN_UTF8_ACTIVE" not in p.stdout,
        "disabled feature was activated",
    )
    print("PASS: 9 Windows UTF-8 preprocessing configurations")


def make_commands(directory, file, target, variables):
    args = [MAKE, "-Bn", "-f", file, target] + variables
    p = subprocess.run(
        args,
        cwd=str(ROOT / directory),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    check(p.returncode == 0, "make -n %s failed: %s" % (directory, p.stderr))
    return p.stdout.splitlines()


def check_commands(lines, label, required):
    compiles = [
        line for line in lines if " -c " in line and ("gcc" in line or "clang" in line)
    ]
    check(len(compiles) > 0, "%s has no compiler commands" % label)
    for line in compiles:
        for flag in required:
            check(flag in line, "%s lost %s: %s" % (label, flag, line))
    return len(compiles)


def test_build_contract():
    count = 0
    for triple in ("i686-w64-mingw32", "x86_64-w64-mingw32"):
        unzip_vars = [
            "CC=" + triple + "-gcc",
            "RC=" + triple + "-windres",
            "NOASM=1",
            "LOCAL_UNZIP=-DXTR_WIN_NATIVE -DXTR_WIN_UTF8_PATHS -DXTR_TEST_UNZIP=1",
        ]
        lines = make_commands("unzip60", "win32/Makefile.gcc", "unzips", unzip_vars)
        for mode, selector in (
            ("console", " -o unzip.o "),
            ("SFX", " -o unzipsfx.o "),
            ("fUnZip", " -o cryptf.o "),
        ):
            selected = [x for x in lines if selector in x]
            check(len(selected) == 1, "missing %s compile command" % mode)
            check_commands(
                selected, mode, ["-DXTR_WIN_UTF8_PATHS", "-DXTR_TEST_UNZIP=1"]
            )
            count += 1
        for name in ("zipopt", "zipdedup"):
            v = [
                "CC=" + triple + "-gcc",
                "LOCAL_UNZIP=-DXTR_WIN_UTF8_PATHS -DXTR_TEST_UNZIP=1",
                "LOCAL_ZIP=-DXTR_TEST_ZIP=1",
            ]
            l = make_commands(name, "Makefile.win32", "all", v)
            uz = [x for x in l if " -c " in x and "-DXTR_TEST_UNZIP=1" in x]
            check(len(uz) > 0, "%s did not compile UnZip objects" % name)
            check_commands(uz, name, ["-DXTR_WIN_UTF8_PATHS", "-DXTR_TEST_UNZIP=1"])
            count += 1
        # Zip's objects must continue receiving their own independent flag.
        z = make_commands(
            "zip30",
            "win32/makefile.gcc",
            "zips",
            ["CC=" + triple + "-gcc", "NOASM=1", "LOCAL_ZIP=-DXTR_TEST_ZIP=1"],
        )
        check_commands(z, "Zip", ["-DXTR_TEST_ZIP=1"])
        count += 1
    # Unicode command-line shim must be linked only into console UnZip;
    # LOCAL_UNZIP must nevertheless remain on every UnZip-object compile.
    for triple in ("i686-w64-mingw32", "x86_64-w64-mingw32"):
        opts = [
            "CC=" + triple + "-gcc",
            "NOASM=1",
            "LOCAL_UNZIP=-DXTR_WIN_NATIVE -DXTR_WIN_UTF8_PATHS",
        ]
        commands = make_commands("unzip60", "win32/Makefile.gcc", "unzips", opts)
        links = [
            line
            for line in commands
            if " -o unzip.exe " in line
            or " -o funzip.exe " in line
            or " -o unzipsfx.exe " in line
        ]
        check(len(links) == 3, "expected 3 executable link commands")
        for line in links:
            check(
                ("-lshell32" in line) == (" -o unzip.exe " in line),
                "Unicode argv dependency leaked to other executable: %s" % line,
            )
    print("PASS: W3D2 link contract, i686 and x86_64")
    print("PASS: LOCAL_ZIP/LOCAL_UNZIP contract across %d build groups" % count)


if __name__ == "__main__":
    test_guard()
    test_build_contract()
    print("PASS: Windows UTF-8 build feature contract")
