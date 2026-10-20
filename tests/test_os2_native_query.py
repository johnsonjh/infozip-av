#!/usr/bin/env python3
"""Run the native OS/2 EA query implementation against a Linux Dos* mock."""

from pathlib import Path
import os
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="xtro-os2-native-query-") as tmp:
    cmd = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c89",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-O2",
        "-I" + str(root / "tests" / "os2native_mock"),
        str(root / "tests" / "test_os2_native_query.c"),
        str(root / "xtrmeta" / "xtros2_native.c"),
        str(root / "xtrmeta" / "xtros2_ea.c"),
        "-o",
        str(Path(tmp) / "native_query"),
    ]
    subprocess.run(cmd, check=True)
    subprocess.run([str(Path(tmp) / "native_query")], check=True)
