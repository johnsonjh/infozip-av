#!/usr/bin/env python3
"""Build/run the portable OS/2 EA reader mock against the actual C backend."""

from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
cc = shlex.split(os.environ.get("CC", "cc"))
with tempfile.TemporaryDirectory(prefix="xtro-os2-link-test-") as tmp:
    exe = Path(tmp) / "os2-link-mock"
    cmd = cc + [
        "-std=c89",
        "-D_DEFAULT_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-I" + str(ROOT / "tests" / "os2mock"),
        str(ROOT / "tests" / "test_os2link_mock.c"),
        str(ROOT / "zip30" / "os2" / "os2link.c"),
        "-o",
        str(exe),
    ]
    subprocess.run(cmd, check=True)
    subprocess.run([str(exe)], check=True)
