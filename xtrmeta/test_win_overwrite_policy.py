#!/usr/bin/env python3
"""W3D2 overwrite policy regression. Host-side only, not a Windows test.

Compile the production option-selection macro under C89 and exercise every
EA/ADS selection combination. An unselected metadata class must not be
lost by selecting the historical delete/recreate path. SPDX: MIT-0.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "unzip60" / "fileio.c").read_text()
CC = os.environ.get("CC", "cc")


def check_source():
    match = re.search(
        r"^#define XTR_WIN_PRESERVE_OUTPUT[^\n]*$", SOURCE, flags=re.MULTILINE
    )
    if not match:
        raise AssertionError("native Windows overwrite policy macro is missing")
    definition = match.group(0)
    if SOURCE.count("if (XTR_WIN_PRESERVE_OUTPUT)") != 2:
        raise AssertionError("backup/overwrite policies are not both guarded")
    if SOURCE.count("if (xtr_preserve_existing)") != 2:
        raise AssertionError("both output-file modes must use the pinned opener")
    # Compile the exact definition extracted from the production file. The
    # original W3D2 definition fails this test for the both-disabled case.
    program = (
        "#include <stdio.h>\n"
        "int xtr_unzip_xattrs, xtr_unzip_streams;\n" + definition + "\n"
        "int main(void) {\n"
        "  int x, s;\n"
        "  for (x=0; x<=1; ++x) for (s=0; s<=1; ++s) {\n"
        "    xtr_unzip_xattrs=x; xtr_unzip_streams=s;\n"
        "    if (!XTR_WIN_PRESERVE_OUTPUT) return 10+x*2+s;\n"
        "  }\n"
        "  return 0;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="xtr-win-overwrite-") as temp:
        src = Path(temp) / "contract.c"
        exe = Path(temp) / "contract"
        src.write_text(program)
        proc = subprocess.run(
            [
                CC,
                "-std=c89",
                "-pedantic",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(src),
                "-o",
                str(exe),
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode:
            raise AssertionError("C89 policy compilation: " + proc.stderr)
        proc = subprocess.run([str(exe)], capture_output=True, text=True)
        if proc.returncode:
            raise AssertionError(
                "native overwrite bypasses preservation for "
                "at least one option selection (exit %d)" % proc.returncode
            )
    print("PASS: native Windows overwrite policy; 4 EA/ADS selections; C89")


if __name__ == "__main__":
    check_source()
