#!/usr/bin/env python3
"""Verify the real UnZip archive-open branches under relevant platform macros.

Host-only preprocessing check; native MinGW and NTFS execution are separate.
SPDX-License-Identifier: MIT-0.
"""

from pathlib import Path
import os
import subprocess

root = Path(__file__).resolve().parent.parent
source = (root / "unzip60" / "fileio.c").read_text()
probe = (root / "unzip60" / "process.c").read_text()
begin = source.index("#ifdef USE_STRM_INPUT\n", source.index("int open_input_file("))
end = source.index("#endif /* ?USE_STRM_INPUT */", begin) + len(
    "#endif /* ?USE_STRM_INPUT */"
)
section = source[begin:end]
start_probe = probe.index(
    "#if defined(XTR_WIN_UTF8_ACTIVE)", probe.index("int zip99_lzfse_probe(")
)
end_probe = probe.index("#endif", start_probe) + len("#endif")
probe_section = probe[start_probe:end_probe]


def run(flags, fragment):
    args = [os.environ.get("CC", "cc"), "-E", "-P", "-x", "c"]
    args.extend("-D" + flag for flag in flags)
    args.append("-")
    p = subprocess.run(args, input=fragment, text=True, capture_output=True)
    if p.returncode:
        raise AssertionError("preprocessor failed: " + p.stderr)
    return p.stdout


cases = [
    (
        ("WIN32", "XTR_WIN_UTF8_ACTIVE"),
        "xtr_win_u8_archive_fd(",
        "open(G.zipfn, O_RDONLY",
    ),
    (
        ("WIN32", "XTR_WIN_UTF8_ACTIVE", "USE_STRM_INPUT"),
        "xtr_win_u8_fopen(",
        "G.zipfd = fopen(G.zipfn, FOPR)",
    ),
    (("WIN32",), "open(G.zipfn, O_RDONLY", "xtr_win_u8_archive_fd("),
    (
        ("WIN32", "USE_STRM_INPUT"),
        "G.zipfd = fopen(G.zipfn, FOPR)",
        "xtr_win_u8_fopen(",
    ),
    ((), "open(G.zipfn, O_RDONLY", "xtr_win_u8_archive_fd("),
]
for flags, present, absent in cases:
    actual = run(flags, section)
    if present not in actual or absent in actual:
        raise AssertionError("wrong input transport for %r:\n%s" % (flags, actual))
for flags, present, absent in [
    (("WIN32", "XTR_WIN_UTF8_ACTIVE"), "xtr_win_u8_fopen(", "fp = fopen("),
    (("WIN32",), "fp = fopen(", "xtr_win_u8_fopen("),
]:
    actual = run(flags, probe_section)
    if present not in actual or absent in actual:
        raise AssertionError(
            "wrong method-99 probe transport for %r:\n%s" % (flags, actual)
        )
print("PASS: Windows archive-opening preprocessor contract; 7 configurations")
