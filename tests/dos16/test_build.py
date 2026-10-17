#!/usr/bin/env python3
"""Structural checks for native Open Watcom 8086 DOS MZ targets.

Does NOT replace runtime, CPU-instruction, or DOS conventional-memory tests.
"""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys

TOOLS = ("zip", "unzip", "zipnote", "zipcloak", "zipsplit", "funzip", "unzipsfx")
# A deliberately conservative static startup budget, leaving >256 KiB of
# 640 KiB for DOS, runtime allocations and temporary buffers. Not a DOS runtime test.
MAX_STATIC_STARTUP = 384 * 1024


def inspect_mz(path):
    content = path.read_bytes()
    if len(content) < 28 or content[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    (
        last_page,
        pages,
        reloc_count,
        hdr_pars,
        min_pars,
        max_pars,
        ss,
        sp,
        check,
        ip,
        cs,
        reloc_off,
        overlay,
    ) = struct.unpack_from("<13H", content, 2)
    if pages == 0 or hdr_pars < 2 or hdr_pars * 16 > len(content):
        raise ValueError("invalid MZ header or declared size")
    declared_len = 512 * pages - (512 - last_page if last_page else 0)
    if declared_len > len(content) or declared_len < 16 * hdr_pars:
        raise ValueError("truncated MZ load module")
    if reloc_off + 4 * reloc_count > 16 * hdr_pars:
        raise ValueError("relocations outside MZ header")
    if overlay != 0:
        raise ValueError("unexpected DOS overlay index")
    image = declared_len - 16 * hdr_pars
    min_startup = image + 16 * min_pars + 256  # DOS PSP
    if min_startup > MAX_STATIC_STARTUP:
        raise ValueError(
            "startup requires %d KiB, budget is %d KiB"
            % ((min_startup + 1023) // 1024, MAX_STATIC_STARTUP // 1024)
        )
    return len(content), image, min_pars * 16, min_startup


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2] / "dos16",
    )
    ap.add_argument(
        "--with-zipdedup",
        action="store_true",
        help="also check the optional experimental DOS16 ZipDedup executable",
    )
    args = ap.parse_args()
    targets = TOOLS + (("zipdedup",) if args.with_zipdedup else ())
    for target in targets:
        exe = args.dir / (target + ".exe")
        try:
            fsize, image, minimum, startup = inspect_mz(exe)
        except (OSError, ValueError) as error:
            print("FAIL: %s: %s" % (exe.name, error), file=sys.stderr)
            return 1
        print(
            "PASS %-12s disk=%6d image=%6d minalloc=%6d PSP+image+minalloc=%6.1f KiB"
            % (exe.name, fsize, image, minimum, startup / 1024.0)
        )
    print(
        "PASS: %d real-mode MZ images below 384-KiB static startup budget"
        % len(targets)
    )
    print(
        "NOTE: execution and 640-KiB DOS memory tests have NOT been performed by this check"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
