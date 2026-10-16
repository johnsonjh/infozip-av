#!/usr/bin/env python3
"""MIT-0. Generate minimal canonical XTMD corpus for LLVM libFuzzer."""

import struct
import sys
from pathlib import Path


def main(folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    owner = bytes(range(1, 17))
    header = b"XTMD\x01\0\0\0" + owner
    (folder / "empty.xtm").write_bytes(header + struct.pack("<IQ", 0, 0))
    tlv = struct.pack("<HHIH", 1, 0, 2, 1)
    record = (
        struct.pack("<HHHHIIIQ", 1, 0, 1, 0, 4, 4, len(tlv), 8)
        + b"user"
        + b"test"
        + tlv
        + b"12345678"
    )
    (folder / "valid.xtm").write_bytes(
        header + struct.pack("<IQ", 1, len(record)) + record
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: fuzzer_seeds.py DIRECTORY")
    main(sys.argv[1])
