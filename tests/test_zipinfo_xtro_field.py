#!/usr/bin/env python3
"""ZipInfo must identify Xtro V1's 0x5854 field on every build target."""

import argparse
import pathlib
import struct
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--unzip", required=True, help="UnZip binary with -Z")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="zipinfo-xtro-") as directory:
        archive = pathlib.Path(directory) / "extra.zip"
        member = zipfile.ZipInfo("metadata.txt")
        # The verbose listing is a field-ID registry, not a V1 decoder.
        # An arbitrary payload suffices to ensure display is independent of
        # native EA support and the optional --xattrs extraction feature.
        member.extra = (
            struct.pack("<HH", 0x5854, 4)
            + b"XTRO"
            + struct.pack("<HH", 0x1234, 1)
            + b"x"
        )
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as output:
            output.writestr(member, b"test")

        result = subprocess.run(
            [args.unzip, "-Z", "-v", str(archive)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode:
            raise SystemExit(
                "ZipInfo returned {}:\n{}".format(
                    result.returncode, result.stdout + result.stderr
                )
            )
        if "0x5854 (Xtro metadata)" not in result.stdout:
            raise SystemExit("FAIL: ZipInfo did not identify Xtro metadata")
        if "0x1234 (unknown)" not in result.stdout:
            raise SystemExit("FAIL: unknown extra-field fallback changed")
    print("ZipInfo Xtro and unknown extra-field labels: PASS")


if __name__ == "__main__":
    main()
