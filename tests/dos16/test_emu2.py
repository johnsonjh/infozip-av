#!/usr/bin/env python3
"""Optional real execution smoke tests for DOS16 Zip/UnZip under emu2.

Usage: python3 tests/dos16/test_emu2.py --emu2 /path/to/emu2
Requires a compatible DOS filesystem emulator. Not run by build-all.sh.
For full release validation, also test 640 KiB conventional DOS and AES AE-3.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emu2", default="emu2")
    parser.add_argument(
        "--bin",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2] / "dos16",
    )
    args = parser.parse_args()
    binary = shutil.which(args.emu2)
    if binary is None:
        parser.error("emu2 not available; this runtime test cannot be executed")
    with tempfile.TemporaryDirectory(prefix="xtro-dos16-") as tmp:
        root = pathlib.Path(tmp)
        # Keep all DOS-visible names within 8.3 for original DOS compatibility.
        payload = (b"16-bit DOS Zip round trip\r\n" * 101) + bytes(range(256))
        (root / "INPUT.TXT").write_bytes(payload)

        def run(tool, *opts):
            command = [binary, str((args.bin / (tool + ".exe")).resolve()), *opts]
            print("RUN", tool, " ".join(opts), flush=True)
            result = subprocess.run(
                command,
                cwd=root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=False,
            )
            if result.returncode:
                raise RuntimeError(
                    "%s exit %d: %s"
                    % (
                        tool,
                        result.returncode,
                        result.stdout.decode("latin-1", "replace")[-1200:],
                    )
                )
            return result.stdout

        run("zip", "-0", "STORE.ZIP", "INPUT.TXT")
        run("zip", "-9", "DEFL.ZIP", "INPUT.TXT")
        run("unzip", "-t", "STORE.ZIP")
        run("unzip", "-t", "DEFL.ZIP")
        # AES-128 standard checks AES availability and interoperability without
        # the very high KDF cost of AE-3 on an 8086; AE-3 needs a separate test.
        run(
            "zip",
            "-0",
            "-eP",
            "dos16test",
            "--aes-strength",
            "128",
            "AES.ZIP",
            "INPUT.TXT",
        )
        run("unzip", "-t", "-P", "dos16test", "AES.ZIP")
        if not (root / "STORE.ZIP").exists() or not (root / "AES.ZIP").exists():
            raise RuntimeError("DOS emulator did not publish expected archive")
        import zipfile

        with zipfile.ZipFile(root / "STORE.ZIP") as z:
            if z.read("INPUT.TXT") != payload:
                raise RuntimeError("STORE round-trip mismatch")
        with zipfile.ZipFile(root / "DEFL.ZIP") as z:
            if z.read("INPUT.TXT") != payload:
                raise RuntimeError("DEFLATE round-trip mismatch")
        print("PASS: emu2 STORE, DEFLATE, AES-standard smoke tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
