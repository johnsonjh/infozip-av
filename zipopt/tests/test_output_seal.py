#!/usr/bin/env python3
"""ZipOpt independent output verification and PPMd publication regression.

Exercises a real method-98 stream after the writer was closed.  On OS/2 the
native equivalent previously reopened the still-open writer and could hit a
file-sharing error; host testing also locks in the publish/no-overwrite path.
SPDX-License-Identifier: MIT-0
"""

from pathlib import Path
import subprocess
import tempfile
import zipfile


ZIPOPT = Path(__file__).resolve().parent.parent / "zipopt"
DECODECHECK = ZIPOPT.with_name("zipopt-decodecheck")


def run(*args):
    return subprocess.run(
        [str(ZIPOPT), *map(str, args)],
        text=True,
        capture_output=True,
        timeout=120,
    )


def main():
    with tempfile.TemporaryDirectory(prefix="zipopt-output-seal-") as tmp:
        base = Path(tmp)
        source = base / "input.zip"
        output = base / "output.zip"
        data = (b"OS2-ZIPOPT-PPMD-VERIFY-" * 8192) + (bytes(range(256)) * 1024)

        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("payload.bin", data, compress_type=zipfile.ZIP_STORED)

        result = run("--methods=ppmd", "--compress-level=ppmd=3", source, output)
        assert result.returncode == 0, result.stderr
        assert output.is_file(), result.stderr
        with zipfile.ZipFile(output) as archive:
            info = archive.getinfo("payload.bin")
            assert info.compress_type == 98, info.compress_type
            assert info.file_size == len(data), info.file_size

        subprocess.run(
            [str(DECODECHECK), str(output)],
            check=True,
            capture_output=True,
            timeout=120,
        )

        previous = output.read_bytes()
        result = run("--methods=ppmd", "--compress-level=ppmd=3", source, output)
        assert result.returncode != 0, result.stderr
        assert output.read_bytes() == previous, "published ZIP was overwritten"
        assert sorted(base.iterdir()) == [source, output], "temporary ZIP left behind"

    print("zipopt independent PPMd output verification: PASS")


if __name__ == "__main__":
    main()
