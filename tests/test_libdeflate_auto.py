#!/usr/bin/env python3
"""Deterministic `--libdeflate-size auto` parser and error-path tests (Linux)."""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux /proc/meminfo only")
class LibdeflateAutoTests(unittest.TestCase):
    def test_mocked_windows_and_dos(self):
        mocks = ROOT / "tests/libdeflate_auto_mocks"
        with tempfile.TemporaryDirectory(prefix="xtr-auto-mocks-") as folder:
            exe = pathlib.Path(folder) / "auto-probe"
            for label, define, fake, expected in (
                ("windows", "WIN32", "windows_fake.c", 268435456),
                ("dos", "__DJGPP__", "dpmi_fake.c", 1500000),
            ):
                with self.subTest(target=label):
                    subprocess.run(
                        [
                            os.environ.get("CC", "cc"),
                            "-std=gnu89",
                            "-Wall",
                            "-Wextra",
                            "-Werror",
                            "-U__linux__",
                            f"-D{define}",
                            f"-I{mocks}",
                            str(ROOT / "tests/libdeflate_auto_probe.c"),
                            str(mocks / fake),
                            "-o",
                            str(exe),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    p = subprocess.run(
                        [str(exe), "auto"], capture_output=True, text=True
                    )
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(int(p.stdout), expected)
                    failed = subprocess.run(
                        [str(exe), "auto"],
                        capture_output=True,
                        env={**os.environ, "XLD_TEST_FAIL": "1"},
                    )
                    self.assertEqual(failed.returncode, 2)

    def test_linux_memory_query(self):
        with tempfile.TemporaryDirectory(prefix="xtr-auto-") as folder:
            tmp = pathlib.Path(folder)
            fixture = tmp / "meminfo"
            exe = tmp / "auto-probe"
            compiler = os.environ.get("CC", "cc")
            subprocess.run(
                [
                    compiler,
                    "-std=c89",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    f'-DXLD_MEMINFO_PATH="{fixture}"',
                    str(ROOT / "tests/libdeflate_auto_probe.c"),
                    "-o",
                    str(exe),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                subprocess.run(
                    [str(exe), "numeric"], capture_output=True, text=True
                ).stdout.strip(),
                "1048576",
            )
            for contents, expected in (
                ("MemTotal: 30000 kB\nMemAvailable: 8192 kB\n", 4194304),
                ("MemAvailable:\t3 kB\n", 1536),
                ("MemAvailable: 1 kB\n", 512),
                ("MemAvailable: 65536 kB\r\n", 33554432),
            ):
                with self.subTest(contents=contents):
                    fixture.write_text(contents, encoding="ascii")
                    p = subprocess.run(
                        [str(exe), "auto"], capture_output=True, text=True
                    )
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(int(p.stdout), expected)

            for contents in (
                "MemFree: 1234 kB\n",
                "MemAvailable: \n",
                "MemAvailable: 0 kB\n",
                "MemAvailable: -1 kB\n",
                "MemAvailable: +1 kB\n",
                "MemAvailable: 42 MB\n",
                "MemAvailable: 42 kB trailing\n",
            ):
                with self.subTest(invalid=contents):
                    fixture.write_text(contents, encoding="ascii")
                    p = subprocess.run([str(exe), "auto"], capture_output=True)
                    self.assertEqual(p.returncode, 2)

            fixture.unlink()
            self.assertEqual(
                subprocess.run([str(exe), "auto"], capture_output=True).returncode,
                2,
            )


if __name__ == "__main__":
    unittest.main()
