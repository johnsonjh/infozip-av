#!/usr/bin/env python3
"""Regression tests for optional libdeflate's automatic zipopt build probe.

The miniature library keeps these tests independent of a system libdeflate
installation.  The full Unix and OS/2 build wrappers are tested separately.
"""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LibdeflateBuildDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = os.environ.get("CC", "cc")
        cls.make = os.environ.get("MAKE", "make")
        cls.ar = os.environ.get("AR", "ar")
        if not all(
            shutil.which(command) for command in (cls.compiler, cls.make, cls.ar)
        ):
            raise unittest.SkipTest("requires a C compiler, make, and ar")

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="xtr-ld-build-")
        self.addCleanup(self.folder.cleanup)
        self.path = pathlib.Path(self.folder.name)
        (self.path / "libdeflate.h").write_text(
            "struct libdeflate_compressor;\n"
            "struct libdeflate_decompressor;\n"
            "struct libdeflate_compressor *libdeflate_alloc_compressor(int);\n"
            "struct libdeflate_decompressor *libdeflate_alloc_decompressor(void);\n"
            "void libdeflate_free_compressor(struct libdeflate_compressor *);\n"
            "void libdeflate_free_decompressor(struct libdeflate_decompressor *);\n",
            encoding="ascii",
        )
        (self.path / "stub.c").write_text(
            '#include "libdeflate.h"\n'
            "struct libdeflate_compressor { int value; };\n"
            "struct libdeflate_decompressor { int value; };\n"
            "static struct libdeflate_compressor c;\n"
            "static struct libdeflate_decompressor d;\n"
            "struct libdeflate_compressor *libdeflate_alloc_compressor(int n)\n"
            "{ (void)n; return &c; }\n"
            "struct libdeflate_decompressor *libdeflate_alloc_decompressor(void)\n"
            "{ return &d; }\n"
            "void libdeflate_free_compressor(struct libdeflate_compressor *p)\n"
            "{ (void)p; }\n"
            "void libdeflate_free_decompressor(struct libdeflate_decompressor *p)\n"
            "{ (void)p; }\n",
            encoding="ascii",
        )
        subprocess.run(
            [
                self.compiler,
                "-std=c89",
                "-I" + str(self.path),
                "-c",
                str(self.path / "stub.c"),
                "-o",
                str(self.path / "stub.o"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                self.ar,
                "rcs",
                str(self.path / "libdeflate.a"),
                str(self.path / "stub.o"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def probe(self, mode, library=None):
        library = library or self.path / "libdeflate.a"
        return subprocess.run(
            [
                self.make,
                "--no-print-directory",
                "-s",
                "-C",
                str(ROOT / "zipopt"),
                "--eval=print-libdeflate-mode:;@echo $(ZO_LIBDEFLATE_EFFECTIVE)",
                "print-libdeflate-mode",
                "ZO_LIBDEFLATE=" + mode,
                "ZO_LIBDEFLATE_CFLAGS=-I" + str(self.path),
                "ZO_LIBDEFLATE_LIBS=" + str(library),
            ],
            capture_output=True,
            text=True,
        )

    def test_auto_enables_linkable_library(self):
        process = self.probe("auto")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), "on")

    def test_auto_skips_missing_library(self):
        process = self.probe("auto", self.path / "absent.a")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), "off")

    def test_off_never_probes_or_enables(self):
        process = self.probe("off")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), "off")

    def test_on_requires_linkable_library(self):
        process = self.probe("on", self.path / "absent.a")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("requires linkable libdeflate", process.stderr)

    def test_on_enables_linkable_library(self):
        process = self.probe("on")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), "on")

    def test_invalid_modes_fail(self):
        for mode in ("garbage", "auto off", ""):
            with self.subTest(mode=mode):
                process = self.probe(mode)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn("must be auto, on or off", process.stderr)


if __name__ == "__main__":
    unittest.main()
