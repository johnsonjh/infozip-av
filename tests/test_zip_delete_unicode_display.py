#!/usr/bin/env python3
"""Follow-up display tests for Debian #971664 / Info-ZIP #78.

Run after applying the Unicode-delete selection patch and building Zip:
    python3 tests/test_zip_delete_unicode_display.py --zip zip30/zip
"""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from test_zip_delete_unicode_path import (
    ORIGINAL,
    UNICODE_NAME,
    LEGACY_NAME,
    make_archive,
)


class DeleteDisplayTests(unittest.TestCase):
    zip_program = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xtro-delete-display-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.archive = self.work / "archive.zip"
        self.archive.write_bytes(ORIGINAL)

    def runzip(self, args=None, locale="C.utf8", isolate_locale=True):
        if args is None:
            args = ["-d", "archive.zip", UNICODE_NAME]
        env = os.environ.copy()
        env["LC_ALL"] = locale
        if isolate_locale:
            # On glibc this prevents the hard-coded en_US.UTF-8 fallback
            # from accidentally succeeding through an installed locale.
            lp = self.work / "empty_locales"
            lp.mkdir(exist_ok=True)
            env["LOCPATH"] = str(lp)
        return subprocess.run(
            [self.zip_program, *args],
            cwd=self.work,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_debian_attachment_utf8_requested_locale(self):
        r = self.runzip()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(b"deleting: " + UNICODE_NAME.encode("utf-8") + b"\n", r.stdout)
        self.assertIn(b"zip warning: zip file empty", r.stdout)
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(len(z.infolist()), 0)

    def test_non_utf8_requested_locale_preserves_legacy_display(self):
        r = self.runzip(locale="C")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(b"deleting: " + LEGACY_NAME + b"\n", r.stdout)
        self.assertNotIn(UNICODE_NAME.encode("utf-8"), r.stdout)

    def test_logfile_matches_stdout_unicode(self):
        r = self.runzip(["-lf", "delete.log", "-li", "-d", "archive.zip", UNICODE_NAME])
        self.assertEqual(r.returncode, 0, r.stdout)
        expected = b"deleting: " + UNICODE_NAME.encode("utf-8")
        self.assertIn(expected, r.stdout)
        self.assertIn(expected, (self.work / "delete.log").read_bytes())

    def test_filesync_deletion_message_uses_unicode(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (LEGACY_NAME, b"", UNICODE_NAME, False, 0),
                    (b"kept.txt", b"keep", None, False, 0),
                ]
            )
        )
        (self.work / "kept.txt").write_bytes(b"keep")
        r = self.runzip(["-FS", "archive.zip", "kept.txt"])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(b"deleting: " + UNICODE_NAME.encode("utf-8"), r.stdout)
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(z.namelist(), ["kept.txt"])
            self.assertEqual(z.read("kept.txt"), b"keep")

    def test_utf8_flagged_native_archive(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (UNICODE_NAME.encode("utf-8"), b"payload", None, False, 0x800),
                    (b"other.txt", b"data", None, False, 0),
                ]
            )
        )
        r = self.runzip()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(b"deleting: " + UNICODE_NAME.encode("utf-8"), r.stdout)
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(z.namelist(), ["other.txt"])

    def test_unicode_disabled_keeps_original_ascii_name(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (b"legacy.txt", b"", UNICODE_NAME, False, 0),
                    (b"other.txt", b"data", None, False, 0),
                ]
            )
        )
        r = self.runzip(["-UN=no", "-d", "archive.zip", "legacy.txt"])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(b"deleting: legacy.txt", r.stdout)
        self.assertNotIn(UNICODE_NAME.encode("utf-8"), r.stdout)

    def test_invalid_utf8_extra_field_preserves_original_failure(self):
        payload = make_archive(
            [
                (b"legacy.txt", b"", "\u00e9.txt", False, 0),
                (b"other.txt", b"data", None, False, 0),
            ]
        )
        damaged = payload.replace(b"\xc3\xa9.txt", b"\xc3\xc3.txt")
        self.archive.write_bytes(damaged)
        r = self.runzip(["-d", "archive.zip", "legacy.txt"])
        # The pre-existing parser refuses this malformed archive; retain
        # its failure behavior and leave the input untouched.
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.archive.read_bytes(), damaged)
        self.assertNotIn(b"\xc3\xc3.txt", r.stdout)

    def test_unicode_control_character_does_not_enter_diagnostics(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (b"legacy.txt", b"", "unsafe\x1b[31m.txt", False, 0),
                    (b"other.txt", b"data", None, False, 0),
                ]
            )
        )
        r = self.runzip(["-d", "archive.zip", "legacy.txt"])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(b"deleting: legacy.txt", r.stdout)
        self.assertNotIn(b"\x1b[31m", r.stdout)

    def test_successfully_initialized_utf8_locale(self):
        glibc_locale = Path("/usr/lib/locale/C.utf8")
        if not glibc_locale.is_dir():
            self.skipTest("glibc C.utf8 locale directory unavailable")
        locpath = self.work / "locales"
        locpath.mkdir()
        (locpath / "en_US.utf8").symlink_to(glibc_locale, target_is_directory=True)
        env = dict(os.environ, LC_ALL="en_US.UTF-8", LOCPATH=str(locpath))
        try:
            rloc = subprocess.run(["locale", "charmap"], env=env, capture_output=True)
        except OSError:
            self.skipTest("locale command unavailable")
        if rloc.returncode or rloc.stdout.strip().upper() != b"UTF-8":
            self.skipTest("isolated en_US.UTF-8 alias unavailable")
        r = subprocess.run(
            [self.zip_program, "-d", "archive.zip", UNICODE_NAME],
            cwd=self.work,
            env=env,
            capture_output=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(b"deleting: " + UNICODE_NAME.encode("utf-8"), r.stdout + r.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, help="path to the built Zip binary")
    args = parser.parse_args()
    DeleteDisplayTests.zip_program = str(Path(args.zip).resolve())
    unittest.main(argv=[__file__], verbosity=2)
