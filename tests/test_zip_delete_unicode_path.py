#!/usr/bin/env python3
"""Regression coverage for Debian #971664 / Info-ZIP #78 (Unix Zip).

Build zip30/zip, then run:
    python3 tests/test_zip_delete_unicode_path.py --zip zip30/zip

The original 192-byte attachment is embedded to make the test reproducible.
"""

import argparse
import base64
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zipfile
import zlib

ORIGINAL = base64.b64decode(
    "UEsDBAoAAAAAANy78FAAAAAAAAAAAAAAAAAIABUA4qXh4i50eHR1cBEAAX4D053RgtC10YHR"
    "gi50eHRQSwECFAAKAAAAAADcu/BQAAAAAAAAAAAAAAAACAA5AAAAAAAAACAAAAAAAAAA4qXh"
    "4i50eHR1cBEAAX4D053RgtC10YHRgi50eHQKACAAAAAAAAEAGAAAAAECsFvWAQBIiLyG"
    "56gB4G4tpnZc1gFQSwUGAAAAAAEAAQBvAAAAOwAAAAAA"
)
UNICODE_NAME = "\u0442\u0435\u0441\u0442.txt"
LEGACY_NAME = UNICODE_NAME.encode("cp866")
ESCAPED_NAME = "#U0442#U0435#U0441#U0442.txt"


def make_archive(entries):
    """Build minimal independent STORE ZIP with optional Info-ZIP Unicode Path EF.

    entries: iterable (filename bytes, content bytes, Unicode path string or
                       None, wrong CRC flag, GPBF flags).
    """
    local = bytearray()
    central = bytearray()
    for name, data, uname, bad_crc, flags in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        extra = b""
        if uname is not None:
            name_crc = zlib.crc32(name) & 0xFFFFFFFF
            if bad_crc:
                name_crc ^= 0x100
            field = struct.pack("<BI", 1, name_crc) + uname.encode("utf-8")
            extra = struct.pack("<HH", 0x7075, len(field)) + field
        offset = len(local)
        local.extend(
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                flags,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(name),
                len(extra),
            )
        )
        local.extend(name + extra + data)
        central.extend(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                flags,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(name),
                len(extra),
                0,
                0,
                0,
                0,
                offset,
            )
        )
        central.extend(name + extra)
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central),
        len(local),
        0,
    )
    return bytes(local + central + end)


class UnicodeDeleteTests(unittest.TestCase):
    zip_program = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xtro-unicode-del-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.archive = self.work / "archive.zip"
        self.archive.write_bytes(ORIGINAL)

    def command(self, *arguments, locale_name="C", extra_env=None):
        env = os.environ.copy()
        env["LC_ALL"] = locale_name
        env.pop("LOCPATH", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [self.zip_program, *arguments],
            cwd=self.work,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def delete(self, pattern=UNICODE_NAME, *options, locale_name="C", extra_env=None):
        return self.command(
            "-d",
            *options,
            "archive.zip",
            pattern,
            locale_name=locale_name,
            extra_env=extra_env
        )

    @staticmethod
    def member_has_name(member, name):
        # Python's zipfile has differed by version in whether it displays
        # the 0x7075 name or the header's legacy code-page spelling.
        if member.filename == name:
            return True
        extra = member.extra
        at = 0
        while at + 4 <= len(extra):
            kind, length = struct.unpack_from("<HH", extra, at)
            at += 4
            if at + length > len(extra):
                break
            payload = extra[at : at + length]
            if kind == 0x7075 and len(payload) >= 5 and payload[0] == 1:
                if payload[5:] == name.encode("utf-8"):
                    return True
            at += length
        return False

    def assert_deleted(self, result, remaining=()):
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("deleting:", result.stdout)
        with zipfile.ZipFile(self.archive) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(len(z.infolist()), len(remaining))
            for name in remaining:
                self.assertTrue(
                    any(self.member_has_name(e, name) for e in z.infolist()), name
                )

    def assert_unmatched(self, result, before):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("name not matched", result.stdout)
        self.assertEqual(
            before,
            self.archive.read_bytes(),
            "unmatched name unexpectedly changed archive",
        )

    def test_exact_debian_attachment_C_locale(self):
        self.assertEqual(len(ORIGINAL), 192)
        self.assert_deleted(self.delete())

    def test_exact_debian_attachment_utf8_environment_without_en_us(self):
        # LC_ALL=C.utf8 alone does not guarantee Zip's hardcoded
        # setlocale(LC_CTYPE, "en_US.UTF-8") will succeed.
        self.assert_deleted(self.delete(locale_name="C.utf8"))

    def test_successfully_initialized_utf8_locale(self):
        # glibc-specific optional fixture: make an en_US.UTF-8 alias of the
        # installed C.utf8 locale under LOCPATH without changing the system.
        lc = Path("/usr/lib/locale/C.utf8")
        if not lc.is_dir() or os.name != "posix":
            self.skipTest("glibc C.utf8 locale directory is unavailable")
        locpath = self.work / "locales"
        locpath.mkdir()
        (locpath / "en_US.utf8").symlink_to(lc, target_is_directory=True)
        try:
            cmd = subprocess.run(
                ["locale", "charmap"],
                env={**os.environ, "LOCPATH": str(locpath), "LC_ALL": "en_US.UTF-8"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if cmd.returncode or cmd.stdout.strip().upper() != b"UTF-8":
                self.skipTest("en_US.UTF-8 locale alias is not functional")
        except OSError:
            self.skipTest("locale utility is unavailable")
        # Confirm that Zip now renders the Unicode field directly instead
        # of escaped #U names, then check the existing matching behavior.
        listing = self.command(
            "-su",
            "archive.zip",
            locale_name="C.utf8",
            extra_env={"LOCPATH": str(locpath)},
        )
        self.assertEqual(listing.returncode, 0, listing.stdout)
        self.assertIn("Escaped Unicode:  " + UNICODE_NAME, listing.stdout)
        self.assert_deleted(
            self.delete(locale_name="C.utf8", extra_env={"LOCPATH": str(locpath)})
        )

    def test_original_escaped_unicode_spelling_still_matches(self):
        self.assert_deleted(self.delete(ESCAPED_NAME))

    def test_no_unicode_option_preserves_old_behavior(self):
        before = self.archive.read_bytes()
        self.assert_unmatched(self.delete(UNICODE_NAME, "-UN=no"), before)

    def test_bad_crc_does_not_enable_unicode_alias(self):
        self.archive.write_bytes(
            make_archive([(LEGACY_NAME, b"", UNICODE_NAME, True, 0)])
        )
        before = self.archive.read_bytes()
        self.assert_unmatched(self.delete(UNICODE_NAME, "-UN=ignore"), before)

    def test_no_unicode_extra_does_not_enable_alias(self):
        self.archive.write_bytes(make_archive([(LEGACY_NAME, b"", None, False, 0)]))
        before = self.archive.read_bytes()
        self.assert_unmatched(self.delete(), before)

    def test_wildcard_and_other_members_preserved(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (LEGACY_NAME, b"alpha", UNICODE_NAME, False, 0),
                    (b"readme.doc", b"other", None, False, 0),
                    (b"unrelated.txt", b"third", None, False, 0),
                ]
            )
        )
        self.assert_deleted(
            self.delete("\u0442\u0435\u0441\u0442.*"), ("readme.doc", "unrelated.txt")
        )
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(z.read("readme.doc"), b"other")
            self.assertEqual(z.read("unrelated.txt"), b"third")

    def test_ascii_entry_delete_unchanged(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (b"readme.txt", b"abc", None, False, 0),
                    (b"other.txt", b"def", None, False, 0),
                ]
            )
        )
        self.assert_deleted(self.delete("readme.txt"), ("other.txt",))

    def test_native_utf8_gpbf11_unchanged(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (UNICODE_NAME.encode("utf-8"), b"data", None, False, 0x800),
                    (b"other.txt", b"other", None, False, 0),
                ]
            )
        )
        self.assert_deleted(self.delete(), ("other.txt",))

    def test_existing_filesystem_name_does_not_change_selection(self):
        # -d must select an archive member even when a same-named disk file
        # happens to exist; it must not open or modify that disk file.
        filesystem_entry = self.work / UNICODE_NAME
        filesystem_entry.write_bytes(b"leave this on disk")
        self.assert_deleted(self.delete())
        self.assertEqual(filesystem_entry.read_bytes(), b"leave this on disk")

    def test_exact_delete_with_multiple_unicode_members(self):
        second = "\u0434\u043e\u043c.txt"
        second_cp866 = second.encode("cp866")
        self.archive.write_bytes(
            make_archive(
                [
                    (LEGACY_NAME, b"first", UNICODE_NAME, False, 0),
                    (second_cp866, b"second", second, False, 0),
                    (b"plain.txt", b"plain", None, False, 0),
                ]
            )
        )
        self.assert_deleted(self.delete(), ("plain.txt", second))
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(z.read("plain.txt"), b"plain")
            self.assertEqual(
                z.read(
                    next(e for e in z.infolist() if self.member_has_name(e, second))
                ),
                b"second",
            )

    def test_bad_crc_default_is_rejected_without_modifying_archive(self):
        self.archive.write_bytes(
            make_archive(
                [
                    (LEGACY_NAME, b"", UNICODE_NAME, True, 0),
                ]
            )
        )
        before = self.archive.read_bytes()
        result = self.delete()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, self.archive.read_bytes())

    def test_copy_mode_with_unicode_fallback(self):
        # The same archive matcher also implements --copy. Copy should
        # preserve archive member bytes, contents and the Unicode Path EF.
        self.archive.write_bytes(
            make_archive(
                [
                    (LEGACY_NAME, b"first", UNICODE_NAME, False, 0),
                    (b"plain.txt", b"second", None, False, 0),
                ]
            )
        )
        result = self.command(
            "--copy", "archive.zip", UNICODE_NAME, "--out", "copied.zip"
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        with zipfile.ZipFile(self.work / "copied.zip") as z:
            self.assertEqual(len(z.infolist()), 1)
            self.assertEqual(z.read(z.infolist()[0]), b"first")
            self.assertTrue(z.infolist()[0].extra.startswith(b"up"))

    def test_wrong_unicode_spelling_not_matched(self):
        before = self.archive.read_bytes()
        self.assert_unmatched(self.delete("wrong.txt"), before)

    def test_utf8_locale_created_archive(self):
        # Correctly encoded archives created by Python must continue to work.
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(UNICODE_NAME, b"payload")
            z.writestr("ascii.txt", b"other")
        self.assert_deleted(self.delete(), ("ascii.txt",))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--zip", required=True, help="path to the built Zip binary")
    args = p.parse_args()
    UnicodeDeleteTests.zip_program = str(Path(args.zip).resolve())
    unittest.main(argv=[__file__], verbosity=2)
