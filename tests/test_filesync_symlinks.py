#!/usr/bin/env python3
"""Regression tests for Info-ZIP Debian #1005943 / upstream #74.

Run on a POSIX system after building zip30/zip:
    python3 tests/test_filesync_symlinks.py --zip zip30/zip
"""

import argparse
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
import zipfile


class FileSyncSymlinkTests(unittest.TestCase):
    zip_program = None

    def setUp(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        self.tmp = tempfile.TemporaryDirectory(prefix="xtro-filesync-")
        self.addCleanup(self.tmp.cleanup)
        self.work = pathlib.Path(self.tmp.name)
        self.tree = self.work / "tree"
        self.tree.mkdir()
        (self.tree / "file").write_bytes(b"foo\n")

    def link(self, target="file", name="link"):
        try:
            os.symlink(target, self.tree / name)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("cannot create symlinks: {}".format(exc))

    def run_zip(self, symlinks=True):
        cmd = [self.zip_program, "--verbose", "--recurse-paths", "--filesync"]
        if symlinks:
            cmd.append("--symlinks")
        cmd += ["test.zip", "tree"]
        cp = subprocess.run(
            cmd,
            cwd=str(self.work),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(cp.returncode, 0, "zip failed: {}".format(cp.stdout))
        with zipfile.ZipFile(self.work / "test.zip") as archive:
            self.assertIsNone(archive.testzip(), "ZIP CRC verification failed")
        return cp.stdout

    def contents(self, name):
        with zipfile.ZipFile(self.work / "test.zip") as archive:
            return archive.read(name)

    def names(self):
        with zipfile.ZipFile(self.work / "test.zip") as archive:
            return set(archive.namelist())

    def archive_bytes(self):
        return (self.work / "test.zip").read_bytes()

    def expect_current(self, symlinks=True):
        before = self.archive_bytes()
        output = self.run_zip(symlinks=symlinks)
        self.assertIn("Archive is current", output)
        self.assertNotIn("updating:", output)
        self.assertEqual(
            self.archive_bytes(), before, "FileSync rewrote an unchanged archive"
        )

    def test_unchanged_symlink(self):
        self.link()
        self.run_zip()
        self.assertEqual(self.contents("tree/link"), b"file")
        with zipfile.ZipFile(self.work / "test.zip") as archive:
            mode = archive.getinfo("tree/link").external_attr >> 16
            self.assertTrue(stat.S_ISLNK(mode))
        self.expect_current()
        self.expect_current()

    def test_dangling_symlink(self):
        self.link("target-does-not-exist")
        self.run_zip()
        self.assertEqual(self.contents("tree/link"), b"target-does-not-exist")
        self.expect_current()

    def test_symlink_to_directory(self):
        (self.tree / "subdir").mkdir()
        (self.tree / "subdir" / "nested").write_bytes(b"nested\n")
        self.link("subdir")
        self.run_zip()
        self.assertEqual(self.contents("tree/link"), b"subdir")
        self.assertIn("tree/subdir/nested", self.names())
        self.expect_current()

    def test_symlink_target_size_change(self):
        self.link()
        self.run_zip()
        os.unlink(self.tree / "link")
        self.link("nonexistent-longer-target")
        output = self.run_zip()
        self.assertIn("updating: tree/link", output)
        self.assertEqual(self.contents("tree/link"), b"nonexistent-longer-target")
        self.expect_current()

    def test_same_size_target_changed_timestamp(self):
        self.link()
        self.run_zip()
        old_mtime = os.lstat(self.tree / "link").st_mtime
        os.unlink(self.tree / "link")
        self.link("next")
        try:
            os.utime(
                self.tree / "link",
                (old_mtime + 6, old_mtime + 6),
                follow_symlinks=False,
            )
        except (NotImplementedError, OSError) as exc:
            self.skipTest("cannot set symlink mtime: {}".format(exc))
        output = self.run_zip()
        self.assertIn("updating: tree/link", output)
        self.assertEqual(self.contents("tree/link"), b"next")
        self.expect_current()

    def test_regular_file_update_does_not_update_symlink(self):
        self.link()
        self.run_zip()
        old_mtime = (self.tree / "file").stat().st_mtime
        (self.tree / "file").write_bytes(b"bar\n")
        os.utime(self.tree / "file", (old_mtime + 6, old_mtime + 6))
        output = self.run_zip()
        self.assertIn("updating: tree/file", output)
        self.assertNotIn("updating: tree/link", output)
        self.assertEqual(self.contents("tree/file"), b"bar\n")
        self.assertEqual(self.contents("tree/link"), b"file")
        self.expect_current()

    def test_default_follows_symlink(self):
        self.link()
        self.run_zip(symlinks=False)
        self.assertEqual(self.contents("tree/link"), b"foo\n")
        with zipfile.ZipFile(self.work / "test.zip") as archive:
            mode = archive.getinfo("tree/link").external_attr >> 16
            self.assertTrue(stat.S_ISREG(mode))
        self.expect_current(symlinks=False)

    def test_add_and_delete_symlink(self):
        self.run_zip()
        self.expect_current()
        self.link()
        self.run_zip()
        self.assertIn("tree/link", self.names())
        self.expect_current()
        os.unlink(self.tree / "link")
        self.run_zip()
        self.assertNotIn("tree/link", self.names())
        self.expect_current()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", default="zip30/zip", help="Zip executable")
    args = parser.parse_args()
    FileSyncSymlinkTests.zip_program = str(pathlib.Path(args.zip).resolve())
    unittest.main(argv=[__file__], verbosity=2)
