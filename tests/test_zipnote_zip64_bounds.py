#!/usr/bin/env python3
"""ZIP64 extra-field bounds regression for Debian #952509 (ZipNote 3.0).

Runs without external packages.  Pass --zipnote PATH; optionally pass
--baseline PATH to assert unchanged output bytes for valid archives.
"""

import argparse
import base64
import hashlib
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

# Original 718-byte Debian/Info-ZIP sample, supplied with bug #952509.
DEBIAN_SAMPLE = base64.b64decode(
    "UEsDBAoAAAAKADxpJVAAAAAAAAAAHACUAAAJAAIALQAybXBsZXMvVVQJAAN0JhJegiYSXnV4CwAB"
    "BOkDAAAE6QMAAFBLAQIeAwoAAAAAADxpJVAAAAAAAAAAAP////8pABgAAAAAAAAAEADtTwAAAABl"
    "eGFtcGxlcy9VVAUAA3QmEl6QbAsAAQTpAwAABOkDAABQSwUGAAAAAAEAHwBPAPW/jSzjg5ss44Od"
    "LOOCuyws44OfLOODj0Djg5gsLCzjg4pdPVshIeOCpl0rIeOCpivjgqYu44KmKVvjgqIrPeOCpivj"
    "g4or44OYK+ODjSvjg5sr45mMK+OCoivjg40r4wAAUEsBAh4DCgAAAAAAPGklUAAAAAAAAAAA////"
    "/ykAGAAAAAAAAAAQAO1DAAAAAGV4YW1wbGVzAAAE6QMAAFBLBQYAAAAAAQABAE8A9YONLOODmyzj"
    "g4ws44K7LCzjg58s44OPLOODmCwsLOODil09WyEh44KmXSsh44KmK+OCAwMDAwMDAwMDAwMDAwMD"
    "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAwMDAwMD"
    "AAAAG2klUAAAPT09PT09PT09PT09PT09PT09PT0AAAAAAAAAAP/reAsAAQTpAwAABOkDAAFQSwUG"
    "AO9QSwEDAAAE6QMAAVBLBQYAAAAAAQACAHQmAABDAAAApwBAIChbLOOCpiwsLCzjgr9dPVtdK3t9"
    "LFvjg40s44ObPuODjCzjgrssLOODnyzjg48s44OYLCws44OKXT1bISHjgqZdKyHjgqYr44KmLuOC"
    "pilb44KiKz3jgqYr44OKK+ODmCvjg40r44ObK+ODjCvjgqIr4wAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAA=="
)


def field(tag, data):
    return struct.pack("<HH", tag, len(data)) + data


def synthetic(case):
    """One stored empty file with independently configurable ZIP64 fields."""
    markers = case.get("markers", "")
    zdata = case.get("zip64", b"")
    preceding = case.get("preceding", b"")
    following = case.get("following", b"")
    extra_c = preceding + (field(1, zdata) if zdata is not None else b"") + following
    local_extra = case.get("local_extra", b"")
    name = case.get("name", b"test.txt")
    loc_size = 0xFFFFFFFF if case.get("local_marker") else 0
    header_l = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        45,
        0,
        0,
        0,
        0,
        0,
        loc_size,
        loc_size,
        len(name),
        len(local_extra),
    )
    local = header_l + name + local_extra
    comp = 0xFFFFFFFF if "s" in markers else 0
    uncomp = 0xFFFFFFFF if "l" in markers else 0
    off = 0xFFFFFFFF if "o" in markers else 0
    disk = 0xFFFF if "d" in markers else 0
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            (3 << 8) | 45,
            45,
            0,
            0,
            0,
            0,
            0,
            comp,
            uncomp,
            len(name),
            len(extra_c),
            0,
            disk,
            0,
            0,
            off,
        )
        + name
        + extra_c
    )
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def run(args, data=None):
    p = subprocess.run(
        args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8
    )
    combined = p.stdout + p.stderr
    if (
        p.returncode < 0
        or b"AddressSanitizer" in combined
        or b"UndefinedBehaviorSanitizer" in combined
        or b"runtime error:" in combined
    ):
        raise AssertionError(
            "crash/sanitizer failure: %r\n%s"
            % (args, combined[-2500:].decode("utf8", "replace"))
        )
    return p


class Zip64Bounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="zipnote-952509-")
        cls.dir = pathlib.Path(cls.tmp.name)
        cls.zipnote = pathlib.Path(OPTIONS.zipnote).resolve()
        cls.baseline = (
            pathlib.Path(OPTIONS.baseline).resolve() if OPTIONS.baseline else None
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def execute(self, payload, want_success, comments=False):
        file = self.dir / (self.id().split(".")[-1] + ".zip")
        file.write_bytes(payload)
        before = hashlib.sha256(payload).hexdigest()
        read = run([str(self.zipnote), str(file)])
        if want_success:
            self.assertEqual(read.returncode, 0, read.stderr)
            note = read.stdout
            if comments:
                note = note.replace(
                    b"@ (comment above this line)",
                    b"entry comment\n@ (comment above this line)",
                    1,
                )
                note += b"archive comment\n"
            write = run([str(self.zipnote), "-w", str(file)], note)
            self.assertEqual(write.returncode, 0, write.stderr)
            with zipfile.ZipFile(file) as z:
                self.assertEqual(z.namelist(), ["test.txt"])
                self.assertIsNone(z.testzip())
                self.assertEqual(z.read("test.txt"), b"")
                if comments:
                    self.assertEqual(z.comment, b"archive comment")
                    self.assertEqual(z.getinfo("test.txt").comment, b"entry comment")
            if self.baseline:
                comparison = self.dir / (file.stem + "-baseline.zip")
                comparison.write_bytes(payload)
                baseline_note = run([str(self.baseline), str(comparison)])
                self.assertEqual(baseline_note.returncode, 0, baseline_note.stderr)
                if comments:
                    old_note = baseline_note.stdout.replace(
                        b"@ (comment above this line)",
                        b"entry comment\n@ (comment above this line)",
                        1,
                    )
                    old_note += b"archive comment\n"
                else:
                    old_note = baseline_note.stdout
                self.assertEqual(
                    run(
                        [str(self.baseline), "-w", str(comparison)], old_note
                    ).returncode,
                    0,
                )
                self.assertEqual(
                    file.read_bytes(),
                    comparison.read_bytes(),
                    "valid archive differs from unpatched output",
                )
        else:
            # A malformed archive can be rejected while reading or writing,
            # but must never crash or be damaged by a failed rewrite.
            note = read.stdout if read.returncode == 0 else b""
            write = run([str(self.zipnote), "-w", str(file)], note)
            self.assertNotEqual(
                write.returncode, 0, "malformed ZIP64 field unexpectedly accepted"
            )
            self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), before)

    def test_01_debian_original(self):
        file = self.dir / "debian_crash00.zip"
        file.write_bytes(DEBIAN_SAMPLE)
        initial = hashlib.sha256(file.read_bytes()).digest()
        r = run([str(self.zipnote), str(file)])
        w = run(
            [str(self.zipnote), "-w", str(file)], r.stdout if r.returncode == 0 else b""
        )
        self.assertNotEqual(w.returncode, 0)
        self.assertEqual(hashlib.sha256(file.read_bytes()).digest(), initial)

    def test_02_truncated_zip64_0(self):
        self.execute(synthetic(dict(markers="ls", zip64=b"")), False)

    def test_03_truncated_zip64_4(self):
        self.execute(synthetic(dict(markers="ls", zip64=b"\0" * 4)), False)

    def test_04_truncated_zip64_8(self):
        self.execute(synthetic(dict(markers="ls", zip64=b"\0" * 8)), False)

    def test_05_truncated_zip64_12(self):
        self.execute(synthetic(dict(markers="ls", zip64=b"\0" * 12)), False)

    def test_06_truncated_zip64_offset(self):
        self.execute(synthetic(dict(markers="o", zip64=b"")), False)

    def test_07_truncated_zip64_disk(self):
        self.execute(synthetic(dict(markers="d", zip64=b"")), False)

    def test_08_truncated_zip64_combo(self):
        self.execute(synthetic(dict(markers="lsod", zip64=b"\0" * 24)), False)

    def test_09_truncated_local_zip64(self):
        self.execute(
            synthetic(
                dict(
                    markers="",
                    zip64=None,
                    local_marker=True,
                    local_extra=field(1, b"\0" * 8),
                )
            ),
            False,
        )

    def test_10_valid_zip64_16(self):
        self.execute(synthetic(dict(markers="ls", zip64=b"\0" * 16)), True)

    def test_11_valid_zip64_8_len(self):
        self.execute(synthetic(dict(markers="l", zip64=b"\0" * 8)), True)

    def test_12_valid_zip64_8_size(self):
        self.execute(synthetic(dict(markers="s", zip64=b"\0" * 8)), True)

    def test_13_valid_zip64_offset(self):
        self.execute(synthetic(dict(markers="o", zip64=b"\0" * 8)), True)

    def test_14_valid_zip64_with_other_fields(self):
        self.execute(
            synthetic(
                dict(
                    markers="ls",
                    zip64=b"\0" * 16,
                    preceding=field(0x5455, b"\x03\0\0\0\0"),
                    following=field(0x7875, b"\x01\0"),
                )
            ),
            True,
        )

    def test_15_valid_zip64_and_comments(self):
        self.execute(
            synthetic(dict(markers="ls", zip64=b"\0" * 16)), True, comments=True
        )

    def test_16_valid_simple_archive(self):
        self.execute(synthetic(dict(markers="", zip64=None)), True, comments=True)

    def test_17_valid_local_zip64(self):
        self.execute(
            synthetic(
                dict(
                    markers="",
                    zip64=None,
                    local_marker=True,
                    local_extra=field(1, b"\0" * 16),
                )
            ),
            True,
        )

    def test_19_deterministic_zip64_mutations(self):
        # Boundary sweep of payload lengths, all four sentinel types,
        # field placement, and local-field layout.  Check that no invalid
        # or inconvenient input can crash either ZipNote operation.
        cases = 0
        for markers in ("l", "s", "ls", "o", "d", "lsod"):
            for size in range(0, 33, 2):
                for prefix in (b"", field(0x5455, b"\x03\0\0\0\0")):
                    sample = synthetic(
                        dict(markers=markers, zip64=b"\0" * size, preceding=prefix)
                    )
                    file = self.dir / ("mutation_%04d.zip" % cases)
                    file.write_bytes(sample)
                    old = hashlib.sha256(sample).digest()
                    read = run([str(self.zipnote), str(file)])
                    write = run(
                        [str(self.zipnote), "-w", str(file)],
                        read.stdout if read.returncode == 0 else b"",
                    )
                    if write.returncode:
                        self.assertEqual(
                            hashlib.sha256(file.read_bytes()).digest(), old
                        )
                    cases += 1
        self.assertEqual(cases, 204)

    def test_18_valid_ordinary_python_zip(self):
        p = self.dir / "standard.zip"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("name.txt", b"infozip zipnote comment test" * 60)
        input_bytes = p.read_bytes()
        r = run([str(self.zipnote), str(p)])
        self.assertEqual(r.returncode, 0, r.stderr)
        w = run([str(self.zipnote), "-w", str(p)], r.stdout)
        self.assertEqual(w.returncode, 0, w.stderr)
        with zipfile.ZipFile(p) as z:
            self.assertEqual(z.read("name.txt"), b"infozip zipnote comment test" * 60)
        if self.baseline:
            base = self.dir / "standard-base.zip"
            base.write_bytes(input_bytes)
            n = run([str(self.baseline), str(base)])
            self.assertEqual(
                run([str(self.baseline), "-w", str(base)], n.stdout).returncode, 0
            )
            self.assertEqual(p.read_bytes(), base.read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zipnote", required=True)
    parser.add_argument("--baseline")
    OPTIONS, unittest_args = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0]] + unittest_args)
