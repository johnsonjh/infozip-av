#!/usr/bin/env python3
"""SOURCE_DATE_EPOCH runtime regression tests for an already-built Xtro Zip.

Run from the project root: python3 tests/test_source_date_epoch.py --zip zip30/zip
"""

import argparse
import os
from pathlib import Path
import select
import signal
import subprocess
import struct
import tempfile
import time
import unittest
import zipfile

EPOCH = "946684801"  # 2000-01-01 00:00:01 UTC; ZIP must round DOWN.
BAD = [
    "",
    "1",
    "315532799",
    "2147483648",
    "-315532800",
    "+315532800",
    " 946684801",
    "946684801 ",
    "946684801x",
    "99999999999999999999",
    "946684801;touch injected",
    "946684801\n0",
]


def run(*argv, epoch=EPOCH, tz="UTC", insecure=None, cwd=None, locale="C"):
    env = os.environ.copy()
    env.pop("SOURCE_DATE_EPOCH", None)
    env.pop("SOURCE_DATE_EPOCH_INSECURE", None)
    if epoch is not None:
        env["SOURCE_DATE_EPOCH"] = epoch
    if insecure is not None:
        env["SOURCE_DATE_EPOCH_INSECURE"] = insecure
    env["TZ"] = tz
    env["LC_ALL"] = locale
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)


def run_zipcloak_tty(program, source, output, decrypt=False, insecure=None):
    """Drive ZipCloak's documented interactive password prompt on POSIX."""
    import pty

    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = EPOCH
    env.pop("SOURCE_DATE_EPOCH_INSECURE", None)
    if insecure is not None:
        env["SOURCE_DATE_EPOCH_INSECURE"] = insecure
    argv = [str(program), "-O", str(output)]
    if decrypt:
        argv.append("-d")
    argv.append(str(source))
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(str(program), argv, env)
    transcript = b""
    enter_sent = verify_sent = False
    status = None
    try:
        end = time.monotonic() + 15
        while time.monotonic() < end:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    data = b""
                transcript += data
            if not enter_sent and b"Enter password:" in transcript:
                os.write(fd, b"testing\n")
                enter_sent = True
            if not verify_sent and b"Verify password:" in transcript:
                os.write(fd, b"testing\n")
                verify_sent = True
            child, code = os.waitpid(pid, os.WNOHANG)
            if child == pid:
                status = code
                break
        if status is None:
            raise AssertionError(
                "ZipCloak password prompt timed out: " + repr(transcript[-500:])
            )
        return os.waitstatus_to_exitcode(status), transcript.decode(errors="replace")
    finally:
        os.close(fd)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


class ReproducibleZip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zip = Path(ARGS.zip).resolve()
        if not cls.zip.is_file():
            raise unittest.SkipTest("Zip executable not built: " + str(cls.zip))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xtro-sde-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        for name in ("z-file", "A-file", "e-file"):
            (self.data / name).write_bytes((name * 199).encode("ascii"))
        for path in self.data.iterdir():
            os.utime(path, (1735689000, 1735689000))

    def test_invalid_epoch_prevents_publication(self):
        for bad in BAD:
            output = self.root / "out.zip"
            p = run(
                self.zip, "-q", str(output), "data/A-file", cwd=self.root, epoch=bad
            )
            self.assertNotEqual(p.returncode, 0, repr(bad))
            self.assertIn("SOURCE_DATE_EPOCH", p.stderr, repr(bad))
            self.assertFalse(output.exists(), repr(bad))

    def test_posix_build_validator(self):
        helper = Path("tests/source-date-epoch-build.sh").resolve()
        for bad in BAD:
            p = run("sh", str(helper), "flags", epoch=bad, cwd=self.root)
            self.assertNotEqual(p.returncode, 0, repr(bad))
            self.assertIn("SOURCE_DATE_EPOCH", p.stderr, repr(bad))
        for value, expected in (
            ("315532800", "1980-01-01T00:00:00Z"),
            ("946684801", "2000-01-01T00:00:01Z"),
            ("2147483647", "2038-01-19T03:14:07Z"),
        ):
            p = run("sh", str(helper), "utc", epoch=value, cwd=self.root)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), expected)

    def test_every_available_utility_rejects_invalid_epoch(self):
        tools = (
            self.zip,
            Path(ARGS.zipopt),
            Path(ARGS.zipdedup),
            Path(ARGS.zipcloak),
            Path(ARGS.zipnote),
            Path(ARGS.zipsplit),
            Path(ARGS.unzip),
            Path(ARGS.funzip),
        )
        for candidate in tools:
            program = candidate.resolve()
            if not program.is_file():
                continue
            p = run(program, "-h", epoch="2147483648", cwd=self.root)
            self.assertNotEqual(p.returncode, 0, str(program))
            self.assertIn("SOURCE_DATE_EPOCH", p.stdout + p.stderr, str(program))

    def test_identical_archive_across_timezone_and_file_mtime(self):
        outputs = []
        for index, (tz, locale) in enumerate(
            (("Pacific/Auckland", "C"), ("America/New_York", "en_US.utf8"))
        ):
            for path in self.data.iterdir():
                os.utime(path, (1735689600 + index * 3600, 1735689600 + index * 3600))
            output = self.root / ("run%d.zip" % index)
            p = run(
                self.zip,
                "-q",
                "-r",
                str(output),
                "data",
                cwd=self.root,
                tz=tz,
                locale=locale,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            outputs.append(output.read_bytes())
            with zipfile.ZipFile(output) as zf:
                names = zf.namelist()
                self.assertEqual(names, sorted(names, key=lambda n: n.encode()))
                for info in zf.infolist():
                    self.assertEqual(info.date_time, (2000, 1, 1, 0, 0, 0))
        self.assertEqual(outputs[0], outputs[1])

    def test_old_serialized_dates_not_raised(self):
        output = self.root / "old.zip"
        os.utime(self.data / "A-file", (315532800, 315532800))
        p = run(self.zip, "-q", str(output), "data/A-file", cwd=self.root)
        self.assertEqual(p.returncode, 0, p.stderr)
        with zipfile.ZipFile(output) as zf:
            self.assertEqual(zf.infolist()[0].date_time, (1980, 1, 1, 0, 0, 0))

    def test_explicit_file_order(self):
        output = self.root / "ordered.zip"
        p = run(
            self.zip, "-q", str(output), "data/z-file", "data/A-file", cwd=self.root
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        with zipfile.ZipFile(output) as zf:
            self.assertEqual(zf.namelist(), ["data/z-file", "data/A-file"])

    def test_log_build_time_is_epoch_utc(self):
        output = self.root / "logged.zip"
        logfile = self.root / "logged.txt"
        p = run(
            self.zip,
            "-q",
            "-lf",
            str(logfile),
            str(output),
            "data/A-file",
            cwd=self.root,
            tz="Pacific/Auckland",
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        log = logfile.read_text()
        self.assertIn("Zip log opened Sat Jan  1 00:00:01 2000", log)
        self.assertIn("Done Sat Jan  1 00:00:01 2000", log)

    def test_preserved_members_keep_original_timestamp(self):
        output = self.root / "updated.zip"
        old = zipfile.ZipInfo("preserved", (2030, 1, 1, 0, 0, 0))
        old.extra = b"\x34\x12\x04\x00ABCD"  # unknown vendor field
        with zipfile.ZipFile(output, "w") as zf:
            zf.writestr(old, b"untouched content")
        p = run(self.zip, "-q", str(output), "data/A-file", cwd=self.root)
        self.assertEqual(p.returncode, 0, p.stderr)
        with zipfile.ZipFile(output) as zf:
            info = zf.getinfo("preserved")
            self.assertEqual(info.date_time, (2030, 1, 1, 0, 0, 0))
            self.assertEqual(info.extra, old.extra)
            self.assertEqual(zf.read("preserved"), b"untouched content")
            self.assertEqual(zf.getinfo("data/A-file").date_time, (2000, 1, 1, 0, 0, 0))

    def test_double_optin_traditional_encryption(self):
        output = self.root / "encrypted.zip"
        p = run(
            self.zip, "-q", "-P", "testing", str(output), "data/A-file", cwd=self.root
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(
            "SOURCE_DATE_EPOCH_INSECURE",
            p.stderr + p.stdout,
            (p.returncode, p.stderr, p.stdout),
        )
        self.assertFalse(output.exists())
        empty = run(
            self.zip,
            "-q",
            "-P",
            "testing",
            str(output),
            "data/A-file",
            cwd=self.root,
            insecure="",
        )
        self.assertNotEqual(empty.returncode, 0)
        self.assertFalse(output.exists())
        first = run(
            self.zip,
            "-q",
            "-P",
            "testing",
            str(output),
            "data/A-file",
            cwd=self.root,
            insecure="yes",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("INSECURE", first.stderr)
        next_output = self.root / "second.zip"
        second = run(
            self.zip,
            "-q",
            "-P",
            "testing",
            str(next_output),
            "data/A-file",
            cwd=self.root,
            insecure="yes",
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(output.read_bytes(), next_output.read_bytes())
        with zipfile.ZipFile(output) as zf:
            self.assertEqual(
                zf.read("data/A-file", pwd=b"testing"),
                (self.data / "A-file").read_bytes(),
            )

    def test_insecure_alone_does_nothing(self):
        p = run(self.zip, "-h", cwd=self.root, epoch=None, insecure="yes")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("SOURCE_DATE_EPOCH_INSECURE", p.stderr)

    def test_unset_epoch_matches_pristine_cu109(self):
        if not ARGS.baseline_zip:
            self.skipTest("pass --baseline-zip for pristine byte comparison")
        baseline = Path(ARGS.baseline_zip).resolve()
        if not baseline.is_file():
            self.skipTest("pristine Zip executable not built")
        for index, args in enumerate(
            (
                ["-q", "-r"],
                ["-q", "-Z", "store", "-r"],
                ["-q", "--fwkcs-md5", "-r"],
                ["-q", "-Z", "deflate64", "-r"],
            )
        ):
            snapshots = []
            for program in (baseline, self.zip):
                for path in self.data.iterdir():
                    os.utime(path, (1735689600, 1735689600))
                output = self.root / (
                    "comparison%d-%s.zip" % (index, program.parent.name)
                )
                p = run(program, *args, str(output), "data", cwd=self.root, epoch=None)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                snapshots.append(output.read_bytes())
            self.assertEqual(
                snapshots[0], snapshots[1], "unset epoch differs on case " + repr(args)
            )

    def test_double_optin_aes_streams(self):
        for name, options in (("aes", []), ("ae3", ["--aes-mode", "quantum"])):
            first = self.root / (name + "1.zip")
            second = self.root / (name + "2.zip")
            args = ["-q", "-eP", "testing"] + options
            reject = run(self.zip, *args, str(first), "data/A-file", cwd=self.root)
            self.assertNotEqual(reject.returncode, 0, reject.stdout + reject.stderr)
            self.assertIn("SOURCE_DATE_EPOCH_INSECURE", reject.stdout + reject.stderr)
            self.assertFalse(first.exists())
            a = run(
                self.zip,
                *args,
                str(first),
                "data/A-file",
                cwd=self.root,
                insecure="unsafe",
                tz="Asia/Tokyo"
            )
            b = run(
                self.zip,
                *args,
                str(second),
                "data/A-file",
                cwd=self.root,
                insecure="unsafe",
                tz="America/New_York"
            )
            self.assertEqual(a.returncode, 0, a.stdout + a.stderr)
            self.assertEqual(b.returncode, 0, b.stdout + b.stderr)
            self.assertIn("INSECURE", a.stdout + a.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_zipopt_selective_timestamps(self):
        tool = Path(ARGS.zipopt).resolve()
        if not tool.is_file():
            self.skipTest("zipopt not built")
        source = self.root / "zopt-input.zip"
        newer = zipfile.ZipInfo("repacked", (2030, 1, 1, 0, 0, 0))
        newer.compress_type = zipfile.ZIP_DEFLATED
        newer.extra = b"\x55\x54\x05\x00\x01" + struct.pack("<I", 1893456000)
        preserved = zipfile.ZipInfo("preserved-store", (2030, 1, 1, 0, 0, 0))
        preserved.extra = newer.extra
        with zipfile.ZipFile(source, "w") as zf:
            zf.writestr(newer, b"abcdef" * 300)
            zf.writestr(preserved, b"stable")
        a = self.root / "zopt-a.zip"
        b = self.root / "zopt-b.zip"
        for dst, tz in ((a, "Asia/Tokyo"), (b, "America/New_York")):
            p = run(
                tool, "--methods=store", str(source), str(dst), cwd=self.root, tz=tz
            )
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            with zipfile.ZipFile(dst) as zf:
                self.assertEqual(zf.read("repacked"), b"abcdef" * 300)
                self.assertEqual(
                    zf.getinfo("repacked").date_time, (2000, 1, 1, 0, 0, 0)
                )
                self.assertEqual(
                    zf.getinfo("preserved-store").date_time, (2030, 1, 1, 0, 0, 0)
                )
                self.assertEqual(zf.getinfo("preserved-store").extra, preserved.extra)
        self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_linux_xattrs_deterministic_owner_ids(self):
        if os.name != "posix" or not hasattr(os, "setxattr"):
            self.skipTest("native xattrs unavailable")
        path = self.data / "A-file"
        try:
            os.setxattr(path, "user.sde-alpha", b"alpha")
            os.setxattr(path, "user.sde-beta", b"beta")
        except OSError:
            self.skipTest("filesystem does not permit user xattrs")
        output = []
        for i, tz in enumerate(("Asia/Tokyo", "America/New_York")):
            os.utime(path, (1735689600 + i * 3600, 1735689600 + i * 3600))
            archive = self.root / ("xattrs%d.zip" % i)
            p = run(
                self.zip,
                "--xattrs",
                "-q",
                str(archive),
                "data/A-file",
                cwd=self.root,
                tz=tz,
            )
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            output.append(archive.read_bytes())
            with zipfile.ZipFile(archive) as zf:
                self.assertIn("data/A-file", zf.namelist())
                self.assertGreater(len(zf.getinfo("data/A-file").extra), 20)
        self.assertEqual(output[0], output[1])

    def test_zipdedup_refptr_deterministic_and_selective(self):
        tool = Path(ARGS.zipdedup).resolve()
        if not tool.is_file():
            self.skipTest("zipdedup not built")
        source = self.root / "zd-input.zip"
        with zipfile.ZipFile(source, "w") as zf:
            for name, payload in (
                ("first", b"duplicate" * 2048),
                ("second", b"duplicate" * 2048),
                ("preserved", b"unique payload"),
            ):
                zi = zipfile.ZipInfo(name, (2030, 1, 1, 0, 0, 0))
                zi.extra = b"\x34\x12\x03\x00ABC"
                zf.writestr(zi, payload)
        a = self.root / "zd-a.zip"
        b = self.root / "zd-b.zip"
        for dst, tz in ((a, "Asia/Tokyo"), (b, "America/New_York")):
            p = run(tool, str(source), str(dst), cwd=self.root, tz=tz)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            with zipfile.ZipFile(dst) as zf:
                self.assertEqual(zf.getinfo("second").compress_type, 92)
                for name in ("first", "second"):
                    self.assertEqual(zf.getinfo(name).date_time, (2000, 1, 1, 0, 0, 0))
                self.assertEqual(
                    zf.getinfo("preserved").date_time, (2030, 1, 1, 0, 0, 0)
                )
                self.assertEqual(zf.getinfo("preserved").extra, b"\x34\x12\x03\x00ABC")
        self.assertEqual(a.read_bytes(), b.read_bytes())

    @unittest.skipUnless(os.name == "posix", "PTY prompts need POSIX")
    def test_zipcloak_double_optin_timestamp(self):
        cloak = Path(ARGS.zipcloak).resolve()
        if not cloak.is_file():
            self.skipTest("zipcloak not built")
        plain = self.root / "plain.zip"
        info = zipfile.ZipInfo("payload", (2030, 1, 1, 0, 0, 0))
        info.extra = b"\x55\x54\x05\x00\x01" + struct.pack("<I", 1893456000)
        with zipfile.ZipFile(plain, "w") as zf:
            zf.writestr(info, b"encrypted payload test" * 100)
        output = self.root / "cloak1.zip"
        reject = run(cloak, "-O", output, plain, cwd=self.root)
        self.assertNotEqual(reject.returncode, 0)
        self.assertFalse(output.exists())
        code, details = run_zipcloak_tty(cloak, plain, output, insecure="yes")
        self.assertEqual(code, 0, details)
        self.assertIn("INSECURE", details)
        other = self.root / "cloak2.zip"
        code, details = run_zipcloak_tty(cloak, plain, other, insecure="yes")
        self.assertEqual(code, 0, details)
        self.assertEqual(output.read_bytes(), other.read_bytes())
        with zipfile.ZipFile(output) as zf:
            self.assertEqual(zf.getinfo("payload").date_time, (2000, 1, 1, 0, 0, 0))
            self.assertEqual(
                zf.read("payload", pwd=b"testing"), b"encrypted payload test" * 100
            )
        restored = self.root / "restored.zip"
        code, details = run_zipcloak_tty(cloak, output, restored, decrypt=True)
        self.assertEqual(code, 0, details)
        with zipfile.ZipFile(restored) as zf:
            self.assertEqual(zf.read("payload"), b"encrypted payload test" * 100)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", default="zip30/zip")
    parser.add_argument("--zipopt", default="zipopt/zipopt")
    parser.add_argument("--zipdedup", default="zipdedup/zipdedup")
    parser.add_argument("--baseline-zip", default=None)
    parser.add_argument("--zipcloak", default="zip30/zipcloak")
    parser.add_argument("--zipnote", default="zip30/zipnote")
    parser.add_argument("--zipsplit", default="zip30/zipsplit")
    parser.add_argument("--unzip", default="unzip60/unzip")
    parser.add_argument("--funzip", default="unzip60/funzip")
    ARGS = parser.parse_args()
    unittest.main(argv=[__file__], verbosity=2)
