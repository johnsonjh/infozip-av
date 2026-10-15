#!/usr/bin/env python3
"""On-target traditional FreeBSD/NetBSD extattr(2) Zip/UnZip acceptance.

No ZFS, root privileges, system mount changes or external Python packages.
Only temporary paths under --workdir are modified. Exit 77 means the chosen
filesystem does not provide the required writable user namespace; it is NOT
a passing result. --require-companion turns an unsupported large-EA case into
a failure. This does not exercise FreeBSD 15 O_NAMEDATTR streams.

--linux-bsd-emulation is for the project's Linux-hosted BSD ABI shim ONLY;
never count a result from that mode as an on-target acceptance result.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import zipfile

CORE_LIMIT = 180
XTR_FIELD = 0x5854
COMPANION_PREFIX = "__XTRO_ZIP__/x/"


class UnsupportedFS(Exception):
    pass


class NativeEA:
    def __init__(self, system):
        libc = ctypes.CDLL(None, use_errno=True)
        self.system = system
        self.set_fd = libc.extattr_set_fd
        self.set_fd.restype = ctypes.c_ssize_t if system == "freebsd" else ctypes.c_int
        self.set_fd.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.get_fd = libc.extattr_get_fd
        self.get_fd.restype = ctypes.c_ssize_t
        self.get_fd.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.list_fd = libc.extattr_list_fd
        self.list_fd.restype = ctypes.c_ssize_t
        self.list_fd.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.delete_fd = libc.extattr_delete_fd
        self.delete_fd.restype = ctypes.c_int
        self.delete_fd.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p]

    @staticmethod
    def raise_error(operation):
        number = ctypes.get_errno()
        raise OSError(number, "%s: %s" % (operation, os.strerror(number)))

    def with_fd(self, path, operation):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            return operation(fd)
        finally:
            os.close(fd)

    def put(self, path, name, data):
        def work(fd):
            buf = ctypes.create_string_buffer(
                data if data else b"\x00", max(1, len(data))
            )
            result = self.set_fd(fd, 1, name.encode("ascii"), buf, len(data))
            if result < 0:
                self.raise_error("extattr_set_fd(%s)" % name)
            expected = len(data) if self.system == "freebsd" else 0
            if result != expected:
                raise AssertionError(
                    "extattr_set_fd ABI expected %d, got %d" % (expected, result)
                )

        return self.with_fd(path, work)

    def get(self, path, name):
        def work(fd):
            key = name.encode("ascii")
            count = self.get_fd(fd, 1, key, None, 0)
            if count < 0:
                self.raise_error("extattr_get_fd(%s)" % name)
            buf = ctypes.create_string_buffer(max(1, count))
            result = self.get_fd(fd, 1, key, buf, count)
            if result < 0:
                self.raise_error("extattr_get_fd(%s)" % name)
            if result != count:
                raise AssertionError(
                    "extattr_get_fd changed size: %d/%d" % (result, count)
                )
            return buf.raw[:count]

        return self.with_fd(path, work)

    def names(self, path):
        def work(fd):
            count = self.list_fd(fd, 1, None, 0)
            if count < 0:
                self.raise_error("extattr_list_fd")
            buf = ctypes.create_string_buffer(max(1, count))
            result = self.list_fd(fd, 1, buf, count)
            if result < 0:
                self.raise_error("extattr_list_fd")
            if result != count:
                raise AssertionError("extattr_list_fd count changed")
            raw = buf.raw[:count]
            at = 0
            result_names = []
            while at < len(raw):
                size = raw[at]
                at += 1
                if not size or size > len(raw) - at:
                    raise AssertionError("malformed length-prefixed BSD native EA list")
                value = raw[at : at + size]
                if b"\x00" in value:
                    raise AssertionError("NUL in BSD native EA name")
                result_names.append(value.decode("ascii"))
                at += size
            if len(result_names) != len(set(result_names)):
                raise AssertionError("duplicate names in native extattr list")
            return sorted(result_names)

        return self.with_fd(path, work)

    def delete(self, path, name):
        def work(fd):
            if self.delete_fd(fd, 1, name.encode("ascii")) != 0:
                self.raise_error("extattr_delete_fd(%s)" % name)

        return self.with_fd(path, work)


class Suite:
    def __init__(self, args, native):
        self.args = args
        self.native = native
        self.ea = NativeEA(native)
        self.passed = 0
        self.skipped = []
        self.cases = []

    def check(self, value, label):
        if not value:
            raise AssertionError(label)
        self.passed += 1

    def mark(self, label):
        self.cases.append(label)
        print("PASS: " + label, flush=True)

    def skip(self, label, reason):
        self.skipped.append(label + ": " + str(reason))
        print("SKIP: " + label + ": " + str(reason), flush=True)

    @staticmethod
    def command(argv, cwd=None, expected=True):
        proc = subprocess.run(
            [str(v) for v in argv],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=CORE_LIMIT,
        )
        if expected and proc.returncode:
            raise AssertionError(
                "command %s failed (%s): stdout=%s stderr=%s"
                % (
                    argv,
                    proc.returncode,
                    proc.stdout.decode("utf-8", "replace")[-1600:],
                    proc.stderr.decode("utf-8", "replace")[-1600:],
                )
            )
        return proc

    def archive_info(self, path, owners, companions=0):
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            ordinary = [i for i in infos if not i.filename.startswith(COMPANION_PREFIX)]
            extras = [i for i in ordinary if self.has_xtr_field(i.extra)]
            side = [i for i in infos if i.filename.startswith(COMPANION_PREFIX)]
            self.check(
                sorted(i.filename for i in ordinary) == sorted(owners),
                "ordinary archive member list",
            )
            self.check(len(side) == companions, "metadata companion count")
            self.check(
                len(extras) == len(ordinary), "each owner has XTRO central extra"
            )
            return side

    @staticmethod
    def has_xtr_field(data):
        at = 0
        while at < len(data):
            if len(data) - at < 4:
                raise AssertionError("malformed ZIP extra header")
            field, length = struct.unpack_from("<HH", data, at)
            at += 4
            if length > len(data) - at:
                raise AssertionError("truncated ZIP extra field")
            if field == XTR_FIELD and data[at : at + 4] == b"XTRO":
                return True
            at += length
        return False

    def prepare(self, root):
        self.src = root / "src"
        self.dst = root / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        self.one = self.src / "one"
        self.one.write_bytes(b"BSD native extattr\x00payload\xff" * 119)
        self.folder = self.src / "folder"
        self.folder.mkdir()
        self.binary = b"\x00\xff\x80native\x00value\x01"
        self.ea.put(self.one, "binary", self.binary)
        self.ea.put(self.one, "empty", b"")
        self.ea.put(self.folder, "folder", b"\x00\xff\x01")
        self.check(
            self.ea.get(self.one, "binary") == self.binary, "native fd EA binary setup"
        )
        self.check(self.ea.get(self.one, "empty") == b"", "native fd EA empty setup")
        self.check(
            self.ea.get(self.folder, "folder") == b"\x00\xff\x01",
            "native fd EA directory setup",
        )
        self.check(
            self.ea.names(self.one) == ["binary", "empty"],
            "native fd length-prefixed enumeration",
        )
        self.mark("traditional FD syscall preflight")

    def basic(self, root):
        self.command(
            [self.args.zip, "-q", "-r", "--xattrs", "plain.zip", "one", "folder"],
            self.src,
        )
        arc = self.src / "plain.zip"
        self.archive_info(arc, ["one", "folder/"])
        self.command([self.args.unzip, "-tq", arc], root)
        self.command([self.args.unzip, "-q", "--xattrs", arc], self.dst)
        self.check(
            (self.dst / "one").read_bytes() == self.one.read_bytes(), "owner data exact"
        )
        self.check(
            self.ea.get(self.dst / "one", "binary") == self.binary, "binary EA exact"
        )
        self.check(self.ea.get(self.dst / "one", "empty") == b"", "empty EA exact")
        self.check(
            self.ea.get(self.dst / "folder", "folder") == b"\x00\xff\x01",
            "directory EA exact",
        )
        self.mark("plain file, directory and empty/binary EA round trips")
        for options, expect in (
            (["--xattrs", "--no-xattrs"], False),
            (["--no-xattrs", "--xattrs"], True),
        ):
            out = root / ("on" if expect else "off")
            out.mkdir()
            self.command([self.args.unzip, "-q"] + options + [arc], out)
            self.check(
                (out / "one").read_bytes() == self.one.read_bytes(),
                "option precedence retains owner data",
            )
            self.check(
                ("binary" in self.ea.names(out / "one")) == expect,
                "option precedence controls EA writes",
            )
        self.mark("--xattrs/--no-xattrs precedence and disabled restoration")

    def malformed_central(self, root):
        # Change the owner's Xtro identity in CENTRAL metadata only, leaving
        # the local header and ordinary ZIP payload untouched. A mismatched
        # local/central association must not cause native restoration.
        arc = self.src / "plain.zip"
        raw = bytearray(arc.read_bytes())
        at = 0
        changed = False
        while True:
            at = raw.find(b"PK\x01\x02", at)
            if at < 0:
                break
            if len(raw) - at < 46:
                break
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", raw, at + 28)
            name_start = at + 46
            end = name_start + name_len + extra_len + comment_len
            if end > len(raw):
                raise AssertionError("central directory extent outside ZIP")
            if raw[name_start : name_start + name_len] == b"one":
                field_at = name_start + name_len
                field_end = field_at + extra_len
                while field_at + 4 <= field_end:
                    field_id, length = struct.unpack_from("<HH", raw, field_at)
                    if length > field_end - field_at - 4:
                        raise AssertionError("malformed central Xtro extra")
                    if (
                        field_id == XTR_FIELD
                        and raw[field_at + 4 : field_at + 8] == b"XTRO"
                    ):
                        if length < 40:
                            raise AssertionError("short central XTRO field")
                        raw[field_at + 12] ^= 0x80
                        changed = True
                        break
                    field_at += 4 + length
                break
            at = end
        self.check(changed, "central Xtro identity located")
        malformed = root / "central-mismatch.zip"
        malformed.write_bytes(raw)
        out = root / "central-mismatch-output"
        out.mkdir()
        rv = self.command([self.args.unzip, "-q", "--xattrs", malformed], out, False)
        self.check(rv.returncode != 0, "local/central owner mismatch rejected")
        self.check(
            not (out / "one").exists() or not self.ea.names(out / "one"),
            "central association mismatch cannot restore metadata",
        )
        self.mark("local/central XTRO identity mismatch rejection")

    def overwrite_skip(self, root):
        arc = self.src / "plain.zip"
        target = self.dst / "one"
        self.ea.put(target, "stale", b"stale")
        target.write_bytes(b"changed contents: skip must not modify")
        before = target.read_bytes()
        self.command([self.args.unzip, "-nq", "--xattrs", arc], self.dst)
        self.check(target.read_bytes() == before, "skipped owner unchanged")
        self.check(
            self.ea.get(target, "stale") == b"stale", "skipped native EA unchanged"
        )
        self.command([self.args.unzip, "-oq", "--xattrs", arc], self.dst)
        self.check(target.read_bytes() == self.one.read_bytes(), "overwrite data exact")
        self.check(
            "stale" not in self.ea.names(target), "stale EA cleared on overwrite"
        )
        self.check(
            self.ea.get(target, "binary") == self.binary, "replacement EA restored"
        )
        self.mark("skip, overwrite and stale-attribute removal")

    def integrity_crypto(self, root):
        self.command(
            [self.args.zip, "-q", "--fwkcs-md5", "--xattrs", "fwkcs.zip", "one"],
            self.src,
        )
        fwk = root / "fwk"
        fwk.mkdir()
        self.command([self.args.unzip, "-q", "--xattrs", self.src / "fwkcs.zip"], fwk)
        self.check(
            self.ea.get(fwk / "one", "binary") == self.binary,
            "FWKCS-independent metadata restoration",
        )
        self.mark("FWKCS with Xtro")
        self.command(
            [self.args.zip, "-q", "-P", "correct", "--xattrs", "zipcrypto.zip", "one"],
            self.src,
        )
        good = root / "crypt-good"
        bad = root / "crypt-bad"
        good.mkdir()
        bad.mkdir()
        arc = self.src / "zipcrypto.zip"
        self.command([self.args.unzip, "-q", "-P", "correct", "--xattrs", arc], good)
        self.check(
            self.ea.get(good / "one", "binary") == self.binary, "ZipCrypto native EA"
        )
        failed = self.command(
            [self.args.unzip, "-q", "-P", "incorrect", "--xattrs", arc], bad, False
        )
        self.check(failed.returncode != 0, "wrong ZipCrypto password rejected")
        self.check(
            not (bad / "one").exists() or not self.ea.names(bad / "one"),
            "wrong password cannot write metadata",
        )
        self.mark("ZipCrypto password/metadata integrity")
        for mode in ("standard", "quantum"):
            arc = self.src / ("aes-" + mode + ".zip")
            self.command(
                [
                    self.args.zip,
                    "-q",
                    "-eP",
                    "correct",
                    "--aes-mode",
                    mode,
                    "--aes-strength",
                    "256",
                    "--xattrs",
                    arc,
                    "one",
                ],
                self.src,
            )
            output = root / ("aes-" + mode)
            output.mkdir()
            self.command(
                [self.args.unzip, "-q", "--xattrs", "-P", "correct", arc], output
            )
            self.check(
                self.ea.get(output / "one", "binary") == self.binary,
                "AES %s native restoration" % mode,
            )
            wrong = root / ("bad-aes-" + mode)
            wrong.mkdir()
            fail = self.command(
                [self.args.unzip, "-q", "--xattrs", "-P", "wrong", arc], wrong, False
            )
            self.check(fail.returncode != 0, "AES %s wrong password" % mode)
            self.check(
                not (wrong / "one").exists() or not self.ea.names(wrong / "one"),
                "AES %s wrong password no EA writes" % mode,
            )
            self.mark("AES %s encrypted metadata" % mode)

    def companion(self, root):
        # Native traditional EAs may have very small FS-specific limits.
        # Try multiple layouts, always on a NEW owner, never an existing file.
        layouts = ((36864, 2), (20480, 4), (10240, 8), (4096, 20))
        good = None
        reason = "filesystem does not accommodate >64KiB traditional EAs"
        for size, count in layouts:
            owner = self.src / "large"
            # Each trial needs a new inode. Merely overwriting file content
            # leaves earlier trial attributes and falsely exhausts FS limits.
            if owner.exists():
                owner.unlink()
            owner.write_bytes(b"large-companion-source\x00" * 55)
            data = []
            try:
                for index in range(count):
                    value = bytes(((index * 19 + i) & 255) for i in range(size))
                    name = "part%02d" % index
                    self.ea.put(owner, name, value)
                    data.append((name, value))
            except OSError as exc:
                reason = "%s while attempting %d x %d bytes" % (exc, count, size)
                continue
            good = (owner, data)
            break
        if good is None:
            if self.args.require_companion:
                raise AssertionError(
                    "required native companion test unavailable: " + reason
                )
            self.skip("native large companion", reason)
            return
        owner, data = good
        arc = self.src / "large.zip"
        self.command([self.args.zip, "-q", "--xattrs", arc, owner.name], self.src)
        side = self.archive_info(arc, [owner.name], 1)
        self.check(
            side[0].compress_type in (0, 8), "standard companion ZIP compression"
        )
        out = root / "large-out"
        out.mkdir()
        self.command([self.args.unzip, "-q", "--xattrs", arc], out)
        self.check(
            (out / owner.name).read_bytes() == owner.read_bytes(),
            "companion-associated ordinary data exact",
        )
        for name, value in data:
            self.check(
                self.ea.get(out / owner.name, name) == value,
                "companion native value %s" % name,
            )
        self.mark("native >64KiB aggregate Deflate/STORE companion")
        # Mutate compressed companion data without changing headers: the test
        # only checks rejection and absence of native EA writes.
        contents = bytearray(arc.read_bytes())
        info = side[0]
        loc = info.header_offset
        self.check(contents[loc : loc + 4] == b"PK\x03\x04", "local ZIP header found")
        name_len, extra_len = struct.unpack_from("<HH", contents, loc + 26)
        position = loc + 30 + name_len + extra_len
        self.check(info.compress_size > 20, "companion has nontrivial payload")
        contents[position + info.compress_size // 2] ^= 0x40
        corrupt = root / "bad-companion.zip"
        corrupt.write_bytes(contents)
        bad = root / "bad-companion-output"
        bad.mkdir()
        result = self.command([self.args.unzip, "-q", "--xattrs", corrupt], bad, False)
        self.check(result.returncode != 0, "mutated companion rejected")
        self.check(
            not (bad / owner.name).exists() or not self.ea.names(bad / owner.name),
            "mutated companion cannot write native attributes",
        )
        self.mark("companion-corruption rejection before native writes")

    def symlink(self, root):
        path = self.src / "sym"
        path.symlink_to("one")
        arc = self.src / "sym.zip"
        failed = self.command(
            [self.args.zip, "-q", "-y", "--xattrs", arc, "sym"], self.src, False
        )
        self.check(failed.returncode != 0, "unsupported symlink capture rejected")
        self.check(not arc.exists(), "failed symlink capture did not publish ZIP")
        self.mark("fail-closed symlink capture")

    def report(self, root):
        report = {
            "result": "PASS",
            "system": platform.platform(),
            "native_kernel_test": not self.args.linux_bsd_emulation,
            "workdir": str(self.args.workdir or tempfile.gettempdir()),
            "checks_passed": self.passed,
            "cases_passed": self.cases,
            "cases_skipped": self.skipped,
            "zip": str(self.args.zip),
            "unzip": str(self.args.unzip),
        }
        if self.args.report:
            Path(self.args.report).write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
        print(
            "RESULT: PASS; %d assertions; %d cases passed; %d cases skipped; %s"
            % (
                self.passed,
                len(self.cases),
                len(self.skipped),
                (
                    "LINUX EMULATION ONLY"
                    if self.args.linux_bsd_emulation
                    else "NATIVE BSD"
                ),
            )
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    base = Path(__file__).resolve().parent.parent
    p.add_argument("--workdir", help="Writable filesystem to test, no ZFS required")
    p.add_argument("--zip", type=Path, default=base / "zip30" / "zip")
    p.add_argument("--unzip", type=Path, default=base / "unzip60" / "unzip")
    p.add_argument(
        "--probe-only", action="store_true", help="Probe user extattr_* only"
    )
    p.add_argument(
        "--require-companion",
        action="store_true",
        help="Fail if native filesystem cannot hold >64KiB of EAs",
    )
    p.add_argument("--report", help="Write reproducible summary outside temp workdir")
    p.add_argument(
        "--linux-bsd-emulation", choices=("freebsd", "netbsd"), help=argparse.SUPPRESS
    )
    args = p.parse_args()
    if args.linux_bsd_emulation:
        if not sys.platform.startswith("linux") or not os.environ.get("LD_PRELOAD"):
            p.error(
                "Linux shim mode requires Linux with explicitly supplied LD_PRELOAD"
            )
        native = args.linux_bsd_emulation
        print("EMULATION ONLY: this is not a native BSD acceptance test", flush=True)
    elif sys.platform.startswith("freebsd"):
        native = "freebsd"
    elif sys.platform.startswith("netbsd"):
        native = "netbsd"
    else:
        p.error("native acceptance requires FreeBSD or NetBSD")
    if args.workdir and not Path(args.workdir).is_dir():
        p.error("--workdir must name an existing writable directory")
    try:
        suite = Suite(args, native)
    except AttributeError as exc:
        print(
            "UNAVAILABLE: platform libc lacks extattr_* calls: %s" % exc,
            file=sys.stderr,
        )
        return 77
    with tempfile.TemporaryDirectory(
        prefix="xtro-native-extattr-", dir=args.workdir
    ) as work:
        work = Path(work)
        probe = work / "probe"
        probe.write_bytes(b"extattr probe")
        try:
            suite.ea.put(probe, "xtro_probe", b"\x00\xffprobe\x00")
            if suite.ea.get(probe, "xtro_probe") != b"\x00\xffprobe\x00":
                raise AssertionError("readback differs from set value")
            if "xtro_probe" not in suite.ea.names(probe):
                raise AssertionError("extattr_list_fd does not list probe")
            suite.ea.delete(probe, "xtro_probe")
            if "xtro_probe" in suite.ea.names(probe):
                raise AssertionError("extattr_delete_fd did not remove probe")
        except OSError as exc:
            print(
                "UNAVAILABLE: writable traditional user extattrs are not supported "
                "on this directory (errno %s): %s" % (exc.errno, exc),
                file=sys.stderr,
            )
            print(
                "RESULT: NOT RUN; native filesystem feature unavailable",
                file=sys.stderr,
            )
            return 77
        if args.probe_only:
            print(
                "RESULT: PASS; traditional extattr_* probe; %s"
                % ("LINUX EMULATION ONLY" if args.linux_bsd_emulation else "NATIVE BSD")
            )
            return 0
        for executable in (args.zip, args.unzip):
            if not executable.is_file():
                p.error("binary missing: " + str(executable))
        suite.prepare(work)
        suite.basic(work)
        suite.malformed_central(work)
        suite.overwrite_skip(work)
        suite.integrity_crypto(work)
        suite.companion(work)
        suite.symlink(work)
        suite.report(work)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
        print("RESULT: FAIL: %s" % exc, file=sys.stderr)
        sys.exit(1)
