#!/usr/bin/env python3
"""M7B: full Zip/UnZip integration against BSD extattr ABI emulated on Linux.
This intentionally does not certify a real BSD kernel/filesystem."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import zipfile
import sys
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKS = 0


def ck(pred, msg):
    global CHECKS
    CHECKS += 1
    if not pred:
        raise AssertionError(msg)


def run(args, cwd, ok=True, env=None):
    p = subprocess.run(
        list(map(str, args)),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=95,
    )
    if ok and p.returncode:
        raise AssertionError(
            "command failed: %r (%d)\n%s\n%s"
            % (
                args,
                p.returncode,
                p.stdout.decode(errors="replace")[-1300:],
                p.stderr.decode(errors="replace")[-1300:],
            )
        )
    return p


def clone(work):
    for dirname in ("zip30", "unzip60", "xtrmeta"):
        shutil.copytree(
            ROOT / dirname,
            work / dirname,
            ignore=shutil.ignore_patterns(
                "*.o",
                "*.a",
                "*.so",
                "*.pyc",
                "__pycache__",
                "zip",
                "unzip",
                "zipcloak",
                "zipsplit",
                "zipnote",
                "funzip",
                "unzipsfx",
                "zipinfo",
                "test_*",
            ),
        )
    # Test sources are not needed in temporary C builds.


def suite(work, native, origin):
    global CHECKS
    zd = work / "zip30" / "zip"
    ud = work / "unzip60" / "unzip"
    # Remove the host Linux macro: a Linux guard must not hide missing BSD code.
    opt = "-U__linux__ -DXTR_BSD_TEST" + (
        " -DXTR_BSD_TEST_NETBSD" if native == "NetBSD" else ""
    )
    run(
        [
            "make",
            "-C",
            "zip30",
            "-f",
            "unix/Makefile",
            "zip",
            "CC=gcc -std=gnu89",
            "LOCAL_ZIP=" + opt,
            "-j4",
        ],
        work,
    )
    run(
        [
            "make",
            "-C",
            "unzip60",
            "-f",
            "unix/Makefile",
            "unzip",
            "CC=gcc -std=gnu89",
            "LOCAL_UNZIP=" + opt,
            "-j4",
        ],
        work,
    )
    ck(zd.exists() and ud.exists(), native + " binaries")
    base = pathlib.Path("/dev/shm") if os.path.isdir("/dev/shm") else work
    with tempfile.TemporaryDirectory(prefix="xtro-bsd-staging-", dir=base) as scratch:
        previous_tmp = os.environ.get("TMPDIR")
        os.environ["TMPDIR"] = scratch
        try:
            suite_cases(work, native, origin, zd, ud, base)
        finally:
            if previous_tmp is None:
                os.environ.pop("TMPDIR", None)
            else:
                os.environ["TMPDIR"] = previous_tmp
        ck(not list(pathlib.Path(scratch).iterdir()), "private scratch removed")


def suite_cases(work, native, origin, zd, ud, base):
    with tempfile.TemporaryDirectory(prefix="xtro-bsd-integration-", dir=base) as td:
        t = pathlib.Path(td)
        input = t / "input"
        input.mkdir()
        extracted = t / "extracted"
        extracted.mkdir()
        (input / "a").write_bytes(b"file-data\0" * 123)
        (input / "dir").mkdir()
        # No attributes on symlinks: the FD-only M7A policy currently rejects
        # requested symlink capture; test separately below.
        binary = b"\x00\xff\x80x\0"
        os.setxattr(input / "a", "user.test", binary)
        os.setxattr(input / "a", "user.empty", b"")
        os.setxattr(input / "dir", "user.dir", b"\x11\x00")
        run([zd, "-q", "-r", "--xattrs", "small.zip", "a", "dir"], input)
        small = input / "small.zip"
        shutil.copy2(small, work / (native + "-small.zip"))
        with zipfile.ZipFile(small) as z:
            ck(sorted(z.namelist()) == ["a", "dir/"], "inline names")
            ck(sum(1 for i in z.infolist() if b"XTRO" in i.extra) == 2, "inline extra")
        run([ud, "-q", "--xattrs", small], extracted)
        ck((extracted / "a").read_bytes() == (input / "a").read_bytes(), "file data")
        ck(os.getxattr(extracted / "a", "user.test") == binary, "binary inline")
        ck(os.getxattr(extracted / "a", "user.empty") == b"", "empty inline")
        ck(os.getxattr(extracted / "dir", "user.dir") == b"\x11\0", "directory inline")
        # Both switches must be recognized on BSD, and the last must win.
        without = t / "no-xattrs"
        without.mkdir()
        run([ud, "-q", "--xattrs", "--no-xattrs", small], without)
        ck(
            (without / "a").read_bytes() == (input / "a").read_bytes(),
            "no-xattrs retains ordinary extraction",
        )
        ck(
            not os.listxattr(without / "a") and not os.listxattr(without / "dir"),
            "no-xattrs disables native metadata restoration",
        )
        # Two >32KiB attributes need tmpfs on Linux; force companion path.
        # Normal Linux overlay/other FSs often have a 4KiB total EA budget.
        bigA = bytes(range(256)) * 128
        bigB = bytes(range(255, -1, -1)) * 128
        try:
            os.setxattr(input / "a", "user.bigA", bigA)
            os.setxattr(input / "a", "user.bigB", bigB)
        except OSError as e:
            raise RuntimeError(
                "BSD shim companion test needs an EA-capable Linux FS (e.g., /dev/shm): %s"
                % e
            )
        run([zd, "-q", "--xattrs", "big.zip", "a"], input)
        big = input / "big.zip"
        with zipfile.ZipFile(big) as z:
            ck(len(z.namelist()) == 2, "companion count")
            ck(z.namelist()[1].startswith("__XTRO_ZIP__/x/"), "reserved companion path")
            ck(z.getinfo(z.namelist()[1]).compress_type == 8, "deflate companion")
        other = t / "large"
        other.mkdir()
        run([ud, "-q", "--xattrs", big], other)
        for name, value in [
            ("user.test", binary),
            ("user.empty", b""),
            ("user.bigA", bigA),
            ("user.bigB", bigB),
        ]:
            ck(os.getxattr(other / "a", name) == value, "companion value " + name)
        # Corrupt a raw Deflate companion: no native EA restoration is allowed
        # when the decoded ZIP member integrity or manifest check fails.
        corrupt = t / "corrupt.zip"
        content = bytearray(big.read_bytes())
        with zipfile.ZipFile(big) as z:
            side = z.infolist()[1]
        loc = side.header_offset
        ck(content[loc : loc + 4] == b"PK\x03\x04", "companion local signature")
        name_len, extra_len = struct.unpack_from("<HH", content, loc + 26)
        data_at = loc + 30 + name_len + extra_len
        ck(side.compress_size > 32, "companion compressed bytes available")
        content[data_at + 12] ^= 0x40
        corrupt.write_bytes(content)
        negative = t / "corrupt-dest"
        negative.mkdir()
        rv = run([ud, "-q", "--xattrs", corrupt], negative, ok=False)
        ck(rv.returncode != 0, "corrupted companion refused")
        ck(
            not (negative / "a").exists() or not os.listxattr(negative / "a"),
            "corrupted metadata did not apply native attributes",
        )
        # Overwrite removes stale EAs; verify source and archive untouched.
        os.setxattr(other / "a", "user.stale", b"stale")
        run([ud, "-oq", "--xattrs", big], other)
        ck("user.stale" not in os.listxattr(other / "a"), "stale attr removed")
        ck(
            os.getxattr(other / "a", "user.bigA") == bigA,
            "retained bigA after overwrite",
        )
        # Plain owner FWKCS MD5 is independent of Xtro manifest integrity.
        run([zd, "-q", "--fwkcs-md5", "--xattrs", "fwkcs.zip", "a"], input)
        with zipfile.ZipFile(input / "fwkcs.zip") as z:
            ck(b"FK" in z.getinfo("a").extra, "owner FWKCS extra exists")
        fw = t / "fwk"
        fw.mkdir()
        run([ud, "-q", "--xattrs", input / "fwkcs.zip"], fw)
        ck(os.getxattr(fw / "a", "user.bigA") == bigA, "FWKCS owner round trip")
        # AES transport uses method 99; ordinary owner and metadata must
        # have matching strength/version and authenticate before restoration.
        for mode in ("standard", "quantum"):
            if mode == "quantum" and native == "NetBSD":
                # Already tested for FreeBSD ABI; keep test duration bounded.
                continue
            archive = "aes-" + mode + ".zip"
            run(
                [
                    zd,
                    "-q",
                    "-eP",
                    "secret123",
                    "--aes-mode",
                    mode,
                    "--aes-strength",
                    "256",
                    "--xattrs",
                    archive,
                    "a",
                ],
                input,
            )
            path = input / archive
            with zipfile.ZipFile(path) as z:
                ck(len(z.namelist()) == 2, "AES owner+companion")
                ck(all(i.compress_type == 99 for i in z.infolist()), "AES method 99")
            aout = t / ("aesout-" + mode)
            aout.mkdir()
            run([ud, "-q", "--xattrs", "-P", "secret123", path], aout)
            ck(
                os.getxattr(aout / "a", "user.bigA") == bigA,
                "AES " + mode + " large restore",
            )
        # Incorrect password and metadata must not write attributes on output.
        run([zd, "-q", "-P", "pass123", "--xattrs", "crypt.zip", "a"], input)
        enc = input / "crypt.zip"
        with zipfile.ZipFile(enc) as z:
            ck(len(z.namelist()) == 2, "encrypted companion count")
            ck(
                all(i.flag_bits & 1 for i in z.infolist()),
                "encrypted owner and companion",
            )
        good = t / "good"
        good.mkdir()
        run([ud, "-q", "--xattrs", "-P", "pass123", enc], good)
        ck(os.getxattr(good / "a", "user.bigB") == bigB, "ZipCrypto native restore")
        bad = t / "bad"
        bad.mkdir()
        rv = run([ud, "-q", "--xattrs", "-P", "wrong", enc], bad, ok=False)
        ck(rv.returncode != 0, "bad password rejected")
        ck(
            not (bad / "a").exists() or not os.listxattr(bad / "a"),
            "bad password did not restore EA",
        )
        # Explicit unsupported symlink case must fail closed and not publish.
        (input / "link").symlink_to("a")
        rv = run([zd, "-q", "-y", "--xattrs", "symlink.zip", "link"], input, ok=False)
        ck(rv.returncode != 0, "symlink capture explicitly rejected")
        ck(
            not (input / "symlink.zip").exists(),
            "failed symlink did not publish archive",
        )
        # Cross-origin restore must fail and never silently reinterpret values.
        ck(origin in (2, 3), "Bsd origin mock")
        print("%s BSD ABI integration: %d checks passed" % (native, CHECKS))


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-m7b-", dir="/mnt/data") as td:
        base = pathlib.Path(td)
        for osname, origin in [("FreeBSD", 2), ("NetBSD", 3)]:
            wd = base / osname
            wd.mkdir()
            clone(wd)
            suite(wd, osname, origin)
        # FreeBSD-origin manifest must never be installed on NetBSD and
        # vice versa, even though the mock uses the same Linux EA store.
        for source, target in (("FreeBSD", "NetBSD"), ("NetBSD", "FreeBSD")):
            src = base / source / (source + "-small.zip")
            with tempfile.TemporaryDirectory(
                prefix="xtro-cross-origin-", dir="/dev/shm"
            ) as out:
                p = run(
                    [base / target / "unzip60" / "unzip", "-q", "--xattrs", src],
                    out,
                    ok=False,
                )
                ck(
                    p.returncode != 0,
                    "cross-origin native EA rejected: " + source + " -> " + target,
                )
                output = pathlib.Path(out) / "a"
                ck(
                    not output.exists() or "user.test" not in os.listxattr(output),
                    "cross-origin produced no native EAs",
                )
    print(
        "M7B all %d full integration checks passed (Linux syscall emulation; NOT native BSD certification)"
        % CHECKS
    )


if __name__ == "__main__":
    main()
