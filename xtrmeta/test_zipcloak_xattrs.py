#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""M6E1: ZipCloak may transform unrelated members, never Xtro transport.

Linux regression: pty-backed password prompts; requires production Zip,
ZipCloak and UnZip plus a user-xattr-capable test filesystem.
"""

import hashlib
import os
import pathlib
import pty
import select
import struct
import signal
import subprocess
import tempfile
import time
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
CLOAK = ROOT / "zip30/zipcloak"
UNZIP = ROOT / "unzip60/unzip"
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(*args, cwd=None, good=True):
    p = subprocess.run(
        [str(x) for x in args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=50,
    )
    check(
        (p.returncode == 0) == good,
        "command %r status=%d stdout=%r stderr=%r"
        % (args, p.returncode, p.stdout[-300:], p.stderr[-300:]),
    )
    return p


def cloak(cwd, args, prompts):
    """Real controlling TTY, no external pexpect/script dependencies."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(str(cwd))
        os.execv(str(CLOAK), [str(CLOAK)] + list(args))
    output = b""
    cursor = 0
    sent = 0
    status = None
    deadline = time.monotonic() + 25
    try:
        while time.monotonic() < deadline:
            if sent < prompts:
                prompt = b"Enter password:" if sent == 0 else b"Verify password:"
                position = output.find(prompt, cursor)
                if position >= 0:
                    # ZipCloak prints the prompt before switching the TTY
                    # into password-reading mode.  An immediate write may
                    # be discarded by its termios flush (especially ASan).
                    time.sleep(0.12)
                    os.write(fd, b"secret\n")
                    cursor = position + len(prompt)
                    sent += 1
                    continue
            readable, _, _ = select.select([fd], [], [], 0.1)
            if readable:
                try:
                    b = os.read(fd, 4096)
                except OSError:
                    b = b""
                if not b:
                    break
                output += b
                if len(output) > 131072:
                    raise AssertionError("excessive ZipCloak output")
            got, st = os.waitpid(pid, os.WNOHANG)
            if got:
                status = st
                break
        if status is None:
            got, status = os.waitpid(pid, os.WNOHANG)
            if not got:
                os.kill(pid, signal.SIGKILL)
                _, status = os.waitpid(pid, 0)
                raise AssertionError("ZipCloak timed out: %r" % output[-500:])
    finally:
        os.close(fd)
    rc = os.waitstatus_to_exitcode(status)
    return rc, output


def contents(archive):
    with zipfile.ZipFile(archive) as z:
        return {
            e.filename: (
                e.extra,
                e.flag_bits,
                e.compress_type,
                e.CRC,
                e.file_size,
                e.compress_size,
            )
            for e in z.infolist()
        }


def setup_case(root, label, encrypted_xtr, large):
    d = root / label
    d.mkdir()
    (d / "owner.bin").write_bytes(b"owner-data\x00" * 100)
    (d / "other.bin").write_bytes(b"other-data\xff" * 100)
    attrs = {b"user.note": b"\x00test\xff"}
    if large:
        attrs.update({b"user.left": b"A" * 35000, b"user.right": b"B" * 35000})
    for k, v in attrs.items():
        os.setxattr(d / "owner.bin", k, v)
    if encrypted_xtr:
        run(ZIP, "--xattrs", "-P", "secret", "input.zip", "owner.bin", cwd=d)
        run(ZIP, "input.zip", "other.bin", cwd=d)
    else:
        run(ZIP, "--xattrs", "input.zip", "owner.bin", cwd=d)
        run(ZIP, "-P", "secret", "input.zip", "other.bin", cwd=d)
    return d, attrs


def validate_retained(d, attrs, encrypted_xtr, output):
    old = contents(d / "input.zip")
    new = contents(d / output)
    check(old.keys() == new.keys(), "member set unchanged")
    protected = [name for name in old if name != "other.bin"]
    check(bool(protected), "metadata owner exists")
    for name in protected:
        # Compressed bytes can be relocated, but logical fields remain intact.
        check(old[name] == new[name], "Xtro member descriptor unchanged: %s" % name)
    check(
        (new["other.bin"][1] & 1) == (1 if encrypted_xtr else 0),
        "unrelated member encryption state transitioned",
    )
    check(
        (old["other.bin"][1] & 1) != (new["other.bin"][1] & 1),
        "unrelated member encrypted bit changed",
    )
    run(UNZIP, "-tq", "-P", "secret", output, cwd=d)
    dest = d / "restored"
    dest.mkdir()
    run(UNZIP, "-o", "--xattrs", "-P", "secret", output, "-d", dest, cwd=d)
    check(
        (dest / "owner.bin").read_bytes() == (d / "owner.bin").read_bytes(),
        "owner contents preserved",
    )
    check(
        (dest / "other.bin").read_bytes() == (d / "other.bin").read_bytes(),
        "unrelated contents preserved",
    )
    for k, v in attrs.items():
        check(os.getxattr(dest / "owner.bin", k) == v, "native xattr round trip %r" % k)


def case_success(root, encrypted, large):
    label = ("encrypted" if encrypted else "public") + (
        "-large" if large else "-inline"
    )
    d, attrs = setup_case(root, label, encrypted, large)
    before = hashlib.sha256((d / "input.zip").read_bytes()).digest()
    argv = ["-O", "output.zip", "input.zip"]
    if not encrypted:
        argv = ["-d"] + argv
    code, output = cloak(d, argv, 2 if encrypted else 1)
    check(code == 0, "ZipCloak completed: %s" % output[-500:])
    check((d / "output.zip").exists(), "output published")
    check(
        hashlib.sha256((d / "input.zip").read_bytes()).digest() == before,
        "original archive unchanged with -O",
    )
    validate_retained(d, attrs, encrypted, "output.zip")


def case_reject(root, encrypted, large):
    label = ("deny-public" if not encrypted else "deny-encrypted") + (
        "-large" if large else "-inline"
    )
    d, _ = setup_case(root, label, encrypted, large)
    before = (d / "input.zip").read_bytes()
    # Public inline and Deflate companion transitions are supported now.
    # The reverse encrypted-to-public transition remains fail-closed.
    args = ["-d"] if encrypted else []
    for out in (True, False):
        cmd = args + (["-O", "rejected.zip"] if out else []) + ["input.zip"]
        if not encrypted:
            code, output = cloak(d, cmd, 2)
            check(code == 0, "public metadata encryption succeeds: %r" % output[-350:])
            result = d / ("rejected.zip" if out else "input.zip")
            with zipfile.ZipFile(result) as f:
                owner = f.getinfo("owner.bin")
                side = next(
                    e for e in f.infolist() if e.filename.startswith("__XTRO_ZIP__/")
                )
                check(
                    owner.flag_bits & 1 and side.flag_bits & 1,
                    "owner and companion encrypted",
                )
                check(
                    side.compress_type == (8 if large else 0),
                    "companion method preserved or selected",
                )
            if not out:
                before = result.read_bytes()
        else:
            failed = subprocess.run(
                [str(CLOAK)] + cmd,
                cwd=d,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            code, output = failed.returncode, failed.stdout + failed.stderr
            check(
                code != 0 and b"Xtro" in output,
                "unsafe Xtro state transition rejected before prompting",
            )
            check(
                (d / "input.zip").read_bytes() == before,
                "rejected transition preserves source bytes",
            )
            check(
                not (d / "rejected.zip").exists(),
                "rejected transition does not publish output",
            )


def case_bad_graph(root):
    d, _ = setup_case(root, "bad-graph", False, True)
    broken = d / "broken.zip"
    # Recreate an orphaned central graph without modifying original.
    with zipfile.ZipFile(d / "input.zip") as src, zipfile.ZipFile(broken, "w") as dest:
        for entry in src.infolist():
            if entry.filename.startswith("__XTRO_ZIP__/"):
                continue
            data = src.read(entry, pwd=b"secret" if entry.flag_bits & 1 else None)
            new = zipfile.ZipInfo(entry.filename, entry.date_time)
            new.extra = entry.extra
            new.compress_type = zipfile.ZIP_DEFLATED
            dest.writestr(new, data)
    before = broken.read_bytes()
    p = subprocess.run(
        [str(CLOAK), "-O", "invalid.zip", "broken.zip"],
        cwd=d,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    code, output = p.returncode, p.stdout + p.stderr
    check(code != 0 and b"Xtro" in output, "orphan metadata rejected")
    check(broken.read_bytes() == before, "invalid input unchanged")
    check(not (d / "invalid.zip").exists(), "no publication for bad graph")


def case_bad_headers(root):
    d, _ = setup_case(root, "bad-headers", True, True)
    original = (d / "input.zip").read_bytes()
    with zipfile.ZipFile(d / "input.zip") as z:
        owner = z.getinfo("owner.bin")
        side = next(e for e in z.infolist() if e.filename.startswith("__XTRO_ZIP__/"))
        side_name = side.filename.encode("ascii")
    # A local owner ID change must not be republished even if central identity
    # and the companion's ZIP integrity are otherwise valid.
    bad = bytearray(original)
    pos = owner.header_offset
    check(bad[pos : pos + 4] == b"PK\x03\x04", "owner local signature")
    name_len, extra_len = struct.unpack_from("<HH", bad, pos + 26)
    cur = pos + 30 + name_len
    end = cur + extra_len
    changed = False
    while cur < end:
        kind, length = struct.unpack_from("<HH", bad, cur)
        check(cur + 4 + length <= end, "local extra bounds")
        if kind == 0x5854 and bad[cur + 4 : cur + 8] == b"XTRO":
            bad[cur + 12] ^= 0x20
            changed = True
        cur += 4 + length
    check(changed, "owner local Xtro field located")
    local = d / "local-mismatch.zip"
    local.write_bytes(bad)
    before = local.read_bytes()
    code, output = cloak(d, ["-O", "local-output.zip", "local-mismatch.zip"], 2)
    check(code != 0, "local Xtro mismatch rejected")
    check(
        local.read_bytes() == before and not (d / "local-output.zip").exists(),
        "local mismatch not republished",
    )

    # The central graph must reject different encryption transports before
    # asking for a password or opening a destination archive.
    bad = bytearray(original)
    endpos = bad.rfind(b"PK\x05\x06")
    check(endpos >= 0, "EOCD located")
    count = struct.unpack_from("<H", bad, endpos + 10)[0]
    cur = struct.unpack_from("<I", bad, endpos + 16)[0]
    changed = False
    for _ in range(count):
        check(bad[cur : cur + 4] == b"PK\x01\x02", "central signature")
        nl, el, cl = struct.unpack_from("<HHH", bad, cur + 28)
        if bytes(bad[cur + 46 : cur + 46 + nl]) == side_name:
            flags = struct.unpack_from("<H", bad, cur + 8)[0]
            struct.pack_into("<H", bad, cur + 8, flags ^ 1)
            changed = True
        cur += 46 + nl + el + cl
    check(changed, "central companion located")
    central = d / "central-mismatch.zip"
    central.write_bytes(bad)
    before = central.read_bytes()
    p = subprocess.run(
        [str(CLOAK), "-O", "central-output.zip", "central-mismatch.zip"],
        cwd=d,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    code, output = p.returncode, p.stdout + p.stderr
    check(code != 0 and b"Xtro" in output, "transport mismatch rejected in preflight")
    check(
        central.read_bytes() == before and not (d / "central-output.zip").exists(),
        "central mismatch not republished",
    )


def case_aes_preserved(root, mode):
    d = root / ("aes-" + mode)
    d.mkdir()
    (d / "owner.bin").write_bytes(b"AES-owner\x00" * (1 if mode == "ae2" else 250))
    (d / "other.bin").write_bytes(b"unencrypted extra" * 100)
    attrs = {
        b"user.note": b"\x00\xffAES",
        b"user.large1": b"X" * 35000,
        b"user.large2": b"Y" * 35000,
    }
    for k, v in attrs.items():
        os.setxattr(d / "owner.bin", k, v)
    opts = ["--xattrs", "--aes-strength", "256"]
    if mode == "ae3":
        opts += ["--aes-mode", "quantum"]
    run(ZIP, *opts, "-eP", "secret", "input.zip", "owner.bin", cwd=d)
    run(ZIP, "input.zip", "other.bin", cwd=d)
    with zipfile.ZipFile(d / "input.zip") as z:
        aes_versions = []
        for e in z.infolist():
            if e.filename == "other.bin":
                continue
            check(
                e.compress_type == 99 and bool(e.flag_bits & 1),
                "Xtro AES transport is encrypted",
            )
            at = 0
            while at < len(e.extra):
                ident, length = struct.unpack_from("<HH", e.extra, at)
                if ident == 0x9901:
                    aes_versions.append(struct.unpack_from("<H", e.extra, at + 4)[0])
                at += 4 + length
        check(
            len(aes_versions) == 2 and aes_versions[0] == aes_versions[1],
            "AES owner and companion version agree",
        )
        check(
            aes_versions[0] == (3 if mode == "ae3" else 2 if mode == "ae2" else 1),
            "specific AES vendor version",
        )
    before = (d / "input.zip").read_bytes()
    rc, output = cloak(d, ["-O", "result.zip", "input.zip"], 2)
    check(
        rc == 0,
        "ZipCloak ordinary encryption alongside AES metadata: %r" % output[-250:],
    )
    check((d / "input.zip").read_bytes() == before, "original AES archive unchanged")
    validate_retained(d, attrs, True, "result.zip")


def main():
    staging = os.environ.get("XTRO_XATTR_TEST_TMPDIR")
    if staging is None and os.path.isdir("/dev/shm"):
        staging = "/dev/shm"
    with tempfile.TemporaryDirectory(prefix="xtr-m6e1-", dir=staging) as t:
        root = pathlib.Path(t)
        for encrypted in (False, True):
            for large in (False, True):
                case_success(root, encrypted, large)
                case_reject(root, encrypted, large)
        case_bad_graph(root)
        case_bad_headers(root)
        for mode in ("ae1", "ae2", "ae3"):
            case_aes_preserved(root, mode)
    print("M6E1 ZipCloak preservation: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
