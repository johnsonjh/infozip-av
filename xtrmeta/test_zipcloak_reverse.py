#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""M6E2F Linux end-to-end ZipCrypto metadata reversal test."""

import pathlib, tempfile, os, sys, subprocess, zipfile, hashlib, struct, shutil, pty, select, time
from test_zipcloak_xattrs import cloak

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
UNZIP = ROOT / "unzip60/unzip"
N = 0


def ck(cond, desc):
    global N
    N += 1
    if not cond:
        raise AssertionError(desc)


def run(argv, cwd, okay=True):
    p = subprocess.run([str(a) for a in argv], cwd=cwd, capture_output=True, timeout=65)
    ck(
        (p.returncode == 0) == okay,
        "command %s returned %s: %r %r"
        % (argv, p.returncode, p.stdout[-500:], p.stderr[-500:]),
    )
    return p


def fields(extra):
    pos = 0
    while pos < len(extra):
        ck(len(extra) - pos >= 4, "extra header")
        typ, num = struct.unpack_from("<HH", extra, pos)
        ck(pos + 4 + num <= len(extra), "extra bounds")
        yield typ, extra[pos + 4 : pos + 4 + num]
        pos += 4 + num


def trial(root, name, large=False, store=False, fw=False):
    d = root / name
    d.mkdir()
    payload = b"ordinary-data\x00" * 139
    (d / "a.bin").write_bytes(payload)
    expected = {}
    if large:
        expected = {"user.a": b"A" * 34000, "user.b": b"B" * 34000}
    else:
        expected = {"user.binary": b"\x00\xfftest\x00"}
    for k, v in expected.items():
        os.setxattr(d / "a.bin", k, v)
    opts = [ZIP, "--xattrs"]
    if store:
        opts += ["-0"]
    if fw:
        opts += ["--fwkcs"]
    run(opts + ["original.zip", "a.bin"], d)
    rc, log = cloak(d, ["-O", "encrypted.zip", "original.zip"], 2)
    ck(rc == 0, repr(log[-1000:]))
    rc, log = cloak(d, ["-d", "-O", "decrypted.zip", "encrypted.zip"], 1)
    ck(rc == 0, "decrypt " + repr(log[-1000:]))
    with zipfile.ZipFile(d / "decrypted.zip") as z:
        entries = z.infolist()
        ck(len(entries) == (2 if large else 2), "companion persists after decryption")
        ck(all(not (it.flag_bits & 1) for it in entries), "every member now public")
        ck(z.read("a.bin") == payload, "owner content unchanged")
        owner = next(it for it in entries if it.filename == "a.bin")
        xe = dict(fields(owner.extra))[0x5854]
        ck(xe[6] == 2 and xe[7] == 0, "public companion envelope")
        ck(len(xe) == 72, "public digest in central metadata")
        side = next(it for it in entries if it.filename.startswith("__XTRO_ZIP__/"))
        data = z.read(side)
        ck(
            data[:4] == b"XTMD"
            and not data.endswith(b"XTCS" + hashlib.sha256(data[:-36]).digest()),
            "public metadata without protected trailer",
        )
        ck(xe[40:72] == hashlib.sha256(data).digest(), "public SHA digest correct")
        ck(
            not any(tag == 0x4B46 for tag, _ in fields(side.extra)),
            "no stale companion FWKCS",
        )
    (d / "out").mkdir()
    run([UNZIP, "--xattrs", "-o", "decrypted.zip", "-d", "out"], d)
    for k, v in expected.items():
        ck(os.getxattr(d / "out/a.bin", k) == v, "native xattr " + k)
    return d


def cloak_password(cwd, args, password):
    from test_zipcloak_xattrs import CLOAK

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(str(cwd))
        os.execv(str(CLOAK), [str(CLOAK)] + list(args))
    output = b""
    sent = False
    status = None
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if not sent and b"Enter password:" in output:
                time.sleep(0.12)
                os.write(fd, password + b"\n")
                sent = True
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    part = os.read(fd, 4096)
                except OSError:
                    part = b""
                if part:
                    output += part
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = os.waitstatus_to_exitcode(st)
                break
    finally:
        os.close(fd)
        if status is None:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    return status, output


def negative(root):
    d = root / "negative"
    d.mkdir()
    (d / "a.bin").write_bytes(b"prefix" * 100)
    os.setxattr(d / "a.bin", "user.raw", b"\x00\xff" * 100)
    run([ZIP, "--xattrs", "plain.zip", "a.bin"], d)
    rc, log = cloak(d, ["-O", "encrypted.zip", "plain.zip"], 2)
    ck(rc == 0, "make encrypted negative fixture " + repr(log[-200:]))
    data = (d / "encrypted.zip").read_bytes()
    code, out = cloak_password(
        d, ["-d", "-O", "wrong.zip", "encrypted.zip"], b"WRONG_PASSWORD"
    )
    ck(code != 0, "wrong password rejected")
    ck(not (d / "wrong.zip").exists(), "wrong password not published")
    ck(
        (d / "encrypted.zip").read_bytes() == data,
        "source unchanged after wrong password",
    )
    with zipfile.ZipFile(d / "encrypted.zip") as z:
        side = next(
            it for it in z.infolist() if it.filename.startswith("__XTRO_ZIP__/")
        )
        off = side.header_offset
        hn, he = struct.unpack_from("<HH", data, off + 26)
        at = off + 30 + hn + he + 12 + 10
    corrupted = bytearray(data)
    corrupted[at] ^= 0x20
    (d / "bad.zip").write_bytes(corrupted)
    code, out = cloak_password(d, ["-d", "-O", "recovered.zip", "bad.zip"], b"secret")
    ck(code != 0, "encrypted companion tamper rejected")
    ck(not (d / "recovered.zip").exists(), "tamper not published")
    ck((d / "bad.zip").read_bytes() == corrupted, "corrupt source unchanged")
    shutil.copyfile(d / "encrypted.zip", d / "inplace.zip")
    code, out = cloak_password(d, ["-d", "inplace.zip"], b"secret")
    ck(code == 0, "in-place reverse conversion " + repr(out[-250:]))
    with zipfile.ZipFile(d / "inplace.zip") as z:
        ck(
            all(not (it.flag_bits & 1) for it in z.infolist()),
            "in-place decrypted all members",
        )
    run([UNZIP, "--xattrs", "-o", "inplace.zip", "-d", "out"], d)
    ck(
        os.getxattr(d / "out/a.bin", "user.raw") == b"\x00\xff" * 100,
        "in-place xattr restored",
    )


def multiple(root):
    d = root / "multiple"
    d.mkdir()
    expected = {}
    for i in range(2):
        name = "owner%d.bin" % i
        (d / name).write_bytes(b"IDENTICAL-DATA\x00" * 150)
        value = bytes((i + 1, 0, 255)) + b"X" * (100 + i * 68000)
        if i:
            os.setxattr(d / name, "user.part1", value[:34000])
            os.setxattr(d / name, "user.part2", value[34000:])
        else:
            os.setxattr(d / name, "user.identity", value)
        expected[name] = value
    run([ZIP, "--xattrs", "plain.zip", "owner0.bin", "owner1.bin"], d)
    code, out = cloak(d, ["-O", "encrypted.zip", "plain.zip"], 2)
    ck(code == 0, "two owners encrypted")
    code, out = cloak_password(
        d, ["-d", "-O", "decrypted.zip", "encrypted.zip"], b"secret"
    )
    ck(code == 0, "two owners decrypted " + repr(out[-400:]))
    with zipfile.ZipFile(d / "decrypted.zip") as z:
        ck(len(z.namelist()) == 4, "two owner companion pairs")
        ck(all(not (it.flag_bits & 1) for it in z.infolist()), "two public pairs")
    run([UNZIP, "--xattrs", "-o", "decrypted.zip", "-d", "out"], d)
    for i in range(2):
        name = "owner%d.bin" % i
        if i:
            value = os.getxattr(d / "out" / name, "user.part1") + os.getxattr(
                d / "out" / name, "user.part2"
            )
        else:
            value = os.getxattr(d / "out" / name, "user.identity")
        ck(value == expected[name], "two distinct native xattrs")


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-reverse-", dir="/dev/shm") as td:
        r = pathlib.Path(td)
        trial(r, "inline", False)
        trial(r, "inline_fwk", False, False, True)
        trial(r, "big", True)
        trial(r, "big_store", True, True)
        negative(r)
        multiple(r)
    print("M6E2F reverse ZipCrypto: %d checks, 0 failures" % N)


if __name__ == "__main__":
    main()
