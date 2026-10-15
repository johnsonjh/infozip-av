#!/usr/bin/env python3
"""Linux native archive-replacement regression for Xtro-ZIP (M6A).

This test intentionally exercises the production Zip writer/UnZip reader and
ordinary ZIP central/local fields rather than calling the metadata core alone.
"""

import hashlib
import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = (HERE / "../zip30/zip").resolve()
UNZIP = (HERE / "../unzip60/unzip").resolve()
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(*args, cwd=None, should_pass=True):
    p = subprocess.run(
        [str(x) for x in args], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if should_pass != (p.returncode == 0):
        raise AssertionError(
            "command %r returned %d:\n%s\n%s"
            % (
                args,
                p.returncode,
                p.stdout.decode("utf8", "replace"),
                p.stderr.decode("utf8", "replace"),
            )
        )
    return p


def ef(data):
    at = 0
    while at < len(data):
        check(at + 4 <= len(data), "complete extra header")
        tag, length = struct.unpack_from("<HH", data, at)
        at += 4
        check(at + length <= len(data), "complete extra payload")
        yield tag, data[at : at + length]
        at += length


def state(path):
    with zipfile.ZipFile(path) as z:
        items = z.infolist()
        owners = {}
        sides = {}
        for entry in items:
            x = [v for k, v in ef(entry.extra) if k == 0x5854 and v[:4] == b"XTRO"]
            check(len(x) <= 1, "one Xtro owner field per member")
            if x:
                check(len(x[0]) >= 40, "full owner envelope")
                identity = x[0][8:24].hex()
                check(identity not in owners, "no owner ID collision")
                owners[identity] = entry.filename
                check(identity != "00" * 16, "nonzero identity")
            if entry.filename.startswith("__XTRO_ZIP__/"):
                check(entry.filename.startswith("__XTRO_ZIP__/x/"), "reserved prefix")
                token = entry.filename[15:47]
                check(
                    entry.filename == "__XTRO_ZIP__/x/" + token + ".xtm",
                    "canonical companion name",
                )
                check(token not in sides, "unique companion identity")
                sides[token] = entry.filename
        for identity, name in sides.items():
            check(identity in owners, "no orphan companion")
        return owners, sides, items


def native_restore(
    archive, expected_contents, expected_xattrs, password=None, filename="src.bin"
):
    with tempfile.TemporaryDirectory(
        prefix="xtr-m6-restore-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None
    ) as td:
        args = [UNZIP, "-o", "--xattrs"]
        if password is not None:
            args += ["-P", password]
        run(*args, archive, "-d", td)
        target = pathlib.Path(td) / filename
        check(target.read_bytes() == expected_contents, "restored exact bytes")
        check(
            {name: os.getxattr(target, name) for name in os.listxattr(target)}
            == expected_xattrs,
            "restored native xattrs",
        )
        check(
            not (pathlib.Path(td) / "__XTRO_ZIP__").exists(),
            "no physical metadata companion output",
        )


def corrupt_local_owner(archive):
    with zipfile.ZipFile(archive) as z:
        owner = z.infolist()[0]
        offset = owner.header_offset
        raw = bytearray(pathlib.Path(archive).read_bytes())
        check(raw[offset : offset + 4] == b"PK\x03\x04", "local header present")
        name_len, extra_len = struct.unpack_from("<HH", raw, offset + 26)
        pos = offset + 30 + name_len
        end = pos + extra_len
        while pos < end:
            tag, length = struct.unpack_from("<HH", raw, pos)
            if tag == 0x5854 and raw[pos + 4 : pos + 8] == b"XTRO":
                raw[pos + 4 + 8] ^= 0x80
                pathlib.Path(archive).write_bytes(raw)
                return
            pos += 4 + length
        raise AssertionError("missing local metadata")


def main():
    base = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="xtr-m6-replace-", dir=base) as td:
        root = pathlib.Path(td)
        src = root / "src.bin"
        src.write_bytes(b"A" * 50)
        os.setxattr(src, b"user.test", b"one\0two")
        os.setxattr(src, b"user.empty", b"")
        inline = root / "inline.zip"
        run(ZIP, "--xattrs", inline, src.name, cwd=root)
        old_owner = next(iter(state(inline)[0]))
        check(len(state(inline)[2]) == 1, "initial inline archive")
        src.write_bytes(b"B" * 100)
        os.setxattr(src, b"user.test", b"new\0value")
        run(ZIP, "--xattrs", inline, src.name, cwd=root)
        check(len(state(inline)[2]) == 1, "replaced inline remains inline")
        check(
            next(iter(state(inline)[0])) != old_owner,
            "replaced inline gets new owner identity",
        )
        native_restore(
            inline, b"B" * 100, {"user.test": b"new\0value", "user.empty": b""}
        )
        src.write_bytes(b"C" * 150)
        p = run(ZIP, inline, src.name, cwd=root)
        check(
            b"previous metadata discarded" in p.stderr + p.stdout,
            "replacement without capture issues warning",
        )
        check(state(inline)[0] == {}, "obsolete inline metadata removed")
        with zipfile.ZipFile(inline) as z:
            check(z.read(src.name) == b"C" * 150, "ordinary replacement bytes")

        big = bytes(range(256)) * 235
        os.setxattr(src, b"user.big", big)
        archive = root / "large.zip"
        run(ZIP, "--xattrs", archive, src.name, cwd=root)
        previous = next(iter(state(archive)[0]))
        check(len(state(archive)[2]) == 2, "initial companion")
        extra = root / "keep.txt"
        extra.write_bytes(b"unchanged companion test")
        run(ZIP, archive, extra.name, cwd=root)
        check(previous in state(archive)[0], "unchanged owner identity retained")
        src.write_bytes(b"D" * 203)
        os.setxattr(src, b"user.big", big[::-1])
        run(ZIP, "--xattrs", archive, src.name, cwd=root)
        owners, sides, items = state(archive)
        check(len(items) == 3, "replaced companion and unrelated member")
        check(
            previous not in owners and previous not in sides,
            "old metadata identity fully removed",
        )
        check(len(owners) == len(sides) == 1, "new companion associated")
        native_restore(
            archive,
            b"D" * 203,
            {"user.test": b"new\0value", "user.empty": b"", "user.big": big[::-1]},
        )
        with zipfile.ZipFile(archive) as z:
            check(
                z.read(extra.name) == extra.read_bytes(),
                "unrelated member remains intact",
            )
        old = archive.read_bytes()
        bad = root / "corrupt.zip"
        bad.write_bytes(old)
        corrupt_local_owner(bad)
        before = hashlib.sha256(bad.read_bytes()).digest()
        src.write_bytes(b"E" * 303)
        run(ZIP, "--xattrs", bad, src.name, cwd=root, should_pass=False)
        check(
            hashlib.sha256(bad.read_bytes()).digest() == before,
            "bad local header never publishes partial replacement",
        )

        src.write_bytes(b"F" * 91)
        run(ZIP, archive, src.name, cwd=root)
        check(state(archive)[0] == {}, "old metadata removed without capture")
        check(state(archive)[1] == {}, "old companion member removed")
        with zipfile.ZipFile(archive) as z:
            check(
                z.namelist() == [src.name, extra.name],
                "no orphan and unrelated entry preserved",
            )

        # FWKCS remains a separate, content-MD5 layer. A public metadata
        # companion may carry FWKCS, but replacing it must recalculate the
        # digest against the *new* uncompressed companion bytes.
        src.write_bytes(b"J" * 111)
        fwk = root / "fwkcs-replacement.zip"
        run(ZIP, "--xattrs", "--fwkcs-md5", fwk, src.name, cwd=root)
        src.write_bytes(b"K" * 211)
        os.setxattr(src, b"user.big", big)
        run(ZIP, "--xattrs", "--fwkcs-md5", fwk, src.name, cwd=root)
        with zipfile.ZipFile(fwk) as z:
            check(len(z.infolist()) == 2, "FWKCS replacement pair count")
            for entry in z.infolist():
                tags = [v for k, v in ef(entry.extra) if k == 0x4B46]
                check(len(tags) == 1, "FWKCS on public replacement member")
                check(
                    tags[0] == b"MD5" + hashlib.md5(z.read(entry)).digest(),
                    "recalculated FWKCS MD5",
                )
        native_restore(
            fwk,
            b"K" * 211,
            {"user.test": b"new\0value", "user.empty": b"", "user.big": big},
        )
        # User explicitly required FWKCS for all members, but an encrypted
        # companion must not disclose its digest. Reject without publication.
        fwk_before = hashlib.sha256(fwk.read_bytes()).digest()
        run(
            ZIP,
            "--xattrs",
            "--fwkcs-md5",
            "-P",
            "xtr-password",
            fwk,
            src.name,
            cwd=root,
            should_pass=False,
        )
        check(
            hashlib.sha256(fwk.read_bytes()).digest() == fwk_before,
            "FWKCS/encryption conflict leaves archive intact",
        )

        os.setxattr(src, b"user.big", big[::-1])
        for mode, options, size in (
            ("zipcrypto", ["-P", "xtr-password"], 120),
            ("ae1", ["-eP", "xtr-password", "--aes-strength", "256"], 200),
            ("ae2", ["-eP", "xtr-password", "--aes-strength", "256"], 8),
            (
                "ae3",
                [
                    "-eP",
                    "xtr-password",
                    "--aes-strength",
                    "256",
                    "--aes-mode",
                    "quantum",
                ],
                300,
            ),
        ):
            src.write_bytes(b"G" * size)
            encrypted = root / (mode + ".zip")
            run(ZIP, "--xattrs", *options, encrypted, src.name, cwd=root)
            old = next(iter(state(encrypted)[0]))
            src.write_bytes(b"H" * size)
            run(ZIP, "--xattrs", *options, encrypted, src.name, cwd=root)
            own, side, entries = state(encrypted)
            check(len(entries) == 2 and old not in own, mode + " replacement")
            check(
                all(e.flag_bits & 1 for e in entries),
                mode + " encrypted transport retained",
            )
            native_restore(
                encrypted,
                b"H" * size,
                {"user.test": b"new\0value", "user.empty": b"", "user.big": big[::-1]},
                "xtr-password",
            )
            src.write_bytes(b"I" * size)
            run(ZIP, encrypted, src.name, cwd=root)
            check(
                state(encrypted)[0] == {} and state(encrypted)[1] == {},
                mode + " no-capture removal",
            )
            run(UNZIP, "-t", "-P", "xtr-password", encrypted)

        print("Xtro archive replacement: %d assertions, 0 failures" % checks)


if __name__ == "__main__":
    main()
