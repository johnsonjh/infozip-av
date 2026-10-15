#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Linux production Zip --xattrs tests; no native UnZip restore is claimed."""

import hashlib
import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = HERE.parent / "zip30/zip"
UNZIP = HERE.parent / "unzip60/unzip"
VERIFY = HERE / "verify_fixture"
assert ZIP.is_file() and UNZIP.is_file() and VERIFY.is_file()
checks = 0


def check(v, what):
    global checks
    checks += 1
    if not v:
        raise AssertionError(what)


def call(*argv, cwd=None):
    return subprocess.run(
        [str(x) for x in argv], cwd=cwd, capture_output=True, timeout=60
    )


def extra(raw):
    at = 0
    got = []
    while at < len(raw):
        check(at + 4 <= len(raw), "extra truncated header")
        kind, n = struct.unpack_from("<HH", raw, at)
        check(at + 4 + n <= len(raw), "extra truncated field")
        got.append((kind, raw[at + 4 : at + 4 + n]))
        at += 4 + n
    return got


def local_fields(buf, member):
    at = member.header_offset
    check(buf[at : at + 4] == b"PK\x03\x04", "local signature")
    n, e = struct.unpack_from("<HH", buf, at + 26)
    check(buf[at + 30 : at + 30 + n] == member.filename.encode(), "local name")
    return extra(buf[at + 30 + n : at + 30 + n + e])


def parse_manifest(data, id):
    check(data[:8] == b"XTMD\x01\0\0\0", "manifest magic")
    check(data[8:24] == id, "manifest owner")
    num = struct.unpack_from("<I", data, 24)[0]
    size = struct.unpack_from("<Q", data, 28)[0]
    check(size == len(data) - 36, "manifest length")
    at = 36
    result = {}
    for i in range(num):
        typ, flags, origin, enc, nsl, nl, tl, vl = struct.unpack_from(
            "<HHHHIIIQ", data, at
        )
        at += 28
        ns = data[at : at + nsl]
        at += nsl
        name = data[at : at + nl]
        at += nl
        native = data[at : at + tl]
        at += tl
        val = data[at : at + vl]
        at += vl
        check(
            (typ, flags, origin, enc, ns, native)
            == (1, 0, 1, 0, b"user", b"\x01\0\0\0\x02\0\0\0\x01\0"),
            "Linux record",
        )
        check(name not in result, "duplicate name")
        result[name] = val
    check(at == len(data), "manifest trailing bytes")
    return result


def check_archive(root, name, attrs, encrypted=None, fwkcs=False, force_sidecar=False):
    archive = root / name
    raw = archive.read_bytes()
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        check(
            len(members) == (2 if force_sidecar or encrypted or len(attrs) > 1 else 1),
            "count",
        )
        owner = members[0]
        check(owner.filename == "sample.dat", "owner filename")
        cef = extra(owner.extra)
        xf = [v for k, v in cef if k == 0x5854]
        check(len(xf) == 1, "one Xtro central field")
        xp = xf[0]
        check(xp[:6] == b"XTRO\x01\0", "Xtro signature")
        lid = xp[8:24]
        check(any(lid), "owner ID nonzero")
        lx = [v for k, v in local_fields(raw, owner) if k == 0x5854]
        check(len(lx) == 1 and lx[0] == xp[:40], "local/central payload equality")
        mode = xp[6]
        check(mode in (1, 2), "mode")
        check(bool(xp[7] & 1) == bool(encrypted), "privacy bit")
        if mode == 1:
            check(not encrypted and len(members) == 1, "inline conditions")
            manifest = xp[40:]
            sha = None
        else:
            check(len(members) == 2, "companion exists")
            side = members[1]
            check(
                side.filename == "__XTRO_ZIP__/x/" + lid.hex() + ".xtm", "reserved name"
            )
            check(
                side.compress_type in (0, 8) or side.compress_type == 99,
                "companion ZIP method",
            )
            check(
                bool(side.flag_bits & 1) == bool(encrypted),
                "companion transport encryption",
            )
            check(
                not [x for x in extra(side.extra) if x[0] == 0x5854],
                "no nested Xtro extra",
            )
            check(
                not encrypted or not [x for x in extra(side.extra) if x[0] == 0x4B46],
                "no plaintext FWKCS on encrypted companion",
            )
            if encrypted in ("ae1", "ae2", "ae3"):
                x = [v for k, v in extra(owner.extra) if k == 0x9901]
                y = [v for k, v in extra(side.extra) if k == 0x9901]
                check(
                    len(x) == len(y) == 1 and x[0][:5] == y[0][:5],
                    "AES vendor/strength",
                )
                check(
                    struct.unpack_from("<H", x[0])[0]
                    == (2 if encrypted == "ae2" else 1 if encrypted == "ae1" else 3),
                    "AES version",
                )
                output = call(
                    UNZIP, "-p", "-P", "sample-password", archive, side.filename
                )
                check(output.returncode == 0, "AES authenticated extract")
                stream = output.stdout
            else:
                stream = z.read(side, pwd=b"sample-password" if encrypted else None)
            if encrypted:
                check(stream[-36:-32] == b"XTCS", "encrypted footer magic")
                manifest = stream[:-36]
                check(
                    hashlib.sha256(manifest).digest() == stream[-32:],
                    "encrypted SHA256",
                )
                sha = None
            else:
                manifest = stream
                check(hashlib.sha256(manifest).digest() == xp[40:72], "central SHA256")
                sha = xp[40:72]
        records = parse_manifest(manifest, lid)
        check(records == attrs, "exact source xattrs")
        if mode == 2:
            with tempfile.TemporaryDirectory(dir=root) as t:
                t = pathlib.Path(t)
                (t / "manifest").write_bytes(stream)
                (t / "loc").write_bytes(lx[0])
                (t / "cen").write_bytes(xp)
                rv = call(VERIFY, t / "manifest", t / "loc", t / "cen")
                check(rv.returncode == 0, ("standalone C89 verifier", rv.stderr))
        if fwkcs:
            for member in members:
                vals = [v for k, v in extra(member.extra) if k == 0x4B46]
                check(len(vals) == 1, "FWKCS on public member")
                data = z.read(member)
                check(
                    vals[0] == b"MD5" + hashlib.md5(data).digest(), "FWKCS content MD5"
                )
    check(
        call(
            UNZIP, "-t", *(["-P", "sample-password"] if encrypted else []), archive
        ).returncode
        == 0,
        "native UnZip CRC and authentication test",
    )


def main():
    rootdir = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="xtro-m4-", dir=rootdir) as td:
        root = pathlib.Path(td)
        (root / "sample.dat").write_bytes(b"content\n")
        small = {b"user.note": b"foo\x00bar", b"user.empty": b""}
        for k, v in small.items():
            os.setxattr(root / "sample.dat", k, v)
        run = call(ZIP, "--xattrs", "small.zip", "sample.dat", cwd=root)
        check(run.returncode == 0, ("small Zip", run.stdout, run.stderr))
        # Multiple small values remain inline, exactly one logical record set.
        with zipfile.ZipFile(root / "small.zip") as z:
            xf = [v for k, v in extra(z.infolist()[0].extra) if k == 0x5854]
            check(len(xf) == 1 and xf[0][6] == 1, "small inline")
        # Big aggregate metadata (>64 KiB) despite individual FS xattr caps.
        big = dict(small)
        big[b"user.large"] = bytes(range(256)) * 235  # 60,160 bytes
        big[b"user.medium"] = bytes(range(230)) * 62  # 14,260 bytes
        for k, v in big.items():
            os.setxattr(root / "sample.dat", k, v)
        run = call(ZIP, "--xattrs", "large.zip", "sample.dat", cwd=root)
        check(run.returncode == 0, ("large Zip", run.stdout, run.stderr))
        check_archive(root, "large.zip", big, force_sidecar=True)
        run = call(ZIP, "--xattrs", "--fwkcs-md5", "fwkcs.zip", "sample.dat", cwd=root)
        check(run.returncode == 0, "FWKCS Zip")
        check_archive(root, "fwkcs.zip", big, fwkcs=True, force_sidecar=True)
        for mode, options in [
            ("zipcrypto", ["-P", "sample-password"]),
            ("ae2", ["-eP", "sample-password", "--aes-strength", "256"]),
            (
                "ae3",
                [
                    "-eP",
                    "sample-password",
                    "--aes-strength",
                    "256",
                    "--aes-mode",
                    "quantum",
                ],
            ),
        ]:
            run = call(ZIP, "--xattrs", *options, mode + ".zip", "sample.dat", cwd=root)
            check(run.returncode == 0, (mode, run.stdout, run.stderr))
            check_archive(root, mode + ".zip", big, encrypted=mode, force_sidecar=True)
        (root / "sample.dat").write_bytes(b"abcdefghijklmnopqrstuvwxyz: AE-1 payload\n")
        run = call(
            ZIP,
            "--xattrs",
            "-eP",
            "sample-password",
            "--aes-strength",
            "256",
            "ae1.zip",
            "sample.dat",
            cwd=root,
        )
        check(run.returncode == 0, "AE-1 Zip")
        check_archive(root, "ae1.zip", big, encrypted="ae1", force_sidecar=True)
        run = call(
            ZIP,
            "--xattrs",
            "--fwkcs-md5",
            "-P",
            "sample-password",
            "reject.zip",
            "sample.dat",
            cwd=root,
        )
        check(
            run.returncode != 0 and not (root / "reject.zip").exists(),
            "FWKCS encrypted metadata conflict failed closed",
        )
        run = call(ZIP, "--xattrs", "-X", "reject-extra.zip", "sample.dat", cwd=root)
        check(
            run.returncode != 0 and not (root / "reject-extra.zip").exists(),
            "historic -X conflict failed closed",
        )
        # Copy/delete from existing Xtro archives preserves the graph.
        (root / "unrelated.txt").write_bytes(b"unrelated\n")
        a = root / "large.zip"
        run = call(ZIP, a, "unrelated.txt", cwd=root)
        check(run.returncode == 0, "unrelated append to Xtro archive")
        with zipfile.ZipFile(a) as z:
            check(len(z.infolist()) == 3, "unchanged graph plus unrelated file")
        run = call(ZIP, "-d", a, "sample.dat", cwd=root)
        check(run.returncode == 0, "delete owner with companion")
        with zipfile.ZipFile(a) as z:
            check(z.namelist() == ["unrelated.txt"], "owner+companion deletion")
        # Repeat on an existing Xtro archive: a second owner with native EAs
        # must not detach, overwrite, or otherwise disturb the first pair.
        (root / "other.dat").write_bytes(b"new owner content")
        os.setxattr(root / "other.dat", b"user.second", b"B")
        a = root / "zipcrypto.zip"
        run = call(ZIP, "--xattrs", "-P", "sample-password", a, "other.dat", cwd=root)
        check(run.returncode == 0, "append second encrypted owner to Xtro archive")
        with zipfile.ZipFile(a) as z:
            check(len(z.infolist()) == 4, "both encrypted metadata pairs remain")
            check(
                all(z.infolist()[i].flag_bits & 1 for i in range(4)),
                "all members retain encrypted transport",
            )
        # Directory EAs are supported without following an entry's pathname.
        (root / "directory").mkdir()
        os.setxattr(root / "directory", b"user.dirlabel", b"D")
        run = call(ZIP, "--xattrs", "directory.zip", "directory/", cwd=root)
        check(run.returncode == 0, "directory owner capture")
        with zipfile.ZipFile(root / "directory.zip") as z:
            check(len(z.infolist()) == 1, "directory inline metadata")
            record = dict(extra(z.infolist()[0].extra))[0x5854]
            check(
                record[6] == 1 and record[8:24] == record[48:64],
                "directory owner inline reference",
            )
        # Directory entries themselves aren't encrypted by conventional ZIP.
        # Never silently downgrade encrypted directory metadata to plaintext.
        run = call(
            ZIP,
            "--xattrs",
            "-P",
            "sample-password",
            "reject-dir-encrypted.zip",
            "directory/",
            cwd=root,
        )
        check(
            run.returncode != 0 and not (root / "reject-dir-encrypted.zip").exists(),
            "encrypted directory metadata rejected until secure format",
        )
        # Explicitly exercise existing ZIP64 creation and old extractor paths.
        run = call(ZIP, "--xattrs", "-fz", "forced-zip64.zip", "sample.dat", cwd=root)
        check(run.returncode == 0, "forced ZIP64 metadata archive")
        check(
            call(UNZIP, "-t", root / "forced-zip64.zip").returncode == 0,
            "forced ZIP64 older UnZip test",
        )
        # No automatic extraction into the reserved path on Xtro-aware
        # extractors until production UnZip restoration is integrated.
        (root / "__XTRO_ZIP__").mkdir()
        (root / "__XTRO_ZIP__" / "x").mkdir()
        (root / "__XTRO_ZIP__" / "x" / "user.txt").write_text("collision")
        run = call(
            ZIP, "--xattrs", "reject-reserved.zip", "__XTRO_ZIP__/x/user.txt", cwd=root
        )
        check(
            run.returncode != 0 and not (root / "reject-reserved.zip").exists(),
            "reserved member pathname rejected",
        )
        # M5D: a link with no eligible user.* attributes can be stored
        # normally under -y; the writer probes llistxattr rather than
        # following the link to the metadata-bearing target.
        os.symlink("sample.dat", root / "sym")
        run = call(ZIP, "--xattrs", "-y", "allow-sym.zip", "sym", cwd=root)
        check(
            run.returncode == 0 and (root / "allow-sym.zip").exists(),
            "metadata-free symbolic link compatible with --xattrs",
        )
        with zipfile.ZipFile(root / "allow-sym.zip") as zz:
            check(
                zz.namelist() == ["sym"]
                and not [k for k, v in extra(zz.getinfo("sym").extra) if k == 0x5854],
                "symlink does not inherit target xattrs",
            )
        # No-attribute files produce no gratuitous Xtro fields or companions.
        run = call(ZIP, "--xattrs", "plain.zip", "unrelated.txt", cwd=root)
        check(run.returncode == 0, "no xattr successful")
        with zipfile.ZipFile(root / "plain.zip") as z:
            check(
                len(z.infolist()) == 1
                and not [k for k, v in extra(z.infolist()[0].extra) if k == 0x5854],
                "no empty xattr output",
            )
    print("Linux Zip --xattrs integration: {} checks, 0 failures".format(checks))


if __name__ == "__main__":
    main()
