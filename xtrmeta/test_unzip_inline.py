#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""M5-A Linux real UnZip inline xattrs, negative guards and adjacent features."""

import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = HERE.parent / "zip30" / "zip"
UNZIP = HERE.parent / "unzip60" / "unzip"
checks = 0


def check(ok, message):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(message)


def call(args, cwd=None):
    return subprocess.run(
        [str(v) for v in args], cwd=cwd, capture_output=True, timeout=35
    )


def fields(data):
    i = 0
    while i < len(data):
        check(i + 4 <= len(data), "valid extra length header")
        fid, n = struct.unpack_from("<HH", data, i)
        check(i + 4 + n <= len(data), "valid extra length value")
        yield fid, data[i + 4 : i + 4 + n]
        i += 4 + n


def assert_xattrs(file, expected):
    actual = {v.encode(): os.getxattr(file, v) for v in os.listxattr(file)}
    check(actual == expected, "attribute bytes match for %s: %r" % (file, actual))


def main():
    directory = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="xtrm5-", dir=directory) as td:
        root = pathlib.Path(td)
        src = root / "src"
        src.mkdir()
        (src / "sub").mkdir()
        owner = src / "sub" / "file.dat"
        owner.write_bytes(b"abc\x00\xff" * 600)
        attrs = {
            b"user.binary": b"\x00\xff\x01\x00\xfe",
            b"user.empty": b"",
            b"user.text": b"xtr-data",
        }
        for key, value in attrs.items():
            os.setxattr(owner, key, value)
        archive = root / "archive.zip"
        run = call([ZIP, "--xattrs", archive, "sub/file.dat"], cwd=src)
        check(
            run.returncode == 0, "Zip inline create: %r %r" % (run.stdout, run.stderr)
        )
        raw = archive.read_bytes()
        with zipfile.ZipFile(archive) as z:
            zi = z.infolist()[0]
            check(len(z.infolist()) == 1, "inline archive has one member")
            check(
                any(
                    k == 0x5854 and v[:8] == b"XTRO\x01\0\x01\0"
                    for k, v in fields(zi.extra)
                ),
                "inline V1 central",
            )
            central_off = raw.find(b"PK\x01\x02")
            check(central_off > 0, "central directory located")
            name_len = struct.unpack_from("<H", raw, central_off + 28)[0]
            cen_extra_at = central_off + 46 + name_len
            xtro_at = next(
                cen_extra_at + sum(4 + len(v) for _, v in list(fields(zi.extra))[:i])
                for i, (k, v) in enumerate(fields(zi.extra))
                if k == 0x5854
            )
            loc_off = zi.header_offset
            ln, le = struct.unpack_from("<HH", raw, loc_off + 26)
            loc_extra_at = loc_off + 30 + ln
            loc_xtr = next(
                loc_extra_at
                + sum(
                    4 + len(v)
                    for _, v in list(fields(raw[loc_extra_at : loc_extra_at + le]))[:i]
                )
                for i, (k, v) in enumerate(
                    fields(raw[loc_extra_at : loc_extra_at + le])
                )
                if k == 0x5854
            )
        dest = root / "dest"
        dest.mkdir()
        rv = call([UNZIP, "--xattrs", archive], cwd=dest)
        check(
            rv.returncode == 0, "UnZip inline restore: %r %r" % (rv.stdout, rv.stderr)
        )
        check(
            (dest / "sub/file.dat").read_bytes() == owner.read_bytes(),
            "content round trip",
        )
        assert_xattrs(dest / "sub/file.dat", attrs)
        # No opt in means no xattr application, and --no-xattrs cancels opt-in.
        for opts in ([], ["--xattrs", "--no-xattrs"]):
            d = root / ("off%d" % len(opts))
            d.mkdir()
            rv = call([UNZIP] + opts + [archive], cwd=d)
            check(rv.returncode == 0, "extraction with xattrs off")
            assert_xattrs(d / "sub/file.dat", {})
        # Skip extraction must not mutate existing metadata.
        os.setxattr(dest / "sub/file.dat", "user.keep", b"unchanged")
        rv = call([UNZIP, "-n", "--xattrs", archive], cwd=dest)
        check(rv.returncode == 0, "-n skip")
        check(
            os.getxattr(dest / "sub/file.dat", "user.keep") == b"unchanged",
            "skipped not modified",
        )
        # Overwrite paths still produce and validate requested attrs.
        rv = call([UNZIP, "-o", "--xattrs", archive], cwd=dest)
        check(rv.returncode == 0, "overwrite succeeds")
        for key, val in attrs.items():
            check(
                os.getxattr(dest / "sub/file.dat", key) == val,
                "overwrite xattrs restored",
            )
        # Corruption of local association must not apply attributes.
        corrupted = bytearray(raw)
        corrupted[loc_xtr + 4 + 8] ^= 0x80
        (root / "mismatched.zip").write_bytes(corrupted)
        d = root / "mismatch"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", root / "mismatched.zip"], cwd=d)
        check(rv.returncode != 0, "local/central mismatch rejected")
        if (d / "sub/file.dat").exists():
            assert_xattrs(d / "sub/file.dat", {})
        # Tampered (but still parseable header) central checksum denied before output.
        corrupted = bytearray(raw)
        corrupted[xtro_at + 4 + 36] ^= 0x80
        (root / "badcentral.zip").write_bytes(corrupted)
        d = root / "badcen"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", root / "badcentral.zip"], cwd=d)
        check(rv.returncode != 0, "central digest rejected")
        check(
            not (d / "sub/file.dat").exists(), "corrupt central did not publish member"
        )
        # FWKCS on ordinary owner remains independent of Xtro CRC.
        fwk = root / "fwkcs.zip"
        rv = call([ZIP, "--xattrs", "--fwkcs-md5", fwk, "sub/file.dat"], cwd=src)
        check(rv.returncode == 0, "FWKCS owner create")
        d = root / "fwkout"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", fwk], cwd=d)
        check(rv.returncode == 0, "FWKCS owner verified and restored")
        assert_xattrs(d / "sub/file.dat", attrs)
        # A wrong FWKCS digest must block metadata application even when the
        # normal ZIP CRC and Xtro metadata headers are otherwise valid.
        fwraw = bytearray(fwk.read_bytes())
        with zipfile.ZipFile(fwk) as z:
            info = z.infolist()[0]
            cen = fwraw.find(b"PK\x01\x02")
            start = cen + 46 + struct.unpack_from("<H", fwraw, cen + 28)[0]
            off = start
            for kind, value in fields(info.extra):
                if kind == 0x4B46:
                    check(value[:3] == b"MD5", "FWKCS record")
                    fwraw[off + 4 + 3] ^= 0x01
                    break
                off += 4 + len(value)
            else:
                raise AssertionError("missing FWKCS")
        (root / "badfwkcs.zip").write_bytes(fwraw)
        d = root / "badfwout"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", root / "badfwkcs.zip"], cwd=d)
        check(rv.returncode != 0, "bad FWKCS detected")
        if (d / "sub/file.dat").exists():
            assert_xattrs(d / "sub/file.dat", {})
        # A corrupt owner payload (valid Xtro headers) must not apply xattrs.
        stored = root / "stored.zip"
        rv = call([ZIP, "--xattrs", "-0", stored, "sub/file.dat"], cwd=src)
        check(rv.returncode == 0, "stored Xtro owner")
        storedraw = bytearray(stored.read_bytes())
        with zipfile.ZipFile(stored) as z:
            info = z.infolist()[0]
            off = info.header_offset
            nl, el = struct.unpack_from("<HH", storedraw, off + 26)
            storedraw[off + 30 + nl + el] ^= 0x01
        (root / "badpayload.zip").write_bytes(storedraw)
        d = root / "badpayloadout"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", root / "badpayload.zip"], cwd=d)
        check(rv.returncode != 0, "bad file-content CRC detected")
        if (d / "sub/file.dat").exists():
            assert_xattrs(d / "sub/file.dat", {})
        # A ZIP64 owner still has an ordinary Xtro local/central association.
        force = root / "zip64.zip"
        rv = call([ZIP, "--xattrs", "-fz", force, "sub/file.dat"], cwd=src)
        check(rv.returncode == 0, "forced ZIP64 owner")
        d = root / "zip64out"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", force], cwd=d)
        check(rv.returncode == 0, "ZIP64 inline extraction")
        assert_xattrs(d / "sub/file.dat", attrs)
        # -d is supported, and descriptor/path checks remain scoped to it.
        d = root / "exdir"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", "-d", d, archive], cwd=root)
        check(
            rv.returncode == 0,
            "explicit extraction directory: %r %r" % (rv.stdout, rv.stderr),
        )
        assert_xattrs(d / "sub/file.dat", attrs)
        # Relative -d and no-directory (-j) options retain safe owner lookup.
        d = root / "relative"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", "-d", "relative", archive], cwd=root)
        check(rv.returncode == 0, "relative -d: %r %r" % (rv.stdout, rv.stderr))
        assert_xattrs(d / "sub/file.dat", attrs)
        d = root / "junk"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", "-j", archive], cwd=d)
        check(rv.returncode == 0, "-j flatten extraction")
        assert_xattrs(d / "file.dat", attrs)
        # Internal companions are not extracted as ordinary metadata with --xattrs.
        os.setxattr(owner, "user.large", bytes(range(256)) * 235)
        os.setxattr(owner, "user.medium", bytes(range(230)) * 62)
        side = root / "side.zip"
        rv = call([ZIP, "--xattrs", side, "sub/file.dat"], cwd=src)
        check(rv.returncode == 0, "create large companion")
        with zipfile.ZipFile(side) as z:
            check(len(z.infolist()) == 2, "companion present")
        d = root / "sideout"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", side], cwd=d)
        check(
            rv.returncode == 0,
            "large companion restored: %r %r" % (rv.stdout, rv.stderr),
        )
        assert_xattrs(
            d / "sub/file.dat",
            {
                **attrs,
                b"user.large": bytes(range(256)) * 235,
                b"user.medium": bytes(range(230)) * 62,
            },
        )
        check(
            not (d / "__XTRO_ZIP__").exists(), "no internal companion folder published"
        )
        # Existing standard Zip extraction, listing and test remain usable.
        check(call([UNZIP, "-t", side]).returncode == 0, "large archive ordinary test")
        # No metadata behavior is changed for ordinary archives.
        plain = root / "plain.zip"
        rv = call([ZIP, plain, "sub/file.dat"], cwd=src)
        check(rv.returncode == 0, "ordinary Zip")
        d = root / "plainout"
        d.mkdir()
        rv = call([UNZIP, "--xattrs", plain], cwd=d)
        check(rv.returncode == 0, "ordinary Zip read with optional --xattrs")
        assert_xattrs(d / "sub/file.dat", {})
        # Flag conflicts are explicitly rejected.
        check(
            call([UNZIP, "--xattrs", "-p", archive], cwd=d).returncode != 0,
            "--xattrs -p is not silently accepted",
        )
        check(
            call([UNZIP, "--xattrs", "-t", archive], cwd=d).returncode != 0,
            "--xattrs -t is not silently accepted",
        )
        # Linux path opener may not traverse symlinks, even if regular UnZip
        # extraction permitted them as parent directories.
        d = root / "linkout"
        d.mkdir()
        external = root / "external"
        external.mkdir()
        (d / "sub").symlink_to(external, target_is_directory=True)
        rv = call([UNZIP, "--xattrs", archive], cwd=d)
        check(rv.returncode != 0, "xattr restore does not follow intermediate symlinks")
        if (external / "file.dat").exists():
            assert_xattrs(external / "file.dat", {})
    print("Linux UnZip inline integration: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
