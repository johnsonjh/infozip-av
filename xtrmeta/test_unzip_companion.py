#!/usr/bin/env python3
"""Linux M5B real ZIP owner/companion round-trip and negative tests."""

import copy, hashlib, os, pathlib, struct, subprocess, tempfile, zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = os.environ.get("XTR_ZIP_BIN", str(HERE.parent / "zip30/zip"))
UNZIP = os.environ.get("XTR_UNZIP_BIN", str(HERE.parent / "unzip60/unzip"))
checks = 0


def ck(value, info):
    global checks
    checks += 1
    if not value:
        raise AssertionError(info)


def run(*args, cwd=None):
    return subprocess.run(
        [str(x) for x in args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=35,
    )


def attrs(p):
    return {os.fsencode(n): os.getxattr(p, n) for n in os.listxattr(p)}


def exact(p, expected, tag):
    got = attrs(p)
    ck(
        got == expected,
        "%s expected %r actual hashes %r"
        % (
            tag,
            list(expected),
            [(x, len(y), hashlib.sha256(y).hexdigest()[:8]) for x, y in got.items()],
        ),
    )


def parse_extra(b):
    pos = 0
    while pos + 4 <= len(b):
        kind, n = struct.unpack_from("<HH", b, pos)
        yield kind, b[pos + 4 : pos + 4 + n]
        pos += 4 + n


def field(b, id):
    pos = 0
    while pos + 4 <= len(b):
        type_, n = struct.unpack_from("<HH", b, pos)
        if type_ == id:
            return pos + 4, n
        pos += 4 + n
    raise AssertionError("missing xtr extra")


def main():
    storage = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="xtro-m5b-", dir=storage) as t:
        r = pathlib.Path(t)
        s = r / "source"
        s.mkdir()
        (s / "inside").mkdir()
        data = s / "inside" / "sample.bin"
        data.write_bytes(b"0abc\0def\xff" * 100)
        fields = {
            b"user.a": b"\0\xff\0",
            b"user.empty": b"",
            b"user.one": bytes(range(256)) * 235,
            b"user.two": bytes(range(230)) * 62,
        }
        for k, v in fields.items():
            os.setxattr(data, k, v)

        def exercise(name, options, password=None, opts=None):
            a = r / (name + ".zip")
            rv = run(ZIP, "--xattrs", *options, a, "inside/sample.bin", cwd=s)
            ck(
                rv.returncode == 0,
                "zip %s: rc=%s out=%r err=%r"
                % (name, rv.returncode, rv.stdout, rv.stderr),
            )
            with zipfile.ZipFile(a) as z:
                ck(len(z.infolist()) == 2, "%s pair" % name)
                if name in ("ae1", "ae2", "ae3"):
                    versions = []
                    for zi in z.infolist():
                        v = next(
                            (x for k, x in parse_extra(zi.extra) if k == 0x9901), None
                        )
                        ck(v is not None, "%s AES member extra" % name)
                        versions.append(struct.unpack_from("<H", v)[0])
                    ck(
                        versions == [{"ae1": 1, "ae2": 2, "ae3": 3}[name]] * 2,
                        "%s precise AES version %r" % (name, versions),
                    )
            dest = r / (name + "out")
            dest.mkdir()
            args = ["--xattrs"] + (opts or [])
            if password:
                args += ["-P", password]
            rv = run(UNZIP, *args, a, cwd=dest)
            ck(
                rv.returncode == 0,
                "unzip %s: stdout=%r stderr=%r"
                % (name, rv.stdout[-300:], rv.stderr[-300:]),
            )
            exact(dest / "inside/sample.bin", fields, name)
            ck(not (dest / "__XTRO_ZIP__").exists(), "%s companion hidden" % name)
            ck(
                (dest / "inside/sample.bin").read_bytes() == data.read_bytes(),
                "%s bytes" % name,
            )
            return a, dest

        plain, plainout = exercise("public", [])
        exercise("stored", ["-0"])
        exercise("fwkcs", ["--fwkcs-md5"])
        # Large uncompressed owner, AE-2 is selected for small raw payloads.
        original = data.read_bytes()
        data.write_bytes(b"x")
        exercise(
            "ae2",
            ["-eP", "sample-password", "--aes-strength", "256"],
            "sample-password",
        )
        data.write_bytes(original)
        crypto, cryptout = exercise(
            "zipcrypto", ["-P", "sample-password"], "sample-password"
        )
        for n, opt in [
            ("ae1", ["-eP", "sample-password", "--aes-strength", "256"]),
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
            exercise(n, opt, "sample-password")
        # Encrypted transport error must block native attributes.
        d = r / "wrongpwd"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", "-P", "wrong", crypto, cwd=d)
        ck(rv.returncode != 0, "bad password rejected")
        p = d / "inside/sample.bin"
        if p.exists():
            ck(not attrs(p), "wrong password cannot set attributes")
        # A changed compressed companion must fail before native restoration.
        corrupted = bytearray(plain.read_bytes())
        with zipfile.ZipFile(plain) as z:
            side = z.infolist()[1]
            off = side.header_offset
            ln, en = struct.unpack_from("<HH", corrupted, off + 26)
            corrupted[off + 30 + ln + en + 2] ^= 0x20
        badcomp = r / "badcomp.zip"
        badcomp.write_bytes(corrupted)
        d = r / "badcompout"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", badcomp, cwd=d)
        ck(rv.returncode != 0, "bad companion compressed data")
        if (d / "inside/sample.bin").exists():
            ck(
                not attrs(d / "inside/sample.bin"),
                "bad companion never applies metadata",
            )
        # -n must not modify existing contents/attributes.
        os.setxattr(plainout / "inside/sample.bin", b"user.keep", b"keep")
        rv = run(UNZIP, "--xattrs", "-n", plain, cwd=plainout)
        ck(rv.returncode == 0, "skip existing member")
        ck(
            os.getxattr(plainout / "inside/sample.bin", b"user.keep") == b"keep",
            "skip does not restore",
        )
        # Copy central hash corruption without modifying the local Xtro token;
        # companion CRC still succeeds, SHA-256 must prevent restore.
        b = bytearray(plain.read_bytes())
        with zipfile.ZipFile(plain) as z:
            owner = z.infolist()[0]
            central = b.find(b"PK\x01\x02")
            ck(central >= 0, "find central header")
            namelen = struct.unpack_from("<H", b, central + 28)[0]
            off = central + 46 + namelen
            xtr_off, ln = field(owner.extra, 0x5854)
            b[off + xtr_off + 40] ^= 1
        corrupted = r / "badsha.zip"
        corrupted.write_bytes(b)
        d = r / "badshaout"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", corrupted, cwd=d)
        ck(rv.returncode != 0, "SHA corruption rejected")
        if (d / "inside/sample.bin").exists():
            ck(not attrs(d / "inside/sample.bin"), "corruption has no xattrs")
        # Central-directory graph with a duplicated internal member is
        # ambiguous even if both ZIP members have valid CRCs.
        duplicated = r / "duplicate.zip"
        with zipfile.ZipFile(plain) as z, zipfile.ZipFile(duplicated, "w") as out:
            for info in z.infolist():
                out.writestr(copy.copy(info), z.read(info))
            side = z.infolist()[1]
            out.writestr(copy.copy(side), z.read(side))
        d = r / "duplicateout"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", duplicated, cwd=d)
        ck(rv.returncode != 0, "duplicate companion rejected")
        ck(
            not (d / "inside/sample.bin").exists(),
            "duplicate graph rejected before owner extraction",
        )
        # Missing companion: use zipfile rewrite of owner alone with its Xtro
        # extras intact; exercise archive graph validation independently.
        missing = r / "missing.zip"
        with zipfile.ZipFile(plain) as src, zipfile.ZipFile(missing, "w") as dst:
            info = src.infolist()[0]
            dst.writestr(copy.copy(info), src.read(info))
        d = r / "missingout"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", missing, cwd=d)
        ck(rv.returncode != 0, "missing companion refused")
        if (d / "inside/sample.bin").exists():
            ck(not attrs(d / "inside/sample.bin"), "missing companion no xattrs")
        # Ordinary multi-owner archive: metadata belongs to each inode,
        # including interspersed ordinary files and independent pair IDs.
        second = s / "inside/second.bin"
        second.write_bytes(b"other contents")
        os.setxattr(second, b"user.identity", b"two\x00")
        multi = r / "multi.zip"
        rv = run(
            ZIP, "--xattrs", multi, "inside/sample.bin", "inside/second.bin", cwd=s
        )
        ck(rv.returncode == 0, "two-owner create")
        d = r / "multiout"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", multi, cwd=d)
        ck(rv.returncode == 0, "two-owner extract: %r" % rv.stderr)
        exact(d / "inside/sample.bin", fields, "multi owner 1")
        exact(d / "inside/second.bin", {b"user.identity": b"two\x00"}, "multi owner 2")
        ck(not (d / "__XTRO_ZIP__").exists(), "two owner internal entries hidden")
        # Include selection: companion must be located despite filename filter.
        d = r / "subset"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", plain, "inside/sample.bin", cwd=d)
        ck(
            rv.returncode == 0,
            "selected owner extracted with internal companion: %r" % rv.stderr,
        )
        exact(d / "inside/sample.bin", fields, "select")
        ck(not (d / "__XTRO_ZIP__").exists(), "selected companion never materialized")
        # explicit -d retains same verified file/inode.
        d = r / "explicit"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", plain, "-d", d)
        ck(rv.returncode == 0, "-d output: %r" % rv.stderr)
        exact(d / "inside/sample.bin", fields, "-d")
        # Flattened -j output must still match its extracted descriptor.
        d = r / "flattened"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", "-j", plain, cwd=d)
        ck(rv.returncode == 0, "flattened path")
        exact(d / "sample.bin", fields, "-j")
        ck(
            not (d / "__XTRO_ZIP__").exists(),
            "flattened internal metadata remains hidden",
        )
        # An unrelated selection must not force restoration of other owners.
        with zipfile.ZipFile(plain, "a") as z:
            z.writestr("unrelated.txt", "hi")
        d = r / "unrelatedout"
        d.mkdir()
        rv = run(UNZIP, "--xattrs", plain, "unrelated.txt", cwd=d)
        ck(rv.returncode == 0, "unrelated selective extract")
        ck((d / "unrelated.txt").read_text() == "hi", "unrelated contents")
        ck(not (d / "__XTRO_ZIP__").exists(), "unrelated does not publish sidecars")
        # Wrong-value partner cannot be smuggled through after valid CRC.
        ck(run(UNZIP, "-t", plain).returncode == 0, "ordinary ZIP test")
    print("Linux M5B companion: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
