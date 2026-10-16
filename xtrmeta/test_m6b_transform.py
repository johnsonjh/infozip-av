#!/usr/bin/env python3
"""M6B public Xtro archive transformation tests (Linux filesystem and ZIP)."""

import os, pathlib, subprocess, tempfile, zipfile, struct, hashlib, random

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
UNZIP = ROOT / "unzip60/unzip"
ZO = ROOT / "zipopt/zipopt"
ZD = ROOT / "zipdedup/zipdedup"
checks = 0


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        raise AssertionError(msg)


def run(*args, cwd=None, ok=True):
    p = subprocess.run(
        [str(a) for a in args], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if (p.returncode == 0) != ok:
        raise AssertionError(
            "%s rc=%s stdout=%s stderr=%s"
            % (args, p.returncode, p.stdout[-1000:], p.stderr[-2000:])
        )
    return p


def fields(e):
    p = e.extra
    at = 0
    while at < len(p):
        check(at + 4 <= len(p), "extra header")
        tag, n = struct.unpack_from("<HH", p, at)
        at += 4
        check(at + n <= len(p), "extra data")
        yield tag, p[at : at + n]
        at += n


def metadata(path):
    with zipfile.ZipFile(path) as a:
        owners = {}
        sides = {}
        modes = {}
        payloads = {}
        for e in a.infolist():
            x = [v for k, v in fields(e) if k == 0x5854]
            check(len(x) <= 1, "at most one Xtro extra")
            if x:
                ident = x[0][8:24].hex()
                check(ident not in owners, "unique owner identity")
                owners[ident] = e.filename
                modes[ident] = x[0][6]
                payloads[e.filename] = x[0]
            if e.filename.startswith("__XTRO_ZIP__/x/"):
                token = e.filename[15:47]
                check(token not in sides, "unique companion")
                sides[token] = e.filename
        check(all(ident in owners for ident in sides), "no orphan")
        check(
            all((mode == 2) == (ident in sides) for ident, mode in modes.items()),
            "full graph",
        )
        return owners, sides, modes, payloads


def native_roundtrip(archive, expected):
    with tempfile.TemporaryDirectory(
        prefix="xtro-m6b-restore-",
        dir="/dev/shm" if os.path.isdir("/dev/shm") else None,
    ) as d:
        run(UNZIP, "-o", "--xattrs", archive, "-d", d)
        for name, (data, attrs) in expected.items():
            target = pathlib.Path(d) / name
            check(target.read_bytes() == data, "content " + name)
            check(
                {
                    os.fsencode(key): os.getxattr(target, key)
                    for key in os.listxattr(target)
                }
                == attrs,
                "xattrs " + name,
            )
        check(not (pathlib.Path(d) / "__XTRO_ZIP__").exists(), "no sidecar extracted")


def main():
    base = "/dev/shm" if pathlib.Path("/dev/shm").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="xtro-m6b-", dir=base) as td:
        d = pathlib.Path(td)
        same = b"same content, different metadata\n" * 40
        src = {}
        for i in (1, 2):
            name = "owner%d.bin" % i
            (d / name).write_bytes(same)
            attrs = {b"user.identity": (b"owner%d\x00" % i)}
            # Force companions by aggregate > 64KiB, but each xattr <=64KiB.
            if i == 2:
                attrs[b"user.large1"] = b"A" * 36000
                attrs[b"user.large2"] = b"B" * 36000
            for k, v in attrs.items():
                os.setxattr(d / name, k, v)
            src[name] = (same, attrs)
        random_data = random.Random(76418).randbytes(75000)
        for name in ("plain1.bin", "plain2.bin"):
            (d / name).write_bytes(random_data)
        archive = d / "source.zip"
        run(ZIP, "--xattrs", archive, *src.keys(), cwd=d)
        # Include unrelated duplicates. They should be eligible for RefPtr.
        run(ZIP, "-0", archive, "plain1.bin", "plain2.bin", cwd=d)
        before = metadata(archive)
        check(len(before[0]) == 2, "two owners")
        check(len(before[1]) == 1, "one companion")
        native_roundtrip(archive, src)
        opt = d / "opt.zip"
        run(ZO, "--methods=store", archive, opt)
        after = metadata(opt)
        check(before == after, "ZipOpt exact metadata envelopes and identities")
        check(
            zipfile.ZipFile(opt).getinfo(next(iter(after[1].values()))).compress_type
            in (0, 8),
            "companion codec",
        )
        native_roundtrip(opt, src)
        dedup = d / "dedup.zip"
        run(ZD, archive, dedup)
        third = metadata(dedup)
        check(before == third, "ZipDedup exact metadata envelopes and identities")
        with zipfile.ZipFile(dedup) as z:
            check(
                z.getinfo("plain2.bin").compress_type == 92,
                "unrelated duplicate optimized",
            )
            check(
                z.getinfo("owner1.bin").compress_type != 92,
                "metadata owner not converted",
            )
            check(
                z.getinfo("owner2.bin").compress_type != 92,
                "metadata owner 2 not converted",
            )
        native_roundtrip(dedup, src)
        # FWKCS is independent of the owner Xtro SHA and must not silently
        # attach a digest to an encrypted companion (encrypted inputs are
        # unsupported by these two transformers in this increment).
        optmd5 = d / "opt-md5.zip"
        run(ZO, "--methods=store", "--fwkcs-md5", archive, optmd5)
        check(
            metadata(optmd5) == before, "ZipOpt --fwkcs-md5 leaves Xtro fields intact"
        )
        native_roundtrip(optmd5, src)
        dedupmd5 = d / "dedup-md5.zip"
        run(ZD, "--fwkcs-md5", archive, dedupmd5)
        check(
            metadata(dedupmd5) == before,
            "ZipDedup --fwkcs-md5 leaves Xtro fields intact",
        )
        native_roundtrip(dedupmd5, src)
        # The central SHA is not covered by ordinary file CRCs. Neither
        # transformer may publish the archive with substituted digest.
        raw = bytearray(archive.read_bytes())
        marker = b"XTRO\x01\x00\x02\x00"
        markerat = raw.rfind(marker)
        check(markerat >= 0, "central Xtro companion owner reference")
        # Central companion extra data: magic + 40-byte fixed header + SHA.
        raw[markerat + 40] ^= 1
        badsha = d / "badsha.zip"
        badsha.write_bytes(raw)
        for tool, args in (
            (ZO, ["--methods=store", badsha, d / "badsha-opt.zip"]),
            (ZD, [badsha, d / "badsha-dedup.zip"]),
        ):
            run(tool, *args, ok=False)
            check(not pathlib.Path(args[-1]).exists(), "no malformed-SHA output")
        # A semantically invalid inline TLV with correctly recomputed
        # outer CRC must still be rejected by the native TLV parser.
        raw = bytearray(archive.read_bytes())
        import zlib

        with zipfile.ZipFile(archive) as z:
            e = z.getinfo("owner1.bin")
            central = z.start_dir
            central_data = None
            for info in z.infolist():
                check(raw[central : central + 4] == b"PK\x01\x02", "central signature")
                nam, extr, com = struct.unpack_from("<HHH", raw, central + 28)
                if info.filename == "owner1.bin":
                    at = central + 46 + nam
                    limit = at + extr
                    while at < limit:
                        tag, length = struct.unpack_from("<HH", raw, at)
                        if tag == 0x5854:
                            central_data = at + 4
                            break
                        at += 4 + length
                central += 46 + nam + extr + com
            check(central_data is not None, "inline owner central offset")
            name_len, extra_len = struct.unpack_from("<HH", raw, e.header_offset + 26)
            at = e.header_offset + 30 + name_len
            limit = at + extra_len
            local_data = None
            while at < limit:
                tag, length = struct.unpack_from("<HH", raw, at)
                if tag == 0x5854:
                    local_data = at + 4
                    break
                at += 4 + length
            check(local_data is not None, "inline owner local offset")
            field_len = struct.unpack_from("<H", raw, central_data - 2)[0]
            payload = bytearray(raw[central_data + 40 : central_data + field_len])
            check(payload[:4] == b"XTMD", "valid inline manifest header")
            # The first metadata record begins after the 36-byte manifest
            # header. A type-1 xattr requires a non-empty name.
            struct.pack_into("<I", payload, 36 + 12, 0)
            crc = zlib.crc32(payload)
            raw[central_data + 40 : central_data + field_len] = payload
            struct.pack_into("<I", raw, central_data + 36, crc)
            struct.pack_into("<I", raw, local_data + 36, crc)
        badtlv = d / "badtlv.zip"
        badtlv.write_bytes(raw)
        for tool, args in (
            (ZO, ["--methods=store", badtlv, d / "badtlv-opt.zip"]),
            (ZD, [badtlv, d / "badtlv-dedup.zip"]),
        ):
            run(tool, *args, ok=False)
            check(not pathlib.Path(args[-1]).exists(), "invalid TLV rejected")
        # Encrypted metadata is not silently downgraded or decrypted by a
        # utility lacking authenticated Xtro transform support.
        encrypted = d / "encrypted.zip"
        run(ZIP, "-P", "secret", "--xattrs", encrypted, "owner2.bin", cwd=d)
        for tool, args in (
            (ZO, ["--methods=store", encrypted, d / "noenc-opt.zip"]),
            (ZD, [encrypted, d / "noenc-dedup.zip"]),
        ):
            run(tool, *args, ok=False)
            check(
                not pathlib.Path(args[-1]).exists(),
                "encrypted mode refused before output",
            )
        # Invalid missing companion: output must never appear.
        with zipfile.ZipFile(archive) as z:
            missing = d / "missing.zip"
            with zipfile.ZipFile(missing, "w") as out:
                for entry in z.infolist():
                    if entry.filename.startswith("__XTRO_ZIP__/"):
                        continue
                    out.writestr(entry, z.read(entry))
        for tool, args in (
            (ZO, ["--methods=store", missing, d / "noopt.zip"]),
            (ZD, [missing, d / "nodedup.zip"]),
        ):
            run(tool, *args, ok=False)
            check(not pathlib.Path(args[-1]).exists(), "no failed output")
        # Alter one half of the local Xtro identity without altering central.
        raw = bytearray(archive.read_bytes())
        with zipfile.ZipFile(archive) as z:
            e = z.getinfo("owner1.bin")
            off = e.header_offset
            nl, xl = struct.unpack_from("<HH", raw, off + 26)
            at = off + 30 + nl
            stop = at + xl
            while at < stop:
                tag, n = struct.unpack_from("<HH", raw, at)
                if tag == 0x5854:
                    raw[at + 4 + 8] ^= 1
                    break
                at += n + 4
            else:
                raise AssertionError("missing local Xtro field")
        corrupt = d / "corrupt.zip"
        corrupt.write_bytes(raw)
        for tool, args in (
            (ZO, ["--methods=store", corrupt, d / "noopt2.zip"]),
            (ZD, [corrupt, d / "nodedup2.zip"]),
        ):
            run(tool, *args, ok=False)
            check(not pathlib.Path(args[-1]).exists(), "no corrupted publication")
    print("M6B transformations: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
