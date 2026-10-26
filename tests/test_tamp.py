#!/usr/bin/env python3

import argparse
import io
import random
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

TAMP = 31340
LEVEL_WINDOWS = {1: 8, 2: 8, 3: 9, 4: 10, 5: 11, 6: 12, 7: 13, 8: 14, 9: 15, 11: 15}


def run(*args, good=True, input_bytes=None):
    result = subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if (result.returncode == 0) != good:
        raise AssertionError(
            f"Unexpected exit {result.returncode}: {args}\n"
            f"stdout={result.stdout[-1200:]!r}\n"
            f"stderr={result.stderr[-1200:]!r}"
        )
    return result


def member(archive):
    with zipfile.ZipFile(archive) as zf:
        assert len(zf.infolist()) == 1
        info = zf.infolist()[0]
        with open(archive, "rb") as f:
            f.seek(info.header_offset)
            head = f.read(30)
            assert len(head) == 30 and head[:4] == b"PK\x03\x04"
            name_len, extra_len = struct.unpack_from("<HH", head, 26)
            f.seek(name_len + extra_len, 1)
            payload = f.read(info.compress_size)
            assert len(payload) == info.compress_size
        return info, payload


def reference_zip(path, name, original, compressed):
    """Write a one-member ZIP with a reference Tamp bitstream (no data descriptor)."""
    encoded_name = name.encode("ascii")
    crc = zlib.crc32(original) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        TAMP,
        0,
        0,
        crc,
        len(compressed),
        len(original),
        len(encoded_name),
        0,
    )
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        TAMP,
        0,
        0,
        crc,
        len(compressed),
        len(original),
        len(encoded_name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    central_offset = len(local) + len(encoded_name) + len(compressed)
    footer = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central) + len(encoded_name),
        central_offset,
        0,
    )
    path.write_bytes(
        local + encoded_name + compressed + central + encoded_name + footer
    )


def expect_tamp(
    zip_bin,
    unzip_bin,
    funzip_bin,
    directory,
    original,
    level,
    extra=(),
    upstream=None,
    tag="profile",
):
    source = directory / "INPUT.BIN"
    source.write_bytes(original)
    archive = directory / f"{tag}_{level}.zip"
    run(
        str(zip_bin),
        "-j",
        "-q",
        "--disable-store-fallback",
        "-Z",
        "tamp",
        f"-{level}",
        *extra,
        str(archive),
        str(source),
    )
    info, raw = member(archive)
    assert info.compress_type == TAMP, (level, info.compress_type)
    assert ((raw[0] >> 5) + 8) == LEVEL_WINDOWS[level]
    assert ((raw[0] >> 3) & 3) + 5 == 8
    assert raw[0] & 7 == 2  # extended, no custom dictionary/reset
    run(str(unzip_bin), "-tqq", str(archive))
    if funzip_bin:
        result = run(str(funzip_bin), str(archive))
        assert result.stdout == original, (level, "fUnZip mismatch")
    if upstream:
        assert bytes(upstream.decompress(raw)) == original
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--unzip", required=True, type=Path)
    parser.add_argument("--funzip", type=Path)
    parser.add_argument("--zipopt", type=Path)
    parser.add_argument("--zipdedup", type=Path)
    parser.add_argument("--upstream-dir", type=Path)
    args = parser.parse_args()
    for attr in ("zip", "unzip", "funzip", "zipopt", "zipdedup"):
        value = getattr(args, attr)
        if value is not None:
            setattr(args, attr, value.resolve())

    upstream = None
    if args.upstream_dir:
        sys.path.insert(0, str(args.upstream_dir.resolve()))
        import tamp as upstream  # noqa: PLC0415 - optional independent reference

    rng = random.Random(0x31340)
    sample = (b"AABAACAADAABAACAAD\x00\xff" * 320) + bytes(
        rng.randrange(256) for _ in range(3000)
    )

    count = 0
    with tempfile.TemporaryDirectory(prefix="xtro-tamp-") as temp:
        directory = Path(temp)
        streams = {}
        for level in LEVEL_WINDOWS:
            streams[level] = expect_tamp(
                args.zip,
                args.unzip,
                args.funzip,
                directory,
                sample,
                level,
                upstream=upstream,
            )
            count += 1
        assert streams[1] == streams[2], "-1 and -2 are not identical"

        default_archive = directory / "default.zip"
        run(
            str(args.zip),
            "-j",
            "-q",
            "--disable-store-fallback",
            "-Z",
            "tamp",
            str(default_archive),
            str(directory / "INPUT.BIN"),
        )
        assert member(default_archive)[1] == streams[6], "default is not -6"
        count += 1

        off_11 = expect_tamp(
            args.zip,
            args.unzip,
            args.funzip,
            directory,
            sample,
            11,
            ("--tamp-lazy-matching-",),
            upstream,
            "off",
        )
        on_9 = expect_tamp(
            args.zip,
            args.unzip,
            args.funzip,
            directory,
            sample,
            9,
            ("--tamp-lazy-matching",),
            upstream,
            "on",
        )
        assert off_11 == streams[9], "-11 lazy OFF differs from -9"
        assert on_9 == streams[11], "-9 lazy ON differs from -11"

        last_off = expect_tamp(
            args.zip,
            args.unzip,
            args.funzip,
            directory,
            sample,
            11,
            ("--tamp-lazy-matching", "--tamp-lazy-matching-"),
            upstream,
            "lastoff",
        )
        last_on = expect_tamp(
            args.zip,
            args.unzip,
            args.funzip,
            directory,
            sample,
            9,
            ("--tamp-lazy-matching-", "--tamp-lazy-matching"),
            upstream,
            "laston",
        )
        assert last_off == off_11 and last_on == on_9
        count += 4

        # Empty/single-byte members and data much larger than a 16-bit
        # segment exercise the streaming encoder and decoder boundaries.
        for tag, data in (("empty", b""), ("one", b"Z")):
            source = directory / "INPUT.BIN"
            source.write_bytes(data)
            fixture = directory / f"{tag}.zip"
            run(
                str(args.zip),
                "-j",
                "-q",
                "--disable-store-fallback",
                "-Z",
                "tamp",
                "-6",
                str(fixture),
                str(source),
            )
            info, raw = member(fixture)
            # Zip has an existing unconditional STORE fast path for tiny
            # inputs, independent of the chosen compression method.
            assert info.compress_type in (0, TAMP)
            if info.compress_type == TAMP and upstream:
                assert upstream.decompress(raw) == data
            run(str(args.unzip), "-tqq", str(fixture))
            if args.funzip:
                assert run(str(args.funzip), str(fixture)).stdout == data
            count += 1
        expect_tamp(
            args.zip,
            args.unzip,
            args.funzip,
            directory,
            bytes(rng.randrange(256) for _ in range(131072)),
            6,
            upstream=upstream,
            tag="large",
        )
        count += 1

        # Continue using the normal sample for the remaining CLI checks.
        source = directory / "INPUT.BIN"
        source.write_bytes(sample)

        # Non-Tamp methods must reject the Tamp-specific override.
        run(
            str(args.zip),
            "-q",
            "-Z",
            "deflate",
            "--tamp-lazy-matching",
            str(directory / "bad.zip"),
            str(source),
            good=False,
        )
        count += 1
        # Reserve -10 explicitly: parsing it as -1 followed by -0 silently
        # chooses STORE.  Neither spelling may create an archive.
        for spelling, tag in (("-10", "short"), ("--compress-10", "long")):
            rejected = directory / f"level10_{tag}.zip"
            result = run(
                str(args.zip),
                "-q",
                "-Z",
                "tamp",
                spelling,
                str(rejected),
                str(source),
                good=False,
            )
            assert result.returncode == 16, (spelling, result.returncode)
            assert (
                b"invalid argument" in (result.stdout + result.stderr).lower()
            ), spelling
            assert not rejected.exists(), spelling
            count += 1

        # Tamp must also pass through the ordinary ZIP encryption layers.
        # AES stores method 99 in the ZIP headers and 31340 in extra 0x9901.
        password = "xtro-tamp-regression"
        for kind, encrypt_args in (
            ("zipcrypto", ("-P", password)),
            ("aes", ("-eP", password)),
        ):
            fixture = directory / f"encrypted_{kind}.zip"
            run(
                str(args.zip),
                "-j",
                "-q",
                "--disable-store-fallback",
                "-Z",
                "tamp",
                "-6",
                *encrypt_args,
                str(fixture),
                str(source),
            )
            with zipfile.ZipFile(fixture) as zf:
                info = zf.infolist()[0]
                assert info.flag_bits & 1, kind
                assert info.compress_type == (99 if kind == "aes" else TAMP)
                if kind == "aes":
                    start = info.extra.index(b"\x01\x99\x07\x00")
                    assert struct.unpack_from("<H", info.extra, start + 9)[0] == TAMP
            run(str(args.unzip), "-tqq", "-P", password, str(fixture))
            run(str(args.unzip), "-tqq", "-P", "incorrect", str(fixture), good=False)
            count += 2
            if kind == "zipcrypto" and args.funzip:
                command = (str(args.funzip), "-" + password, str(fixture))
                if info.flag_bits & 8:
                    # Tamp has no self-delimiting end marker.  fUnZip can
                    # decode it only when the local header has a fixed size.
                    result = run(*command, good=False)
                    assert b"local compressed size" in result.stderr
                else:
                    assert run(*command).stdout == sample
                count += 1

        if upstream:
            # Independent reference streams: both format revisions and all
            # supported literal widths.  The input respects each literal mask.
            for extended in (False, True):
                for literal in range(5, 9):
                    data = bytes((i * 11) % (1 << literal) for i in range(1450))
                    compressed = upstream.compress(
                        data, window=10, literal=literal, extended=extended
                    )
                    fixture = directory / f"reference_{literal}_{extended}.zip"
                    reference_zip(fixture, "reference.bin", data, compressed)
                    run(str(args.unzip), "-tqq", str(fixture))
                    count += 1

            # Resettable streams use the supported two-byte Tamp v2 header
            # and a double-FLUSH signal at the dictionary reset boundary.
            left = b"abacabad" * 151
            right = b"XYZ000123" * 173
            encoded = io.BytesIO()
            writer = upstream.Compressor(
                encoded, window=10, extended=True, dictionary_reset=True
            )
            writer.write(left)
            writer.reset_dictionary()
            writer.write(right)
            writer.flush(write_token=False)
            fixture = directory / "reset.zip"
            reference_zip(fixture, "reset.bin", left + right, encoded.getvalue())
            run(str(args.unzip), "-tqq", str(fixture))
            count += 1

            payload = upstream.compress(sample[:4000], window=10, extended=True)
            fixture = directory / "custom.zip"
            reference_zip(
                fixture,
                "custom.bin",
                sample[:4000],
                bytes([payload[0] | 0x04]) + payload[1:],
            )
            result = run(str(args.unzip), "-t", str(fixture), good=False)
            assert b"custom-dictionary" in (result.stdout + result.stderr)
            count += 1

            fixture = directory / "truncated.zip"
            reference_zip(fixture, "broken.bin", sample[:4000], payload[:20])
            run(str(args.unzip), "-tqq", str(fixture), good=False)
            count += 1

        if args.zipopt:
            # ZipOpt must decode Tamp, but never select or retain Tamp as
            # output.  Its CMPSC and LZFSE read-only methods use this policy.
            tamp_archive = directory / "profile_6.zip"
            for method, expected in (("store", 0), ("deflate", 8)):
                candidate = directory / f"zipopt_{method}.zip"
                run(
                    str(args.zipopt),
                    f"--methods={method}",
                    str(tamp_archive),
                    str(candidate),
                )
                info, _ = member(candidate)
                assert info.compress_type == expected
                run(str(args.unzip), "-tqq", str(candidate))
                with zipfile.ZipFile(candidate) as zf:
                    assert zf.read(info) == sample
                count += 1
            for option in (
                "--methods=tamp",
                "--compress-level=tamp=11",
                "--tamp-lazy-matching",
                "--tamp-lazy-matching-",
            ):
                run(
                    str(args.zipopt),
                    option,
                    str(tamp_archive),
                    str(directory / "invalid-opt.zip"),
                    good=False,
                )
                count += 1

        if args.zipdedup:
            fixture = directory / "deduplicated.zip"
            run(str(args.zipdedup), str(directory / "profile_6.zip"), str(fixture))
            info, payload = member(fixture)
            assert info.compress_type == TAMP
            assert payload == streams[6]
            run(str(args.unzip), "-tqq", str(fixture))
            count += 1

    print(f"PASS: {count} Tamp archive/profile/interoperability checks")


if __name__ == "__main__":
    main()
