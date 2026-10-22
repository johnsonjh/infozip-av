#!/usr/bin/env python3
"""Opt-in libdeflate regression checks against native Xtro-ZIP binaries.

Run after compiling with optional libdeflate support:
  python3 tests/test_libdeflate_integration.py
"""

import argparse
import os
import pathlib
import random
import subprocess
import struct
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(args, *, cwd, expect=0, env=None):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, env=env)
    if expect is not None and p.returncode != expect:
        raise AssertionError(
            f"{' '.join(map(str, args))}: exit {p.returncode}, "
            f"expected {expect}\nstdout={p.stdout}\nstderr={p.stderr}"
        )
    return p


def run_invalid(args, *, cwd):
    p = run(args, cwd=cwd, expect=None)
    if p.returncode == 0:
        raise AssertionError(f"invalid option unexpectedly succeeded: {args}")
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", type=pathlib.Path, default=ROOT / "zip30/zip")
    ap.add_argument("--unzip", type=pathlib.Path, default=ROOT / "unzip60/unzip")
    ap.add_argument("--zipopt", type=pathlib.Path, default=ROOT / "zipopt/zipopt")
    ap.add_argument("--zipdedup", type=pathlib.Path, default=ROOT / "zipdedup/zipdedup")
    ap.add_argument(
        "--baseline-zip",
        type=pathlib.Path,
        help="Unmodified cu110 Zip binary for byte-identical default comparisons",
    )
    opts = ap.parse_args()
    zipbin = str(opts.zip.resolve())
    unzipbin = str(opts.unzip.resolve())
    zipoptbin = str(opts.zipopt.resolve())
    zipdedupbin = str(opts.zipdedup.resolve())
    baselinezip = str(opts.baseline_zip.resolve()) if opts.baseline_zip else None
    rng = random.Random(0xD3F1A7E)

    with tempfile.TemporaryDirectory(prefix="xtro-libdeflate-") as folder:
        tmp = pathlib.Path(folder)
        samples = {
            "empty": b"",
            "one": b"X",
            "text": (b"Alpha beta delta\n" * 2100),
            "dos_text": (b"DOS line\r\n" * 4000),
            "random": rng.randbytes(200001),
            "edge": b"xy" * 524288,
            "edge_random": rng.randbytes(1048576),
            "over": (b"abc123\n" * 170000),
        }
        for name, content in samples.items():
            (tmp / name).write_bytes(content)
            os.utime(tmp / name, (946684800, 946684800))

        for level in (1, 6, 9, 11):
            for name in samples:
                target = tmp / f"ld-{level}-{name}.zip"
                run(
                    [zipbin, "-q", f"-{level}", "--use-libdeflate", str(target), name],
                    cwd=tmp,
                )
                with zipfile.ZipFile(target) as zf:
                    assert zf.read(name) == samples[name], (level, name)
                    assert zf.getinfo(name).compress_type in (0, 8)
                run([unzipbin, "-tq", "--use-libdeflate", str(target)], cwd=tmp)
                run(
                    [
                        unzipbin,
                        "-tq",
                        "--use-libdeflate",
                        "--libdeflate-size",
                        "1MiB",
                        str(target),
                    ],
                    cwd=tmp,
                )

        # Deflate may be a few bytes larger than its declared original size.
        # The decompressor must then decline the whole-buffer path based on
        # the *compressed* size, even at the exact uncompressed-size limit.
        incompressible = tmp / "uncompressed-edge.zip"
        run(
            [
                zipbin,
                "-q",
                "-6",
                "--disable-store-fallback",
                "--use-libdeflate",
                str(incompressible),
                "edge_random",
            ],
            cwd=tmp,
        )
        with zipfile.ZipFile(incompressible) as zf:
            info = zf.getinfo("edge_random")
            assert info.file_size == 1048576 and info.compress_size > 1048576
        run([unzipbin, "-tq", "--use-libdeflate", str(incompressible)], cwd=tmp)

        # Both traditional encryption and AE-2 must pass through the existing
        # input decryption, authentication and CRC paths unmodified.
        for crypt, flags in (
            ("zipcrypto", ["-P", "regression-password"]),
            ("aes", ["-eP", "regression-password"]),
        ):
            target = tmp / f"encrypted-{crypt}.zip"
            run(
                [zipbin, "-q", "-6", "--use-libdeflate", *flags, str(target), "text"],
                cwd=tmp,
            )
            run(
                [
                    unzipbin,
                    "-tq",
                    "-P",
                    "regression-password",
                    "--use-libdeflate",
                    str(target),
                ],
                cwd=tmp,
            )
            run(
                [
                    unzipbin,
                    "-tq",
                    "-P",
                    "regression-password",
                    "--use-libdeflate-",
                    str(target),
                ],
                cwd=tmp,
            )

        # The buffered decoder must feed the ordinary output/text-conversion
        # path, including a CRLF pair that may span a flush boundary.
        archive = tmp / "ld-6-dos_text.zip"
        off = run(
            [unzipbin, "-p", "--use-libdeflate-", str(archive), "dos_text"], cwd=tmp
        )
        on = run(
            [unzipbin, "-p", "--use-libdeflate", str(archive), "dos_text"], cwd=tmp
        )
        assert off.stdout == on.stdout
        for label, flag in (
            ("normal", "--use-libdeflate-"),
            ("buffered", "--use-libdeflate"),
        ):
            destination = tmp / ("extract-" + label)
            destination.mkdir()
            run(
                [
                    unzipbin,
                    "-o",
                    "-qq",
                    "-aa",
                    flag,
                    str(archive),
                    "-d",
                    str(destination),
                ],
                cwd=tmp,
            )
        assert (tmp / "extract-normal/dos_text").read_bytes() == (
            tmp / "extract-buffered/dos_text"
        ).read_bytes()

        # Corruption must fail both decoders; no partial success on a fully
        # buffered but malformed raw-Deflate payload.
        malformed = tmp / "malformed.zip"
        with zipfile.ZipFile(tmp / "ld-6-text.zip") as zf:
            info = zf.getinfo("text")
            raw = bytearray((tmp / "ld-6-text.zip").read_bytes())
            local = info.header_offset
            name_len, extra_len = struct.unpack_from("<HH", raw, local + 26)
            payload = local + 30 + name_len + extra_len
            assert info.compress_size > 16
            raw[payload + 8] ^= 0xFF
        malformed.write_bytes(raw)
        run_invalid([unzipbin, "-tq", "--use-libdeflate", str(malformed)], cwd=tmp)
        run_invalid([unzipbin, "-tq", "--use-libdeflate-", str(malformed)], cwd=tmp)

        # The opt-in encoder must also respect cu110's SOURCE_DATE_EPOCH
        # reproducibility contract, independently of destination path.
        sde = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
        for i in (1, 2):
            run(
                [
                    zipbin,
                    "-q",
                    "-6",
                    "--use-libdeflate",
                    str(tmp / f"sde-{i}.zip"),
                    "text",
                ],
                cwd=tmp,
                env=sde,
            )
        assert (tmp / "sde-1.zip").read_bytes() == (tmp / "sde-2.zip").read_bytes()

        # No opt-in means no change, even when support is compiled in.
        run([zipbin, "-q", "-6", str(tmp / "normal.zip"), "text"], cwd=tmp)
        run(
            [zipbin, "-q", "-6", "--use-libdeflate-", str(tmp / "off.zip"), "text"],
            cwd=tmp,
        )
        assert (tmp / "normal.zip").read_bytes() == (tmp / "off.zip").read_bytes()

        # A cap smaller than this file forces the original Deflate backend.
        run(
            [
                zipbin,
                "-q",
                "-6",
                "--use-libdeflate",
                "--libdeflate-size",
                "1K",
                str(tmp / "fallback.zip"),
                "text",
            ],
            cwd=tmp,
        )
        assert (tmp / "normal.zip").read_bytes() == (tmp / "fallback.zip").read_bytes()

        if baselinezip:
            # Compare the entire ZIP structure, not just extracted bytes.
            # With libdeflate compiled but disabled, all default backends
            # must produce precisely the same archive as pristine cu110.
            for level in (1, 6, 9, 11):
                for name in ("one", "text", "random"):
                    patched = tmp / f"patched-{level}-{name}.zip"
                    original = tmp / f"baseline-{level}-{name}.zip"
                    run([zipbin, "-q", f"-{level}", str(patched), name], cwd=tmp)
                    run([baselinezip, "-q", f"-{level}", str(original), name], cwd=tmp)
                    assert patched.read_bytes() == original.read_bytes(), (level, name)

        for size in (
            "",
            "0",
            "-1",
            "+2",
            "1.5M",
            "1XB",
            "1 MB",
            "18446744073709551616",
        ):
            run_invalid(
                [
                    zipbin,
                    "--use-libdeflate",
                    "--libdeflate-size",
                    size,
                    "-q",
                    str(tmp / "bad.zip"),
                    "text",
                ],
                cwd=tmp,
            )
        for valid in (
            "1024",
            "1K",
            "1KiB",
            "1kb",
            "1m",
            "1MB",
            "1MiB",
            "1gigabyte",
            "1TB",
            "1TiB",
        ):
            run(
                [
                    zipbin,
                    "-q",
                    "--use-libdeflate",
                    "--libdeflate-size",
                    valid,
                    str(tmp / f"valid-{valid}.zip"),
                    "one",
                ],
                cwd=tmp,
            )
        run_invalid(
            [zipbin, "--libdeflate-size", "1M", str(tmp / "bad.zip"), "one"], cwd=tmp
        )
        run_invalid(
            [unzipbin, "-t", "--libdeflate-size", "1M", str(tmp / "normal.zip")],
            cwd=tmp,
        )

        run([zipoptbin, "--methods=list"], cwd=tmp)
        run(
            [
                zipoptbin,
                "--methods=deflate,libdeflate",
                "--libdeflate-size=1M",
                str(tmp / "normal.zip"),
                str(tmp / "both.zip"),
            ],
            cwd=tmp,
        )
        run(
            [
                zipoptbin,
                "--methods=libdeflate",
                "--compress-level=libdeflate=11",
                str(tmp / "normal.zip"),
                str(tmp / "only.zip"),
            ],
            cwd=tmp,
        )
        for archive in ("both.zip", "only.zip"):
            with zipfile.ZipFile(tmp / archive) as zf:
                assert zf.read("text") == samples["text"]
        run_invalid(
            [
                zipoptbin,
                "--libdeflate-size=1.5M",
                str(tmp / "normal.zip"),
                str(tmp / "invalid-opt.zip"),
            ],
            cwd=tmp,
        )

        # zipdedup has an independent CLI but shares the opt-in UnZip decoder
        # for hashing, metadata validation and ordinary source extraction.
        source = tmp / "ld-6-text.zip"
        for flag in ("--use-libdeflate", "--use-libdeflate-"):
            output = tmp / (
                "dedup-on.zip" if flag == "--use-libdeflate" else "dedup-off.zip"
            )
            run([zipdedupbin, flag, str(source), str(output)], cwd=tmp)
            with zipfile.ZipFile(output) as zf:
                assert zf.read("text") == samples["text"]
        run_invalid(
            [
                zipdedupbin,
                "--libdeflate-size=1MiB",
                str(source),
                str(tmp / "bad-dedup.zip"),
            ],
            cwd=tmp,
        )

    print("PASS: libdeflate ZIP/UnZip/zipopt integration, boundaries and opt-in")


if __name__ == "__main__":
    main()
