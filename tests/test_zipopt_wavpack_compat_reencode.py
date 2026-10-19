#!/usr/bin/env python3
"""Regression checks for opt-in rejection of original WavPack 5 ZIP streams.

Uses the installed libwavpack 5 runtime to generate genuine old/new streams,
never an invalid version byte patched into a legacy stream for success cases.
The same script can smoke-test builds lacking the optional encoder SDK.
"""

import argparse
import ctypes
import hashlib
import pathlib
import random
import struct
import subprocess
import tempfile
import zipfile

from test_wavpack97_stream_versions import (
    BLOCK_OUTPUT,
    WavpackConfig,
    encode,
    load_library,
    make_wav,
    make_zip,
)

checks = 0


def run(command, success=True):
    global checks
    result = subprocess.run([str(v) for v in command], capture_output=True, timeout=120)
    checks += 1
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"{command}: unexpected return code {result.returncode}; "
            f"{result.stderr[-1000:]!r}"
        )
    return result


def compressed_member(path):
    with zipfile.ZipFile(path) as zf:
        (info,) = zf.infolist()
        data = path.read_bytes()
        pos = info.header_offset
        assert data[pos : pos + 4] == b"PK\x03\x04"
        name_len, extra_len = struct.unpack_from("<HH", data, pos + 26)
        start = pos + 30 + name_len + extra_len
        return info.compress_type, data[start : start + info.compress_size]


def blocks(payload):
    out = []
    off = 0
    while off < len(payload):
        assert len(payload) - off >= 32 and payload[off : off + 4] == b"wvpk"
        size = struct.unpack_from("<I", payload, off + 4)[0] + 8
        version = struct.unpack_from("<H", payload, off + 8)[0]
        assert size >= 32 and size <= len(payload) - off
        out.append(version)
        off += size
    assert out
    return out


def assert_method97_legacy(path, decodecheck):
    global checks
    method, payload = compressed_member(path)
    assert method == 97, method
    assert all(version == 0x407 for version in blocks(payload))
    run([decodecheck, path])
    checks += 1
    return payload


def encode_multiblock(lib, wav, samples, version5):
    """Generate authentic multi-block streams, forcing 1,024-frame blocks."""
    pieces = []

    @BLOCK_OUTPUT
    def output(_id, ptr, count):
        if count < 0:
            return 0
        pieces.append(ctypes.string_at(ptr, count))
        return 1

    ctx = lib.WavpackOpenFileOutput(output, None, None)
    assert ctx
    try:
        config = WavpackConfig()
        config.bits_per_sample = 16
        config.bytes_per_sample = 2
        config.num_channels = 2
        config.sample_rate = 44100
        config.channel_mask = 3
        config.block_samples = 1024
        if version5:
            result = lib.WavpackSetConfiguration64(
                ctx, ctypes.byref(config), len(samples), None
            )
        else:
            result = lib.WavpackSetConfiguration(
                ctx, ctypes.byref(config), len(samples)
            )
        assert result
        riff = ctypes.create_string_buffer(wav[:44], 44)
        assert lib.WavpackAddWrapper(ctx, riff, 44)
        assert lib.WavpackPackInit(ctx)
        buf = (ctypes.c_int32 * (len(samples) * 2))(
            *[x for sample in samples for x in (sample, sample)]
        )
        assert lib.WavpackPackSamples(ctx, buf, len(samples))
        assert lib.WavpackFlushSamples(ctx)
    finally:
        lib.WavpackCloseFile(ctx)
    data = b"".join(pieces)
    versions = blocks(data)
    assert len(versions) > 1
    assert all(v == (0x410 if version5 else 0x407) for v in versions)
    return data


def main():
    global checks
    parser = argparse.ArgumentParser()
    parser.add_argument("--zipopt", type=pathlib.Path, required=True)
    parser.add_argument("--decodecheck", type=pathlib.Path)
    args = parser.parse_args()
    zipopt = args.zipopt.resolve()
    decoder = args.decodecheck.resolve() if args.decodecheck else None
    available = b"wavpack " in run([zipopt, "--methods=list"]).stdout
    with tempfile.TemporaryDirectory(prefix="zipopt-wv-compat-") as tmp:
        d = pathlib.Path(tmp)
        plain = d / "plain.zip"
        with zipfile.ZipFile(plain, "w") as zf:
            zf.writestr("text.txt", b"ordinary unrelated ZIP" * 50)
        run(
            [
                zipopt,
                "--methods=store",
                "--wavpack-compat-reencode",
                plain,
                d / "plain-out.zip",
            ]
        )
        assert (
            zipfile.ZipFile(d / "plain-out.zip").read("text.txt")
            == b"ordinary unrelated ZIP" * 50
        )
        checks += 1
        if not available:
            run(
                [
                    zipopt,
                    "--methods=wavpack",
                    "--wavpack-compat-reencode",
                    plain,
                    d / "unsupported.zip",
                ],
                success=False,
            )
            assert not (d / "unsupported.zip").exists()
            print(f"WavPack-absent compatibility checks: {checks} passed")
            return
        assert decoder, "--decodecheck is required for a WavPack-enabled build"
        library = load_library()
        wav, samples = make_wav()
        v4 = encode(library, wav, samples, True)
        v5 = encode(library, wav, samples, False)
        assert all(v < 0x410 for v in blocks(v4))
        assert all(v == 0x410 for v in blocks(v5))
        assert len(v5) < len(v4), "fixture must exercise smaller original V5"
        original = d / "v5.zip"
        legacy = d / "v4.zip"
        original.write_bytes(make_zip(v5, wav))
        legacy.write_bytes(make_zip(v4, wav))
        original_digest = hashlib.sha256(original.read_bytes()).digest()
        run([decoder, original])
        run([decoder, legacy])

        # Opt-out is important: the old original-stream retention rule remains.
        retained = d / "retained-v5.zip"
        run(
            [
                zipopt,
                "--methods=wavpack",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                original,
                retained,
            ]
        )
        assert compressed_member(retained)[1] == v5
        checks += 1

        # Opt-in: original V5 can never win despite its size advantage.
        upgraded = d / "upgraded.zip"
        run(
            [
                zipopt,
                "--methods=wavpack",
                "--wavpack-compat-reencode",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                original,
                upgraded,
            ]
        )
        replacement = assert_method97_legacy(upgraded, decoder)
        assert len(replacement) > len(v5)
        checks += 1
        assert hashlib.sha256(original.read_bytes()).digest() == original_digest
        checks += 1

        # The flag must apply to every WavPack block, not just the first.
        multiblock = encode_multiblock(library, wav, samples, True)
        multi_input = d / "v5-many-blocks.zip"
        multi_output = d / "v4-many-blocks.zip"
        multi_input.write_bytes(make_zip(multiblock, wav))
        run([decoder, multi_input])
        run(
            [
                zipopt,
                "--methods=wavpack",
                "--wavpack-compat-reencode",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                multi_input,
                multi_output,
            ]
        )
        assert_method97_legacy(multi_output, decoder)

        # Restricting methods takes precedence over a desire to keep WavPack.
        store = d / "store.zip"
        run([zipopt, "--wavpack-compat-reencode", "--methods=store", original, store])
        assert compressed_member(store)[0] == 0
        assert zipfile.ZipFile(store).read("audio.wav") == wav
        checks += 1
        alternative = d / "alternative.zip"
        run(
            [
                zipopt,
                "--wavpack-compat-reencode",
                "--methods=store,deflate",
                "--disable-zopfli",
                original,
                alternative,
            ]
        )
        assert compressed_member(alternative)[0] in (0, 8)
        assert zipfile.ZipFile(alternative).read("audio.wav") == wav
        checks += 1

        # If wavpack is selected, a proven V4 original remains eligible.
        kept_old = d / "kept-old.zip"
        run(
            [
                zipopt,
                "--wavpack-compat-reencode",
                "--methods=wavpack",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                legacy,
                kept_old,
            ]
        )
        assert compressed_member(kept_old)[1] == v4
        checks += 1

        # A decodable, but malformed RIFF wrapper is not eligible for
        # lossless legacy re-encoding. WavPack-only must fail atomically.
        unsupported = bytearray(wav)
        unsupported[4:8] = b"\x00\x00\x00\x00"
        unsupported = bytes(unsupported)
        bad_path = d / "v5-unsupported-wav.zip"
        bad_path.write_bytes(
            make_zip(encode(library, unsupported, samples, False), unsupported)
        )
        run([decoder, bad_path])
        before_input = bad_path.read_bytes()
        before_files = set(d.iterdir())
        failed = d / "must-not-appear.zip"
        run(
            [
                zipopt,
                "--wavpack-compat-reencode",
                "--methods=wavpack",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                bad_path,
                failed,
            ],
            success=False,
        )
        assert not failed.exists() and bad_path.read_bytes() == before_input
        assert set(d.iterdir()) == before_files, "unexpected leftover temp output"
        checks += 1
        fallback = d / "fallback.zip"
        run(
            [
                zipopt,
                "--wavpack-compat-reencode",
                "--methods=store,wavpack",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                bad_path,
                fallback,
            ]
        )
        assert compressed_member(fallback)[0] == 0
        assert zipfile.ZipFile(fallback).read("audio.wav") == unsupported
        checks += 1

        # The flag changes only selection, not the wavpack tuning parser.
        for level in ("fast", "standard", "high", "extra"):
            for xmode in (0, 1, 6):
                p = d / f"mode-{level}-{xmode}.zip"
                run(
                    [
                        zipopt,
                        "--wavpack-compat-reencode",
                        "--methods=wavpack",
                        f"--wavpack-level={level}",
                        f"--wavpack-extra-level={xmode}",
                        original,
                        p,
                    ]
                )
                assert_method97_legacy(p, decoder)
        for _ in range(8):
            p = d / f"plain-{_}.zip"
            run(
                [
                    zipopt,
                    "--wavpack-compat-reencode",
                    "--methods=store",
                    "--wavpack-level=extra",
                    "--wavpack-extra-level=6",
                    plain,
                    p,
                ]
            )
            assert zipfile.ZipFile(p).read("text.txt") == b"ordinary unrelated ZIP" * 50
            checks += 1
        # Invalid inputs must not be published, especially near block bounds.
        rng = random.Random(971101)
        for ix in range(12):
            damaged = bytearray(v5)
            bytepos = (4 if ix % 2 == 0 else 8) + rng.randrange(4)
            damaged[bytepos] ^= 1 << rng.randrange(8)
            corrupt = d / f"corrupt{ix}.zip"
            dest = d / f"recovered{ix}.zip"
            corrupt.write_bytes(make_zip(bytes(damaged), wav))
            run(
                [
                    zipopt,
                    "--wavpack-compat-reencode",
                    "--methods=wavpack",
                    corrupt,
                    dest,
                ],
                success=False,
            )
            assert not dest.exists()
            checks += 1
    print(f"WavPack V5 compatibility re-encoding: {checks} checks passed")


if __name__ == "__main__":
    main()
