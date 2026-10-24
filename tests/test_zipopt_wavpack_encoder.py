#!/usr/bin/env python3
"""Method 97 encoder, compatibility, selection and WAV preflight regressions."""

import argparse
import io
import math
import pathlib
import random
import struct
import subprocess
import tempfile
import wave
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1] / "zipopt"
checks = 0


def call(*args, success=True, timeout=45):
    global checks
    r = subprocess.run(
        [str(x) for x in args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    checks += 1
    if (r.returncode == 0) != success:
        raise AssertionError(
            "command %s failed (%d): %s"
            % (args, r.returncode, r.stderr.decode("utf8", "replace")[-900:])
        )
    return r


def chunk(tag, body):
    return (
        tag + struct.pack("<I", len(body)) + body + (b"\xff" if len(body) % 2 else b"")
    )


def audio(
    width=2, channels=2, frames=256, floating=False, extra=False, extensible=False
):
    pcm = bytearray()
    rng = random.Random(100)
    for i in range(frames * channels):
        if floating:
            pcm += struct.pack("<f", math.sin(i / 20) / 2)
        elif width == 1:
            pcm += bytes([(i * 17) % 256])
        else:
            signed = (i * 12345) % (2 ** (8 * width - 1))
            if i % 2:
                signed = -signed
            pcm += signed.to_bytes(width, "little", signed=True)
    nbits = width * 8
    tag = 3 if floating else 1
    fmt = struct.pack(
        "<HHIIHH",
        tag if not extensible else 0xFFFE,
        channels,
        44100,
        44100 * channels * width,
        channels * width,
        nbits,
    )
    if extensible:
        guid = struct.pack("<IHH8s", tag, 0, 0x10, b"\x80\x00\x00\xaa\x00\x38\x9b\x71")
        fmt += struct.pack("<HHI", 22, nbits, 0) + guid
    parts = [chunk(b"fmt ", fmt)]
    if extra:
        parts.append(chunk(b"JUNK", b"hello"))
    parts.append(chunk(b"data", bytes(pcm)))
    if extra:
        parts.append(chunk(b"LIST", b"odd"))
    contents = b"".join(parts)
    return b"RIFF" + struct.pack("<I", len(contents) + 4) + b"WAVE" + contents


def archive(path, data, name="recording.wav"):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr(name, data)


def compressed_member(path):
    with zipfile.ZipFile(path) as z:
        info = z.infolist()[0]
        contents = path.read_bytes()
        off = info.header_offset
        assert contents[off : off + 4] == b"PK\x03\x04"
        name_len, extra_len = struct.unpack_from("<HH", contents, off + 26)
        off += 30 + name_len + extra_len
        return info.compress_type, contents[off : off + info.compress_size]


def validate(method, source, out, decoded):
    global checks
    found, payload = compressed_member(out)
    assert found == method, (found, method)
    with zipfile.ZipFile(out) as z:
        assert z.infolist()[0].extract_version == 20
    assert payload[:4] == b"wvpk"
    assert struct.unpack_from("<H", payload, 8)[0] == 0x407
    assert struct.unpack_from("<I", payload, 4)[0] + 8 <= len(payload)
    call(decoded, out)
    checks += 1
    return payload


def main():
    global checks
    parser = argparse.ArgumentParser()
    parser.add_argument("--zipopt", default=str(ROOT / "zipopt"))
    parser.add_argument("--decodecheck", default=str(ROOT / "zipopt-decodecheck"))
    args = parser.parse_args()
    executable = pathlib.Path(args.zipopt)
    decoder = pathlib.Path(args.decodecheck)
    helptext = call(executable, "--methods=list").stdout
    if b"wavpack " not in helptext:
        # The same suite is used for optional builds without the SDK.
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            src = base / "src.zip"
            out = base / "out.zip"
            archive(src, audio())
            call(executable, "--methods=wavpack", src, out, success=False)
            call(
                executable,
                "--methods=store",
                "--wavpack-level=extra",
                "--wavpack-extra-level=6",
                src,
                out,
            )
            assert not (out.parent / "missing").exists()
        print("WavPack unavailable: correctly optional (%d checks)" % checks)
        return
    with tempfile.TemporaryDirectory(prefix="zo-wv-") as d:
        base = pathlib.Path(d)
        src = base / "source.zip"
        out = base / "output.zip"
        # PCM, float, extensible, ancillary wrappers, different channels.
        modes = [
            (1, 1, False, False, False),
            (2, 2, False, False, False),
            (3, 1, False, True, False),
            (4, 2, False, True, True),
            (4, 2, True, True, False),
            (2, 6, False, True, True),
        ]
        for i, (width, ch, floating, extras, ext) in enumerate(modes):
            data = audio(width, ch, 1024, floating, extras, ext)
            archive(src, data)
            output = base / ("format%d.zip" % i)
            call(
                executable,
                "--methods=wavpack",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                src,
                output,
            )
            validate(97, src, output, decoder)
        # Cross product: all 28 modes including extra processing disabled.
        archive(src, audio(frames=80))
        for level in range(1, 5):
            for extra in range(7):
                dest = base / ("level%d-extra%d.zip" % (level, extra))
                call(
                    executable,
                    "--methods=wavpack",
                    "--wavpack-level=%d" % level,
                    "--wavpack-extra-level=%d" % extra,
                    src,
                    dest,
                )
                validate(97, src, dest, decoder)
        # Defaults must be equivalent to extra / x6.
        d0 = base / "default.zip"
        d1 = base / "explicit.zip"
        call(executable, "--methods=wavpack", src, d0)
        call(
            executable,
            "--methods=wavpack",
            "--wavpack-level=extra",
            "--wavpack-extra-level=6",
            src,
            d1,
        )
        assert d0.read_bytes() == d1.read_bytes()
        checks += 1
        # All documented synonyms must be accepted.
        for variant in (
            "very",
            "veryhigh",
            "very-high",
            "extra",
            "4",
            "fast",
            "standard",
            "high",
        ):
            call(
                executable,
                "--methods=wavpack",
                "--wavpack-level=" + variant,
                "--wavpack-extra-level=0",
                src,
                base / ("syn%d.zip" % checks),
            )
        # Encoder absent from selection: options accepted, no method97 generated.
        other = base / "other.zip"
        call(
            executable,
            "--methods=store",
            "--wavpack-level=very-high",
            "--wavpack-extra-level=6",
            src,
            other,
        )
        with zipfile.ZipFile(other) as z:
            assert z.infolist()[0].compress_type == 0
        # Retain existing method 97 when the method is selected.
        retain = base / "retained.zip"
        call(
            executable,
            "--methods=wavpack",
            "--wavpack-level=extra",
            "--wavpack-extra-level=6",
            d0,
            retain,
        )
        assert compressed_member(retain)[1] == compressed_member(d0)[1]
        call(decoder, retain)
        # Existing WavPack may be decoded, re-encoded with other method.
        recompressed = base / "recompressed.zip"
        call(executable, "--methods=store", d0, recompressed)
        with zipfile.ZipFile(recompressed) as z:
            assert z.infolist()[0].compress_type == 0
            assert z.read("recording.wav") == audio(frames=80)
        # Non-WAV magic and malformed formats are rejected as candidates.
        invalid = [
            b"RIFF" + b"\x00" * 44,
            b"OggS" + b"\x00" * 90,
            audio()[:-1],
            audio().replace(b"WAVE", b"AVI ", 1),
            audio().replace(b"fmt ", b"fact", 1),
            audio().replace(b"data", b"junk", 1),
        ]
        for i, data in enumerate(invalid):
            bad = base / ("bad%d.zip" % i)
            dest = base / ("bad-out%d.zip" % i)
            archive(bad, data)
            rejected = call(executable, "--methods=wavpack", bad, dest, success=False)
            assert b"skipping failed compressor wavpack" not in rejected.stderr
            assert not dest.exists()
            fallback = base / ("bad-fallback%d.zip" % i)
            ordinary = call(executable, "--methods=store,wavpack", bad, fallback)
            assert b"skipping failed compressor wavpack" not in ordinary.stderr
            assert compressed_member(fallback)[0] == 0
        # Deterministic structural/audio mutations: unsupported WAV must not
        # crash or prevent a different selected candidate from succeeding.
        rng = random.Random(29097)
        reference = audio(width=2, channels=2, frames=70, extra=True)
        for i in range(64):
            modified = bytearray(reference)
            for j in range(1 + i % 3):
                at = rng.randrange(len(modified))
                modified[at] ^= 1 << rng.randrange(8)
            bad = base / ("mut%d.zip" % i)
            dest = base / ("mut-out%d.zip" % i)
            archive(bad, bytes(modified))
            call(
                executable,
                "--methods=store,wavpack",
                "--wavpack-level=fast",
                "--wavpack-extra-level=0",
                bad,
                dest,
            )
            call(decoder, dest)
        for option in (
            "--wavpack-level=0",
            "--wavpack-level=5",
            "--wavpack-level=unknown",
            "--wavpack-extra-level=7",
            "--wavpack-extra-level=-1",
            "--wavpack-extra-level=3x",
        ):
            call(
                executable,
                "--methods=store",
                option,
                src,
                base / "invalidopts.zip",
                success=False,
            )
    print("method 97 encoder: %d checks passed" % checks)


if __name__ == "__main__":
    main()
