#!/usr/bin/env python3
"""Regression test for ZIP method 97 with WavPack 4/5 stream versions.

Requires an UnZip binary compiled with USE_WAVP and libwavpack 5.x.
The Python standard library is the only Python dependency. The test uses
libwavpack through ctypes to generate genuine old and new-format streams.
"""

import argparse
import ctypes
import ctypes.util
import math
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import wave
import zipfile
import zlib


class WavpackConfig(ctypes.Structure):
    _fields_ = [
        ("bitrate", ctypes.c_float),
        ("shaping_weight", ctypes.c_float),
        ("bits_per_sample", ctypes.c_int),
        ("bytes_per_sample", ctypes.c_int),
        ("qmode", ctypes.c_int),
        ("flags", ctypes.c_int),
        ("xmode", ctypes.c_int),
        ("num_channels", ctypes.c_int),
        ("float_norm_exp", ctypes.c_int),
        ("block_samples", ctypes.c_int32),
        ("worker_threads", ctypes.c_int32),
        ("sample_rate", ctypes.c_int32),
        ("channel_mask", ctypes.c_int32),
        ("md5_checksum", ctypes.c_ubyte * 16),
        ("md5_read", ctypes.c_ubyte),
        ("num_tag_strings", ctypes.c_int),
        ("tag_strings", ctypes.c_void_p),
    ]


BLOCK_OUTPUT = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32
)


def load_library():
    name = ctypes.util.find_library("wavpack")
    if name is None:
        raise RuntimeError("libwavpack 5.x is required for fixture generation")
    lib = ctypes.CDLL(name)
    lib.WavpackGetLibraryVersion.restype = ctypes.c_uint32
    version = lib.WavpackGetLibraryVersion()
    if version < 0x050000:
        raise RuntimeError("libwavpack 5.x or newer is required")
    lib.WavpackOpenFileOutput.argtypes = [
        BLOCK_OUTPUT,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.WavpackOpenFileOutput.restype = ctypes.c_void_p
    lib.WavpackSetConfiguration.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(WavpackConfig),
        ctypes.c_uint32,
    ]
    lib.WavpackSetConfiguration.restype = ctypes.c_int
    lib.WavpackSetConfiguration64.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(WavpackConfig),
        ctypes.c_int64,
        ctypes.c_void_p,
    ]
    lib.WavpackSetConfiguration64.restype = ctypes.c_int
    lib.WavpackAddWrapper.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    lib.WavpackAddWrapper.restype = ctypes.c_int
    lib.WavpackPackInit.argtypes = [ctypes.c_void_p]
    lib.WavpackPackInit.restype = ctypes.c_int
    lib.WavpackPackSamples.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int32),
        ctypes.c_uint32,
    ]
    lib.WavpackPackSamples.restype = ctypes.c_int
    lib.WavpackFlushSamples.argtypes = [ctypes.c_void_p]
    lib.WavpackFlushSamples.restype = ctypes.c_int
    lib.WavpackCloseFile.argtypes = [ctypes.c_void_p]
    lib.WavpackCloseFile.restype = ctypes.c_void_p
    return lib


def make_wav():
    # Standard 16-bit, 44.1kHz stereo PCM, with identical L/R channels.
    # This triggers the WavPack 5 false-stereo optimization (0x410 format).
    values = [int(24000 * math.sin(2 * math.pi * i / 93)) for i in range(40000)]
    frames = b"".join(struct.pack("<hh", v, v) for v in values)
    import io

    out = io.BytesIO()
    with wave.open(out, "wb") as writer:
        writer.setnchannels(2)
        writer.setsampwidth(2)
        writer.setframerate(44100)
        writer.writeframes(frames)
    return out.getvalue(), values


def encode(lib, wav, values, compatible):
    blocks = []

    @BLOCK_OUTPUT
    def blockout(_id, buffer, length):
        if length < 0:
            return 0
        blocks.append(ctypes.string_at(buffer, length))
        return 1

    ctx = lib.WavpackOpenFileOutput(blockout, None, None)
    if not ctx:
        raise RuntimeError("cannot open WavPack output")
    try:
        cfg = WavpackConfig()
        cfg.bits_per_sample = 16
        cfg.bytes_per_sample = 2
        cfg.num_channels = 2
        cfg.sample_rate = 44100
        cfg.channel_mask = 3
        count = len(values)
        if compatible:
            ok = lib.WavpackSetConfiguration(ctx, ctypes.byref(cfg), count)
        else:
            ok = lib.WavpackSetConfiguration64(ctx, ctypes.byref(cfg), count, None)
        if not ok:
            raise RuntimeError("WavPack configuration failed")
        riff = ctypes.create_string_buffer(wav[:44], 44)
        if not lib.WavpackAddWrapper(ctx, riff, 44):
            raise RuntimeError("WavPack wrapper creation failed")
        if not lib.WavpackPackInit(ctx):
            raise RuntimeError("WavPack initialization failed")
        samples = (ctypes.c_int32 * (count * 2))(*[x for v in values for x in (v, v)])
        if not lib.WavpackPackSamples(ctx, samples, count):
            raise RuntimeError("WavPack sample encoding failed")
        if not lib.WavpackFlushSamples(ctx):
            raise RuntimeError("WavPack flush failed")
    finally:
        lib.WavpackCloseFile(ctx)
    data = b"".join(blocks)
    if data[:4] != b"wvpk" or len(data) < 32:
        raise AssertionError("missing WavPack block header")
    return data


def make_zip(compressed, plain, filename=b"audio.wav"):
    crc = zlib.crc32(plain) & 0xFFFFFFFF
    loc = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            97,
            0,
            0,
            crc,
            len(compressed),
            len(plain),
            len(filename),
            0,
        )
        + filename
    )
    cen = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            97,
            0,
            0,
            crc,
            len(compressed),
            len(plain),
            len(filename),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + filename
    )
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cen), len(loc) + len(compressed), 0
    )
    return loc + compressed + cen + end


def run(unzip, data, directory, name, good, wav=None):
    archive = directory / (name + ".zip")
    archive.write_bytes(data)
    checked = subprocess.run(
        [str(unzip), "-t", str(archive)], capture_output=True, timeout=30
    )
    if good:
        if checked.returncode != 0:
            raise AssertionError(
                name + " failed test: " + repr(checked.stderr + checked.stdout)
            )
        extracted = subprocess.run(
            [str(unzip), "-p", str(archive)], capture_output=True, timeout=30
        )
        if extracted.returncode != 0 or extracted.stdout != wav:
            raise AssertionError(name + " extracted WAV differs from input")
    elif checked.returncode == 0:
        raise AssertionError(name + " unexpectedly accepted an invalid stream")
    print("PASS", name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--unzip", type=Path, required=True)
    args = parser.parse_args()
    unzip = args.unzip.resolve()
    lib = load_library()
    wav, values = make_wav()
    older = encode(lib, wav, values, compatible=True)
    newer = encode(lib, wav, values, compatible=False)
    oldver = struct.unpack_from("<H", older, 8)[0]
    newver = struct.unpack_from("<H", newer, 8)[0]
    if oldver >= 0x410 or newver != 0x410:
        raise RuntimeError(
            "libwavpack did not generate expected 0x410 stream; got %04x / %04x"
            % (oldver, newver)
        )
    # Make certain we actually exercise a v5-only coding feature.
    if not struct.unpack_from("<I", newer, 24)[0] & 0x40000000:
        raise RuntimeError("new stream did not enable false-stereo optimization")
    with tempfile.TemporaryDirectory(prefix="zip-wavpack97-") as tmp:
        dest = Path(tmp)
        run(unzip, make_zip(older, wav), dest, "legacy_0x%04x" % oldver, True, wav)
        run(unzip, make_zip(newer, wav), dest, "modern_0x410", True, wav)
        for version in (0x401, 0x411, 0x500):
            changed = bytearray(newer)
            struct.pack_into("<H", changed, 8, version)
            run(
                unzip,
                make_zip(changed, wav),
                dest,
                "unsupported_0x%04x" % version,
                False,
            )
        run(unzip, make_zip(newer[:12], wav), dest, "truncated_block", False)
        changed = bytearray(newer)
        changed[:4] = b"XXXX"
        run(unzip, make_zip(changed, wav), dest, "bad_signature", False)
        # An unrelated ordinary ZIP file must be unaffected by method 97 support.
        regular = dest / "regular.zip"
        with zipfile.ZipFile(regular, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("ordinary.txt", b"ordinary deflate data" * 200)
        checked = subprocess.run(
            [str(unzip), "-t", str(regular)], capture_output=True, timeout=30
        )
        if checked.returncode:
            raise AssertionError(
                "ordinary Deflate ZIP fails: " + repr(checked.stderr + checked.stdout)
            )
        print("PASS ordinary_deflate")
    print("All 8 WavPack ZIP method-97 regression checks passed")


if __name__ == "__main__":
    main()
