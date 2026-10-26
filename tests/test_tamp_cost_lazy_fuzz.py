#!/usr/bin/env python3

import argparse
import random
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def extract_payload(archive):
    with zipfile.ZipFile(archive) as zf:
        (entry,) = zf.infolist()
        assert entry.compress_type == 31340, entry.compress_type
        with archive.open("rb") as f:
            f.seek(entry.header_offset)
            header = f.read(30)
            assert header[:4] == b"PK\x03\x04"
            namelen, extralen = struct.unpack_from("<HH", header, 26)
            f.seek(namelen + extralen, 1)
            data = f.read(entry.compress_size)
            assert len(data) == entry.compress_size
            return data


def fixture(rng, case):
    size = 512 + rng.randrange(8192)
    style = case % 6
    if style == 0:
        return rng.randbytes(size)
    if style == 1:
        return bytes(rng.randrange(8) for _ in range(size))
    if style == 2:
        phrase = rng.randbytes(rng.randrange(3, 65))
        data = bytearray((phrase * ((size // len(phrase)) + 1))[:size])
        for i in range(3, size, rng.randrange(17, 113)):
            data[i] ^= 1
        return bytes(data)
    if style == 3:
        return b"".join(
            bytes([rng.randrange(256)]) * rng.randrange(1, 250)
            for _ in range(size // 40 + 15)
        )[:size]
    if style == 4:
        fragments = [rng.randbytes(2 + rng.randrange(21)) for _ in range(8)]
        return b"".join(rng.choice(fragments) for _ in range(size // 7 + 2))[:size]
    return bytes((i * i + i // 5 + rng.randrange(5)) & 255 for i in range(size))


def encode(binary, filename, output, level, lazy):
    cmd = [
        str(binary),
        "-q",
        "-j",
        "--disable-store-fallback",
        "-Z",
        "tamp",
        f"-{level}",
        "--tamp-lazy-matching" if lazy else "--tamp-lazy-matching-",
        str(output),
        str(filename),
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 0, (cmd, result.stderr[-900:])
    return extract_payload(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--unzip", required=True, type=Path)
    parser.add_argument("--upstream-dir", required=True, type=Path)
    parser.add_argument("--stock-c", required=True, type=Path)
    parser.add_argument("--cases", type=int, default=200)
    args = parser.parse_args()
    sys.path.insert(0, str(args.upstream_dir.resolve()))
    import tamp as upstream

    rng = random.Random(0x31340CA)
    levels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 11)
    total_baseline = 0
    total_candidate = 0
    better = worse = equal = 0
    with tempfile.TemporaryDirectory(prefix="tamp-cost-lazy-fuzz-") as temp:
        directory = Path(temp)
        source = directory / "INPUT.BIN"
        for case in range(args.cases):
            original = fixture(rng, case)
            source.write_bytes(original)
            level = levels[case % len(levels)]
            lazy = ((case // len(levels)) % 2) != 0
            streams = []
            for name in ("baseline", "candidate"):
                output = directory / (name + ".zip")
                stream = encode(
                    getattr(args, name).resolve(), source, output, level, lazy
                )
                assert upstream.decompress(stream) == original, (case, name, "Python")
                c_decoder = subprocess.run(
                    [str(args.stock_c.resolve())],
                    input=stream,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                assert c_decoder.returncode == 0 and c_decoder.stdout == original, (
                    case,
                    name,
                    "stock C",
                    c_decoder.stderr[-900:],
                )
                streams.append(stream)
                if name == "candidate":
                    checked = subprocess.run(
                        [str(args.unzip.resolve()), "-tqq", str(output)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    assert checked.returncode == 0, (case, checked.stderr[-900:])
                output.unlink()

            if not lazy:
                assert streams[0] == streams[1], (case, "non-lazy stream changed")
            total_baseline += len(streams[0])
            total_candidate += len(streams[1])
            better += len(streams[1]) < len(streams[0])
            worse += len(streams[1]) > len(streams[0])
            equal += len(streams[1]) == len(streams[0])
            if (case + 1) % 50 == 0:
                print(
                    f"{case + 1} cases: better={better}, worse={worse}, "
                    f"equal={equal}, bytes={total_candidate - total_baseline:+d}",
                    flush=True,
                )

    print(
        f"PASS {args.cases} randomized ZIP round trips, "
        f"{2 * args.cases} stock Python decodes, "
        f"{2 * args.cases} stock C decodes, {args.cases} Xtro UnZip CRC checks"
    )
    print(
        f"COMPRESSED-SIZE better={better} worse={worse} equal={equal} "
        f"delta={total_candidate - total_baseline:+d} bytes"
    )


if __name__ == "__main__":
    main()
