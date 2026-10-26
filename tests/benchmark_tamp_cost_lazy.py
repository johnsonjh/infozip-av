#!/usr/bin/env python3

import argparse
import hashlib
import json
import random
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path


def member_payload(path):
    with zipfile.ZipFile(path) as archive:
        (entry,) = archive.infolist()
        assert entry.compress_type == 31340, entry.compress_type
        with path.open("rb") as stream:
            stream.seek(entry.header_offset)
            header = stream.read(30)
            assert header[:4] == b"PK\x03\x04"
            name_size, extra_size = struct.unpack_from("<HH", header, 26)
            stream.seek(name_size + extra_size, 1)
            payload = stream.read(entry.compress_size)
            assert len(payload) == entry.compress_size
            return payload


def corpus(root):
    rng = random.Random(0x31340001)
    source_files = [
        root / "common/xtr_tamp.c",
        root / "zip30/zipup.c",
        root / "zip30/zip.c",
        root / "unzip60/extract.c",
    ]
    source = b"\n".join(path.read_bytes() for path in source_files)[:196608]
    binary = (root / "zip30/zip").read_bytes()[:196608]
    text = b"".join(
        (
            f"2026-10-26 WARN transaction={i % 101} user={i % 41} "
            f"object=item-{(i * 7) % 113}: modified\n"
        ).encode("ascii")
        for i in range(5000)
    )[:196608]
    seed = rng.randbytes(8192)
    altered = bytearray(seed)
    for offset in range(0, 8192, 97):
        altered[offset] ^= 1
    repeated = (seed + bytes(altered)) * 8
    incompressible = rng.randbytes(65536)
    return {
        "source-192k": source,
        "binary-192k": binary,
        "logs-192k": text,
        "repeated-128k": repeated,
        "random-64k": incompressible,
    }


def zip_once(binary, path, archive, level, lazy):
    command = [
        str(binary),
        "-j",
        "-q",
        "--disable-store-fallback",
        "-Z",
        "tamp",
        f"-{level}",
        "--tamp-lazy-matching" if lazy else "--tamp-lazy-matching-",
        str(archive),
        str(path),
    ]
    began = time.perf_counter()
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    elapsed = time.perf_counter() - began
    if result.returncode:
        raise RuntimeError(f"{command!r} failed: {result.stderr[-1200:]!r}")
    return elapsed, member_payload(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument(
        "--stock-c",
        type=Path,
        help="Executable linked only against upstream Tamp C decoder",
    )
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--levels", type=int, nargs="+", default=[3, 5, 6, 7, 8, 9, 11])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    assert args.repeat >= 1
    sys.path.insert(0, str(args.upstream_dir.resolve()))
    import tamp as upstream

    fixtures = corpus(args.root)
    results = []
    nonlazy_checks = 0
    with tempfile.TemporaryDirectory(prefix="tamp-exp-a-bench-") as temp:
        directory = Path(temp)
        input_path = directory / "INPUT.BIN"
        for label, data in fixtures.items():
            input_path.write_bytes(data)
            for level in args.levels:
                durations = {"baseline": [], "candidate": []}
                payloads = {}
                for run_no in range(args.repeat):
                    # Alternate execution order, mitigating cache/thermal bias.
                    names = (
                        ("baseline", "candidate")
                        if run_no % 2 == 0
                        else ("candidate", "baseline")
                    )
                    for name in names:
                        binary = getattr(args, name).resolve()
                        archive = directory / (f"{name}-{level}-{run_no}.zip")
                        seconds, stream = zip_once(
                            binary, input_path, archive, level, True
                        )
                        durations[name].append(seconds)
                        assert upstream.decompress(stream) == data, (label, level, name)
                        if args.stock_c:
                            reference = subprocess.run(
                                [str(args.stock_c.resolve())],
                                input=stream,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=False,
                            )
                            assert reference.returncode == 0, (
                                label,
                                level,
                                name,
                                reference.stderr[-500:],
                            )
                            assert reference.stdout == data, (
                                label,
                                level,
                                name,
                                "stock C",
                            )
                        if name in payloads:
                            assert payloads[name] == stream, (
                                label,
                                level,
                                name,
                                "nondeterministic",
                            )
                        payloads[name] = stream
                        archive.unlink()

                base_size = len(payloads["baseline"])
                candidate_size = len(payloads["candidate"])
                results.append(
                    {
                        "dataset": label,
                        "input_bytes": len(data),
                        "level": level,
                        "baseline_bytes": base_size,
                        "candidate_bytes": candidate_size,
                        "difference_bytes": candidate_size - base_size,
                        "difference_percent": round(
                            100.0 * (candidate_size - base_size) / base_size, 4
                        ),
                        "baseline_median_seconds": round(
                            statistics.median(durations["baseline"]), 5
                        ),
                        "candidate_median_seconds": round(
                            statistics.median(durations["candidate"]), 5
                        ),
                        "baseline_sha256": hashlib.sha256(
                            payloads["baseline"]
                        ).hexdigest(),
                        "candidate_sha256": hashlib.sha256(
                            payloads["candidate"]
                        ).hexdigest(),
                    }
                )
                print(
                    f"{label:14s} -{level:<2} {base_size:>9} -> {candidate_size:>9} "
                    f"({candidate_size - base_size:+8d}, "
                    f"{results[-1]['difference_percent']:+7.3f}%) ",
                    f"time {results[-1]['baseline_median_seconds']:.3f}/"
                    f"{results[-1]['candidate_median_seconds']:.3f}s",
                    flush=True,
                )

            # Non-lazy output must be bit-for-bit unchanged by the experiment.
            for level in (3, 6, 7, 9):
                streams = []
                for name in ("baseline", "candidate"):
                    archive = directory / f"{name}-nonlazy-{level}.zip"
                    _, payload = zip_once(
                        getattr(args, name).resolve(), input_path, archive, level, False
                    )
                    streams.append(payload)
                    archive.unlink()
                assert streams[0] == streams[1], (label, level, "nonlazy changed")
                nonlazy_checks += 1

    summary = {
        "cases": len(results),
        "improvements": sum(r["difference_bytes"] < 0 for r in results),
        "regressions": sum(r["difference_bytes"] > 0 for r in results),
        "unchanged": sum(r["difference_bytes"] == 0 for r in results),
        "combined_baseline_bytes": sum(r["baseline_bytes"] for r in results),
        "combined_candidate_bytes": sum(r["candidate_bytes"] for r in results),
        "nonlazy_bit_identical_checks": nonlazy_checks,
        "stock_decoder_checks": 2 * len(results) * args.repeat,
        "stock_c_decoder_checks": 2 * len(results) * args.repeat if args.stock_c else 0,
    }
    document = {"summary": summary, "results": results}
    print(json.dumps(summary, indent=2), flush=True)
    if args.output:
        args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf8")


if __name__ == "__main__":
    main()
