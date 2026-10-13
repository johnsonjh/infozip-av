#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Focused zipopt command-line level and method-selection regression tests."""

import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIPOPT = ROOT / "zipopt"
DECODER = ROOT / "zipopt-decodecheck"
checks = 0


def run(*args, valid=True, timeout=90):
    global checks
    result = subprocess.run(
        [str(x) for x in args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    checks += 1
    if (result.returncode == 0) != valid:
        raise AssertionError(
            "exit %s: %s\n%s"
            % (result.returncode, args, result.stderr.decode("utf8", "replace")[-1000:])
        )
    return result


with tempfile.TemporaryDirectory(prefix="zipopt-level-") as tmp:
    tmp = pathlib.Path(tmp)
    src = tmp / "src.zip"
    data = (
        b"archive compression configurations and format levels\n" * 80
        + bytes(range(256)) * 4
    )
    with zipfile.ZipFile(src, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("payload.txt", data)

    def create(label, *opts, decoder=True):
        out = tmp / (label + ".zip")
        run(ZIPOPT, *opts, src, out)
        if decoder:
            run(DECODER, out)
        return out

    def payload(out):
        with zipfile.ZipFile(out) as z:
            with z.open("payload.txt") as f:
                return f.read()

    def method(out):
        with zipfile.ZipFile(out) as z:
            return z.getinfo("payload.txt").compress_type

    for flag in ("--version", "-V"):
        out = run(ZIPOPT, flag)
        assert b"zipopt v0.4" in out.stdout
    out = run(ZIPOPT, "--methods=help")
    assert b"reduce                   all four" in out.stdout
    assert run(ZIPOPT, "--methods=list").stdout == out.stdout
    assert method(create("reduce", "--methods=reduce")) in (2, 3, 4, 5)

    # Explicit level precedence is determined by the final relevant option.
    def identical(label, a, b):
        assert (
            create(label + "-a", *a).read_bytes()
            == create(label + "-b", *b).read_bytes()
        ), label

    identical(
        "zstd-native",
        ("--methods=zstd", "--zstd-level=9"),
        ("--methods=zstd", "--compress-level=zstd=9"),
    )
    identical(
        "zstd-native-precedence",
        ("--methods=zstd", "--zstd-level=22", "--compress-level=zstd=9"),
        ("--methods=zstd", "--zstd-level=9"),
    )
    identical(
        "zstd-generic-precedence",
        ("--methods=zstd", "--compress-level=zstd=9", "--zstd-level=22"),
        ("--methods=zstd", "--zstd-level=22"),
    )
    identical(
        "zstd-all-precedence",
        ("--methods=zstd", "--zstd-level=22", "--compress-level=all=5"),
        ("--methods=zstd", "--compress-level=zstd=5"),
    )
    identical(
        "zstd-default",
        ("--methods=zstd",),
        ("--methods=zstd", "--compress-level=all=11"),
    )
    assert method(create("zstd-final", "--methods=zstd", "--zstd-level=22")) == 93

    identical(
        "deflate-ordinary",
        ("--methods=deflate", "--disable-zopfli", "--compress-level=deflate=11"),
        ("--methods=deflate", "--compress-level=deflate=9"),
    )
    identical(
        "deflate-all5",
        ("--methods=deflate", "--compress-level=all=5"),
        ("--methods=deflate", "--compress-level=deflate=5"),
    )
    assert (
        payload(create("deflate5", "--methods=deflate", "--compress-level=deflate=5"))
        == data
    )
    assert (
        payload(create("deflate11", "--methods=deflate", "--compress-level=deflate=11"))
        == data
    )

    # One branch of DCL must be allowed even when using the group level name.
    identical(
        "dcl-optimal",
        ("--methods=dcl-implode-binary", "--compress-level=dcl-implode=11"),
        ("--methods=dcl-implode-binary", "--dcl-implode-optimal"),
    )
    identical(
        "dcl-off-precedence",
        (
            "--methods=dcl-implode-binary",
            "--dcl-implode-optimal",
            "--compress-level=all=5",
        ),
        ("--methods=dcl-implode-binary", "--compress-level=dcl-implode=5"),
    )
    identical(
        "dcl-on-precedence",
        (
            "--methods=dcl-implode-binary",
            "--compress-level=all=5",
            "--dcl-implode-optimal",
        ),
        ("--methods=dcl-implode-binary", "--compress-level=dcl-implode=11"),
    )
    identical(
        "dcl-all11",
        ("--methods=dcl-implode-binary", "--compress-level=all=11"),
        ("--methods=dcl-implode-binary", "--dcl-implode-optimal"),
    )
    identical(
        "deflate-all11",
        ("--methods=deflate", "--compress-level=all=11"),
        ("--methods=deflate",),
    )

    for algo in ("bzip2", "lzma", "xz", "ppmd", "deflate64"):
        for level in (1, 5, 9, 11):
            create(
                algo + "-" + str(level),
                "--methods=" + algo,
                "--compress-level=" + algo + "=" + str(level),
            )

    for options in (
        ("--methods=store", "--zstd-level=9"),
        ("--methods=store", "--compress-level=zstd=9"),
        ("--methods=store", "--compress-level=deflate=9"),
        ("--methods=deflate", "--compress-level=shrink=5"),
        ("--methods=reduce", "--compress-level=reduce=5"),
        ("--methods=deflate", "--compress-level=deflate=0"),
        ("--methods=deflate", "--compress-level=deflate=10"),
        ("--methods=deflate", "--compress-level=deflate=12"),
        ("--methods=deflate", "--compress-level=deflate=-5"),
        ("--methods=deflate", "--compress-level=bogus=5"),
        ("--methods=store", "--disable-zopfli"),
        ("--methods=deflate", "--disable-zopfli", "--zopfli-iterations=5"),
        ("--methods=deflate", "--compress-level=deflate=5", "--zopfli-iterations=5"),
        ("--methods=deflate", "--zstd-level=23"),
        ("--methods=deflate", "--zstd-level=0"),
        ("--methods=deflate", "--compress-level=deflate="),
    ):
        run(ZIPOPT, *options, src, tmp / "reject.zip", valid=False)

    # A group level is legitimate even when no adjustable member is selected.
    create("store-global", "--methods=store", "--compress-level=all=5")
    print("PASS: %d zipopt level/selection/build checks" % checks)
