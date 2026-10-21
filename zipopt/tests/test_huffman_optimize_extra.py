#!/usr/bin/env python3
"""Regression test for --huffman-optimize-extra with optional Zip/ZipOpt.

Requires only Python 3 and a C89 compiler for the shared-header invariant
probe. The full archive checks also require built ZipOpt and system unzip.
"""

import argparse
import csv
import os
import pathlib
import random
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(command, timeout=60):
    done = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )
    if done.returncode:
        raise AssertionError(
            "%r: %s" % (command, done.stderr.decode(errors="replace")[-1000:])
        )
    return done


def payloads():
    rng = random.Random(0x1234567)
    return [
        b"abc" * 1024,
        bytes(range(256)) * 12,
        b"A" * 6000,
        b"aaaaabbbbbcccddd" * 512,
        bytes(rng.choice(b"aaaabbbbccccd123456789;:xy") for _ in range(8000)),
        bytes(rng.randrange(256) for _ in range(4096)),
        (b"const unsigned char foo = 0;\n" * 300),
        bytes(rng.choice(b"aabCDEF0123;, ") for _ in range(6000)),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--zip", default=str(ROOT / "zip30" / "zip"))
    ap.add_argument("--zipopt", default=str(ROOT / "zipopt" / "zipopt"))
    ap.add_argument("--unzip", default="unzip")
    ap.add_argument("--skip-archives", action="store_true")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="xtr-he-") as t:
        temp = pathlib.Path(t)
        probe = temp / "header-probe"
        run(
            args.cc.split()
            + [
                "-std=c89",
                "-pedantic",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                "-I" + str(ROOT / "zip30"),
                str(ROOT / "zipopt/tests/huffman_extra_probe.c"),
                "-o",
                str(probe),
            ]
        )
        run([str(probe)])
        print("PASS: 1,800 randomized C89 header invariants")
        if args.skip_archives:
            return
        # Reject the option when no encoder capable of using it is selected.
        # The destination must not be created or modified on a CLI error.
        negative_src = temp / "invalid-option-input.bin"
        negative_src.write_bytes(b"test unsupported method selection\n" * 100)
        negative_archive = temp / "invalid-option-source.zip"
        with zipfile.ZipFile(negative_archive, "w") as z:
            z.write(negative_src, "input.bin")
        negative_cases = 0
        for method in ("store", "bzip2", "lzma", "zstd"):
            if method != "store":
                # Optional codecs may be absent in stripped-down Zip builds.
                probe = temp / ("available-zip-%s.zip" % method)
                trial = subprocess.run(
                    [args.zip, "-q", "-Z", method, str(probe), str(negative_src)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=60,
                )
                if trial.returncode:
                    continue
            out = temp / ("reject-zip-%s.zip" % method)
            command = [
                args.zip,
                "-q",
                "-Z",
                method,
                "--huffman-optimize-extra",
                str(out),
                str(negative_src),
            ]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
            )
            if result.returncode == 0 or out.exists():
                raise AssertionError((command, result.returncode))
            if b"--huffman-optimize-extra requires Deflate or Deflate64" not in (
                result.stdout + result.stderr
            ):
                raise AssertionError(result.stderr)
            negative_cases += 1
        for method in (None, "deflate", "deflate64"):
            out = temp / ("reject-zip-zero-%s.zip" % (method or "default"))
            command = [args.zip, "-q", "-0"]
            if method:
                command.extend(["-Z", method])
            command.extend(["--huffman-optimize-extra", str(out), str(negative_src)])
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
            )
            if result.returncode == 0 or out.exists():
                raise AssertionError((command, result.returncode))
            if b"--huffman-optimize-extra requires Deflate or Deflate64" not in (
                result.stdout + result.stderr
            ):
                raise AssertionError(result.stdout + result.stderr)
            negative_cases += 1
        available = run([args.zipopt, "--methods=list"]).stdout.decode("ascii")
        for methods in ("store", "bzip2", "lzma", "zstd", "store,bzip2"):
            if any(
                ("  %s " % method) not in available for method in methods.split(",")
            ):
                continue
            out = temp / ("reject-opt-%s.zip" % methods.replace(",", "-"))
            command = [
                args.zipopt,
                "--methods=" + methods,
                "--huffman-optimize-extra",
                str(negative_archive),
                str(out),
            ]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
            )
            if result.returncode == 0 or out.exists():
                raise AssertionError((command, result.returncode))
            if (
                b"--huffman-optimize-extra requires a Deflate or Deflate64 candidate"
                not in result.stderr
            ):
                raise AssertionError(result.stderr)
            negative_cases += 1
        # Existing archive bytes must also survive a rejected option.
        protected = temp / "existing-destination.zip"
        protected.write_bytes(negative_archive.read_bytes())
        original = protected.read_bytes()
        commands = (
            [
                args.zip,
                "-q",
                "-Z",
                "store",
                "--huffman-optimize-extra",
                str(protected),
                str(negative_src),
            ],
            [
                args.zipopt,
                "--methods=store",
                "--huffman-optimize-extra",
                str(negative_archive),
                str(protected),
            ],
        )
        for command in commands:
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
            )
            if result.returncode == 0 or protected.read_bytes() != original:
                raise AssertionError((command, result.returncode))
            negative_cases += 1
        for methods in ("store,deflate", "store,deflate64", "deflate64"):
            out = temp / ("accept-opt-%s.zip" % methods.replace(",", "-"))
            run(
                [
                    args.zipopt,
                    "--methods=" + methods,
                    "--huffman-optimize-extra",
                    str(negative_archive),
                    str(out),
                ]
            )
            run([args.unzip, "-tqq", str(out)])
        for method in ("deflate", "deflate64", None):
            out = temp / ("accept-zip-%s.zip" % (method or "default"))
            cmd = [args.zip, "-q", "-9"]
            if method:
                cmd.extend(["-Z", method])
            run(cmd + ["--huffman-optimize-extra", str(out), str(negative_src)])
            run([args.unzip, "-tqq", str(out)])
        print(
            "PASS: %d unsupported method selections rejected before output"
            % negative_cases
        )
        archive_cases = 0
        savings = {}
        for num, data in enumerate(payloads()):
            member = "case%d.bin" % num
            source = temp / member
            source.write_bytes(data)
            existing = temp / ("source%d.zip" % num)
            with zipfile.ZipFile(existing, "w", compression=zipfile.ZIP_STORED) as z:
                z.write(source, member)
            for method in ("deflate", "deflate64"):
                for level in (1, 6, 9, 11):
                    base, opt = [], []
                    for enabled in (False, True):
                        out = temp / (
                            "out%d-%s-%d-%s.zip"
                            % (num, method, level, "opt" if enabled else "plain")
                        )
                        command = [
                            args.zipopt,
                            "--methods=" + method,
                            "--compress-level=%s=%d" % (method, level),
                        ]
                        if method == "deflate" and level == 11:
                            command.append("--zopfli-iterations=1")
                        if enabled:
                            command.append("--huffman-optimize-extra")
                        command += [str(existing), str(out)]
                        run(command, timeout=120)
                        run([args.unzip, "-tqq", str(out)])
                        with zipfile.ZipFile(out) as z:
                            info = z.getinfo(member)
                            assert info.compress_type == (
                                8 if method == "deflate" else 9
                            )
                            if method == "deflate":
                                assert z.read(member) == data
                            (opt if enabled else base).append(info.compress_size)
                    assert opt[0] <= base[0], (num, method, level, base, opt)
                    savings[method] = savings.get(method, 0) + base[0] - opt[0]
                    archive_cases += 1
        print(
            "PASS: %d ZipOpt paired method/level cases; savings %r"
            % (archive_cases, savings)
        )
        # Exercise the Zip CLI on both internal encoder paths and Zopfli.
        for method, level in (
            ("deflate", 6),
            ("deflate", 9),
            ("deflate", 11),
            ("deflate64", 6),
            ("deflate64", 11),
        ):
            source = temp / "case4.bin"
            out = temp / ("zip-%s-%d.zip" % (method, level))
            cmd = [
                args.zip,
                "-q",
                "-%d" % level,
                "-Z",
                method,
                "--huffman-optimize-extra",
            ]
            if level == 11 and method == "deflate":
                cmd += ["--zopfli-iterations=1"]
            run(cmd + [str(out), str(source)], timeout=120)
            run([args.unzip, "-tqq", str(out)])
        print("PASS: Zip CLI Deflate, Deflate64 and Zopfli archive checks")


if __name__ == "__main__":
    main()
