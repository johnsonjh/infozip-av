#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Check Zip/UnZip-compatible backend precedence and real native ABI probing.

A temporary minimal mock supplies native zlib-ng *symbols* solely for this
compile/link detection regression. It is not a compression implementation,
and does not require an external zlib installation.
"""

import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CC = shlex.split(os.environ.get("CC", "cc"))
MAKE = os.environ.get("MAKE") or shutil.which("gmake") or shutil.which("make") or "make"
checks = 0


def run(command, env=None, should_pass=True):
    global checks
    result = subprocess.run(
        command, env=env, cwd=ROOT, capture_output=True, text=True, timeout=40
    )
    checks += 1
    assert (result.returncode == 0) == should_pass, (
        command,
        result.returncode,
        result.stdout[-500:],
        result.stderr[-1000:],
    )
    return result


def selected(expected=None, env=None, should_pass=True, *args):
    command = [MAKE, "--no-print-directory", "-s", "print-deflate-backend", *args]
    result = run(command, env, should_pass)
    if expected is not None:
        assert result.stdout.strip() == expected, (args, result.stdout)
    return result


with tempfile.TemporaryDirectory(prefix="zo-backends-") as t:
    root = pathlib.Path(t)
    inc, lib, pc = [root / n for n in ("include", "lib", "pkgconfig")]
    for directory in (inc, lib, pc):
        directory.mkdir()
    (inc / "zlib-ng.h").write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        "#define Z_DEFLATED 8\n#define Z_OK 0\n"
        "typedef struct { int unused; } zng_stream;\n"
        "const char *zlibng_version(void);\n"
        "uint32_t zng_crc32_z(uint32_t,const uint8_t *,size_t);\n"
        "int zng_deflateInit2(zng_stream *,int,int,int,int,int);\n"
        "int zng_deflate(zng_stream *,int);\n"
        "int zng_deflateEnd(zng_stream *);\n"
    )
    source = root / "shim.c"
    source.write_text(
        '#include "zlib-ng.h"\n'
        'const char *zlibng_version(void){return "test-shim";}\n'
        "uint32_t zng_crc32_z(uint32_t c,const uint8_t *p,size_t n)"
        "{(void)p;(void)n;return c;}\n"
        "int zng_deflateInit2(zng_stream *s,int l,int m,int w,int b,int t)"
        "{(void)s;(void)l;(void)m;(void)w;(void)b;(void)t;return Z_OK;}\n"
        "int zng_deflate(zng_stream *s,int f){(void)s;(void)f;return Z_OK;}\n"
        "int zng_deflateEnd(zng_stream *s){(void)s;return Z_OK;}\n"
    )
    obj = root / "shim.o"
    run(CC + ["-std=c89", "-I" + str(inc), "-c", str(source), "-o", str(obj)])
    run(["ar", "rcs", str(lib / "libz-ng.a"), str(obj)])
    (pc / "zlib-ng.pc").write_text(
        "prefix=%s\n" % root
        + "libdir=${prefix}/lib\n"
        + "includedir=${prefix}/include\n"
        + "Name: zlib-ng\nDescription: test shim for probe\nVersion: 2.0\n"
        + "Libs: -L${libdir} -lz-ng\n"
        + "Cflags: -I${includedir}\n"
    )
    base = os.environ.copy()
    for key in (
        "EXTERNAL_ZLIB",
        "ZO_DEFLATE_BACKEND",
        "IZ_ZLIBNG_CFLAGS",
        "IZ_ZLIBNG_LIBS",
        "IZ_ZLIB_CFLAGS",
        "IZ_ZLIB_LIBS",
        "LOCAL_ZIP",
        "CPPFLAGS",
        "CFLAGS",
        "MAKEFLAGS",
        "MFLAGS",
        "MAKEOVERRIDES",
        "GNUMAKEFLAGS",
    ):
        base.pop(key, None)
    base["PKG_CONFIG_PATH"] = str(pc)
    native = dict(base)
    selected("native", native)
    selected("native", native, True, "EXTERNAL_ZLIB=-DUSE_ZLIB_NG")
    selected("native", native, True, "EXTERNAL_ZLIB=-DUSE_ZLIB_NG -DNO_ZLIB_NG")
    selected("zlib", native, True, "EXTERNAL_ZLIB=-DUSE_ZLIB")
    selected("internal", native, True, "EXTERNAL_ZLIB=-DNO_ZLIB_NG")
    selected("zlib", native, True, "ZO_DEFLATE_BACKEND=zlib")
    selected("internal", native, True, "ZO_DEFLATE_BACKEND=internal")
    selected("native", native, True, "ZO_DEFLATE_BACKEND=native")
    # The identical EXTERNAL_ZLIB selection must work when inherited through
    # the environment rather than passed on the make command line.
    inherited = dict(native, EXTERNAL_ZLIB="-DUSE_ZLIB")
    selected("zlib", inherited)
    selected(None, native, False, "EXTERNAL_ZLIB=-DUSE_ZLIB -DUSE_ZLIB_NG")
    selected(
        None, native, False, "EXTERNAL_ZLIB=-DUSE_ZLIB", "ZO_DEFLATE_BACKEND=native"
    )
    selected(
        None, native, False, "EXTERNAL_ZLIB=-DNO_ZLIB_NG", "ZO_DEFLATE_BACKEND=native"
    )
    # This deliberately invalid link line must override working pkg-config
    # metadata, proving native detection is not a metadata-only test.
    unavailable = dict(base, IZ_ZLIBNG_LIBS="-lzipopt_missing_zlibng_for_test")
    selected("internal", unavailable)
    selected(None, unavailable, False, "ZO_DEFLATE_BACKEND=native")
    selected(None, unavailable, False, "EXTERNAL_ZLIB=-DUSE_ZLIB_NG")
    # The same native probe succeeds with supplied IZ_ overrides even when
    # pkg-config cannot see any native .pc package.
    override = dict(base)
    override["PKG_CONFIG_LIBDIR"] = str(root / "empty-pkgconfig")
    override["IZ_ZLIBNG_CFLAGS"] = "-I" + str(inc)
    override["IZ_ZLIBNG_LIBS"] = "-L%s -lz-ng" % lib
    selected("native", override)

print("PASS: %d backend selection and native link-probe checks" % checks)
