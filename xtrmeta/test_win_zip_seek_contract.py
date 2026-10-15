#!/usr/bin/env python3
"""Portable, C89 regression for the MinGW Zip buffered 64-bit seek wrapper.

The test compiles the actual zftello()/zfseeko() functions extracted from
win32i64.c with minimal host CRT shims for _ftelli64/_fseeki64; therefore it
also catches an accidental reversion to descriptor-only seeking. MIT-0.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def extract_function(source, signature):
    start = source.find("\n" + signature + "\n")
    if start < 0:
        raise ValueError("missing function: " + signature)
    start += 1
    brace = source.find("{", start)
    if brace < 0:
        raise ValueError("missing function body: " + signature)
    level = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            level += 1
        elif source[i] == "}":
            level -= 1
            if level == 0:
                return source[start : i + 1]
    raise ValueError("unclosed function: " + signature)


PREFIX = r"""
#define _POSIX_C_SOURCE 200809L
#define __MINGW32__ 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
typedef long zoff_t;
/* The host substitutes identical buffered-stream operations for the
 * MinGW CRT's 64-bit operations; this does not validate a MinGW ABI. */
static long _ftelli64(FILE *f) { return ftell(f); }
static int _fseeki64(FILE *f, long offset, int origin)
{ return fseek(f, offset, origin); }
"""

SUFFIX = r"""
static int old_descriptor_seek(FILE *f, long offset, int origin)
{
    long p = ftell(f);
    if (fflush(f)) return -1;
    if (origin == SEEK_CUR) { offset += p; origin = SEEK_SET; }
    return lseek(fileno(f), offset, origin) == -1L ? -1 : 0;
}
static int check(int ok, const char *desc)
{
    if (!ok) { fprintf(stderr, "FAIL: %s\n", desc); return 0; }
    return 1;
}
int main(void)
{
    FILE *f = tmpfile();
    unsigned char block[512], expected[4] = {'P','K',5,6}, got[4];
    int i, ch, checks = 0;
    if (!f) return 2;
    memset(block, 0x33, sizeof(block));
    memcpy(block + 320, expected, 4);
    if (fwrite(block, 1, sizeof(block), f) != sizeof(block)) return 2;
    if (fseek(f, 0L, SEEK_SET)) return 2;
    while ((ch = fgetc(f)) != EOF) { }
    if (!check(feof(f), "scan must reach EOF")) return 1;
    checks++;
    /* Reproduce the historical implementation's descriptor-only defect. */
    if (old_descriptor_seek(f, 320L, SEEK_SET)) return 2;
    if (!check(feof(f) && fgetc(f) == EOF,
               "old lseek left FILE* at EOF despite changed descriptor")) return 1;
    checks++;
    if (zfseeko(f, 320L, SEEK_SET)) return 1;
    if (!check(!feof(f), "CRT seek clears stdio EOF")) return 1;
    checks++;
    if (!check(fread(got, 1, 4, f) == 4 && !memcmp(got, expected, 4),
               "read EOCD signature after scan to EOF")) return 1;
    checks++;
    if (!check(zftello(f) == 324L, "tell tracks buffered stream")) return 1;
    checks++;
    if (zfseeko(f, -4L, SEEK_CUR)) return 1;
    if (!check(zftello(f) == 320L, "SEEK_CUR tracks buffered position")) return 1;
    checks++;
    if (!check(fread(got, 1, 4, f) == 4 && !memcmp(got, expected, 4),
               "re-read signature after relative seek")) return 1;
    checks++;
    if (zfseeko(f, 0L, SEEK_END)) return 1;
    if (!check(zftello(f) == (long)sizeof(block), "SEEK_END works")) return 1;
    checks++;
    for (i = 0; i < 512; i++) {
        if (fwrite(block, 1, sizeof(block), f) != sizeof(block)) return 2;
    }
    if (zfseeko(f, 0L, SEEK_SET)) return 1;
    while ((ch = fgetc(f)) != EOF) { }
    if (zfseeko(f, 150000L, SEEK_SET)) return 1;
    if (!check(!feof(f) && fgetc(f) == 0x33,
               "seek-after-EOF beyond 64KiB")) return 1;
    checks++;
    fclose(f);
    printf("PASS: Windows Zip CRT seek contract; %d checks\n", checks);
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source = (root / "zip30" / "win32" / "win32i64.c").read_text()
    functions = [
        extract_function(source, s)
        for s in (
            "zoff_t zftello(FILE *stream)",
            "int zfseeko(FILE *stream, zoff_t offset, int origin)",
        )
    ]
    if (
        "_ftelli64(stream)" not in functions[0]
        or "_fseeki64(stream, offset, origin)" not in functions[1]
    ):
        raise RuntimeError("MinGW path must call buffered 64-bit CRT seek/tell")
    cc = shutil.which(args.cc)
    if not cc:
        raise RuntimeError("compiler not found: " + args.cc)
    with tempfile.TemporaryDirectory(prefix="xtro-zip-seek-") as td:
        inp = Path(td) / "test.c"
        out = Path(td) / "test"
        inp.write_text(PREFIX + "\n\n".join(functions) + SUFFIX)
        command = [
            cc,
            "-std=c89",
            "-pedantic",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O0",
            str(inp),
            "-o",
            str(out),
        ]
        if args.sanitize:
            command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run(command, check=True)
        subprocess.run([str(out)], check=True, timeout=15)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as ex:
        print("FAIL:", ex, file=sys.stderr)
        sys.exit(1)
