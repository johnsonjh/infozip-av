#!/usr/bin/env python3
"""Debian #1077054: real Zip Unicode names and isolated conversion-bound checks.

Requires C89 compiler.  Optional --baseline checks byte-identical archive output
against unmodified cu99.  Does not modify input files or use the network.
"""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "zip30" / "fileio.c"

HARNESS_HEAD = r"""
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <setjmp.h>
#include <stdio.h>
#include <locale.h>
#include <limits.h>
typedef unsigned long zwchar;
#define ZE_MEM 4
#define ZE_LOGIC 5
static jmp_buf recover;
static int last_error;
static int scenario;
static int conversions;
static void fake_ziperr(int err, const char *msg)
{
  (void)msg;
  last_error = err;
  longjmp(recover, 1);
}
static size_t fake_mbstowcs(wchar_t *dest, const char *src, size_t count)
{
  conversions++;
  if (dest == NULL) {
    if (scenario == 3) return ((size_t)-1) / sizeof(wchar_t);
    if (scenario == 4) return (size_t)-1;
  } else {
    if (scenario == 1) return (size_t)-1;
    if (scenario == 2) return count;  /* no room for NUL */
    if (scenario == 5) return 0;      /* inconsistent shorter result */
  }
  return mbstowcs(dest, src, count);
}
#define mbstowcs fake_mbstowcs
#define ZIPERR(e, msg) fake_ziperr((e), (msg))
"""
HARNESS_TAIL = r"""
#undef mbstowcs
#undef ZIPERR
static int try_valid(const char *s)
{
  size_t count, i;
  wchar_t *expected;
  zwchar *result;
  count = mbstowcs(NULL, s, 0);
  if (count == (size_t)-1) return 10;
  expected = (wchar_t *)malloc((count + 1) * sizeof(wchar_t));
  if (expected == NULL) return 11;
  if (mbstowcs(expected, s, count + 1) != count) return 12;
  scenario = 0;
  conversions = 0;
  result = local_to_wide_string((char *)s);
  if (result == NULL || conversions != 2) return 13;
  for (i = 0; i <= count; i++)
    if (result[i] != (zwchar)expected[i]) return 14;
  free(expected);
  free(result);
  return 0;
}
static int try_error(int which, int want)
{
  zwchar *result;
  scenario = which;
  last_error = 0;
  conversions = 0;
  if (setjmp(recover) == 0) {
    result = local_to_wide_string("name");
    if (which == 4 && result == NULL && conversions == 1) return 0;
    free(result);
    return 20 + which;
  }
  if (last_error != want) return 30 + which;
  if (which != 3 && conversions != 2) return 40 + which;
  return 0;
}
int main(void)
{
  int rc;
  if (setlocale(LC_CTYPE, "C.utf8") == NULL &&
      setlocale(LC_CTYPE, "C.UTF-8") == NULL) return 90;
  if ((rc = try_valid("")) != 0) return rc;
  if ((rc = try_valid("ASCII filename.txt")) != 0) return rc;
  if ((rc = try_valid("There\342\200\231s a Baby in the House.flac")) != 0) return rc;
  if ((rc = try_valid("\320\242\320\265\321\201\321\202.txt")) != 0) return rc;
  if ((rc = try_valid("\360\237\230\200")) != 0) return rc;
  if ((rc = try_error(1, ZE_LOGIC)) != 0) return rc;
  if ((rc = try_error(2, ZE_LOGIC)) != 0) return rc;
  if ((rc = try_error(3, ZE_MEM)) != 0) return rc;
  if ((rc = try_error(4, 0)) != 0) return rc;
  if ((rc = try_error(5, ZE_LOGIC)) != 0) return rc;
  return 0;
}
"""


def run(cmd, **kwargs):
    done = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40, **kwargs
    )
    if done.returncode:
        raise AssertionError(
            "command failed (%s): %r\nstdout=%r\nstderr=%r"
            % (done.returncode, cmd, done.stdout[-1500:], done.stderr[-1500:])
        )
    return done


def bounds_test(cc, root, sanitize):
    source = SRC.read_text()
    start = source.index("zwchar *local_to_wide_string(local_string)\n")
    end = source.index("#endif /* !WIN32 */", start)
    cfile = root / "harness.c"
    binary = root / "harness"
    cfile.write_text(HARNESS_HEAD + source[start:end] + HARNESS_TAIL)
    flags = [
        "-std=c89",
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-D_FORTIFY_SOURCE=3",
        "-Wno-deprecated-non-prototype",
    ]
    if sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    run([cc] + flags + [str(cfile), "-o", str(binary)])
    run([str(binary)])
    # Also compile/run with Clang or GCC instrumentation, when requested.
    return 10


def archives_test(zip_bin, baseline, root):
    names = [
        "plain.txt",
        "There’s a Baby in the House.flac",
        "тест.txt",
        "日本語.dat",
        "emoji-😀.txt",
        "café.txt",
        "e\u0301-composed.txt",
        "subdir/naïve-ä.txt",
        "subdir/" + ("é" * 48) + ".txt",
    ]
    work = root / "in"
    work.mkdir()
    for idx, name in enumerate(names):
        p = work / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(("payload %d\n" % idx).encode() * 2)
        os.utime(p, (1700000000, 1700000000))
    cases = [
        ("C.utf8", []),
        ("C", []),
        ("C.utf8", ["-UN=UTF8"]),
        ("C.utf8", ["-UN=Escape"]),
        ("C.utf8", ["-0"]),
        ("C.utf8", ["-r"]),
        ("C", ["-UN=UTF8"]),
    ]
    comparisons = 0
    for loc, opts in cases:
        for method, exe in [("patched", zip_bin), ("baseline", baseline)]:
            if exe is None:
                continue
            out = root / ("%s_%d.zip" % (method, cases.index((loc, opts))))
            if "-r" in opts:
                args = [str(exe), "-q", "-r"] + opts + [str(out), "subdir"]
            else:
                args = [str(exe), "-q"] + opts + [str(out)] + names
            # Reading source files updates access time, which Zip stores in
            # the UT extra field. Restore deterministic metadata for each run.
            for name in names:
                os.utime(work / name, (1700000000, 1700000000))
            os.utime(work / "subdir", (1700000000, 1700000000))
            run(args, cwd=work, env={**os.environ, "LC_ALL": loc, "LANG": loc})
            with zipfile.ZipFile(out) as z:
                members = z.infolist()
                expected = len(names) if "-r" not in opts else 3
                if len(members) != expected:
                    raise AssertionError(
                        "expected %d members, got %d" % (expected, len(members))
                    )
                for info in members:
                    if not info.is_dir() and not z.read(info.filename).startswith(
                        b"payload "
                    ):
                        raise AssertionError("unexpected member data")
                if z.testzip() is not None:
                    raise AssertionError("CRC failure")
        if baseline:
            b = (root / ("baseline_%d.zip" % cases.index((loc, opts)))).read_bytes()
            p = (root / ("patched_%d.zip" % cases.index((loc, opts)))).read_bytes()
            if p != b:
                raise AssertionError("archive difference in %r %r" % (loc, opts))
            comparisons += 1
    return len(cases), comparisons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", type=Path, default=ROOT / "zip30" / "zip")
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument(
        "--sanitize",
        action="store_true",
        help="instrument the extracted C89 conversion function",
    )
    args = ap.parse_args()
    zip_bin = args.zip.resolve()
    baseline = args.baseline.resolve() if args.baseline else None
    with tempfile.TemporaryDirectory(prefix="zip-1077054-") as td:
        root = Path(td)
        n = bounds_test(args.cc, root, args.sanitize)
        print("PASS: %d standalone C89 conversion/boundary cases" % n)
        a, c = archives_test(zip_bin, baseline, root)
        print(
            "PASS: %d normal archive scenarios, %d byte-identical baseline comparisons"
            % (a, c)
        )


if __name__ == "__main__":
    main()
