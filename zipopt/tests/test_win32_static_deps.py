#!/usr/bin/env python3
"""Mock-toolchain regression of build-win32.sh static-dependency selection.

No MinGW or Windows runtime is required. The compiler and make are mocked;
archive validation uses the real host ar/nm. This does NOT test PE linking.
"""

import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(*args, cwd=None):
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def put(path, value):
    path.write_text(value)
    path.chmod(0o755)


def test():
    for exe in ("ar", "nm", "cc"):
        if shutil.which(exe) is None:
            print("SKIP: missing " + exe)
            return
    with tempfile.TemporaryDirectory(prefix="iz-staticdeps-") as tmp:
        p = pathlib.Path(tmp)
        cc = p / "mock-cc"
        mk = p / "mock-make"
        rc = p / "mock-windres"
        log = p / "args.log"
        put(
            cc,
            """#!/bin/sh
case "$1" in -print-file-name=*) exit 0 ;; esac
out=
printf 'compiler %s\\n' "$*" >> "$IZ_TEST_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then shift; out=$1; break; fi
  case "$1" in -o?*) out=${1#-o}; break;; esac
  shift
done
[ -z "$out" ] || : > "$out"
""",
        )
        put(
            mk,
            """#!/bin/sh
printf 'make %s %s\\n' "$PWD" "$*" >> "$IZ_TEST_LOG"
case "$PWD" in
*/zip30) set -- zip zipcloak zipnote zipsplit ;;
*/unzip60) set -- unzip funzip unzipsfx ;;
*/zipopt) set -- zipopt zipopt-preflight zipopt-decodecheck crc-accel-test ;;
*/zipdedup) set -- zipdedup ;;
*) exit 77;;
esac
for exe in "$@"; do : > "$exe.exe"; done
""",
        )
        put(rc, "#!/bin/sh\nexit 0\n")
        (p / "obj.c").write_text("int mocklib(void) { return 1; }\n")
        run("cc", "-c", str(p / "obj.c"), "-o", str(p / "obj.o"))

        def lib(name, header, archive):
            prefix = p / "deps" / name
            (prefix / "include" / pathlib.Path(header).parent).mkdir(
                parents=True, exist_ok=True
            )
            (prefix / "lib").mkdir(parents=True, exist_ok=True)
            (prefix / "include" / header).write_text("/* test header */\n")
            run("ar", "rcs", str(prefix / "lib" / archive), str(p / "obj.o"))
            return prefix

        def invoke(extra, success=True):
            log.write_text("")
            env = os.environ.copy()
            env.update(
                {
                    "MINGW_CC": str(cc),
                    "MINGW_WINDRES": str(rc),
                    "MAKE": str(mk),
                    "JOBS": "1",
                    "IZ_TEST_LOG": str(log),
                    "WIN32_BUILD_ROOT": str(p / "output"),
                    "WIN32_BZIP2": "off",
                    "WIN32_LZMA": "off",
                    "WIN32_ZSTD": "off",
                    "WIN32_WAVPACK": "off",
                    "WIN32_ZLIBNG": "off",
                }
            )
            env.update(extra)
            proc = subprocess.run(
                [str(ROOT / "build-win32.sh")],
                env=env,
                cwd=p,
                capture_output=True,
                text=True,
            )
            if (proc.returncode == 0) != success:
                raise AssertionError((proc.returncode, proc.stdout, proc.stderr))
            return proc.stdout + proc.stderr, log.read_text()

        out, logtext = invoke({})
        assert "built eleven" in out
        assert "-DUSE_BZIP2" not in logtext
        assert "-DZO_WITH_BZIP2" not in logtext

        bz = lib("bzip2", "bzlib.h", "libbz2.a")
        lz = lib("lzma", "lzma.h", "liblzma.a")
        zw = lib("zlibng", "zlib-ng.h", "libz-ng.a")
        wp = lib("wavpack", "wavpack/wavpack.h", "libwavpack.a")
        out, logtext = invoke(
            {
                "WIN32_DEPS_DIR": str(p / "deps"),
                "WIN32_BZIP2": "auto",
                "WIN32_LZMA": "auto",
                "WIN32_ZLIBNG": "auto",
                "WIN32_WAVPACK": "auto",
            }
        )
        for expected in (
            "static bzip2:",
            "static lzma:",
            "static wavpack:",
            "static zlibng:",
        ):
            assert expected in out, (expected, out)
        for expected in (
            "-DBZIP2_SUPPORT",
            "-DUSE_BZIP2",
            "-DLZMA_SUPPORT",
            "-DUSE_LZMA",
            "-DUSE_XZ",
            "-DUSE_WAVP",
            "-DZO_WITH_LZMA",
            "-DZO_WITH_BZIP2",
            "-DZO_USE_ZLIB_NG",
            "-DUSE_ZLIB_NG",
        ):
            assert expected in logtext, (expected, logtext)
        assert "libz-ng.a" in logtext
        assert "libwavpack.a" in logtext

        out, logtext = invoke({"WIN32_BZIP2": "on"}, success=False)
        assert "static bzip2 requested" in out
        out, logtext = invoke({"WIN32_BZIP2_DIR": str(bz), "WIN32_BZIP2": "auto"})
        assert "static bzip2:" in out
        out, logtext = invoke(
            {"WIN32_BZIP2_DIR": str(p / "no-such-prefix"), "WIN32_BZIP2": "auto"},
            success=False,
        )
        assert "static bzip2 requested" in out

        zlib = lib("zlib", "zlib.h", "libz.a")
        out, logtext = invoke(
            {"EXTERNAL_ZLIB": "-DUSE_ZLIB", "WIN32_ZLIB_DIR": str(zlib)}
        )
        assert "static zlib:" in out
        assert "USEZLIB=1" in logtext
        assert "-DZO_USE_ZLIB" in logtext
        out, logtext = invoke(
            {"EXTERNAL_ZLIB": "-DUSE_ZLIB -DUSE_ZLIB_NG"}, success=False
        )
        assert "conflicting" in out

        # A DLL import archive can have the *same filename* as a static lib.
        (p / "bad.c").write_text("int __IMPORT_DESCRIPTOR_fake = 1;\n")
        run("cc", "-c", str(p / "bad.c"), "-o", str(p / "bad.o"))
        run("ar", "rcs", str(bz / "lib" / "libbz2.a"), str(p / "bad.o"))
        out, logtext = invoke(
            {"WIN32_BZIP2_DIR": str(bz), "WIN32_BZIP2": "auto"}, success=False
        )
        assert "static bzip2 requested" in out

        # Relative paths are made absolute before make changes directories.
        out, logtext = invoke(
            {"WIN32_LZMA": "on", "WIN32_LZMA_DIR": os.path.relpath(lz, p)}
        )
        assert str(lz) in logtext

        # The target CPU triple is *not* enough to identify UCRT: do not
        # search an x86_64-w64-mingw32 MSVCRT subtree for a ucrt-gcc build.
        ucrtcc = p / "x86_64-w64-mingw32ucrt-gcc"
        shutil.copy(cc, ucrtcc)
        ucrtcc.chmod(0o755)
        crtdeps = p / "crt-deps"
        ucrtlib = crtdeps / "x86_64-w64-mingw32ucrt" / "lzma"
        crtlib = crtdeps / "x86_64-w64-mingw32" / "lzma"
        for q in (ucrtlib, crtlib):
            (q / "include").mkdir(parents=True, exist_ok=True)
            (q / "lib").mkdir(parents=True, exist_ok=True)
            (q / "include" / "lzma.h").write_text("/* test header */\n")
            run("ar", "rcs", str(q / "lib" / "liblzma.a"), str(p / "obj.o"))
        out, logtext = invoke(
            {
                "MINGW_CC": str(ucrtcc),
                "MINGW_TARGET": "x86_64-w64-mingw32",
                "WIN32_DEPS_DIR": str(crtdeps),
                "WIN32_LZMA": "on",
            }
        )
        assert str(ucrtlib) in out
        assert str(crtlib) not in out
        print(
            "PASS: Windows static-dependency selection, isolation, "
            "overrides, and import-library rejection"
        )


if __name__ == "__main__":
    test()
