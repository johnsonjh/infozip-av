#!/usr/bin/env python3
"""Check that build-win32.sh stages all Win32 native source modules.

This uses a deliberately fake toolchain. It validates staging only; it does
not claim a MinGW compile or a native Windows runtime result. MIT-0.
"""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    "xtrwin_ea.c",
    "xtrwin_ea.h",
    "xtrwin_txn.c",
    "xtrwin_txn.h",
    "xtrwin_nt.c",
    "xtrwin_nt.h",
    "xtrwin_nt_abi.h",
    "xtrwin_mixed.c",
    "xtrwin_mixed.h",
    "xtrwin_ads.c",
    "xtrwin_ads.h",
    "xtrwin_ads_native.c",
    "xtrwin_ads_native.h",
    "xtrwin_ads_stream.c",
    "xtrwin_ads_stream.h",
    "xtrwin_ads_record.c",
    "xtrwin_ads_record.h",
    "xtrwin_ads_write.c",
    "xtrwin_ads_write.h",
    "xtrwin_mixed_verify.c",
    "xtrwin_mixed_verify.h",
    "xtrwin_restore_plan.c",
    "xtrwin_restore_plan.h",
    "xtrwin_ads_txn.c",
    "xtrwin_ads_txn.h",
    "xtrwin_ads_restore.c",
    "xtrwin_ads_restore.h",
    "xtrwin_utf8path.c",
    "xtrwin_utf8path.h",
    "xtrwin_utf8argv.c",
    "xtrwin_utf8argv.h",
)


def executable(path, data):
    path.write_text(data, encoding="ascii")
    path.chmod(0o755)


def test():
    with tempfile.TemporaryDirectory(prefix="xtro-w3c2-stage-") as scratch:
        tmp = Path(scratch)
        cc = tmp / "cc-mock"
        executable(
            cc,
            '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n'
            ' if [ "$1" = "-o" ]; then shift; : > "$1"; exit 0; fi\n'
            " shift\ndone\nexit 0\n",
        )
        windres = tmp / "windres-mock"
        executable(windres, "#!/bin/sh\nexit 0\n")
        make = tmp / "make-mock"
        sources = " ".join(REQUIRED)
        executable(
            make,
            "#!/bin/sh\nset -eu\n"
            'case "$(pwd)" in */src/zip30) ;; *) exit 91 ;; esac\n'
            "for src in " + sources + "; do\n"
            ' test -s "../xtrmeta/$src" || '
            '{ echo "STAGING MISSING $src" >&2; exit 88; }\n'
            'done\necho "STAGING_CHECK_PASS"\nexit 77\n',
        )
        env = dict(os.environ)
        env.update(
            MINGW_TARGET="x86_64-w64-mingw32",
            MINGW_CC=str(cc),
            MINGW_WINDRES=str(windres),
            MAKE=str(make),
            JOBS="1",
            WIN32_BUILD_ROOT=str(tmp / "output"),
            LOCAL_ZIP="-DXTR_WIN_NATIVE",
            LOCAL_UNZIP="-DXTR_WIN_NATIVE -DXTR_WIN_UTF8_PATHS",
            WIN32_BZIP2="off",
            WIN32_LZMA="off",
            WIN32_WAVPACK="off",
            WIN32_ZSTD="off",
            WIN32_ZLIBNG="off",
            WIN32_ZLIB="off",
        )
        p = subprocess.run(
            ["sh", str(ROOT / "build-win32.sh")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        if p.returncode != 77 or "STAGING_CHECK_PASS" not in p.stdout:
            raise RuntimeError(
                "Win32 staging failed: rc=%d\n%s\n%s"
                % (p.returncode, p.stdout, p.stderr)
            )
    print("PASS: W3C2 Windows native staging; %d required files" % len(REQUIRED))


if __name__ == "__main__":
    test()
