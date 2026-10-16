#!/bin/sh
# SPDX-License-Identifier: MIT-0
# Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>

set -eu

usage()
{
  cat << 'HELP'
Usage: ./build-win32.sh

Environment variables:
  MINGW_TARGET       i686-w64-mingw32 (default) or x86_64-w64-mingw32
  MINGW_CC           Cross C compiler (default: $MINGW_TARGET-gcc)
  MINGW_WINDRES      Windows resource compiler (default: $MINGW_TARGET-windres)
  MAKE               GNU make (gmake or make)
  JOBS               Parallel compile jobs (default: detected CPU count)
  WIN32_BUILD_ROOT   Output root (default: ./build-win32)
  LOCAL_ZIP          Additional Zip compiler flags
  LOCAL_UNZIP        Additional UnZip compiler flags
  EXTERNAL_ZLIB      -DUSE_ZLIB (standard static zlib), -DUSE_ZLIB_NG,
                     or -DNO_ZLIB_NG (disables automatic zlib-ng)
  WIN32_DEPS_DIR     Optional common prefix for static archives and headers
  WIN32_BZIP2_DIR    Prefix with include/bzlib.h and lib/libbz2.a
  WIN32_LZMA_DIR     Prefix with include/lzma.h and lib/liblzma.a
  WIN32_ZLIBNG_DIR   Prefix with include/zlib-ng.h and lib/libz-ng.a
  WIN32_WAVPACK_DIR  Prefix with include/wavpack/wavpack.h and lib/libwavpack.a
  WIN32_ZSTD_DIR     Prefix with include/zstd.h and lib/libzstd.a
  WIN32_ZLIB_DIR     Prefix with include/zlib.h and lib/libz.a
  WIN32_BZIP2        auto (default), on (require), off
  WIN32_LZMA         auto (default), on, off
  WIN32_ZLIBNG       auto (default), on, off
  WIN32_WAVPACK      auto (default), on, off
  WIN32_ZSTD         auto (default), on, off
  WIN32_ZLIB         auto (default), on, off (only with -DUSE_ZLIB)
  MINGW_AR           Target archiver, for static import-library detection
  MINGW_NM           Target symbol scanner, for static import-library detection
HELP
}

case "${1-}" in
-h | --help)
  usage; exit 0
  ;;
'') ;;
*)
  usage >&2; exit 2
  ;;
esac

fail()
{
  printf '%s\n' "build-win32: $*" >&2; exit 1
}

SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit 1
TARGET=${MINGW_TARGET:-i686-w64-mingw32}

case "$TARGET" in
i686-w64-mingw32 | x86_64-w64-mingw32) ;;
*) fail "unsupported MINGW_TARGET '$TARGET' (use i686-w64-mingw32 or x86_64-w64-mingw32)" ;;
esac

CC=${MINGW_CC:-${TARGET}-gcc}
RC=${MINGW_WINDRES:-${TARGET}-windres}
# MINGW_TARGET identifies the PE architecture; the compiler prefix also
# distinguishes Fedora's MSVCRT and UCRT sysroots for dependency lookup.
COMPILER_TRIPLE=${CC##*/}
COMPILER_TRIPLE=${COMPILER_TRIPLE%-gcc}

if [ -z "${MAKE:-}" ]; then
  if command -v gmake > /dev/null 2>&1; then MAKE=gmake; else MAKE=make; fi
fi

if [ -z "${JOBS:-}" ]; then
  JOBS=$(getconf _NPROCESSORS_ONLN 2> /dev/null || printf '1\n')
fi

case "$JOBS" in
'' | *[!0-9]* | 0) fail "JOBS must be a positive integer" ;;
esac

command -v "$CC" > /dev/null 2>&1 || fail "MinGW compiler '$CC' was not found"
command -v "$RC" > /dev/null 2>&1 || fail "MinGW resource compiler '$RC' was not found"
command -v "$MAKE" > /dev/null 2>&1 || fail "make '$MAKE' was not found"

# A target-specific static archive may be selected by compiler search, or
# supplied under a per-codec / common prefix. Never search host pkg-config.
REQUEST_FLAGS=" ${EXTERNAL_ZLIB:-} ${LOCAL_ZIP:-} ${LOCAL_UNZIP:-} "
case "$REQUEST_FLAGS" in
*' -DUSE_ZLIB_NG '* | *' -DUSE_ZLIB_NG='*) REQUEST_ZNG=yes ;;
*) REQUEST_ZNG=no ;;
esac
case "$REQUEST_FLAGS" in
*' -DUSE_ZLIB '* | *' -DUSE_ZLIB='*) REQUEST_ZLIB=yes ;;
*) REQUEST_ZLIB=no ;;
esac
case "$REQUEST_FLAGS" in
*' -DNO_ZLIB_NG '* | *' -DNO_ZLIB_NG='*) BLOCK_ZNG=yes ;;
*) BLOCK_ZNG=no ;;
esac
if [ "$REQUEST_ZNG" = yes ] && {
  [ "$REQUEST_ZLIB" = yes ] || [ "$BLOCK_ZNG" = yes ]
}; then
  fail 'conflicting EXTERNAL_ZLIB / LOCAL_* backend selections'
fi
if [ "$REQUEST_ZLIB" = yes ] && [ "${WIN32_ZLIBNG:-auto}" = on ]; then
  fail 'explicit zlib-ng conflicts with -DUSE_ZLIB'
fi
if [ "$REQUEST_ZNG" = yes ] && [ "${WIN32_ZLIBNG:-auto}" = off ]; then
  fail '-DUSE_ZLIB_NG conflicts with WIN32_ZLIBNG=off'
fi
if [ "$REQUEST_ZLIB" = yes ] && [ "${WIN32_ZLIB:-auto}" = off ]; then
  fail '-DUSE_ZLIB conflicts with WIN32_ZLIB=off'
fi

# A C compiler from the host can otherwise silently build Linux executables
# and a successful make/copy phase would incorrectly report a Windows build.

OUT_ROOT=${WIN32_BUILD_ROOT:-"${SOURCE_ROOT}/build-win32"}
mkdir -p "$OUT_ROOT/$TARGET"

OUT_ROOT=$(CDPATH= cd -- "$OUT_ROOT" && pwd -P) || fail "invalid output directory"
STAGE=$(mktemp -d "$OUT_ROOT/$TARGET/.stage.XXXXXXXX") || fail 'unable to create build stage'

cleanup()
{
  if [ "${KEEP_WIN32_STAGE:-0}" = 1 ]; then
    printf 'build-win32: retained source stage: %s\n' "$STAGE" >&2
  else
    rm -rf -- "$STAGE"
  fi
}

trap cleanup 0
trap 'exit 1' 1 2 3 15

cat > "$STAGE/toolchain.c" << 'PROBE'
#ifndef _WIN32
#error Not a Windows-target compiler
#endif
#include <windows.h>
int main(void) { return (int)(sizeof(DWORD) != 4); }
PROBE

if ! "$CC" -std=gnu89 "$STAGE/toolchain.c" -o "$STAGE/toolchain.exe"; then
  fail "'$CC' cannot compile and link a basic Windows executable"
fi

if [ ! -f "$STAGE/toolchain.exe" ]; then
  fail "'$CC' did not produce a Windows executable"
fi

# Discover and verify static libraries before copying source trees. Explicit
# directories have precedence. Empty common prefixes are not errors, but a
# requested codec or a per-codec directory that cannot link is an error.
# No path with whitespace can be passed reliably via the historical makefiles.
for var in WIN32_DEPS_DIR WIN32_BZIP2_DIR WIN32_LZMA_DIR WIN32_ZLIBNG_DIR WIN32_ZLIB_DIR WIN32_ZSTD_DIR WIN32_WAVPACK_DIR; do
  eval 'val=${'"$var"'-}'
  case "$val" in
  *' '* | *'	'* | *'
'*) fail "$var contains whitespace; use a path without whitespace" ;;
  esac
done

AR=${MINGW_AR:-${CC%-gcc}-ar}
NM=${MINGW_NM:-${CC%-gcc}-nm}
if ! command -v "$AR" > /dev/null 2>&1; then
  [ -z "${MINGW_AR:-}" ] || fail "MINGW_AR '$AR' was not found"
  AR=ar
fi
if ! command -v "$NM" > /dev/null 2>&1; then
  [ -z "${MINGW_NM:-}" ] || fail "MINGW_NM '$NM' was not found"
  NM=nm
fi
command -v "$AR" > /dev/null 2>&1 || fail "missing archiver '$AR'"
command -v "$NM" > /dev/null 2>&1 || fail "missing symbol scanner '$NM'"

# Set: LIBPATH, INCLUDE_FLAGS, EXPLICIT_PREFIX, and FOUND_ARCHIVE.
find_static_library()
{
  codec=$1
  header=$2
  archive=$3
  var=$4
  eval 'prefix=${'"$var"'-}'
  EXPLICIT_PREFIX=no
  FOUND_ARCHIVE=
  INCLUDE_FLAGS=
  LIBPATH=
  if [ -n "$prefix" ]; then
    EXPLICIT_PREFIX=yes
    roots="$prefix"
  elif [ -n "${WIN32_DEPS_DIR:-}" ]; then
    # Never search the MSVCRT target subtree for a distinct UCRT compiler.
    # The caller may still provide a common prefix explicitly for a build.
    roots="${WIN32_DEPS_DIR}/$COMPILER_TRIPLE/$codec ${WIN32_DEPS_DIR}/$COMPILER_TRIPLE ${WIN32_DEPS_DIR}/$codec ${WIN32_DEPS_DIR}"
  else
    roots=
  fi
  for base in $roots; do
    for inc in "$base/include" "$base" "$base/../include"; do
      [ -f "$inc/$header" ] || continue
      for dir in "$base/lib" "$base/lib64" "$base" "$base/lib/$TARGET"; do
        [ -f "$dir/$archive" ] || continue
        absdir=$(CDPATH= cd -- "$dir" && pwd -P) || return 1
        absinc=$(CDPATH= cd -- "$inc" && pwd -P) || return 1
        FOUND_ARCHIVE="$absdir/$archive"
        INCLUDE_FLAGS="-I$absinc"
        LIBPATH=$FOUND_ARCHIVE
        return 0
      done
    done
  done
  # Fallback to compiler search paths only when no per-library prefix given.
  if [ "$EXPLICIT_PREFIX" = no ]; then
    candidate=$("$CC" -print-file-name="$archive" 2> /dev/null || :)
    if [ -f "$candidate" ] && [ "$candidate" != "$archive" ]; then
      # Check the header via the target compiler itself. Never search
      # host /usr/include for native Windows dependencies.
      absdir=$(CDPATH= cd -- "$(dirname -- "$candidate")" && pwd -P) || return 1
      FOUND_ARCHIVE="$absdir/$archive"
      LIBPATH=$FOUND_ARCHIVE
    fi
  fi
}

# Reject archive-shaped import libraries (a renamed *.dll.a would otherwise
# pass GCC's link test). PE import archives define __IMPORT_DESCRIPTOR_<dll>.
check_real_archive()
{
  [ -f "$1" ] || return 1
  "$AR" t "$1" > "$STAGE/ar-list" 2> /dev/null || return 1
  [ -s "$STAGE/ar-list" ] || return 1
  # GNU and LLVM import archives normally define import descriptors. The
  # check is intentionally conservative: unknown/malformed objects fail.
  "$NM" -g "$1" > "$STAGE/nm-list" 2> /dev/null || return 1
  if grep -E '__IMPORT_DESCRIPTOR_|__NULL_IMPORT_DESCRIPTOR|_head_[A-Za-z0-9_]+_dll' "$STAGE/nm-list" > /dev/null; then
    return 1
  fi
  return 0
}

# The probe's selected header must compile against the selected target and
# all required (including transitive) external symbols must resolve.
probe_codec()
{
  "${CC}" -std=gnu89 $INCLUDE_FLAGS "$STAGE/probe-$1.c" "$LIBPATH" -lm -o "$STAGE/probe-$1.exe" > "$STAGE/probe-$1.log" 2>&1
}

cat > "$STAGE/probe-bzip2.c" << 'PROBE'
#include <bzlib.h>
int main(void) { bz_stream s = {0}; int r = BZ2_bzCompressInit(&s, 1, 0, 30); if (r == BZ_OK) BZ2_bzCompressEnd(&s); return BZ2_bzlibVersion() == 0; }
PROBE
cat > "$STAGE/probe-lzma.c" << 'PROBE'
#include <lzma.h>
int main(void) { lzma_stream s = LZMA_STREAM_INIT; lzma_ret r = lzma_easy_encoder(&s, 1, LZMA_CHECK_NONE); if (r == LZMA_OK) lzma_end(&s); return lzma_version_number() == 0; }
PROBE
cat > "$STAGE/probe-zlibng.c" << 'PROBE'
#include <zlib-ng.h>
int main(void) { zng_stream s = {0}; int r = zng_deflateInit2(&s, 1, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY); if (r == Z_OK) zng_deflateEnd(&s); return (int)zng_crc32_z(0, 0, 0); }
PROBE
cat > "$STAGE/probe-zlib.c" << 'PROBE'
#include <zlib.h>
int main(void) { z_stream s = {0}; int r = deflateInit2(&s, 1, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY); if (r == Z_OK) deflateEnd(&s); return (int)crc32(0, Z_NULL, 0); }
PROBE
cat > "$STAGE/probe-wavpack.c" << 'PROBE'
#include <wavpack/wavpack.h>
int main(void) { WavpackContext *c = WavpackOpenFileInputEx64(0,0,0,0,0,0); if(c) WavpackCloseFile(c); return WavpackGetLibraryVersion() == 0; }
PROBE
cat > "$STAGE/probe-zstd.c" << 'PROBE'
#include <zstd.h>
int main(void) { ZSTD_CStream *c = ZSTD_createCStream(); ZSTD_DStream *d = ZSTD_createDStream(); ZSTD_freeCStream(c); ZSTD_freeDStream(d); return ZSTD_versionNumber() == 0; }
PROBE

WIN_STATIC_LIBS=
ZIP_INC=
UNZIP_INC=
WIN_ZIPOPT_CPPFLAGS=
WIN_ZNG_LIBS=
WIN_ZLIB_LIBS=
ZOPT_BACKEND=
ZIP_FEATURES=
UZ_FEATURES=

check_codec()
{
  name=$1
  header=$2
  archive=$3
  switch=$4
  prefixvar=$5
  eval 'mode=${'"$switch"':-auto}'
  case "$mode" in auto | on | off) ;; *) fail "$switch must be auto, on or off" ;; esac
  ENABLED=no
  [ "$mode" != off ] || return 0
  find_static_library "$name" "$header" "$archive" "$prefixvar"
  if [ -n "$LIBPATH" ] && check_real_archive "$LIBPATH" && probe_codec "$name"; then
    ENABLED=yes
    printf 'build-win32: static %s: %s\n' "$name" "$LIBPATH"
    case "$name" in
    bzip2)
      ZIP_FEATURES="$ZIP_FEATURES -DBZIP2_SUPPORT"
      UZ_FEATURES="$UZ_FEATURES -DUSE_BZIP2"
      WIN_ZIPOPT_CPPFLAGS="$WIN_ZIPOPT_CPPFLAGS -DZO_WITH_BZIP2"
      ;;
    lzma)
      ZIP_FEATURES="$ZIP_FEATURES -DLZMA_SUPPORT"
      UZ_FEATURES="$UZ_FEATURES -DUSE_LZMA -DUSE_XZ"
      WIN_ZIPOPT_CPPFLAGS="$WIN_ZIPOPT_CPPFLAGS -DZO_WITH_LZMA"
      ;;
    zstd)
      ZIP_FEATURES="$ZIP_FEATURES -DZSTD_SUPPORT"
      UZ_FEATURES="$UZ_FEATURES -DUSE_ZSTD"
      WIN_ZIPOPT_CPPFLAGS="$WIN_ZIPOPT_CPPFLAGS -DZO_WITH_ZSTD"
      ;;
    wavpack)
      UZ_FEATURES="$UZ_FEATURES -DUSE_WAVP"
      ;;
    zlibng)
      ZIP_FEATURES="$ZIP_FEATURES -DUSE_ZLIB_NG"
      UZ_FEATURES="$UZ_FEATURES -DUSE_ZLIB_NG"
      ZOPT_BACKEND=-DZO_USE_ZLIB_NG
      WIN_ZNG_LIBS=$LIBPATH
      ;;
    zlib)
      ZIP_FEATURES="$ZIP_FEATURES -DUSE_ZLIB"
      UZ_FEATURES="$UZ_FEATURES -DUSE_ZLIB"
      WIN_ZLIB_LIBS=$LIBPATH
      ZOPT_BACKEND=-DZO_USE_ZLIB
      ;;
    esac
    # zlib(-ng) needs unique link order, not duplicating in the other libs.
    case "$name" in zlibng | zlib) ;; *) WIN_STATIC_LIBS="$WIN_STATIC_LIBS $LIBPATH" ;; esac
    ZIP_INC="$ZIP_INC $INCLUDE_FLAGS"
    UNZIP_INC="$UNZIP_INC $INCLUDE_FLAGS"
  else
    if [ "$mode" = on ] || [ "$EXPLICIT_PREFIX" = yes ]; then
      fail "static $name requested but its $archive and headers did not pass the target link probe (see $STAGE/probe-$name.log; KEEP_WIN32_STAGE=1 to inspect)"
    fi
    printf 'build-win32: static %s unavailable; disabled\n' "$name"
  fi
}

check_codec bzip2 bzlib.h libbz2.a WIN32_BZIP2 WIN32_BZIP2_DIR
check_codec lzma lzma.h liblzma.a WIN32_LZMA WIN32_LZMA_DIR
check_codec zstd zstd.h libzstd.a WIN32_ZSTD WIN32_ZSTD_DIR
check_codec wavpack wavpack/wavpack.h libwavpack.a WIN32_WAVPACK WIN32_WAVPACK_DIR

if [ "$REQUEST_ZLIB" = yes ]; then
  check_codec zlib zlib.h libz.a WIN32_ZLIB WIN32_ZLIB_DIR
  [ "$ENABLED" = yes ] || fail 'standard zlib explicitly requested but no static target library found'
else
  # Native zlib-ng is the default external backend when available. Explicit
  # NO_ZLIB_NG forces the bundled internal Deflate path.
  if [ "$BLOCK_ZNG" = yes ]; then
    [ "${WIN32_ZLIBNG:-auto}" != on ] || fail 'WIN32_ZLIBNG=on conflicts with -DNO_ZLIB_NG'
    printf 'build-win32: zlib-ng disabled by NO_ZLIB_NG\n'
  else
    if [ "$REQUEST_ZNG" = yes ]; then WIN32_ZLIBNG=on; fi
    check_codec zlibng zlib-ng.h libz-ng.a WIN32_ZLIBNG WIN32_ZLIBNG_DIR
    [ "$REQUEST_ZNG" = no ] || [ "$ENABLED" = yes ] || fail 'native zlib-ng requested but static target library unavailable'
  fi
fi

# The MinGW SFX rules suppress LZMA, BZip2, WavPack and Zstd by default;
# pass those feature macros to all normal source objects, never enable DLLs.
ZIP_FLAGS="${LOCAL_ZIP:-} ${EXTERNAL_ZLIB:-} $ZIP_FEATURES $ZIP_INC -std=gnu89"
UNZIP_FLAGS="${LOCAL_UNZIP:-} ${EXTERNAL_ZLIB:-} $UZ_FEATURES $UNZIP_INC -std=gnu89"

# The legacy Windows makefiles put objects next to sources. Copying the two
# component trees prevents reuse of Unix, Win32 or Win64 objects and leaves
# build.sh and its outputs untouched. Each run gets its own staging directory.

mkdir -p "$STAGE/src" "$STAGE/bin"
cp -R "$SOURCE_ROOT/zip30" "$STAGE/src/zip30"
cp -R "$SOURCE_ROOT/unzip60" "$STAGE/src/unzip60"
cp -R "$SOURCE_ROOT/zipopt" "$STAGE/src/zipopt"
cp -R "$SOURCE_ROOT/zipdedup" "$STAGE/src/zipdedup"
# ZipOpt and ZipDedup compile Xtro's portable metadata core from the
# staged source tree.  Keep this sibling directory alongside both tools.
sh "$SOURCE_ROOT/xtrmeta/stage-cross.sh" \
  "$SOURCE_ROOT/xtrmeta" "$STAGE/src/xtrmeta"
# The portable stage-cross subset intentionally excludes native Windows code.
# When either Zip or UnZip enables XTR_WIN_NATIVE, stage the complete native
# dependency closure.  Zip's --streams writer needs the mixed EA/ADS module
# plus the native enumerator, stream reader and record builder.  Do not stage
# these files into ordinary (feature-disabled) cross builds.
case " $ZIP_FLAGS $UNZIP_FLAGS " in
*' -DXTR_WIN_NATIVE '*)
  for name in xtrwin_ea.c xtrwin_ea.h xtrwin_txn.c xtrwin_txn.h \
              xtrwin_nt.c xtrwin_nt.h xtrwin_nt_abi.h \
              xtrwin_mixed.c xtrwin_mixed.h \
              xtrwin_ads.c xtrwin_ads.h \
              xtrwin_ads_native.c xtrwin_ads_native.h \
              xtrwin_ads_stream.c xtrwin_ads_stream.h \
              xtrwin_ads_record.c xtrwin_ads_record.h \
              xtrwin_ads_write.c xtrwin_ads_write.h \
              xtrwin_mixed_verify.c xtrwin_mixed_verify.h \
              xtrwin_restore_plan.c xtrwin_restore_plan.h \
              xtrwin_ads_txn.c xtrwin_ads_txn.h \
              xtrwin_ads_restore.c xtrwin_ads_restore.h \
              xtrwin_utf8path.c xtrwin_utf8path.h \
              xtrwin_utf8argv.c xtrwin_utf8argv.h; do
    test -f "$SOURCE_ROOT/xtrmeta/$name" || \
      fail "missing Windows native metadata source $name"
    cp "$SOURCE_ROOT/xtrmeta/$name" "$STAGE/src/xtrmeta/$name"
  done
  ;;
esac
# Private Windows object subdirectories are built afresh for each CRT/arch.
rm -rf "$STAGE/src/zipopt/winbuild" "$STAGE/src/zipdedup/winbuild"

# The source tree may already contain ELF or old MinGW objects from a prior
# build. No object or executable from it may be reused across toolchains.

rm -f "$STAGE/src/zip30/"*.o "$STAGE/src/zip30/"*.obj \
  "$STAGE/src/zip30/"*.exe "$STAGE/src/unzip60/"*.o \
  "$STAGE/src/unzip60/"*.obj "$STAGE/src/unzip60/"*.exe

if [ "$REQUEST_ZLIB" = yes ]; then
  set -- USEZLIB=1
else
  set --
fi

printf 'build-win32: building %s with %s\n' "$TARGET" "$CC"

(
  cd "$STAGE/src/zip30"
  "$MAKE" -j "$JOBS" -f win32/makefile.gcc zips \
    CC="$CC" RC="$RC" NOASM=1 LOCAL_ZIP="$ZIP_FLAGS" \
    WIN_STATIC_LIBS="$WIN_STATIC_LIBS $WIN_ZNG_LIBS" WIN_ZLIB_LIBS="$WIN_ZLIB_LIBS" "$@"
)

(
  cd "$STAGE/src/unzip60"
  "$MAKE" -j "$JOBS" -f win32/Makefile.gcc unzips \
    CC="$CC" RC="$RC" NOASM=1 CC_CPU_OPT=-mtune=generic \
    LOCAL_UNZIP="$UNZIP_FLAGS" \
    WIN_STATIC_LIBS="$WIN_STATIC_LIBS $WIN_ZNG_LIBS" WIN_ZLIB_LIBS="$WIN_ZLIB_LIBS" "$@"
)

# Build the standalone utilities against separate Win32 UnZip API objects.
# These builds deliberately do not use Unix .pic objects or host libraries.
(
  cd "$STAGE/src/zipopt"
  "$MAKE" -j "$JOBS" -f Makefile.win32 all \
    CC="$CC" LOCAL_ZIP="$ZIP_FLAGS" LOCAL_UNZIP="$UNZIP_FLAGS" \
    WIN_UNZIP_CPPFLAGS="" WIN_CODEC_CPPFLAGS="$WIN_ZIPOPT_CPPFLAGS" \
    WIN_ZNG_CPPFLAGS="$ZOPT_BACKEND $UNZIP_INC" \
    WIN_STATIC_LIBS="$WIN_STATIC_LIBS" WIN_ZNG_LIBS="$WIN_ZNG_LIBS $WIN_ZLIB_LIBS" \
    LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}"
)
(
  cd "$STAGE/src/zipdedup"
  "$MAKE" -j "$JOBS" -f Makefile.win32 all \
    CC="$CC" LOCAL_UNZIP="$UNZIP_FLAGS" \
    WIN_UNZIP_CPPFLAGS="" \
    WIN_STATIC_LIBS="$WIN_STATIC_LIBS" WIN_ZNG_LIBS="$WIN_ZNG_LIBS $WIN_ZLIB_LIBS" \
    LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}"
)

# Publish only after all builds finish. Do not publish partial results.
for name in zip zipcloak zipnote zipsplit; do
  test -f "$STAGE/src/zip30/$name.exe" || fail "missing $name.exe"
  cp "$STAGE/src/zip30/$name.exe" "$STAGE/bin/$name.exe"
done

for name in unzip funzip unzipsfx; do
  test -f "$STAGE/src/unzip60/$name.exe" || fail "missing $name.exe"
  cp "$STAGE/src/unzip60/$name.exe" "$STAGE/bin/$name.exe"
done
for name in zipopt zipopt-preflight zipopt-decodecheck; do
  test -f "$STAGE/src/zipopt/$name.exe" || fail "missing $name.exe"
  cp "$STAGE/src/zipopt/$name.exe" "$STAGE/bin/$name.exe"
done
test -f "$STAGE/src/zipdedup/zipdedup.exe" || fail 'missing zipdedup.exe'
cp "$STAGE/src/zipdedup/zipdedup.exe" "$STAGE/bin/zipdedup.exe"
test -f "$STAGE/src/zipopt/crc-accel-test.exe" || fail 'missing crc-accel-test.exe'

OUTPUT="$OUT_ROOT/$TARGET/bin"
mkdir -p "$OUTPUT" "$OUT_ROOT/$TARGET/tests"

for name in zip zipcloak zipnote zipsplit unzip funzip unzipsfx zipopt zipdedup zipopt-preflight zipopt-decodecheck; do
  cp "$STAGE/bin/$name.exe" "$OUTPUT/$name.exe"
done

cp "$STAGE/src/zipopt/crc-accel-test.exe" "$OUT_ROOT/$TARGET/tests/crc-accel-test.exe"
printf 'build-win32: built eleven native Windows binaries in %s\n' "$OUTPUT"
printf 'build-win32: CRC A/B test: %s\n' "$OUT_ROOT/$TARGET/tests/crc-accel-test.exe"
