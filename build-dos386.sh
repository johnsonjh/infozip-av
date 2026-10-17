#!/bin/sh
# SPDX-License-Identifier: MIT-0
# Cross-build the standalone 32-bit protected-mode DOS command-line tools.
set -eu

usage()
{
  cat << 'HELP'
Usage: ./build-dos386.sh

Environment:
  DJGPP_CC             Cross compiler (default: /opt/djgpp/bin/i586-pc-msdosdjgpp-gcc
                       if installed, otherwise i586-pc-msdosdjgpp-gcc from PATH)
  DJGPP_MAKE           GNU make (default: gmake or make)
  DJGPP_JOBS           Parallel compilation jobs (default: detected CPU count)
  DOS386_BUILD_ROOT    Output root (default: ./build-dos386)
  DOS386_CFLAGS        Additional DOS compiler flags (default: none)
  DOS386_LDFLAGS       Additional DOS linker flags (default: none)
  DOS386_BZIP2         auto (default), on (require), off
  DOS386_LZMA          auto (default), on (require), off
  DOS386_WAVPACK       auto (default), on (require), off
  DOS386_ZSTD          auto (default), on (require), off
  DOS386_BZIP2_DIR     Prefix containing bzlib.h and libbz2.a
                       (default: build-dos386/bzip2)
  DOS386_LZMA_DIR      Prefix with include/lzma.h and lib/liblzma.a
                       (default: build-dos386/lzma/install)
  DOS386_WAVPACK_DIR   Prefix with include/wavpack/wavpack.h and lib/libwavpack.a
                       (default: build-dos386/wavpack/install)
  DOS386_ZSTD_DIR      Prefix with include/zstd.h and lib/libzstd.a
                       (default: build-dos386/zstd/install)
  DOS386_CWSDSTUB      DPMI stub (default: /opt/cwsdpmi/cwsdstub.exe)
  DOS386_EXE2COFF      Path to host exe2coff utility (optional override)
  DOS386_EMBED_STUB    auto (default), on, or off; auto embeds when stub exists
  KEEP_DOS386_STAGE=1  Retain the temporary source tree for debugging

Bundled codecs and CRC are always available. BZip2, LZMA/XZ, WavPack, and Zstd
are selected independently after target link probes; no x86 assembly.
funzip and unzipsfx remain self-contained. Generates zip, zipcloak, zipnote, zipsplit,
unzip, funzip, unzipsfx, zipopt, zipopt-preflight, zipopt-decodecheck and zipdedup.
HELP
}
fail()
{
  printf 'build-dos386: %s\n' "$*" >&2; exit 1
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
SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit 1
if [ -n "${DJGPP_CC:-}" ]; then
  CC=$DJGPP_CC
elif [ -x /opt/djgpp/bin/i586-pc-msdosdjgpp-gcc ]; then
  CC=/opt/djgpp/bin/i586-pc-msdosdjgpp-gcc
else
  CC=i586-pc-msdosdjgpp-gcc
fi
if [ -n "${DJGPP_MAKE:-}" ]; then
  MAKE=$DJGPP_MAKE
elif command -v gmake > /dev/null 2>&1; then
  MAKE=gmake
else
  MAKE=make
fi
if [ -n "${DJGPP_JOBS:-}" ]; then
  JOBS=$DJGPP_JOBS
else
  JOBS=$(getconf _NPROCESSORS_ONLN 2> /dev/null || printf '1\n')
fi
case "$JOBS" in
'' | *[!0-9]* | 0) fail 'DJGPP_JOBS must be a positive integer' ;;
esac
command -v "$CC" > /dev/null 2>&1 || fail "DJGPP compiler '$CC' not found"
command -v "$MAKE" > /dev/null 2>&1 || fail "make '$MAKE' not found"

# CWSDSTUB is optional by default, but never silently skip a usable stub
# merely because the required host-side exe2coff tool cannot be found.
STUB=${DOS386_CWSDSTUB:-/opt/cwsdpmi/cwsdstub.exe}
case ${DOS386_EMBED_STUB:-auto} in
auto) if [ -f "$STUB" ]; then EMBED=yes; else EMBED=no; fi ;;
on)
  [ -f "$STUB" ] || fail "CWSDSTUB not found: $STUB"
  EMBED=yes
  ;;
off) EMBED=no ;;
*) fail 'DOS386_EMBED_STUB must be auto, on, or off' ;;
esac
if [ "$EMBED" = yes ]; then
  [ -s "$STUB" ] || fail "CWSDSTUB is empty: $STUB"
  STUB=$(CDPATH= cd -- "$(dirname -- "$STUB")" && pwd -P)/$(basename -- "$STUB")
  EXE2COFF=${DOS386_EXE2COFF:-}
  if [ -z "$EXE2COFF" ]; then
    COMPILER_DIR=$(dirname -- "$(command -v "$CC")")
    for candidate in \
      "$COMPILER_DIR/exe2coff" \
      "$COMPILER_DIR/i586-pc-msdosdjgpp-exe2coff" \
      "$COMPILER_DIR/../i586-pc-msdosdjgpp/bin/exe2coff" \
      /opt/djgpp/i586-pc-msdosdjgpp/bin/exe2coff \
      /opt/djgpp/bin/exe2coff exe2coff i586-pc-msdosdjgpp-exe2coff; do
      if command -v "$candidate" > /dev/null 2>&1; then
        EXE2COFF=$candidate
        break
      fi
    done
  fi
  [ -n "$EXE2COFF" ] && command -v "$EXE2COFF" > /dev/null 2>&1 \
    || fail "CWSDSTUB found at $STUB, but exe2coff is missing (set DOS386_EXE2COFF)"
fi

# The standard global Unix and Windows flags must not leak into DOS builds.
# In particular, -flto/-DUSE_ZLIB_NG from build-all.sh are not inherited.
# Keep the compiler and dependency checks ahead of publishing any binaries.
ROOT=${DOS386_BUILD_ROOT:-"$SOURCE_ROOT/build-dos386"}
mkdir -p "$ROOT"
ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P) || fail 'invalid output directory'
STAGE=$(mktemp -d "$ROOT/.stage.XXXXXXXX") || fail 'cannot create staging directory'
cleanup()
{
  if [ "${KEEP_DOS386_STAGE:-0}" = 1 ]; then
    printf 'build-dos386: retained build stage: %s\n' "$STAGE" >&2
  else
    rm -rf -- "$STAGE"
  fi
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

cat > "$STAGE/probe.c" << 'PROBE'
#if !defined(__DJGPP__) || !defined(__GO32__)
#error DJGPP 32-bit DOS target compiler required
#endif
#if !defined(__i386__) && !defined(__i386)
#error DJGPP compiler is not targeting i386
#endif
typedef char iz_dos386_pointer_check[(sizeof(void *) == 4) ? 1 : -1];
int main(void) { return 0; }
PROBE
if ! "$CC" -std=gnu89 "$STAGE/probe.c" -o "$STAGE/probe.exe" > "$STAGE/probe.log" 2>&1; then
  cat "$STAGE/probe.log" >&2
  fail "'$CC' cannot compile and link a 32-bit DJGPP executable"
fi
[ -s "$STAGE/probe.exe" ] || fail 'DJGPP compiler did not produce a probe executable'

# Optional DOS/386 libraries are never linked based on a header or filename
# alone. Build and link executable probes with the selected DJGPP compiler.
# The default dependency roots are local to DOS386_BUILD_ROOT, not the host.
DOS_ZIP_FLAGS=
DOS_UNZIP_FLAGS=
DOS_CODEC_FLAGS=
DOS_CODEC_INC=
DOS_ZIP_LIBS=
DOS_UNZIP_LIBS=
for setting in DOS386_BZIP2_DIR DOS386_LZMA_DIR DOS386_WAVPACK_DIR DOS386_ZSTD_DIR; do
  eval 'val=${'"$setting"'-}'
  case "$val" in
    *' '* | *'	'* | *'
'*) fail "$setting contains whitespace; use a path without whitespace" ;;
  esac
done
cat > "$STAGE/probe-bzip2.c" << 'PROBE'
#include <bzlib.h>
int main(void) {
    bz_stream c = {0}, d = {0};
    int a = BZ2_bzCompressInit(&c, 1, 0, 30);
    int b = BZ2_bzDecompressInit(&d, 0, 0);
    if (a == BZ_OK) BZ2_bzCompressEnd(&c);
    if (b == BZ_OK) BZ2_bzDecompressEnd(&d);
    return BZ2_bzlibVersion() == 0;
}
PROBE
cat > "$STAGE/probe-lzma.c" << 'PROBE'
#include <lzma.h>
int main(void) {
    lzma_stream c = LZMA_STREAM_INIT, d = LZMA_STREAM_INIT;
    lzma_ret a = lzma_easy_encoder(&c, 1, LZMA_CHECK_NONE);
    lzma_ret b = lzma_stream_decoder(&d, 1024 * 1024, 0);
    if (a == LZMA_OK) lzma_end(&c);
    if (b == LZMA_OK) lzma_end(&d);
    return lzma_version_number() == 0;
}
PROBE
cat > "$STAGE/probe-wavpack.c" << 'PROBE'
#include <wavpack/wavpack.h>
int main(void) {
    WavpackContext *w = WavpackOpenFileInputEx64(0, 0, 0, 0, 0, 0);
    if (w) WavpackCloseFile(w);
    return WavpackGetLibraryVersion() == 0;
}
PROBE
cat > "$STAGE/probe-zstd.c" << 'PROBE'
#include <zstd.h>
int main(void) {
    ZSTD_CStream *c = ZSTD_createCStream();
    ZSTD_DStream *d = ZSTD_createDStream();
    ZSTD_freeCStream(c);
    ZSTD_freeDStream(d);
    return ZSTD_versionNumber() == 0;
}
PROBE

# $1 name; $2 mode setting; $3 prefix; $4 header; $5 archive.
probe_dos_library()
{
  libname=$1
  setting=$2
  prefix=$3
  header=$4
  archive=$5
  eval 'mode=${'"$setting"':-auto}'
  case "$mode" in
    auto | on | off) ;;
    *) fail "$setting must be auto, on or off" ;;
  esac
  DOS_FOUND=no
  [ "$mode" != off ] || { printf 'build-dos386: %s disabled\n' "$libname"; return 0; }
  case "$prefix" in
    *' '* | *'	'* | *'
'*) fail "$libname library prefix contains whitespace" ;;
  esac
  incdir=$prefix/include
  libdir=$prefix/lib
  if [ ! -f "$incdir/$header" ]; then incdir=$prefix; fi
  if [ ! -f "$libdir/$archive" ]; then libdir=$prefix; fi
  if [ -f "$incdir/$header" ] && [ -f "$libdir/$archive" ]; then
    incdir=$(CDPATH= cd -- "$incdir" && pwd -P) || fail "invalid $libname include directory"
    libdir=$(CDPATH= cd -- "$libdir" && pwd -P) || fail "invalid $libname library directory"
    # We need the full paths for reliable ordering, not -l<name> discovery.
    if "$CC" -std=gnu89 -I"$incdir" "$STAGE/probe-$libname.c" \
      "$libdir/$archive" -lm -o "$STAGE/probe-$libname.exe" \
      > "$STAGE/probe-$libname.log" 2>&1 && \
      [ -s "$STAGE/probe-$libname.exe" ]; then
      DOS_FOUND=yes
      DOS_INCLUDE=-I$incdir
      DOS_ARCHIVE=$libdir/$archive
    fi
  fi
  if [ "$DOS_FOUND" != yes ]; then
    prefixvar=${setting}_DIR
    eval 'explicit_prefix=${'"$prefixvar"'-}'
    if [ ! -f "$incdir/$header" ]; then
      reason="missing header $incdir/$header"
    elif [ ! -f "$libdir/$archive" ]; then
      reason="missing target archive $libdir/$archive"
    else
      reason="DJGPP link probe failed; see $STAGE/probe-$libname.log"
    fi
    if [ "$mode" = on ] || [ -n "$explicit_prefix" ]; then
      if [ -f "$STAGE/probe-$libname.log" ]; then
        cat "$STAGE/probe-$libname.log" >&2
      fi
      fail "$libname requested but unavailable: $reason (KEEP_DOS386_STAGE=1 retains probe logs)"
    fi
    printf 'build-dos386: %s unavailable: %s\n' "$libname" "$reason"
  else
    printf 'build-dos386: enabled %s: %s\n' "$libname" "$DOS_ARCHIVE"
  fi
}

probe_dos_library bzip2 DOS386_BZIP2 "${DOS386_BZIP2_DIR:-$ROOT/bzip2}" bzlib.h libbz2.a
if [ "$DOS_FOUND" = yes ]; then
  DOS_ZIP_FLAGS="$DOS_ZIP_FLAGS -DBZIP2_SUPPORT $DOS_INCLUDE"
  DOS_UNZIP_FLAGS="$DOS_UNZIP_FLAGS -DUSE_BZIP2 $DOS_INCLUDE"
  DOS_CODEC_FLAGS="$DOS_CODEC_FLAGS -DZO_WITH_BZIP2"
  DOS_CODEC_INC="$DOS_CODEC_INC $DOS_INCLUDE"
  DOS_ZIP_LIBS="$DOS_ZIP_LIBS $DOS_ARCHIVE"
  DOS_UNZIP_LIBS="$DOS_UNZIP_LIBS $DOS_ARCHIVE"
fi
probe_dos_library lzma DOS386_LZMA "${DOS386_LZMA_DIR:-$ROOT/lzma/install}" lzma.h liblzma.a
if [ "$DOS_FOUND" = yes ]; then
  DOS_ZIP_FLAGS="$DOS_ZIP_FLAGS -DLZMA_SUPPORT $DOS_INCLUDE"
  DOS_UNZIP_FLAGS="$DOS_UNZIP_FLAGS -DUSE_LZMA -DUSE_XZ $DOS_INCLUDE"
  DOS_CODEC_FLAGS="$DOS_CODEC_FLAGS -DZO_WITH_LZMA"
  DOS_CODEC_INC="$DOS_CODEC_INC $DOS_INCLUDE"
  DOS_ZIP_LIBS="$DOS_ZIP_LIBS $DOS_ARCHIVE"
  DOS_UNZIP_LIBS="$DOS_UNZIP_LIBS $DOS_ARCHIVE"
fi
probe_dos_library wavpack DOS386_WAVPACK "${DOS386_WAVPACK_DIR:-$ROOT/wavpack/install}" wavpack/wavpack.h libwavpack.a
if [ "$DOS_FOUND" = yes ]; then
  DOS_UNZIP_FLAGS="$DOS_UNZIP_FLAGS -DUSE_WAVP $DOS_INCLUDE"
  DOS_UNZIP_LIBS="$DOS_UNZIP_LIBS $DOS_ARCHIVE"
fi
probe_dos_library zstd DOS386_ZSTD "${DOS386_ZSTD_DIR:-$ROOT/zstd/install}" zstd.h libzstd.a
if [ "$DOS_FOUND" = yes ]; then
  DOS_ZIP_FLAGS="$DOS_ZIP_FLAGS -DZSTD_SUPPORT $DOS_INCLUDE"
  DOS_UNZIP_FLAGS="$DOS_UNZIP_FLAGS -DUSE_ZSTD $DOS_INCLUDE"
  DOS_CODEC_FLAGS="$DOS_CODEC_FLAGS -DZO_WITH_ZSTD"
  DOS_CODEC_INC="$DOS_CODEC_INC $DOS_INCLUDE"
  DOS_ZIP_LIBS="$DOS_ZIP_LIBS $DOS_ARCHIVE"
  DOS_UNZIP_LIBS="$DOS_UNZIP_LIBS $DOS_ARCHIVE"
fi
# A single set of compile flags drives each private UnZip decoder build.
# WavPack has no ZipOpt compression candidate; it is used for decoding only.
DOS_ZO_LIBS="$DOS_UNZIP_LIBS"

mkdir -p "$STAGE/src" "$STAGE/bin"
cp -R "$SOURCE_ROOT/zip30" "$STAGE/src/zip30"
cp -R "$SOURCE_ROOT/unzip60" "$STAGE/src/unzip60"
cp -R "$SOURCE_ROOT/zipopt" "$STAGE/src/zipopt"
cp -R "$SOURCE_ROOT/zipdedup" "$STAGE/src/zipdedup"
# ZipOpt and ZipDedup compile Xtro's portable metadata core from the
# staged source tree.  Keep this sibling directory alongside both tools.
sh "$SOURCE_ROOT/xtrmeta/stage-cross.sh" \
  "$SOURCE_ROOT/xtrmeta" "$STAGE/src/xtrmeta"
# Clear all objects of prior Unix, MinGW, or DOS builds from the staging copy.
find "$STAGE/src/zip30" "$STAGE/src/unzip60" "$STAGE/src/zipopt" "$STAGE/src/zipdedup" -type f \
  \( -name '*.o' -o -name '*.obj' -o -name '*.exe' \) -exec rm -f '{}' +

printf 'build-dos386: building DJGPP DOS/386 binaries with %s\n' "$CC"
(
  cd "$STAGE/src/zip30"
  "$MAKE" -j "$JOBS" -f msdos/Makefile.dos386 all CC="$CC" \
    DOS386_CFLAGS="${DOS386_CFLAGS:-}" DOS386_LDFLAGS="${DOS386_LDFLAGS:-}" \
    DOS386_ZIP_CPPFLAGS="$DOS_ZIP_FLAGS" DOS386_UNZIP_CPPFLAGS="$DOS_UNZIP_FLAGS" \
    DOS386_CODEC_CPPFLAGS="$DOS_CODEC_FLAGS" DOS386_CODEC_INCFLAGS="$DOS_CODEC_INC" \
    DOS386_ZIP_LIBS="$DOS_ZIP_LIBS" DOS386_UNZIP_LIBS="$DOS_UNZIP_LIBS" \
    DOS386_ZO_LIBS="$DOS_ZO_LIBS"
)
(
  cd "$STAGE/src/unzip60"
  "$MAKE" -j "$JOBS" -f msdos/Makefile.dos386 all CC="$CC" \
    DOS386_CFLAGS="${DOS386_CFLAGS:-}" DOS386_LDFLAGS="${DOS386_LDFLAGS:-}" \
    DOS386_ZIP_CPPFLAGS="$DOS_ZIP_FLAGS" DOS386_UNZIP_CPPFLAGS="$DOS_UNZIP_FLAGS" \
    DOS386_CODEC_CPPFLAGS="$DOS_CODEC_FLAGS" DOS386_CODEC_INCFLAGS="$DOS_CODEC_INC" \
    DOS386_ZIP_LIBS="$DOS_ZIP_LIBS" DOS386_UNZIP_LIBS="$DOS_UNZIP_LIBS" \
    DOS386_ZO_LIBS="$DOS_ZO_LIBS"
)
(
  cd "$STAGE/src/zipopt"
  rm -rf build winbuild dosbuild
  "$MAKE" -j "$JOBS" -f Makefile.dos386 all CC="$CC" \
    DOS386_CFLAGS="${DOS386_CFLAGS:-}" DOS386_LDFLAGS="${DOS386_LDFLAGS:-}" \
    DOS386_ZIP_CPPFLAGS="$DOS_ZIP_FLAGS" DOS386_UNZIP_CPPFLAGS="$DOS_UNZIP_FLAGS" \
    DOS386_CODEC_CPPFLAGS="$DOS_CODEC_FLAGS" DOS386_CODEC_INCFLAGS="$DOS_CODEC_INC" \
    DOS386_ZIP_LIBS="$DOS_ZIP_LIBS" DOS386_UNZIP_LIBS="$DOS_UNZIP_LIBS" \
    DOS386_ZO_LIBS="$DOS_ZO_LIBS"
)
(
  cd "$STAGE/src/zipdedup"
  rm -rf winbuild dosbuild
  "$MAKE" -j "$JOBS" -f Makefile.dos386 all CC="$CC" \
    DOS386_CFLAGS="${DOS386_CFLAGS:-}" DOS386_LDFLAGS="${DOS386_LDFLAGS:-}" \
    DOS386_ZIP_CPPFLAGS="$DOS_ZIP_FLAGS" DOS386_UNZIP_CPPFLAGS="$DOS_UNZIP_FLAGS" \
    DOS386_CODEC_CPPFLAGS="$DOS_CODEC_FLAGS" DOS386_CODEC_INCFLAGS="$DOS_CODEC_INC" \
    DOS386_ZIP_LIBS="$DOS_ZIP_LIBS" DOS386_UNZIP_LIBS="$DOS_UNZIP_LIBS" \
    DOS386_ZO_LIBS="$DOS_ZO_LIBS"
)
for name in zip zipcloak zipnote zipsplit; do
  [ -s "$STAGE/src/zip30/$name.exe" ] || fail "missing $name.exe"
  cp "$STAGE/src/zip30/$name.exe" "$STAGE/bin/$name.exe"
done
for name in unzip funzip unzipsfx; do
  [ -s "$STAGE/src/unzip60/$name.exe" ] || fail "missing $name.exe"
  cp "$STAGE/src/unzip60/$name.exe" "$STAGE/bin/$name.exe"
done
for name in zipopt zipopt-preflight zipopt-decodecheck; do
  [ -s "$STAGE/src/zipopt/$name.exe" ] || fail "missing $name.exe"
  cp "$STAGE/src/zipopt/$name.exe" "$STAGE/bin/$name.exe"
done
[ -s "$STAGE/src/zipdedup/zipdedup.exe" ] || fail 'missing zipdedup.exe'
cp "$STAGE/src/zipdedup/zipdedup.exe" "$STAGE/bin/zipdedup.exe"

# Operate on staged copies only; if conversion fails no published binaries
# are changed. exe2coff writes the extensionless COFF file in its CWD.
DOS_PROGRAMS='zip zipcloak zipnote zipsplit unzip funzip unzipsfx zipopt zipopt-preflight zipopt-decodecheck zipdedup'
if [ "$EMBED" = yes ]; then
  (
    cd "$STAGE/bin"
    for name in $DOS_PROGRAMS; do
      "$EXE2COFF" "$name.exe" || fail "exe2coff failed on $name.exe"
      [ -s "$name" ] || fail "exe2coff produced no $name COFF image"
      # Build the replacement separately and verify it before replacing the
      # staged executable; never delete the only good copy prematurely.
      cat "$STUB" "$name" > "$name.withstub" || fail "cannot embed CWSDSTUB in $name"
      [ -s "$name.withstub" ] || fail "empty combined executable for $name"
      mv -f "$name.withstub" "$name.exe" || fail "cannot install combined executable for $name"
      rm -f "$name"
    done
  )
fi
mkdir -p "$ROOT/bin"
# Build and conversion have fully succeeded before publishing the output set.
for name in $DOS_PROGRAMS; do
  cp "$STAGE/bin/$name.exe" "$ROOT/bin/$name.exe"
  chmod a+x "$ROOT/bin/$name.exe"
done
printf 'build-dos386: built DOS executables in %s/bin\n' "$ROOT"
if [ "$EMBED" = yes ]; then
  printf 'build-dos386: CWSDSTUB embedded in all executables\n'
else
  printf 'build-dos386: external DPMI host required when none is installed\n'
fi
