#!/bin/sh

set -e

# Validate before creating any output tree. The helper emits only inert ASCII
# preprocessor tokens; it never interpolates input into a make/shell program.
IZ_SDE_FLAGS=$(sh ./tests/source-date-epoch-build.sh flags) || exit 2

test -z "${MAKE:-}" && {
  MAKE="$(command -v gmake 2> /dev/null \
    || command -v make 2> /dev/null \
    || printf '%s\n' 'make')"
}

if [ "$(uname -s 2> /dev/null || :)" = "OpenBSD" ]; then
  LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-} -L/usr/local/lib -liconv"
  LOCAL_UNZIP="${LOCAL_UNZIP:-} -I/usr/local/include"
  LOCAL_ZIP="${LOCAL_ZIP:-} -I/usr/local/include"
fi

if [ "$(uname -s 2> /dev/null || :)" = "FreeBSD" ]; then
  LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-} -L/usr/local/lib -liconv"
  LOCAL_UNZIP="${LOCAL_UNZIP:-} -I/usr/local/include"
  LOCAL_ZIP="${LOCAL_ZIP:-} -I/usr/local/include"
fi

test -z "${CC:-}" && {
  CC="$(command -v cc 2> /dev/null \
    || command -v gcc 2> /dev/null \
    || command -v clang 2> /dev/null \
    || printf '%s\n' 'cc')"
} || :

CPUS="$(nproc 2> /dev/null || printf '%s\n' '1')"

test -z "${LTO:-}" && {
  LTO="-flto=auto"
}

test -z "${WLB:-}" && {
  WLB="-Wl,-z,relro"
}

# "-DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD" are "important" RHEL flags, do not remove!
CF_NOOPT="${LTO:-} -I. -DUNIX ${RPM_OPT_FLAGS:--O3} -DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD"
GLDFLAGS="${LTO:-} ${WLB:-}"
if [ -n "$IZ_SDE_FLAGS" ]; then
  CF_NOOPT="$CF_NOOPT $IZ_SDE_FLAGS"
  LOCAL_ZIP="${LOCAL_ZIP:-} $IZ_SDE_FLAGS"
  LOCAL_UNZIP="${LOCAL_UNZIP:-} $IZ_SDE_FLAGS"
fi

# Enable LZMA-enabled unzipsfx
D_USE_LZMA_SFX="-DLZMA_SFX"
L_LZMA_SFX="-llzma"

# Enable Zstd-enabled unzipsfx
D_USE_ZSTD_SFX="-DZSTD_SFX"
L_ZSTD_SFX="-lzstd"

# Enable WavPack-enabled unzipsfx
D_USE_WAVPACK_SFX="-DWAVPACK_SFX"
L_WAVPACK_SFX="-lwavpack"

# Enable RefPtr-enabled unzipsfx
D_USE_REFPTR_SFX="-DREFPTR_SFX"

# Enable WZ-MP3-enabled unzipsfx
D_USE_WZMP3_SFX="-DWZMP3_SFX"

# Uncomment to force external zlib (not zlib-ng).
# Installed zlib-ng is detected automatically.
#EXTERNAL_ZLIB="-DUSE_ZLIB"

case " ${EXTERNAL_ZLIB:-} " in
*" -DUSE_ZLIB_NG "* | *" -DUSE_ZLIB_NG="*) ZD_ZLIB_BACKEND=native ;;
*" -DUSE_ZLIB "* | *" -DUSE_ZLIB="*) ZD_ZLIB_BACKEND=zlib ;;
*" -DNO_ZLIB_NG "* | *" -DNO_ZLIB_NG="*) ZD_ZLIB_BACKEND=internal ;;
*) ZD_ZLIB_BACKEND=${ZD_BACKEND:-auto} ;;
esac

BUILD_CC=${CC:-cc}

ZIPDIR="zip30"
UNZIPDIR="unzip60"
ZIPDEDUPDIR="zipdedup"
ZIPOPTDIR="zipopt"

# Vendored libbzip2 is used only when the system library cannot link or when
# explicitly requested.  Do not alter the flat bzlib.h/libbz2.a lookup used by
# build-win32.sh, build-all.sh, or build-dos386.sh.
case "${BZIP2_BACKEND:-auto}" in
auto | system | vendored) ;;
*)
  echo 'ERROR: BZIP2_BACKEND must be auto, system, or vendored' >&2; exit 2
  ;;
esac

PREFIX="$(pwd -P 2> /dev/null && :)/build"

test "${PREFIX:?}" = "/build" && {
  printf '%s\n' "Bad prefix: ${PREFIX:?}"
  exit 1
}

mkdir -p "${PREFIX:?}/bin" "${PREFIX:?}/man1"

# libdeflate is optional at build time and remains opt-in for Zip's runtime
# compressor.  Detect only through a real header+link probe; 1 requires the
# library, 0 disables it, and the default auto mode skips absent libraries.
XLD_LINK_LIBS=
case "${USE_LIBDEFLATE:-auto}" in
0 | off) ZO_LD_REQUEST=off ;;
auto | 1 | on)
  xld_probe="$PREFIX/.libdeflate-probe-$$"
  LIBDEFLATE_CFLAGS="${LIBDEFLATE_CFLAGS:-$(pkg-config --cflags libdeflate 2> /dev/null || :)}"
  LIBDEFLATE_LIBS="${LIBDEFLATE_LIBS:-$(pkg-config --libs libdeflate 2> /dev/null || printf '%s' '-ldeflate')}"
  cat > "$xld_probe.c" << 'XTR_LD_PROBE'
#include <libdeflate.h>
int main(void) {
  struct libdeflate_compressor *c = libdeflate_alloc_compressor(6);
  if (!c) return 1;
  libdeflate_free_compressor(c);
  return 0;
}
XTR_LD_PROBE
  if "$BUILD_CC" ${LOCAL_ZIP:-} ${LOCAL_UNZIP:-} \
    $LIBDEFLATE_CFLAGS "$xld_probe.c" -o "$xld_probe" \
    ${LOCAL_GLDFLAGS:-} $LIBDEFLATE_LIBS \
    > "$PREFIX/libdeflate-probe.log" 2>&1; then
    LOCAL_ZIP="${LOCAL_ZIP:-} $LIBDEFLATE_CFLAGS -DUSE_LIBDEFLATE"
    LOCAL_UNZIP="${LOCAL_UNZIP:-} $LIBDEFLATE_CFLAGS -DUSE_LIBDEFLATE"
    XLD_LINK_LIBS=$LIBDEFLATE_LIBS
    ZO_LD_REQUEST=on
    echo 'build-unix: libdeflate detected and enabled'
  else
    case "${USE_LIBDEFLATE:-auto}" in
    1 | on)
      echo 'ERROR: USE_LIBDEFLATE=1 but libdeflate headers/library cannot link' >&2
      tail -30 "$PREFIX/libdeflate-probe.log" >&2
      exit 1
      ;;
    esac
    ZO_LD_REQUEST=off
    echo 'build-unix: libdeflate unavailable; using existing codecs'
  fi
  rm -f "$xld_probe" "$xld_probe.c"
  ;;
*)
  echo 'ERROR: USE_LIBDEFLATE must be auto, 0/off, or 1/on' >&2; exit 2
  ;;
esac

# Use a real link test, not merely existence of bzlib.h or an archive.
# Extra flags supplied by the caller participate in both probes.  Keep the
# original external-library directory conventions otherwise unchanged.
BZIP2_CHOICE=${BZIP2_BACKEND:-auto}
if [ "$BZIP2_CHOICE" != vendored ]; then
  bzprobe="$PREFIX/.bz2-probe-$$"
  cat > "$bzprobe.c" << 'XTR_BZ_PROBE'
#include <bzlib.h>
int main(void)
{
    bz_stream strm;
    int result;
    strm.bzalloc = 0;
    strm.bzfree = 0;
    strm.opaque = 0;
    result = BZ2_bzDecompressInit(&strm, 0, 0);
    if (result != BZ_OK) return 1;
    if (BZ2_bzDecompressEnd(&strm) != BZ_OK) return 2;
    return BZ2_bzlibVersion() == 0;
}
XTR_BZ_PROBE
  if "$BUILD_CC" ${LOCAL_ZIP:-} ${LOCAL_UNZIP:-} \
    "$bzprobe.c" ${LOCAL_GLDFLAGS:-} -lbz2 \
    -o "$bzprobe" > "$PREFIX/bzip2-system-probe.log" 2>&1; then
    BZIP2_CHOICE=system
    echo 'build-unix: using existing system libbz2'
  else
    if [ "$BZIP2_CHOICE" = system ]; then
      rm -f "$bzprobe" "$bzprobe.c"
      echo 'ERROR: BZIP2_BACKEND=system but bzlib.h/library link test failed' >&2
      cat "$PREFIX/bzip2-system-probe.log" >&2
      exit 1
    fi
    BZIP2_CHOICE=vendored
  fi
  rm -f "$bzprobe" "$bzprobe.c"
fi

if [ "$BZIP2_CHOICE" = vendored ]; then
  BZIP2_VENDOR_DIR="$PREFIX/bzip2"
  mkdir -p "$BZIP2_VENDOR_DIR"
  # A flat header/archive pair is also understood by the old Info-ZIP
  # configure scripts.  Source and build artifacts remain separate.
  cp "$PWD/vendor/bzip2/bzlib.h" "$BZIP2_VENDOR_DIR/bzlib.h"
  rm -f "$BZIP2_VENDOR_DIR/libbz2.a"
  BZIP2_VENDOR_OBJS=
  for unit in blocksort huffman crctable randtable compress decompress bzlib; do
    "$BUILD_CC" -std=c89 -DBZ_STRICT_ANSI ${BZIP2_VENDOR_CFLAGS:--O2} \
      -I"$PWD/vendor/bzip2" -c "$PWD/vendor/bzip2/$unit.c" \
      -o "$BZIP2_VENDOR_DIR/$unit.o"
    BZIP2_VENDOR_OBJS="$BZIP2_VENDOR_OBJS $BZIP2_VENDOR_DIR/$unit.o"
  done
  # Intentionally unquoted list: each object is a separate archiver argument.
  "${AR:-ar}" rcs "$BZIP2_VENDOR_DIR/libbz2.a" $BZIP2_VENDOR_OBJS
  # Relative to the zip30/ and unzip60/ make working directories.
  BZIP2_ZIP_MAKE_ARG=IZ_BZIP2=../build/bzip2
  BZIP2_UNZIP_MAKE_ARG=IZ_BZIP2=../build/bzip2
  export XTR_BZIP2_FULL_API=1
  LOCAL_ZIP="${LOCAL_ZIP:-} -I$BZIP2_VENDOR_DIR"
  LOCAL_UNZIP="${LOCAL_UNZIP:-} -I$BZIP2_VENDOR_DIR"
  LOCAL_GLDFLAGS="-L$BZIP2_VENDOR_DIR ${LOCAL_GLDFLAGS:-}"
  echo 'build-unix: using vendored libbzip2 (static, full API)'
else
  # Preserve the historical makefile defaults and any existing explicit
  # IZ_BZIP2 settings; do not override them with an empty command-line
  # assignment.  UnZip's link rule emits -L$(IZ_BZIP2), requiring a value.
  BZIP2_ZIP_MAKE_ARG=
  BZIP2_UNZIP_MAKE_ARG=
fi

# The SFX build must not require WavPack when it is unavailable.  Existing
# normal UnZip codec detection is independent of this executable's options.
wprobe="$PREFIX/.wavpack-probe-$$"
cat > "$wprobe.c" << 'XTR_WV_PROBE'
#include <wavpack/wavpack.h>
int main(void) { return WavpackGetLibraryVersion() == 0; }
XTR_WV_PROBE
if "$BUILD_CC" ${LOCAL_UNZIP:-} "$wprobe.c" ${LOCAL_GLDFLAGS:-} \
  -lwavpack -o "$wprobe" > "$PREFIX/wavpack-sfx-probe.log" 2>&1; then
  echo 'build-unix: UnZipSFX WavPack support enabled'
else
  D_USE_WAVPACK_SFX=
  L_WAVPACK_SFX=
  echo 'build-unix: UnZipSFX WavPack unavailable (disabled)'
fi
rm -f "$wprobe" "$wprobe.c"

# Make's historical flags files and codec objects are not automatically
# rebuilt when changing backend.  Force a complete reconfigure when the
# selection changes, including the first run after an older build.
backend_stamp="$PREFIX/.bzip2-backend"
if [ ! -f "$backend_stamp" ] \
  || [ "$(cat "$backend_stamp")" != "$BZIP2_CHOICE" ]; then
  for source_dir in "$UNZIPDIR" "$ZIPDIR" "$ZIPDEDUPDIR" "$ZIPOPTDIR"; do
    case "$source_dir" in
    "$UNZIPDIR" | "$ZIPDIR") clean_makefile='-f unix/Makefile' ;;
    *) clean_makefile= ;;
    esac
    (cd "$source_dir" && "$MAKE" $clean_makefile clean) \
      > "$PREFIX/bzip2-clean-$source_dir.log" 2>&1 || {
      echo "ERROR: cleaning $source_dir before backend switch failed" >&2
      tail -30 "$PREFIX/bzip2-clean-$source_dir.log" >&2
      exit 1
    }
  done
fi

(
  cd "${UNZIPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" -f unix/Makefile generic_gcc \
      CC="${BUILD_CC}" \
      CF_NOOPT="${CF_NOOPT:?}" \
      LFLAGS2="${GLDFLAGS}" \
      D_USE_LZMA_SFX="${D_USE_LZMA_SFX:-}" \
      L_LZMA_SFX="${L_LZMA_SFX:-}" \
      D_USE_ZSTD_SFX="${D_USE_ZSTD_SFX:-}" \
      L_ZSTD_SFX="${L_ZSTD_SFX:-}" \
      D_USE_WAVPACK_SFX="${D_USE_WAVPACK_SFX:-}" \
      L_WAVPACK_SFX="${L_WAVPACK_SFX:-}" \
      D_USE_REFPTR_SFX="${D_USE_REFPTR_SFX:-}" \
      D_USE_WZMP3_SFX="${D_USE_WZMP3_SFX:-}" \
      $BZIP2_UNZIP_MAKE_ARG \
      LOCAL_UNZIP="${LOCAL_UNZIP:-}" \
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}" \
      IZ_LIBDEFLATE_LIBS="$XLD_LINK_LIBS" \
      EXTERNAL_ZLIB="${EXTERNAL_ZLIB:-}" \
      MAKE="${MAKE:-make}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${ZIPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" -f unix/Makefile generic_gcc \
      CC="${BUILD_CC}" \
      CFLAGS_NOOPT="${CF_NOOPT:?}" \
      LFLAGS2="${GLDFLAGS}" \
      $BZIP2_ZIP_MAKE_ARG \
      LOCAL_ZIP="${LOCAL_ZIP:-}" \
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-} $XLD_LINK_LIBS" \
      EXTERNAL_ZLIB="${EXTERNAL_ZLIB:-}" \
      MAKE="${MAKE:-make}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${UNZIPDIR:?}" \
    && "${MAKE:-make}" -f unix/Makefile \
      prefix="${PREFIX:?}" \
      MANDIR="${PREFIX:?}/man1" \
      INSTALL="cp -p" \
      MAKE="${MAKE:-make}" \
      install
)

(
  cd "${ZIPDIR:?}" \
    && "${MAKE:-make}" -f unix/Makefile \
      prefix="${PREFIX:?}" \
      MANDIR="${PREFIX:?}/man1" \
      MAKE="${MAKE:-make}" \
      install
)

(
  cd "${ZIPDEDUPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" all \
      CC="${BUILD_CC}" \
      ZD_BACKEND="${ZD_ZLIB_BACKEND}" \
      LOCAL_UNZIP="${LOCAL_UNZIP:-}" \
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-} $XLD_LINK_LIBS" \
      MAKE="${MAKE:-make}" \
    && cp -p "zipdedup" "${PREFIX:?}/bin/zipdedup" \
    && cp -p "man/zipdedup.1" "${PREFIX:?}/man1/zipdedup.1"
)

(
  cd "${ZIPOPTDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" all \
      CC="${BUILD_CC}" \
      LOCAL_UNZIP="${LOCAL_UNZIP:-}" \
      LOCAL_ZIP="${LOCAL_ZIP:-}" \
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}" \
      EXTERNAL_ZLIB="${EXTERNAL_ZLIB:-}" \
      ZO_LIBDEFLATE="${ZO_LD_REQUEST}" \
      ZO_LIBDEFLATE_CFLAGS="${LIBDEFLATE_CFLAGS:-}" \
      ZO_LIBDEFLATE_LIBS="${LIBDEFLATE_LIBS:-}" \
      MAKE="${MAKE:-make}" \
    && cp -p "zipopt" "${PREFIX:?}/bin/zipopt" \
    && cp -p "man/zipopt.1" "${PREFIX:?}/man1/zipopt.1"
)

"${STRIP:-strip}" "${PREFIX:?}"/bin/* 2> /dev/null || :
"${SSTRIP:-sstrip}" -z "${PREFIX:?}"/bin/* 2> /dev/null || :
upx -qq --best "build/bin/unzipsfx" 2> /dev/null || :

printf '%s\n' "$BZIP2_CHOICE" > "$backend_stamp"
ls -la "${PREFIX}"/*/*
