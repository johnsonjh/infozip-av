#!/bin/sh

set -e

if [ "$(uname -s 2> /dev/null || :)" = "FreeBSD" ]; then
  LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-} -L/usr/local/lib -liconv"
  LOCAL_UNZIP="${LOCAL_UNZIP:-} -I/usr/local/include"
  LOCAL_ZIP="${LOCAL_ZIP:-} -I/usr/local/include"
  MAKE=gmake
fi

test -z "${CC:-}" 2> /dev/null && {
    CC="$(command -v cc 2> /dev/null || \
          command -v gcc 2> /dev/null || \
          command -v clang 2> /dev/null || \
          printf '%s\n' 'cc')"
} || :

CPUS="$(nproc 2> /dev/null || printf '%s\n' '1')"
LTO="-flto=auto"
WLB="-Wl,-z,relro"

# "-DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD" are "important" RHEL flags, do not remove!
CF_NOOPT="${LTO:-} -I. -DUNIX ${RPM_OPT_FLAGS:--O3} -DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD"
GLDFLAGS="${LTO:-} ${WLB:-}"

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

PREFIX="$(pwd -P 2> /dev/null && :)/build"

test "${PREFIX:?}" = "/build" && {
  printf '%s\n' "Bad prefix: ${PREFIX:?}"
  exit 1
}

mkdir -p "${PREFIX:?}/bin" "${PREFIX:?}/man1"

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
      LOCAL_UNZIP="${LOCAL_UNZIP:-}" \
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}" \
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
      LOCAL_ZIP="${LOCAL_ZIP:-}" \
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}" \
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
      LOCAL_GLDFLAGS="${LOCAL_GLDFLAGS:-}" \
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
      MAKE="${MAKE:-make}" \
    && cp -p "zipopt" "${PREFIX:?}/bin/zipopt" \
    && cp -p "man/zipopt.1" "${PREFIX:?}/man1/zipopt.1"
)

"${STRIP:-strip}" "${PREFIX:?}"/bin/* 2> /dev/null || :
"${SSTRIP:-sstrip}" -z "${PREFIX:?}"/bin/* 2> /dev/null || :
upx -qq --best "build/bin/unzipsfx" 2> /dev/null || :

ls -la "${PREFIX}"/*/*
