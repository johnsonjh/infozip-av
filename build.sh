#!/bin/sh

set -e

CPUS="$(nproc 2> /dev/null || printf '%s\n' '1')"
LTO="-flto=auto"
WLB="-Wl,-z,relro"

# "-DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD" are "important" RHEL flags, do not remove!
CF_NOOPT="${LTO:-} -I. -DUNIX ${RPM_OPT_FLAGS:--O3} -DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD"
GLDFLAGS="${LTO:-} ${WLB:-} ${LOCAL_GLDFLAGS:-}"

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

# Uncomment to use external zlib
# Recommended if zlib has hardware accel (e.g., zlib-ng)
#EXTERNAL_ZLIB="-DUSE_ZLIB"
#EXT_ZLIB_LIB="-lz"

LOCAL_UNZIP="${LOCAL_UNZIP:-} ${EXTERNAL_ZLIB:-}"
LOCAL_ZIP="${LOCAL_ZIP:-} ${EXTERNAL_ZLIB:-}"

ZIPDIR="zip30"
UNZIPDIR="unzip60"
ZIPDEDUPDIR="zipdedup"

PREFIX="$(pwd -P 2> /dev/null && :)/build"

test "${PREFIX:?}" = "/build" && {
  printf '%s\n' "Bad prefix: ${PREFIX:?}"
  exit 1
}

mkdir -p "${PREFIX:?}/bin" "${PREFIX:?}/man1"

(
  cd "${UNZIPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" -f unix/Makefile generic_gcc \
      CF_NOOPT="${CF_NOOPT:?} ${LOCAL_UNZIP:-}" \
      LFLAGS2="${GLDFLAGS:?}" \
      D_USE_LZMA_SFX="${D_USE_LZMA_SFX:-}" \
      L_LZMA_SFX="${L_LZMA_SFX:-}" \
      D_USE_ZSTD_SFX="${D_USE_ZSTD_SFX:-}" \
      L_ZSTD_SFX="${L_ZSTD_SFX:-}" \
      D_USE_WAVPACK_SFX="${D_USE_WAVPACK_SFX:-}" \
      L_WAVPACK_SFX="${L_WAVPACK_SFX:-}" \
      D_USE_REFPTR_SFX="${D_USE_REFPTR_SFX:-}" \
      D_USE_WZMP3_SFX="${D_USE_WZMP3_SFX:-}" \
      LOCAL_UNZIP="${LOCAL_UNZIP:-}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${ZIPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" -f unix/Makefile generic_gcc \
      CFLAGS_NOOPT="${CF_NOOPT:?} ${LOCAL_ZIP:-}" \
      LFLAGS2="${GLDFLAGS:?}" \
      LOCAL_ZIP="${LOCAL_ZIP:-}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${UNZIPDIR:?}" \
    && "${MAKE:-make}" -f unix/Makefile \
      prefix="${PREFIX:?}" \
      MANDIR="${PREFIX:?}/man1" \
      INSTALL="cp -p" \
      install
)

(
  cd "${ZIPDIR:?}" \
    && "${MAKE:-make}" -f unix/Makefile \
      prefix="${PREFIX:?}" \
      MANDIR="${PREFIX:?}/man1" \
      install
)

(
  cd "${ZIPDEDUPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" all \
      EXT_ZLIB_LIB="${EXT_ZLIB_LIB:-}" \
    && cp -p "zipdedup" "${PREFIX:?}/bin/zipdedup" \
    && cp -p "man/zipdedup.1" "${PREFIX:?}/man1/zipdedup.1"
)

"${STRIP:-strip}" "${PREFIX:?}"/bin/* 2> /dev/null || :
"${SSTRIP:-sstrip}" -z "${PREFIX:?}"/bin/* 2> /dev/null || :
upx -qq --best "build/bin/unzipsfx" 2> /dev/null || :

ls -la "${PREFIX}"/*/*
