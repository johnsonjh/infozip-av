#!/bin/sh

set -e

CPUS="$(nproc 2> /dev/null || printf '%s\n' '1')"
LTO="-flto=auto"
WLB="-Wl,-z,relro"

# "-DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD" are "important" RHEL flags, do not remove!
CF_NOOPT="${LTO:-} -I. -DUNIX ${RPM_OPT_FLAGS:--O3} -DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD"
GLDFLAGS="${LTO:-} ${WLB:-}"

# Enable LZMA-enabled unzipsfx
D_USE_LZMA_SFX="-DLZMA_SFX"
L_LZMA_SFX="-l:liblzma.a -s"

# Enable Zstd-enabled unzipsfx
D_USE_ZSTD_SFX="-DZSTD_SFX"
L_ZSTD_SFX="-l:libzstd.a -s"

ZIPDIR="zip30"
UNZIPDIR="unzip60"

PREFIX="$(pwd -P 2> /dev/null && :)/build"

test "${PREFIX:?}" = "/build" && {
  printf '%s\n' "Bad prefix: ${PREFIX:?}"
  exit 1
}

mkdir -p "${PREFIX:?}/man1"

(
  cd "${UNZIPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" -f unix/Makefile generic_gcc \
      CF_NOOPT="${CF_NOOPT:?}" \
      LFLAGS2="${GLDFLAGS:?}" \
      D_USE_LZMA_SFX="${D_USE_LZMA_SFX:-}" \
      L_LZMA_SFX="${L_LZMA_SFX:-}" \
      D_USE_ZSTD_SFX="${D_USE_ZSTD_SFX:-}" \
      L_ZSTD_SFX="${L_ZSTD_SFX:-}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${ZIPDIR:?}" \
    && "${MAKE:-make}" -j "${CPUS:?}" -f unix/Makefile generic_gcc \
      CFLAGS_NOOPT="${CF_NOOPT:?}" \
      LFLAGS2="${GLDFLAGS:?}" \
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

"${STRIP:-strip}" "${PREFIX:?}"/bin/* 2> /dev/null || :
"${SSTRIP:-sstrip}" -z "${PREFIX:?}"/bin/* 2> /dev/null || :
upx -qq --best "build/bin/unzipsfx" 2> /dev/null || :

ls -la "${PREFIX}"/*/*
