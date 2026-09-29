#!/bin/sh

set -e

GLDFLAGS="-Wl,-z,relro"
CF_NOOPT="-I. -DUNIX ${RPM_OPT_FLAGS:--O2} -DNOMEMCPY -DIZ_HAVE_UXUIDGID -DNO_LCHMOD"

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
    && make -f unix/Makefile generic_gcc \
      CF_NOOPT="${CF_NOOPT:?}" \
      LFLAGS2="${GLDFLAGS:?}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${ZIPDIR:?}" \
    && make -f unix/Makefile generic_gcc \
      LFLAGS2="${GLDFLAGS:?}" \
      PREFIX="${PREFIX:?}"
)

(
  cd "${UNZIPDIR:?}" \
    && make -f unix/Makefile \
      prefix="${PREFIX:?}" \
      MANDIR="${PREFIX:?}/man1" \
      INSTALL="cp -p" \
      install
)

(
  cd "${ZIPDIR:?}" \
    && make -f unix/Makefile \
      prefix="${PREFIX:?}" \
      MANDIR="${PREFIX:?}/man1" \
      install
)

ls -la "${PREFIX}"/*/*
