#!/bin/sh

set -e

test -z "${MAKE:-}" 2> /dev/null && {
  MAKE="$(command -v gmake 2> /dev/null \
    || command -v make 2> /dev/null \
    || printf '%s\n' 'make')"
}

ZIPDIR="zip30"
UNZIPDIR="unzip60"
ZIPDEDUPDIR="zipdedup"
ZIPOPTDIR="zipopt"

PREFIX="$(pwd -P 2> /dev/null || :)/build"

test "${PREFIX:?}" = "/build" && {
  printf '%s\n' "Bad prefix: ${PREFIX:?}"
  exit 1
}

(
  cd "${UNZIPDIR:?}" \
    && "${MAKE:-make}" -f unix/Makefile clean
)

(
  cd "${ZIPDIR:?}" \
    && "${MAKE:-make}" -f unix/Makefile clean
)

(
  cd "${ZIPDEDUPDIR:?}" \
    && "${MAKE:-make}" clean
  rm -rf ./tests/__pycache__ 2> /dev/null || :
)

(
  cd "${ZIPOPTDIR:?}" \
    && "${MAKE:-make}" clean
  rm -rf ./tests/__pycache__ 2> /dev/null || :
  rm -rf ./build 2> /dev/null || :
)

rm -f "${UNZIPDIR:?}/"*.pic.o

rm -f "${UNZIPDIR:?}/conftest"
rm -f "${UNZIPDIR:?}/conftest.c"

test -d "${PREFIX:?}/man1" && {
  rm -f "${PREFIX:?}/man1/"* || :
  rmdir "${PREFIX:?}/man1"
}

test -d "${PREFIX:?}/bin" && {
  rm -f "${PREFIX:?}/bin/"* || :
  rmdir "${PREFIX:?}/bin"
}

rm -rf ./build-win32 2> /dev/null || :
rm -rf ./win32 2> /dev/null || :
rm -rf ./win64 2> /dev/null || :
rm -rf ./win64ucrt 2> /dev/null || :

find "${ZIPDIR:?}" "${UNZIPDIR:?}" "${ZIPDEDUPDIR:?}" xtrmeta \
  -type f -name '*.err' -exec rm -f '{}' + 2> /dev/null || :

rm -rf ./build-dos16 2> /dev/null || :
rm -rf ./dos16 2> /dev/null || :

rm -rf ./build-dos386 2> /dev/null || :
rm -rf ./dos386 2> /dev/null || :

# Unix fallback archive and OS/2 archive live under these build directories.
rm -rf ./build/bzip2 2> /dev/null || :
rm -f ./build/bzip2-system-probe.log ./build/wavpack-sfx-probe.log 2> /dev/null || :
rm -f ./build/.bzip2-backend ./build/bzip2-clean-*.log 2> /dev/null || :
rm -rf ./build-os2 2> /dev/null || :
rm -rf ./os2 2> /dev/null || :

test -d "${PREFIX:?}" && rmdir "${PREFIX:?}"

git clean -ndx 2> /dev/null || :
