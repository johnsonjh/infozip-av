#!/bin/sh

set -e

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

test -d "${PREFIX:?}" && rmdir "${PREFIX:?}"

git clean -ndx 2> /dev/null || :
