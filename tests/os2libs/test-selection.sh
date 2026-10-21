#!/bin/sh
# Fail-closed detection tests. Do not compile Xtro-ZIP in negative cases.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
watcom=${WATCOM:-/opt/watcom}
if [ ! -x "$watcom/binl64/wcc386" ] && [ ! -x "$watcom/binl/wcc386" ]; then
  echo 'SKIP: OW2 compiler unavailable'; exit 77
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
if WATCOM="$watcom" OS2_LZMA=on OS2_LZMA_DIR="$stage/absent" \
    "$root/build-os2.sh" > "$stage/missing.log" 2>&1; then
  echo 'FAIL: required absent codec silently accepted'; exit 1
fi
grep -q 'explicitly required' "$stage/missing.log" || { cat "$stage/missing.log"; exit 1; }
mkdir -p "$stage/incomplete/include"
printf 'fake\n' > "$stage/incomplete/include/lzma.h"
if WATCOM="$watcom" OS2_LZMA=auto OS2_LZMA_DIR="$stage/incomplete" \
    "$root/build-os2.sh" > "$stage/incomplete.log" 2>&1; then
  echo 'FAIL: incomplete codec installation silently accepted'; exit 1
fi
grep -q 'incomplete lzma installation' "$stage/incomplete.log" || { cat "$stage/incomplete.log"; exit 1; }
echo 'PASS: required missing and incomplete optional library both rejected'
