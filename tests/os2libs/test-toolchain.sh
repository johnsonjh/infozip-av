#!/bin/sh
# Verify CMake's Watcom C compilation and *multiple-object* static archive.
# This test intentionally contains no upstream codec source and does not run LX.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
watcom=${WATCOM:-/opt/watcom}
if [ -x "$watcom/binl64/wcc386" ]; then
  toolpath="$watcom/binl64"
elif [ -x "$watcom/binl/wcc386" ]; then
  toolpath="$watcom/binl"
else
  echo 'SKIP: OW2 compiler unavailable'; exit 77
fi
export WATCOM="$watcom" INCLUDE="$watcom/h:$watcom/h/os2"
PATH="$toolpath:$PATH"
export PATH
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/src/inc"
cat > "$stage/src/CMakeLists.txt" << 'CMAKE'
cmake_minimum_required(VERSION 3.20)
project(os2_link_test C)
include_directories(inc)
add_library(crossprobe STATIC one.c two.c)
CMAKE
printf '#define OS2_SAMPLE_MAGIC 123\n' > "$stage/src/inc/shared.h"
printf '#include "shared.h"\nint os2_one(void){return OS2_SAMPLE_MAGIC;}\n' > "$stage/src/one.c"
printf 'int os2_two(void){return 7;}\n' > "$stage/src/two.c"
cat > "$stage/src/main.c" << 'C'
extern int os2_one(void);
extern int os2_two(void);
int main(void) { return os2_one() - os2_two(); }
C
cmake -S "$stage/src" -B "$stage/build" \
  -DCMAKE_TOOLCHAIN_FILE="$root/tests/os2libs/watcom-toolchain.cmake" \
  -DCMAKE_C_FLAGS='-bt=os2 -3r -mf -zp1 -zq -fr -D__32BIT__' > "$stage/cmake.log" 2>&1 || {
  cat "$stage/cmake.log"; exit 1
}
cmake --build "$stage/build" >> "$stage/cmake.log" 2>&1 || {
  cat "$stage/cmake.log"; exit 1
}
wcc386 -bt=os2 -3r -mf -zp1 -zq -fr -fo="$stage/main.obj" "$stage/src/main.c" > "$stage/link.log" 2>&1 || {
  cat "$stage/link.log"; exit 1
}
{
  printf 'system os2v2\nname %s\nfile %s\nlibrary %s\n' \
    "$stage/probe.exe" "$stage/main.obj" "$stage/build/crossprobe.lib"
} > "$stage/link.lnk"
wlink "@$stage/link.lnk" >> "$stage/link.log" 2>&1 || {
  cat "$stage/link.log"; exit 1
}
python3 - "$stage/probe.exe" << 'PY'
import struct,sys
p=open(sys.argv[1],'rb').read()
assert p[:2] == b'MZ' and p[struct.unpack_from('<I',p,60)[0]:][:2] == b'LX'
PY
printf '%s\n' 'PASS: two-object OW2 library and OS/2 LX link'
