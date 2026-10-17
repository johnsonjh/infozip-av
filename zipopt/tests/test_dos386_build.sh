#!/bin/sh
# SPDX-License-Identifier: MIT-0
# Mock orchestration test only: not a DJGPP compiler or DOS runtime test.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/iz-dos386-XXXXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' 0
trap 'exit 1' 1 2 3 15
cat > "$tmp/gcc" << 'SH'
#!/bin/sh
out= last=
for arg do
  if [ "$last" = -o ]; then out=$arg; break; fi
  last=$arg
done
[ -n "$out" ] || exit 10
if [ "${MOCK_FAIL:-}" = "$(basename -- "$out")" ]; then exit 12; fi
printf 'mock-coff-data\n' > "$out"
SH
cat > "$tmp/exe2coff" << 'SH'
#!/bin/sh
set -eu
case $1 in *.exe) name=${1%.exe} ;; *) exit 1 ;; esac
[ -s "$1" ] || exit 2
if [ "${MOCK_COFF_FAIL:-}" = "$(basename -- "$1")" ]; then exit 5; fi
printf 'COFF' > "$name"
cat "$1" >> "$name"
SH
chmod +x "$tmp/gcc" "$tmp/exe2coff"
printf 'MZ-TEST-STUB' > "$tmp/cwsdstub.exe"
vars="DJGPP_CC=$tmp/gcc"
# Environment assignments are kept on the invocation; no eval needed.
DJGPP_CC="$tmp/gcc" DOS386_CWSDSTUB="$tmp/not-here" \
  DOS386_BUILD_ROOT="$tmp/without" "$root/build-dos386.sh" > "$tmp/no-stub.log" 2>&1
[ "$(find "$tmp/without/bin" -name '*.exe' | wc -l | tr -d ' ')" = 11 ]
DJGPP_CC="$tmp/gcc" DOS386_CWSDSTUB="$tmp/cwsdstub.exe" \
  DOS386_EXE2COFF="$tmp/exe2coff" DOS386_BUILD_ROOT="$tmp/with" \
  "$root/build-dos386.sh" > "$tmp/with-stub.log" 2>&1
[ "$(find "$tmp/with/bin" -name '*.exe' | wc -l | tr -d ' ')" = 11 ]
for exe in "$tmp/with/bin/"*.exe; do
  head -c 12 "$exe" | cmp - "$tmp/cwsdstub.exe"
done
cp "$tmp/with/bin/zipdedup.exe" "$tmp/old.exe"
if DJGPP_CC="$tmp/gcc" MOCK_FAIL=zipdedup.exe \
  DOS386_CWSDSTUB="$tmp/cwsdstub.exe" DOS386_EXE2COFF="$tmp/exe2coff" \
  DOS386_BUILD_ROOT="$tmp/with" "$root/build-dos386.sh" > "$tmp/fail.log" 2>&1; then
  echo 'build should fail' >&2
  exit 1
fi
cmp "$tmp/with/bin/zipdedup.exe" "$tmp/old.exe"
if DJGPP_CC="$tmp/gcc" MOCK_COFF_FAIL=zipdedup.exe \
  DOS386_CWSDSTUB="$tmp/cwsdstub.exe" DOS386_EXE2COFF="$tmp/exe2coff" \
  DOS386_BUILD_ROOT="$tmp/with" "$root/build-dos386.sh" > "$tmp/coff-fail.log" 2>&1; then
  echo 'exe2coff failure should fail' >&2
  exit 1
fi
cmp "$tmp/with/bin/zipdedup.exe" "$tmp/old.exe"
if DJGPP_CC="$tmp/gcc" DOS386_CWSDSTUB="$tmp/cwsdstub.exe" \
  DOS386_EXE2COFF="$tmp/missing-tool" DOS386_BUILD_ROOT="$tmp/unavailable" \
  "$root/build-dos386.sh" > "$tmp/bad-tool.log" 2>&1; then
  echo 'missing exe2coff should fail when stub is present' >&2
  exit 1
fi
# External codecs must appear in the main and embedded decoder builds.
mkdir -p "$tmp/codecs/bzip2" \
  "$tmp/codecs/lzma/include" "$tmp/codecs/lzma/lib" \
  "$tmp/codecs/wavpack/include/wavpack" "$tmp/codecs/wavpack/lib" \
  "$tmp/codecs/zstd/include" "$tmp/codecs/zstd/lib"
for f in \
  "$tmp/codecs/bzip2/bzlib.h" "$tmp/codecs/bzip2/libbz2.a" \
  "$tmp/codecs/lzma/include/lzma.h" "$tmp/codecs/lzma/lib/liblzma.a" \
  "$tmp/codecs/wavpack/include/wavpack/wavpack.h" \
  "$tmp/codecs/wavpack/lib/libwavpack.a" \
  "$tmp/codecs/zstd/include/zstd.h" "$tmp/codecs/zstd/lib/libzstd.a"; do
  printf 'mock-target-file\n' > "$f"
done
run_with_codecs()
{
  DJGPP_CC="$tmp/gcc" DOS386_BUILD_ROOT="$tmp/codecs-build" \
    DOS386_CWSDSTUB="$tmp/not-here" \
    DOS386_BZIP2=on DOS386_BZIP2_DIR="$tmp/codecs/bzip2" \
    DOS386_LZMA=on DOS386_LZMA_DIR="$tmp/codecs/lzma" \
    DOS386_WAVPACK=on DOS386_WAVPACK_DIR="$tmp/codecs/wavpack" \
    DOS386_ZSTD=on DOS386_ZSTD_DIR="$tmp/codecs/zstd" \
    "$root/build-dos386.sh" > "$tmp/codecs.log" 2>&1
}
run_with_codecs
for feature in bzip2 lzma wavpack zstd; do
  grep -q "build-dos386: enabled $feature:" "$tmp/codecs.log"
done
for flag in ZSTD_SUPPORT USE_ZSTD ZO_WITH_ZSTD \
  LZMA_SUPPORT USE_LZMA USE_XZ ZO_WITH_LZMA USE_WAVP; do
  grep -q -- "-D$flag" "$tmp/codecs.log" || {
    echo "missing $flag in DOS386 compilation" >&2; exit 1;
  }
done
[ "$(find "$tmp/codecs-build/bin" -name '*.exe' | wc -l | tr -d ' ')" = 11 ]
# The `on` setting must reject a missing external dependency.
rm -f "$tmp/codecs/zstd/lib/libzstd.a"
if run_with_codecs; then
  echo 'missing required Zstd must fail the DOS386 build' >&2
  exit 1
fi
grep -q 'missing target archive' "$tmp/codecs.log"
# Existing release binaries must survive an unsuccessful rebuild.
[ "$(find "$tmp/codecs-build/bin" -name '*.exe' | wc -l | tr -d ' ')" = 11 ]
printf 'mock-target-file\n' > "$tmp/codecs/zstd/lib/libzstd.a"
if MOCK_FAIL=probe-zstd.exe run_with_codecs; then
  echo 'failed required Zstd link probe must fail the DOS386 build' >&2
  exit 1
fi
grep -q 'DJGPP link probe failed' "$tmp/codecs.log"
# The optional direct-build mode must still permit non-required dependencies.
DJGPP_CC="$tmp/gcc" DOS386_BUILD_ROOT="$tmp/optional-build" \
  DOS386_CWSDSTUB="$tmp/not-here" DOS386_ZSTD=auto \
  "$root/build-dos386.sh" > "$tmp/optional.log" 2>&1
grep -q 'zstd unavailable:' "$tmp/optional.log"
printf 'DOS/386 build orchestration tests passed (mock compiler only)\n'
