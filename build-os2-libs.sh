#!/bin/sh
# Build optional OS/2 static codec libraries with Linux-hosted OW2.
# The upstream Git checkout and the generated objects are separate.
# Most recently cross-built (NOT native OS/2 runtime accepted):
#   xz       299eb5c3f597f107fd6019bf156885ac8bfaa5ea
#   zstd     49cf51799ea051457f57243527aa2058f999f005
#   wavpack  c9515833d1867d9ec03774d954369107f2e88a73
# Revisions are informational: fetch default-branch tip unless user chooses
# a detached commit, custom branch, or OS2_LIBS_FETCH=0.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
watcom=${WATCOM:-/opt/watcom}
[ -d "$watcom" ] || {
  echo "ERROR: WATCOM not found at $watcom" >&2; exit 1
}
watcom=$(CDPATH= cd -- "$watcom" && pwd -P)
export WATCOM="$watcom" INCLUDE="$watcom/h:$watcom/h/os2"
if [ -x "$watcom/binl64/wcc386" ]; then
  PATH="$watcom/binl64:$PATH"
elif [ -x "$watcom/binl/wcc386" ]; then
  PATH="$watcom/binl:$PATH"
else
  echo 'ERROR: wcc386 not found' >&2; exit 1
fi
export PATH
command -v cmake > /dev/null || {
  echo 'ERROR: cmake required' >&2; exit 1
}
command -v git > /dev/null || {
  echo 'ERROR: git required' >&2; exit 1
}
command -v python3 > /dev/null || {
  echo 'ERROR: python3 required for LX validation' >&2; exit 1
}
command -v patch > /dev/null || {
  echo 'ERROR: patch required for OW2 source adapters' >&2; exit 1
}
command -v tar > /dev/null || {
  echo 'ERROR: tar required for staging sources' >&2; exit 1
}
case "${OS2_DEBUG:-0}" in
0) opt='-d0 -ot -oe -ob -oc -oh -oi -ok -ol -ol+ -om -or -s' ;;
1) opt='-d2 -od' ;;
*)
  echo 'ERROR: OS2_DEBUG must be 0 or 1' >&2; exit 2
  ;;
esac
OS2_OPT_FLAGS=$opt
export OS2_OPT_FLAGS
case "${OS2_LIBS_FETCH:-1}" in 0 | 1) ;; *)
  echo 'ERROR: OS2_LIBS_FETCH must be 0 or 1' >&2; exit 2
  ;;
esac
case "${OS2_LIBS:-lzma zstd wavpack libdeflate}" in
*'/'* | *'..'*)
  echo 'ERROR: invalid OS2_LIBS' >&2; exit 2
  ;;
esac
work="$root/build-os2-libs"
mkdir -p "$work"
. "$root/tests/os2libs/probe-library.sh"

# Preserve intentional checked-out commits. Only update an existing checkout
# when it is clean and on its own remote's default branch with upstream set.
checkout()
{
  co_name=$1
  co_url=$2
  co_dir="$work/$co_name/source"
  if [ ! -d "$co_dir/.git" ]; then
    [ "${OS2_LIBS_FETCH:-1}" = 1 ] || {
      echo "ERROR: no local $co_name checkout (OS2_LIBS_FETCH=0)" >&2; return 1
    }
    [ ! -e "$co_dir" ] || {
      echo "ERROR: $co_dir exists but is not a Git checkout" >&2; return 1
    }
    mkdir -p "$work/$co_name"
    git clone --recursive "$co_url" "$co_dir" || return 1
  elif [ "${OS2_LIBS_FETCH:-1}" = 1 ]; then
    co_branch=$(git -C "$co_dir" symbolic-ref --quiet --short HEAD || :)
    co_default=$(git -C "$co_dir" symbolic-ref --quiet --short refs/remotes/origin/HEAD || :)
    co_tracking=$(git -C "$co_dir" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2> /dev/null || :)
    co_dirty=$(git -C "$co_dir" status --porcelain)
    if [ -n "$co_branch" ] && [ "origin/$co_branch" = "$co_default" ] \
      && [ "$co_tracking" = "$co_default" ] && [ -z "$co_dirty" ]; then
      echo "FETCH $co_name upstream default branch $co_branch (fast-forward only)"
      git -C "$co_dir" fetch origin || return 1
      git -C "$co_dir" merge --ff-only "$co_default" || return 1
    else
      echo "KEEP  $co_name checkout unchanged (custom/detached/dirty branch)"
    fi
  fi
  echo "COMMIT $co_name $(git -C "$co_dir" rev-parse HEAD)"
}

# Source adapters are maintained as minimal, context-checked patches under
# tests/os2libs/patches/, applied ONLY to disposable ow2-source staging copies.
# Upstream Git sources remain unmodified for checkout/fast-forward/rebasing.
# These adapters are tested with the three cross-build commits noted above.

# Find precisely a static library, with the CMake install name differing
# between upstream targets. Never accept an unrelated .lib as evidence.
find_archive()
{
  fa_build=$1
  fa_name=$2
  for fa_file in "$fa_build/$fa_name.lib" "$fa_build/lib$fa_name.lib" \
    "$fa_build/lib/lib$fa_name.lib" \
    "$fa_build/lib/$fa_name.lib"; do
    [ -s "$fa_file" ] && {
      printf '%s\n' "$fa_file"; return 0
    }
  done
  find "$fa_build" -type f \( -name "$fa_name.lib" -o -name "lib$fa_name.lib" \) -print | while IFS= read -r fa_file; do
    [ -s "$fa_file" ] && {
      printf '%s\n' "$fa_file"; break
    }
  done
}

build_codec()
{
  bc_name=$1
  case "$bc_name" in
  lzma)
    bc_url=https://codeberg.org/tukaani/xz
    bc_target=liblzma
    bc_cmake=.
    bc_opts='-DTUKLIB_CPUCORES_FOUND:INTERNAL=1 -DHAVE___BUILTIN_BSWAPXX:INTERNAL=0 -DHAVE___BUILTIN_ASSUME_ALIGNED:INTERNAL=0 -DXZ_LZIP_DECODER=OFF -DXZ_MICROLZMA_ENCODER=OFF -DXZ_MICROLZMA_DECODER=OFF -DXZ_NLS=OFF -DXZ_TOOL_XZ=OFF -DXZ_TOOL_XZDEC=OFF -DXZ_TOOL_LZMADEC=OFF -DXZ_TOOL_LZMAINFO=OFF -DXZ_DOC=OFF -DXZ_THREADS=no -DXZ_ASM_I386=OFF'
    ;;
  zstd)
    bc_url=https://github.com/facebook/zstd
    bc_target=libzstd_static
    bc_cmake=build/cmake
    bc_opts='-DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_TESTS=OFF -DZSTD_MULTITHREAD_SUPPORT=OFF'
    ;;
  wavpack)
    bc_url=https://github.com/dbry/wavpack
    bc_target=wavpack
    bc_cmake=.
    bc_opts='-DHAVE___BUILTIN_CLZ:INTERNAL=0 -DWAVPACK_BUILD_PROGRAMS=OFF -DWAVPACK_BUILD_COOLEDIT_PLUGIN=OFF -DWAVPACK_BUILD_WINAMP_PLUGIN=OFF -DWAVPACK_ENABLE_ASM=OFF -DWAVPACK_ENABLE_THREADS=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF'
    ;;
  libdeflate)
    bc_url=https://github.com/ebiggers/libdeflate
    bc_target=libdeflate_static
    bc_cmake=.
    bc_opts='-DLIBDEFLATE_BUILD_STATIC_LIB=ON -DLIBDEFLATE_BUILD_SHARED_LIB=OFF -DLIBDEFLATE_BUILD_GZIP=OFF -DLIBDEFLATE_BUILD_TESTS=OFF -DLIBDEFLATE_INSTALL=OFF -DCMAKE_C_FLAGS_RELEASE:STRING='
    ;;
  *)
    echo "ERROR: unknown codec $bc_name" >&2; return 2
    ;;
  esac
  checkout "$bc_name" "$bc_url" || return 1
  bc_root="$work/$bc_name"
  bc_checkout="$bc_root/source"
  bc_src="$bc_root/ow2-source"
  bc_build="$bc_root/build"
  bc_install="$bc_root/install"
  # Never leave stale, accepted libraries after an unsuccessful rebuild.
  rm -rf "$bc_build" "$bc_install" "$bc_src"
  mkdir -p "$bc_build" "$bc_src" "$bc_install/include" "$bc_install/lib"
  # Compile an independently staged source snapshot. Never patch, reset, or
  # clean an upstream Git checkout; respect user-selected revisions.
  if ! (cd "$bc_checkout" && tar --exclude='./.git' -cf - .) | (cd "$bc_src" && tar -xf -); then
    echo "ERROR: failed staging source for $bc_name" >&2
    rm -rf "$bc_install" "$bc_src"
    return 1
  fi
  bc_portpatch="$root/tests/os2libs/patches/$bc_name-ow2.patch"
  if [ -s "$bc_portpatch" ]; then
    if ! (cd "$bc_src" && patch --batch --fuzz=0 -p1 < "$bc_portpatch"); then
      echo "ERROR: OW2 compatibility patch no longer applies to $bc_name; update it or check out the recorded known-building commit" >&2
      rm -rf "$bc_install" "$bc_src"
      return 1
    fi
  fi
  bc_log="$bc_root/build.log"
  echo "BUILD $bc_name; logging to $bc_log"
  if ! cmake -S "$bc_src/$bc_cmake" -B "$bc_build" \
    -DCMAKE_TOOLCHAIN_FILE="$root/tests/os2libs/watcom-toolchain.cmake" \
    -DCMAKE_BUILD_TYPE= \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_FLAGS="-bt=os2 -za99 -ei -3r -mf -zp1 -zq -fr -D__32BIT__ -DNO_ASM -DZSTD_DISABLE_DEPRECATE_WARNINGS $opt" \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
    $bc_opts > "$bc_log" 2>&1; then
    echo "ERROR: $bc_name configure failed; see $bc_log" >&2
    tail -45 "$bc_log" >&2
    rm -rf "$bc_install"; return 1
  fi
  if ! cmake --build "$bc_build" --target "$bc_target" --parallel "${OS2_LIBS_JOBS:-2}" >> "$bc_log" 2>&1; then
    echo "ERROR: $bc_name compile failed; see $bc_log" >&2
    tail -45 "$bc_log" >&2
    rm -rf "$bc_install"; return 1
  fi
  # Upstream libdeflate calls its static archive deflate.lib, but our
  # staged installation uses libdeflate.lib for unambiguous detection.
  bc_archive_name=$bc_name
  [ "$bc_name" != libdeflate ] || bc_archive_name=deflate
  bc_archive=$(find_archive "$bc_build" "$bc_archive_name")
  if [ -z "$bc_archive" ]; then
    echo "ERROR: $bc_name static archive not found (build may have changed target naming)" >&2
    rm -rf "$bc_install"; return 1
  fi
  case "$bc_name" in
  lzma)
    [ -f "$bc_src/src/liblzma/api/lzma.h" ] || return 1
    cp "$bc_src/src/liblzma/api/lzma.h" "$bc_install/include/"
    cp -R "$bc_src/src/liblzma/api/lzma" "$bc_install/include/"
    bc_name_out=liblzma.lib
    ;;
  zstd)
    cp "$bc_src/lib/zstd.h" "$bc_src/lib/zstd_errors.h" "$bc_install/include/"
    bc_name_out=libzstd.lib
    ;;
  wavpack)
    mkdir -p "$bc_install/include/wavpack"
    if [ -f "$bc_src/include/wavpack/wavpack.h" ]; then
      cp "$bc_src/include/wavpack/wavpack.h" "$bc_install/include/wavpack/"
    elif [ -f "$bc_src/include/wavpack.h" ]; then
      cp "$bc_src/include/wavpack.h" "$bc_install/include/wavpack/"
    else
      echo 'ERROR: WavPack public header missing' >&2; return 1
    fi
    bc_name_out=libwavpack.lib
    ;;
  libdeflate)
    [ -s "$bc_src/libdeflate.h" ] || {
      echo 'ERROR: libdeflate public header missing' >&2; return 1
    }
    cp "$bc_src/libdeflate.h" "$bc_install/include/"
    bc_name_out=libdeflate.lib
    ;;
  esac
  cp "$bc_archive" "$bc_install/lib/$bc_name_out"
  if ! probe_os2_library "$bc_name" "$bc_install" "$bc_root/probe" "$root"; then
    echo "ERROR: $bc_name OW2 target link probe FAILED; see $bc_root/probe/probe-$bc_name.log" >&2
    rm -rf "$bc_install"; return 1
  fi
  git -C "$bc_checkout" rev-parse HEAD > "$bc_install/built-from-commit.txt"
  echo "PASS $bc_name OS/2 LX link probe ($(cat "$bc_install/built-from-commit.txt"))"
}

bad=0
for lib in ${OS2_LIBS:-lzma zstd wavpack libdeflate}; do
  case "$lib" in lzma | zstd | wavpack | libdeflate) ;; *)
    echo "ERROR: unknown OS2_LIBS item '$lib'" >&2; exit 2
    ;;
  esac
  if ! build_codec "$lib"; then bad=1; fi
done
if [ "$bad" -ne 0 ]; then
  echo 'ERROR: at least one requested OS/2 library failed; successful libraries remain staged' >&2
  exit 1
fi
echo 'OS/2 optional libraries built and link-probed; run ./build-os2.sh next'
