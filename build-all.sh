#!/bin/sh

# This script is used by the maintainer and is unlikely
# to be useful to anyone else, at least in unmodified form.

# Reject a malformed reproducibility epoch before building any dependency.
iz_sde_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
sh "$iz_sde_root/tests/source-date-epoch-build.sh" validate || exit 2

set -ex

################################################################################

export WIN32_BZIP2_DIR="$(pwd -P)/build-win32/bzip2"
export WIN32_LZMA_DIR="$(pwd -P)/build-win32/lzma/install"
export WIN32_WAVPACK_DIR="$(pwd -P)/build-win32/wavpack/install"
export WIN32_ZLIBNG_DIR="$(pwd -P)/build-win32/zlib-ng/install"
export WIN32_ZSTD_DIR="$(pwd -P)/build-win32/zstd/install"
export WIN32_LIBDEFLATE_DIR="$(pwd -P)/build-win32/libdeflate/install"

################################################################################

CPUS="$(nproc)"

################################################################################

export LOCAL_ZIP="-O3 -flto=auto"
export LOCAL_UNZIP="-O3 -flto=auto"
export LOCAL_GLDFLAGS="-s -flto=auto"

################################################################################

DOS16_WATCOM=${WATCOM:-/opt/watcom}
if ! {
  test -x "$DOS16_WATCOM/binl64/wcc" \
    && test -x "$DOS16_WATCOM/binl64/wlink"
} \
  && ! {
    test -x "$DOS16_WATCOM/binl/wcc" \
      && test -x "$DOS16_WATCOM/binl/wlink"
  }; then
  printf 'ERROR: Open Watcom V2 not found in %s.\n' "$DOS16_WATCOM" >&2
  exit 1
fi

################################################################################

# Check for git

command -v git > /dev/null 2>&1 \
  || {
    printf '%s\n' "ERROR: git is required but not found."
    exit 1
  }

"$(command -v git)" --version > /dev/null 2>&1 \
  || {
    printf '%s\n' "ERROR: Working git tool required but not found."
    exit 1
  }

################################################################################

test -d ./.git > /dev/null 2>&1 || {
  printf '%s\n' "ERROR: No .git directory."
  exit 1
}

################################################################################

# Check for cwsdstub.exe

test -f /opt/cwsdpmi/cwsdstub.exe || {
  printf '%s\n' "ERROR: /opt/cwsdpmi/cwsdstub.exe not found."
  exit 1
}

################################################################################

"$(command -v /opt/djgpp/bin/i586-pc-msdosdjgpp-gcc)" --version > /dev/null 2>&1 \
  || {
    printf '%s\n' "ERROR: CC=/opt/djgpp/bin/i586-pc-msdosdjgpp-gcc not found."
    exit 1
  }

################################################################################

"$(command -v i686-w64-mingw32-gcc)" --version > /dev/null 2>&1 \
  || {
    printf '%s\n' "ERROR: i686-w64-mingw32-gcc not found."
    exit 1
  }

################################################################################

"$(command -v x86_64-w64-mingw32ucrt-gcc)" --version > /dev/null 2>&1 \
  || {
    printf '%s\n' "ERROR: i686-w64-mingw32-gcc not found."
    exit 1
  }

################################################################################

"$(command -v x86_64-w64-mingw32-gcc)" --version > /dev/null 2>&1 \
  || {
    printf '%s\n' "ERROR: i686-w64-mingw32-gcc not found."
    exit 1
  }

################################################################################

# Cleanup

./clean.sh

################################################################################

# local UNIX build

./build-unix.sh

################################################################################

# Windows build

build_libdeflate()
{
  ld_root="$(pwd -P)/$1"
  ld_system=$2
  ld_flags=$3
  test -d "$ld_root" \
    || git clone https://github.com/ebiggers/libdeflate "$ld_root"
  test -d "$ld_root/.git" || {
    printf '%s\n' "ERROR: libdeflate source is not a git checkout: $ld_root" >&2
    return 1
  }
  if [ "$ld_system" = Generic ]; then
    # Upstream x86 detector invokes CPUID. On a 386 or early 486 this raises #UD.
    # Disabling CPUID compiles AVX/SSE routines with alignments DJGPP cannot emit.
    # Build the scalar x86-independent implementation for DOS386 only.
    ld_flags="$ld_flags -DLIBDEFLATE_PORTABLE_X86"
  fi
  (
    cd "$ld_root" || exit 1
    git clean -fdx || exit 1
    if [ "$ld_system" = Generic ]; then
      for ld_patch in "$iz_sde_root/tests/libdeflate-no-cpuid.patch" \
                      "$iz_sde_root/tests/libdeflate-386-scalar.patch"; do
        if git apply --check "$ld_patch" > /dev/null 2>&1; then
          git apply "$ld_patch" || exit 1
        elif git apply --reverse --check "$ld_patch" > /dev/null 2>&1; then
          # git clean removes build outputs, not edits to tracked files.
          # Each patch may already be applied in a reused checkout.
          :
        else
          printf 'ERROR: libdeflate DJGPP patch does not apply: %s\n' "$ld_patch" >&2
          exit 1
        fi
      done
    fi
    cmake -S . -B build-xtro \
      -DCMAKE_SYSTEM_NAME="$ld_system" \
      -DCMAKE_C_COMPILER="${CC:?}" \
      -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="$ld_flags" \
      -DCMAKE_C_FLAGS_RELEASE:STRING= \
      -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
      -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
      -DLIBDEFLATE_BUILD_GZIP=OFF \
      -DLIBDEFLATE_BUILD_TESTS=OFF \
      -DLIBDEFLATE_INSTALL=OFF \
      && cmake --build build-xtro --target libdeflate_static \
        --parallel "${CPUS:-1}" \
      && test -s build-xtro/libdeflate.a \
      && test -s libdeflate.h \
      && mkdir -p install/include install/lib \
      && cp libdeflate.h install/include/ \
      && cp build-xtro/libdeflate.a install/lib/
  )
}

winbuild()
{
  # Setup
  mkdir -p ./build-win32

  # bzip2
  test -d build-win32/bzip2 \
    || git clone --recursive git://sourceware.org/git/bzip2.git \
      build-win32/bzip2
  (cd build-win32/bzip2 \
    && make clean \
    && make CC="${CC:?}" \
      CFLAGS="-D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -O3 -flto=auto -D_FILE_OFFSET_BITS=64" \
      LDFLAGS="-O3 -flto=auto" -j "${CPUS:-1}" libbz2.a)

  # WavPack
  test -d build-win32/wavpack \
    || git clone https://github.com/dbry/wavpack build-win32/wavpack
  (cd build-win32/wavpack \
    && git clean -fdx \
    && rm -rf ./install \
    && {
      test -x ./configure || autoreconf -vfi
    } \
    && env CC="${CC:?}" CFLAGS="-D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -O3 -flto=auto" LDFLAGS="-O3 -flto=auto" \
      ./configure --disable-apps --disable-shared --enable-static \
      --disable-threads --host="${HOST:?}" --prefix="$(pwd -P)"/install \
    && make -j "${CPUS:-1}" \
    && make install PREFIX="$(pwd -P)"/install)

  # LZMA
  test -d build-win32/lzma \
    || git clone https://codeberg.org/tukaani/xz build-win32/lzma
  (cd build-win32/lzma \
    && rm -rf ./install \
    && git clean -fdx \
    && {
      test -x ./configure || autoreconf -vfi
    } \
    && env CC="${CC:?}" CFLAGS="-D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -O3 -flto=auto" LDFLAGS="-O3 -flto=auto" \
      ./configure --disable-shared --enable-static --disable-nls \
      --host="${HOST:?}" --prefix="$(pwd -P)/install" \
    && make -j "${CPUS:-1}" \
    && make install "$(pwd -P)"/install)

  # zlib-ng
  test -d build-win32/zlib-ng \
    || git clone https://github.com/zlib-ng/zlib-ng build-win32/zlib-ng
  (cd build-win32/zlib-ng \
    && rm -rf ./install \
    && git clean -fdx \
    && {
      test -x ./configure || autoreconf -vfi
    } \
    && env CC="${CC:?}" ./configure --prefix="$(pwd -P)/install" \
    && make -j "${CPUS:-1}" \
    && make install "$(pwd -P)"/install)

  # zstd
  test -d build-win32/zstd \
    || git clone https://github.com/facebook/zstd build-win32/zstd
  (cd build-win32/zstd \
    && rm -rf ./install \
    && git clean -fdx \
    && env HAVE_THREAD=0 cmake -S build/cmake -B build-mingw \
      -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_C_COMPILER="${CC:?}" \
      -D"CMAKE_CXX_FLAGS=" \
      -DCMAKE_C_FLAGS="-D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -O3 -flto=auto" \
      -DCMAKE_STATIC_LINKER_FLAGS="-flto=auto" \
      -DCMAKE_INSTALL_PREFIX="$(pwd -P)/install" \
      -DZSTD_BUILD_PROGRAMS=OFF \
      -DZSTD_BUILD_SHARED=OFF \
      -DZSTD_MULTITHREAD_SUPPORT=OFF \
      -DZSTD_BUILD_STATIC=ON \
    && cmake --build build-mingw --target install \
      --parallel "$(nproc)" --verbose)

  # libdeflate (static, no programs or DLL). The target link probe in
  # build-win32.sh must succeed; do not silently omit it from this build.
  build_libdeflate build-win32/libdeflate Windows \
    "-D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -O3 -flto=auto"

  env \
    LOCAL_ZIP="${LOCAL_ZIP:-} -DXTR_WIN_NATIVE" \
    LOCAL_UNZIP="${LOCAL_UNZIP:-} -DXTR_WIN_NATIVE -DXTR_WIN_UTF8_PATHS" \
    WIN32_LIBDEFLATE=on \
    MINGW_TARGET=x86_64-w64-mingw32 \
    MINGW_CC="${CC:?}" ./build-win32.sh

  test "${CC:?}" = "x86_64-w64-mingw32ucrt-gcc" && {
    mv -f ./build-win32/x86_64-w64-mingw32 \
      ./build-win32/x86_64-w64-mingw32ucrt
  } || :
}

################################################################################

# 32-bit MSVCRT

export HOST="i686-w64-mingw32"
export CC="i686-w64-mingw32-gcc"
export MINGW_WINDRES="i686-w64-mingw32-windres"
winbuild
rm -rf ./win32
mv -f ./build-win32/x86_64-w64-mingw32/bin ./win32
rm -f ./win32/zipopt-decodecheck.exe
rm -f ./win32/zipopt-preflight.exe
cp -f ./win32/unzip.exe ./win32/zipinfo.exe

# 64-bit MSVCRT

export HOST="x86_64-w64-mingw32"
export CC="x86_64-w64-mingw32-gcc"
export MINGW_WINDRES="x86_64-w64-mingw32-windres"
winbuild
rm -rf ./win64
mv -f ./build-win32/x86_64-w64-mingw32/bin/ ./win64
rm -f ./win64/zipopt-decodecheck.exe
rm -f ./win64/zipopt-preflight.exe
cp -f ./win64/unzip.exe ./win64/zipinfo.exe

# 64-bit UCRT

export HOST="x86_64-w64-mingw32ucrt"
export CC="x86_64-w64-mingw32ucrt-gcc"
export MINGW_WINDRES="x86_64-w64-mingw32ucrt-windres"
winbuild
rm -rf ./win64ucrt
mv -f ./build-win32/x86_64-w64-mingw32ucrt/bin ./win64ucrt
rm -f ./win64ucrt/zipopt-decodecheck.exe
rm -f ./win64ucrt/zipopt-preflight.exe
cp -f ./win64ucrt/unzip.exe ./win64ucrt/zipinfo.exe

# Compress stubs

upx -qq --best ./win*/unzipsfx.exe || :

################################################################################

# DOS (DJGPP 386) build

# Setup
export HOST=i586-pc-msdosdjgpp
export CC=/opt/djgpp/bin/i586-pc-msdosdjgpp-gcc
mkdir -p build-dos386

# bzip2
test -d build-dos386/bzip2 \
  || git clone --recursive git://sourceware.org/git/bzip2.git \
    build-dos386/bzip2
(cd build-dos386/bzip2 \
  && make clean \
  && make CC="${CC:?}" \
    CFLAGS="-march=i386 -O3 -flto=auto -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-march=i386 -O3 -flto=auto" -j "${CPUS:-1}" libbz2.a)

# WavPack
test -d build-dos386/wavpack \
  || git clone https://github.com/dbry/wavpack build-dos386/wavpack
(cd build-dos386/wavpack \
  && git clean -fdx \
  && rm -rf ./install \
  && {
    test -x ./configure || autoreconf -vfi
  } \
  && env CC="${CC:?}" CFLAGS="-march=i386 -O3 -flto=auto" LDFLAGS="-O3 -flto=auto" \
    ./configure --disable-apps --disable-shared --enable-static \
    --disable-threads --disable-asm --host="${HOST:?}" --prefix="$(pwd -P)"/install \
  && make -j "${CPUS:-1}" \
  && make install PREFIX="$(pwd -P)"/install)

# LZMA
test -d build-dos386/lzma \
  || git clone https://codeberg.org/tukaani/xz build-dos386/lzma
(cd build-dos386/lzma \
  && rm -rf ./install \
  && git clean -fdx \
  && {
    test -x ./configure || autoreconf -vfi
  } \
  && env CC="${CC:?}" CFLAGS="-march=i386 -Wno-incompatible-pointer-types -O3 -flto=auto" LDFLAGS="-O3 -flto=auto" \
    ./configure --disable-shared --enable-static --enable-threads=no --disable-clmul-crc --disable-nls \
    --host="${HOST:?}" --prefix="$(pwd -P)/install" \
  && make -j "${CPUS:-1}" \
  && make install "$(pwd -P)"/install)

# zstd: build only the static library with DOS-target objects, no threading or
# target-specific assembly.  Use the upstream makefiles instead of host CMake.
test -d build-dos386/zstd \
  || git clone https://github.com/facebook/zstd build-dos386/zstd
(cd build-dos386/zstd \
  && git clean -fdx \
  && rm -rf ./install \
  && make -C lib -j "${CPUS:-1}" libzstd.a \
    CC="${CC:?}" AR="$(dirname "${CC:?}")/${HOST:?}-ar" \
    CFLAGS="-march=i386 -O3 -flto=auto" ZSTD_NO_ASM=1 ZSTD_LEGACY_SUPPORT=0 \
  && mkdir -p install/include install/lib \
  && cp lib/zstd.h lib/zstd_errors.h install/include/ \
  && cp lib/libzstd.a install/lib/)

# libdeflate: use the DJGPP compiler, not the native host compiler.  CMake's
# Generic target and static-only try-compiles avoid attempting to execute a
# DOS program on the build host; build-dos386.sh performs the real link probe.
build_libdeflate build-dos386/libdeflate Generic \
  "-march=i386 -O3 -flto=auto"

# Release builds require every selected external codec. An unsuccessful target
# link probe must fail the build, not silently publish reduced-feature EXEs.
env LOCAL_ZIP="-march=i386 -O3 -flto=auto" \
  LOCAL_UNZIP="-march=i386 -O3 -flto=auto" \
  LOCAL_GLDFLAGS="-march=i386 -s -flto=auto" \
  DOS386_BZIP2="${DOS386_BZIP2:-on}" \
  DOS386_LZMA="${DOS386_LZMA:-on}" \
  DOS386_WAVPACK="${DOS386_WAVPACK:-on}" \
  DOS386_ZSTD="${DOS386_ZSTD:-on}" \
  DOS386_LIBDEFLATE=on \
  ./build-dos386.sh
rm -rf ./dos386
mv -f ./build-dos386/bin dos386
cp -f ./dos386/unzip.exe ./dos386/zipinfo.exe
rm -f ./dos386/zipopt-preflight.exe
rm -f ./dos386/zipopt-decodecheck.exe

# Compress stub

upx -qq --best ./dos386/unzipsfx.exe || :

# 16-bit DOS build

env DOS16_EXPERIMENTAL_ZIPDEDUP=1 ./build-dos16.sh

# OS/2

./build-os2-libs.sh
./build-os2.sh
lxlite /S /C- /LA- /MR3 /ML1 /MF1 /P- /B- /Y os2/unzipsfx.exe || :

# Done

printf '%s\n' "Done" || :
