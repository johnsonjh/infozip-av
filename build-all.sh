#!/bin/sh

set -ex

################################################################################

export WIN32_BZIP2_DIR="$(pwd -P)/build-win32/bzip2"
export WIN32_LZMA_DIR="$(pwd -P)/build-win32/lzma/install"
export WIN32_WAVPACK_DIR="$(pwd -P)/build-win32/wavpack/install"
export WIN32_ZLIBNG_DIR="$(pwd -P)/build-win32/zlib-ng/install"
export WIN32_ZSTD_DIR="$(pwd -P)/build-win32/zstd/install"

################################################################################

CPUS="$(nproc)"

################################################################################

export LOCAL_ZIP="-O3 -flto=auto"
export LOCAL_UNZIP="-O3 -flto=auto"
export LOCAL_GLDFLAGS="-s -flto=auto"

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
      --disable-threads --prefix="$(pwd -P)"/install \
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
      ./configure --disable-shared --enable-static \
      --prefix="$(pwd -P)/install" \
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
      --parallel $(nproc) --verbose)

  env MINGW_TARGET=x86_64-w64-mingw32 \
    MINGW_CC="${CC:?}" ./build-win32.sh

  test "${CC:?}" = "x86_64-w64-mingw32ucrt-gcc" && {
    mv -f ./build-win32/x86_64-w64-mingw32 \
      ./build-win32/x86_64-w64-mingw32ucrt
  } || :
}

################################################################################

# 32-bit MSVCRT

export CC="i686-w64-mingw32-gcc"
export MINGW_WINDRES="i686-w64-mingw32-windres"
winbuild
rm -rf ./win32
mv -f ./build-win32/x86_64-w64-mingw32/bin ./win32
rm -f ./win32/zipopt-decodecheck.exe
rm -f ./win32/zipopt-preflight.exe
cp -f ./win32/unzip.exe ./win32/zipinfo.exe

# 64-bit MSVCRT

export CC="x86_64-w64-mingw32-gcc"
export MINGW_WINDRES="x86_64-w64-mingw32-windres"
winbuild
rm -rf ./win64
mv -f ./build-win32/x86_64-w64-mingw32/bin/ ./win64
rm -f ./win64/zipopt-decodecheck.exe
rm -f ./win64/zipopt-preflight.exe
cp -f ./win64/unzip.exe ./win64/zipinfo.exe

# 64-bit UCRT

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
export CC=/opt/djgpp/bin/i586-pc-msdosdjgpp-gcc
mkdir -p build-dos386

# bzip2
test -d build-dos386/bzip2 \
  || git clone --recursive git://sourceware.org/git/bzip2.git \
    build-dos386/bzip2
(cd build-dos386/bzip2 \
  && make clean \
  && make CC="${CC:?}" \
    CFLAGS="-O3 -flto=auto -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-O3 -flto=auto" -j "${CPUS:-1}" libbz2.a)

# WavPack
test -d build-dos386/wavpack \
  || git clone https://github.com/dbry/wavpack build-dos386/wavpack
(cd build-dos386/wavpack \
  && git clean -fdx \
  && rm -rf ./install \
  && {
    test -x ./configure || autoreconf -vfi
  } \
  && env CC="${CC:?}" CFLAGS="-O3 -flto=auto" LDFLAGS="-O3 -flto=auto" \
    ./configure --disable-apps --disable-shared --enable-static \
    --disable-threads --prefix="$(pwd -P)"/install \
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
  && env CC="${CC:?}" CFLAGS="-Wno-incompatible-pointer-types -O3 -flto=auto" LDFLAGS="-O3 -flto=auto" \
    ./configure --disable-shared --enable-static --enable-threads=no --disable-clmul-crc \
    --prefix="$(pwd -P)/install" \
  && make -j "${CPUS:-1}" \
  && make install "$(pwd -P)"/install)

./build-dos386.sh
rm -rf ./dos386
mv -f ./build-dos386/bin dos386
cp -f ./dos386/unzip.exe ./dos386/zipinfo.exe

# Compress stub

upx -qq --best ./dos386/unzipsfx.exe || :
