#!/bin/sh

set -eux

mkdir -p staging

############################# Linux 32-bit static musl #########################

sudo ./clean.sh

docker run -it -h xtro-zip-build-alpine32 -v "$(pwd -P)":/work \
  -w /work xtro-zip-build-alpine32 \
  sh -xc 'export LOCAL_ZIP="-D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -O3 -flto=auto"; \
    export LOCAL_UNZIP="-D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -O3 -flto=auto"; \
    export LOCAL_GLDFLAGS="-s -static -flto=auto"; ./build-unix.sh'

sudo rm -f build/*.log build/.bzip2-backend
zip --huffman-optimize-extra --fwkcs-md5 -11 --zopfli-iterations 20 \
  staging/linux32.zip -r build

############################# Linux 64-bit static musl #########################

sudo ./clean.sh

docker run -it -h xtro-zip-build-alpine -v "$(pwd -P)":/work \
  -w /work xtro-zip-build-alpine \
  sh -xc 'export LOCAL_ZIP="-O3 -flto=auto"; \
    export LOCAL_UNZIP="-O3 -flto=auto"; \
    export LOCAL_GLDFLAGS="-s -static -flto=auto"; ./build-unix.sh'

sudo rm -f build/*.log build/.bzip2-backend
zip --huffman-optimize-extra --fwkcs-md5 -11 --zopfli-iterations 20 \
  staging/linux64.zip -r build

########################## Windows, DOS, and OS/2 builds #######################

sudo ./clean.sh

docker run -it -h xtro-zip-build-fedora -v "$(pwd -P)":/work \
  -w /work xtro-zip-build-fedora ./build-all.sh

zip --huffman-optimize-extra --fwkcs-md5 \
  --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -11 --zopfli-iterations 20 \
  dos386.zip -r dos386
cat dos386/unzipsfx.exe dos386.zip > dos386.exe
zip -A dos386.exe
mv dos386.exe staging
rm -f dos386.zip

zip --huffman-optimize-extra --fwkcs-md5 \
  --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -11 --zopfli-iterations 20 \
  dos16.zip -r dos16
cat dos16/unzipsfx.exe dos16.zip > dos16.exe
zip -A dos16.exe
mv -f dos16.exe staging
rm -f dos16.zip

zip --huffman-optimize-extra --fwkcs-md5 \
  --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -11 --zopfli-iterations 20 \
  staging/win64.zip -r win64

zip --huffman-optimize-extra --fwkcs-md5 \
  --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -11 --zopfli-iterations 20 \
  staging/win64ucrt.zip -r win64ucrt

zip --huffman-optimize-extra --fwkcs-md5 \
  --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -11 --zopfli-iterations 20 \
  staging/win32.zip -r win32

sudo rm -f os2/zipopt-decodecheck.exe os2/zipopt-preflight.exe
zip --huffman-optimize-extra --fwkcs-md5 \
  --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -11 --zopfli-iterations 20 \
  staging/os2.zip -r os2

sudo ./clean.sh

for i in staging/*; do
  unzip -t "${i:?}"
done

ls -la staging
