#!/bin/sh

# This script is used by the maintainer and is unlikely
# to be useful to anyone else, at least in unmodified form.

##################################### Start ####################################

set -eux

##################################### Setup ####################################

rm -rf ./staging
mkdir -p ./staging

############################# Linux 32-bit static musl #########################

sudo ./clean.sh
docker run -it -h xtro-zip-build-alpine32 -v "$(pwd -P)":/work \
  -w /work xtro-zip-build-alpine32 sh -xc \
  'export LOCAL_ZIP="-D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -O3 -flto=auto"; \
   export LOCAL_UNZIP="-D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -O3 -flto=auto"; \
   export LOCAL_GLDFLAGS="-s -static -no-pie -flto=auto"; ./build-unix.sh'

sudo rm -f ./build/*.log ./build/.bzip2-backend
zip --fwkcs-md5 -9 ./staging/linux32.zip -r build

############################# Linux 64-bit static musl #########################

sudo ./clean.sh
docker run -it -h xtro-zip-build-alpine -v "$(pwd -P)":/work \
  -w /work xtro-zip-build-alpine sh -xc \
  'export LOCAL_ZIP="-O3 -flto=auto"; \
   export LOCAL_UNZIP="-O3 -flto=auto"; \
   export LOCAL_GLDFLAGS="-s -static -no-pie -flto=auto"; ./build-unix.sh'

sudo rm -f ./build/*.log ./build/.bzip2-backend || :
zip --fwkcs-md5 -9 ./staging/linux64.zip -r build

########################## Windows, DOS, and OS/2 builds #######################

sudo ./clean.sh
docker run -it -h xtro-zip-build-fedora -v "$(pwd -P)":/work \
  -w /work xtro-zip-build-fedora ./build-all.sh

zip --fwkcs-md5 --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -9 ./dos386.zip -r dos386
cat ./dos386/unzipsfx.exe ./dos386.zip > ./dos386.exe && zip -A ./dos386.exe
mv -f ./dos386.exe ./staging && rm -f ./dos386.zip

zip --fwkcs-md5 --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -9 ./dos16.zip -r ./dos16
cat ./dos16/unzipsfx.exe ./dos16.zip > ./dos16.exe && zip -A ./dos16.exe
mv -f ./dos16.exe ./staging && rm -f ./dos16.zip

zip --fwkcs-md5 --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -9 ./staging/win64.zip -r win64

zip --fwkcs-md5 --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -9 ./staging/win64ucrt.zip -r win64ucrt

zip --fwkcs-md5 --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -9 ./staging/win32.zip -r win32

sudo rm -f os2/zipopt-decodecheck.exe os2/zipopt-preflight.exe || :
zip --fwkcs-md5 --pkav-name 'Jeffrey H. Johnson <johnsonjh.dev@gmail.com>' \
  --pkav-s1 0uzsvg8 --pkav-s2 1xrdoyg -9 ./staging/os2.zip -r os2

#################################### Cleanup ###################################

sudo ./clean.sh

#################################### Display ###################################

for i in ./staging/*; do
  unzip -t "${i:?}"
done

ls -la ./staging

############################ Clear out GitHub Releases #########################

gh release delete-asset -y v0 dos16.exe || :
gh release delete-asset -y v0 dos386.exe || :
gh release delete-asset -y v0 linux32.zip || :
gh release delete-asset -y v0 linux64.zip || :
gh release delete-asset -y v0 os2.zip || :
gh release delete-asset -y v0 win32.zip || :
gh release delete-asset -y v0 win64ucrt.zip || :
gh release delete-asset -y v0 win64.zip || :

############################ Upload new GitHub Releases ########################

gh release upload --clobber v0 \
  ./staging/dos16.exe \
  ./staging/dos386.exe \
  ./staging/linux32.zip \
  ./staging/linux64.zip \
  ./staging/os2.zip \
  ./staging/win32.zip \
  ./staging/win64ucrt.zip \
  ./staging/win64.zip

sed "s|DATESTRING|$(date -u +'%Y-%m-%d %H:%M:%S UTC')|" ./.v0.md \
  | gh release edit v0 -F -

#################################### Finsished #################################
