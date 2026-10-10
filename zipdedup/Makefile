# Make UnZip DLL-type objects, but link them statically into zipdedup!
# XXX: Needs a full build with bzip2, lzma, and zstd libraries, assumes cc is GCC!
CC = cc
CFLAGS = -O3 -std=c89 -pedantic -Wall -Wextra -flto=auto
ZD_METHODS = -DUSE_DEFLATE64 -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD -DUSE_PPMD -DUSE_WZMP3 -DUSE_WZJPEG
UZDIR = ../unzip60
UZFLAGS = -O3 -fPIC -DUNIX -DDLL -DLARGE_FILE_SUPPORT -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD
# ZipDedup builds its own UnZip objects: it must select and link the same
# external backend in BOTH the objects and the final executable.  Do not rely
# on the separately compiled UnZip executable, or on top-level build.sh.
# Values: auto, native, zlib, internal.  Explicit standard USE_ZLIB from
# LOCAL_UNZIP overrides native auto-detection.
ZD_BACKEND ?= auto
ZD_ZNG_CFLAGS = $(if $(IZ_ZLIBNG_CFLAGS),$(IZ_ZLIBNG_CFLAGS),$(shell pkg-config --cflags zlib-ng 2>/dev/null))
ZD_ZNG_LIBS = $(if $(IZ_ZLIBNG_LIBS),$(IZ_ZLIBNG_LIBS),$(shell pkg-config --libs zlib-ng 2>/dev/null || printf '%s' '-lz-ng'))
ZD_ZNG_FOUND := $(shell printf '#include <zlib-ng.h>\nint main(void) { zng_stream s = {0}; return (int)zng_crc32_z(0,0,0) + zng_deflateInit2(&s,1,Z_DEFLATED,-15,8,0); }\n' | $(CC) -D_GNU_SOURCE $(ZD_ZNG_CFLAGS) -x c - -o /dev/null $(ZD_ZNG_LIBS) >/dev/null 2>&1 && echo yes)
ifneq ($(filter -DUSE_ZLIB -DUSE_ZLIB=1,$(LOCAL_UNZIP)),)
  ifeq ($(ZD_BACKEND),auto)
    ZD_BACKEND := zlib
  endif
endif
ifneq ($(filter -DUSE_ZLIB_NG -DUSE_ZLIB_NG=1,$(LOCAL_UNZIP)),)
  ifeq ($(ZD_BACKEND),auto)
    ZD_BACKEND := native
  endif
endif
ifneq ($(filter -DNO_ZLIB_NG -DNO_ZLIB_NG=1,$(LOCAL_UNZIP)),)
  ifeq ($(ZD_BACKEND),auto)
    ZD_BACKEND := internal
  endif
endif
ifeq ($(ZD_BACKEND),auto)
  ifeq ($(ZD_ZNG_FOUND),yes)
    ZD_BACKEND := native
  else
    ZD_BACKEND := internal
  endif
endif
ifeq ($(ZD_BACKEND),native)
  ifneq ($(ZD_ZNG_FOUND),yes)
    $(error Native zlib-ng selected but its headers/library cannot link)
  endif
  ZD_BACKEND_FLAGS = -D_GNU_SOURCE -DUSE_ZLIB_NG $(ZD_ZNG_CFLAGS)
  ZD_BACKEND_LIBS = $(ZD_ZNG_LIBS)
else ifeq ($(ZD_BACKEND),zlib)
  ZD_BACKEND_FLAGS = -D_GNU_SOURCE -DUSE_ZLIB $(IZ_ZLIB_CFLAGS)
  ZD_BACKEND_LIBS = $(if $(IZ_ZLIB_LIBS),$(IZ_ZLIB_LIBS),-lz)
else ifeq ($(ZD_BACKEND),internal)
  ZD_BACKEND_FLAGS = -DNO_ZLIB_NG
  ZD_BACKEND_LIBS =
else
  $(error Unknown ZD_BACKEND=$(ZD_BACKEND))
endif
ifneq ($(filter -DUSE_ZLIB_NG -DUSE_ZLIB_NG=1,$(LOCAL_UNZIP)),)
  ifeq ($(ZD_BACKEND),zlib)
    $(error USE_ZLIB_NG and USE_ZLIB are mutually exclusive)
  endif
endif
LDLIBS = $(ZD_BACKEND_LIBS) -lbz2 -llzma -lzstd -flto=auto
UZOBJECTS = $(addprefix $(UZDIR)/,unzip.pic.o crc32.pic.o crypt.pic.o \
 envargs.pic.o explode.pic.o extract.pic.o fileio.pic.o globals.pic.o \
 inflate.pic.o list.pic.o match.pic.o process.pic.o ttyio.pic.o \
 ubz2err.pic.o unreduce.pic.o unshrink.pic.o zipinfo.pic.o unix.pic.o api.pic.o)
all: zipdedup
unzip-objects:
	$(MAKE) -B -C $(UZDIR) -f unix/Makefile objsdll CC="gcc -std=gnu89" CFLAGS="$(UZFLAGS) $(ZD_BACKEND_FLAGS)"
zipdedup: zipdedup.c refptr9903.c unzip-objects
	$(CC) $(CFLAGS) $(ZD_METHODS) $(ZD_BACKEND_FLAGS) -DUNIX -DDLL -I$(UZDIR) zipdedup.c refptr9903.c $(UZOBJECTS) -o $@ $(LDLIBS) $(LOCAL_GLDFLAGS)
clean:
	rm -f zipdedup test-refptr9903
.PHONY: all clean unzip-objects

test-refptr9903: refptr9903.c tests/test_refptr9903.c
	$(CC) $(CFLAGS) refptr9903.c tests/test_refptr9903.c -o $@
test: zipdedup test-refptr9903
	./test-refptr9903
	python3 tests/test_zipdedup.py
	python3 tests/test_refptr_metadata.py
.PHONY: test
