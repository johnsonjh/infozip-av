# Make UnZip DLL-type objects, but link them statically into zipdedup!
# Needs bzip2, lzma and zstd libraries; compiler defaults to cc.
ifneq ($(filter default undefined,$(origin CC)),)
CC = cc
endif
CFLAGS = -O3 -std=c89 -pedantic -Wall -Wextra -flto=auto
ZD_METHODS = -DUSE_DEFLATE64 -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD -DUSE_PPMD -DUSE_WZMP3 -DUSE_WZJPEG -DUSE_CMPSC16 -DUSE_LZFSE
UZDIR = ../unzip60
# CMPSC/LZFSE are selected by unzpriv.h according to target capability.
# LZFSE uses GCC/Clang C89-mode 64-bit integers on ILP32/LLP64 (Win32/Win64);
# only 16-bit and non-64-bit-integer compilers are excluded.
UZFLAGS = -std=gnu89 -O3 -fPIC -DUNIX -DDLL -DLARGE_FILE_SUPPORT -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD $(LOCAL_UNZIP)
# ZipDedup builds private UnZip-style objects.  ZD_BACKEND, not LOCAL_UNZIP,
# selects the external compression/CRC backend (auto/native/zlib/internal).
# LOCAL_UNZIP carries only CFLAGS and must not be interpreted as a backend.
ZD_BACKEND ?= auto
ZD_ZNG_CFLAGS = $(if $(IZ_ZLIBNG_CFLAGS),$(IZ_ZLIBNG_CFLAGS),$(shell pkg-config --cflags zlib-ng 2>/dev/null))
ZD_ZNG_LIBS = $(if $(IZ_ZLIBNG_LIBS),$(IZ_ZLIBNG_LIBS),$(shell pkg-config --libs zlib-ng 2>/dev/null || printf '%s' '-lz-ng'))
ZD_ZNG_FOUND := $(shell printf '#include <zlib-ng.h>\nint main(void) { zng_stream s = {0}; return (int)zng_crc32_z(0,0,0) + zng_deflateInit2(&s,1,Z_DEFLATED,-15,8,0); }\n' | $(CC) -D_GNU_SOURCE $(LOCAL_UNZIP) $(ZD_ZNG_CFLAGS) -x c - -o /dev/null $(ZD_ZNG_LIBS) $(LOCAL_GLDFLAGS) >/dev/null 2>&1 && echo yes)
ZD_SELECTED_BACKEND := $(ZD_BACKEND)
ifeq ($(ZD_SELECTED_BACKEND),auto)
  ifeq ($(ZD_ZNG_FOUND),yes)
    ZD_SELECTED_BACKEND := native
  else
    ZD_SELECTED_BACKEND := internal
  endif
endif
ifeq ($(ZD_SELECTED_BACKEND),native)
  ifneq ($(ZD_ZNG_FOUND),yes)
    $(error Native zlib-ng selected but its headers/library cannot link)
  endif
  ZD_BACKEND_FLAGS = -D_GNU_SOURCE -DUSE_ZLIB_NG $(ZD_ZNG_CFLAGS)
  ZD_BACKEND_LIBS = $(ZD_ZNG_LIBS)
else ifeq ($(ZD_SELECTED_BACKEND),zlib)
  ZD_BACKEND_FLAGS = -D_GNU_SOURCE -DUSE_ZLIB $(IZ_ZLIB_CFLAGS)
  ZD_BACKEND_LIBS = $(if $(IZ_ZLIB_LIBS),$(IZ_ZLIB_LIBS),-lz)
else ifeq ($(ZD_SELECTED_BACKEND),internal)
  ZD_BACKEND_FLAGS = -DNO_ZLIB_NG
  ZD_BACKEND_LIBS =
else
  $(error Unknown ZD_BACKEND=$(ZD_BACKEND))
endif
LDLIBS = $(ZD_BACKEND_LIBS) -lbz2 -llzma -lzstd -flto=auto
UZOBJECTS = $(addprefix $(UZDIR)/,unzip.pic.o crc32.pic.o crypt.pic.o \
 envargs.pic.o explode.pic.o extract.pic.o fileio.pic.o globals.pic.o \
 inflate.pic.o list.pic.o match.pic.o process.pic.o ttyio.pic.o \
 ubz2err.pic.o unreduce.pic.o unshrink.pic.o zipinfo.pic.o unix.pic.o api.pic.o)
all: zipdedup
unzip-objects:
	$(MAKE) -B -C $(UZDIR) -f unix/Makefile objsdll CC="$(CC)" CFLAGS="$(UZFLAGS) $(ZD_BACKEND_FLAGS)"
zipdedup: zipdedup.c refptr9903.c unzip-objects
	$(CC) $(CFLAGS) $(LOCAL_UNZIP) $(ZD_METHODS) $(ZD_BACKEND_FLAGS) -DUNIX -DDLL -I$(UZDIR) zipdedup.c refptr9903.c $(UZOBJECTS) -o $@ $(LDLIBS) $(LOCAL_GLDFLAGS)
clean:
	rm -f zipdedup test-refptr9903
.PHONY: all clean unzip-objects

test-refptr9903: refptr9903.c tests/test_refptr9903.c
	$(CC) $(CFLAGS) $(LOCAL_UNZIP) refptr9903.c tests/test_refptr9903.c -o $@ $(LOCAL_GLDFLAGS)
test: zipdedup test-refptr9903
	./test-refptr9903
	python3 tests/test_zipdedup.py
	python3 tests/test_refptr_metadata.py
	python3 tests/test_lzfse_cmpsc.py
.PHONY: test
