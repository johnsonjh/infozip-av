# Make UnZip DLL-type objects, but link them statically into zipdedup!
# XXX: Needs a full build with bzip2, lzma, and zstd libraries, assumes cc is GCC!
CC = cc
CFLAGS = -O3 -std=c89 -pedantic -Wall -Wextra -flto=auto
ZD_METHODS = -DUSE_DEFLATE64 -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD -DUSE_PPMD -DUSE_WZMP3 -DUSE_WZJPEG
UZDIR = ../unzip60
UZFLAGS = -O3 -fPIC -DUNIX -DDLL -DLARGE_FILE_SUPPORT -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD
LDLIBS = -lbz2 -llzma -lzstd -flto=auto
UZOBJECTS = $(addprefix $(UZDIR)/,unzip.pic.o crc32.pic.o crypt.pic.o \
 envargs.pic.o explode.pic.o extract.pic.o fileio.pic.o globals.pic.o \
 inflate.pic.o list.pic.o match.pic.o process.pic.o ttyio.pic.o \
 ubz2err.pic.o unreduce.pic.o unshrink.pic.o zipinfo.pic.o unix.pic.o api.pic.o)
all: zipdedup
unzip-objects:
	$(MAKE) -B -C $(UZDIR) -f unix/Makefile objsdll CC="gcc -std=gnu89" CFLAGS="$(UZFLAGS)"
zipdedup: zipdedup.c refptr9903.c unzip-objects
	$(CC) $(CFLAGS) $(ZD_METHODS) -DUNIX -DDLL -I$(UZDIR) zipdedup.c refptr9903.c $(UZOBJECTS) -o $@ $(LDLIBS) $(LOCAL_GLDFLAGS)
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
