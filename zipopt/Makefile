# zipopt — private, in-process UnZip build (early implementation stages)
# SPDX-License-Identifier: MIT-0
CC ?= cc
CFLAGS ?= -O2 -std=c89 -Wall -Wextra
CPPFLAGS += -D_FILE_OFFSET_BITS=64
UZDIR = ../unzip60
UZFLAGS = -std=gnu89 -O2 -I$(UZDIR) -DUNIX -DDLL -DZIPOPT_EMBED -DNO_EXCEPT_SIGNALS -DLARGE_FILE_SUPPORT -DNO_ZLIB_NG -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD
UZUNITS = unzip crc32 crypt envargs explode extract fileio globals inflate list match process ttyio ubz2err unreduce unshrink zipinfo api unix
UZOBJS = $(addprefix build/uz-,$(addsuffix .o,$(UZUNITS)))
# UnZip frequently changes codec declarations in headers.  Generate private
# dependency files so rebuilding zipopt cannot silently reuse stale objects.
UZDEPS = $(UZOBJS:.o=.d)
# The compressors are directly included C/INC files, not separate object
# targets.  Track them, so changes to Zip's encoders rebuild both clients.
CODEC_DEPS = $(wildcard ../zip30/shrink.c ../zip30/reduce.c \
    ../zip30/implode6.c ../zip30/deflate64.c ../zip30/d64opt.inc \
    ../zip30/d64split.inc ../zip30/pkdcl.c ../zip30/ppmd8.c \
    ../zip30/ppmd8enc.c ../zip30/zopfli.c ../zip30/deflate64.h \
    ../zip30/pkdcl.h ../zip30/ppmd8.h ../zip30/zopfli.h)
LDLIBS += -lbz2 -llzma -lzstd

all: zipopt zipopt-preflight zipopt-decodecheck
zipopt: archive.c archive.h extract.c extract.h writer.c writer.h codec.c codec.h $(CODEC_DEPS) display.h zipopt.c $(UZOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) archive.c extract.c writer.c -DZO_SHARED_UNZIP_CODECS codec.c zipopt.c $(UZOBJS) $(LDLIBS) -lm -o $@
zipopt-preflight: archive.c archive.h preflight.c
	$(CC) $(CPPFLAGS) $(CFLAGS) archive.c preflight.c -o $@
zipopt-decodecheck: archive.c archive.h extract.c extract.h decodecheck.c $(UZOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) archive.c extract.c decodecheck.c $(UZOBJS) $(LDLIBS) -o $@
build:
	mkdir -p $@
build/uz-unix.o: $(UZDIR)/unix/unix.c | build
	$(CC) $(UZFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c $(UZDIR)/unix/unix.c -o $@
build/uz-%.o: $(UZDIR)/%.c | build
	$(CC) $(UZFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c $(UZDIR)/$*.c -o $@
codec-probe: tests/codec_probe.c codec.c codec.h archive.h $(CODEC_DEPS)
	$(CC) $(CPPFLAGS) -O2 -std=gnu89 -I../zip30 tests/codec_probe.c codec.c -lbz2 -llzma -lzstd -lm -o $@
test-display: tests/test_display.c display.h archive.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_display.c -o $@
test-index: tests/test_index.c archive.c extract.c $(UZOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_index.c archive.c extract.c $(UZOBJS) $(LDLIBS) -o $@
test-structures: tests/test_structures.c
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_structures.c -o $@
test-source-stability: tests/test_source_stability.c archive.c archive.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_source_stability.c archive.c -o $@
test-zip64-offset: tests/test_zip64_offset.c archive.c archive.h writer.c writer.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_zip64_offset.c archive.c writer.c -o $@
test-interrupt: tests/test_interrupt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_interrupt.c -o $@
test: test-display test-index test-structures test-zip64-offset test-interrupt test-source-stability codec-probe zipopt zipopt-preflight zipopt-decodecheck
	./test-display
	./test-index
	./test-structures
	./test-zip64-offset
	./test-interrupt
	./tests/test_zipopt.sh
	./test-source-stability
-include $(UZDEPS)
clean:
	rm -f zipopt zipopt-preflight zipopt-decodecheck test-display test-index test-structures test-interrupt test-source-stability codec-probe test-zip64-offset
	rm -rf build
.PHONY: all clean test
