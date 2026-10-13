# zipopt — private, in-process UnZip build (early implementation stages)
# SPDX-License-Identifier: MIT-0
ifneq ($(filter default undefined,$(origin CC)),)
CC = cc
endif
CFLAGS ?= -O2 -std=c89 -Wall -Wextra
# Keep Zip and UnZip compiler flags isolated.  Only the in-process encoder
# adapter compiles with LOCAL_ZIP; only private decoder objects use LOCAL_UNZIP.
CPPFLAGS += -D_FILE_OFFSET_BITS=64
# LPAQ8 decoding (otional)
# Override with PAQ8_METHOD_FLAGS=-DNO_LPAQ8 for memory constrained systems.
LPAQ8_METHOD_FLAGS ?= -DUSE_LPAQ8
UZDIR = ../unzip60
UZFLAGS = $(LPAQ8_METHOD_FLAGS) -std=gnu89 -O2 -I$(UZDIR) -DUNIX -DDLL -DZIPOPT_EMBED -DNO_EXCEPT_SIGNALS -DLARGE_FILE_SUPPORT -DNO_ZLIB_NG -DUSE_BZIP2 -DUSE_LZMA -DUSE_XZ -DUSE_ZSTD $(LOCAL_UNZIP)
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
    ../zip30/pkdcl.h ../zip30/ppmd8.h ../zip30/zopfli.h \
    ../zip30/deflate.c ../zip30/trees.c)
# Match Zip/UnZip's configure policy: automatic native zlib-ng detection,
# otherwise the bundled Info-ZIP Deflate encoder.  EXTERNAL_ZLIB and LOCAL_ZIP
# are checked for the same explicit backend requests as Zip's configure.
ZO_DEFLATE_BACKEND ?= auto
ZO_REQUEST_FLAGS := $(CPPFLAGS) $(CFLAGS) $(LOCAL_ZIP) $(EXTERNAL_ZLIB)
ZO_FORCE_ZLIB := $(filter -DUSE_ZLIB -DUSE_ZLIB=%,$(ZO_REQUEST_FLAGS))
ZO_FORCE_NATIVE := $(filter -DUSE_ZLIB_NG -DUSE_ZLIB_NG=%,$(ZO_REQUEST_FLAGS))
ZO_DISABLE_NATIVE := $(filter -DNO_ZLIB_NG -DNO_ZLIB_NG=%,$(ZO_REQUEST_FLAGS))
ifneq ($(strip $(ZO_FORCE_ZLIB)),)
  ifneq ($(strip $(ZO_FORCE_NATIVE)),)
    $(error USE_ZLIB and USE_ZLIB_NG are mutually exclusive)
  endif
endif
ZO_SELECTED_BACKEND := $(strip $(ZO_DEFLATE_BACKEND))
ifeq ($(ZO_SELECTED_BACKEND),auto)
  ifneq ($(strip $(ZO_FORCE_ZLIB)),)
    ZO_SELECTED_BACKEND := zlib
  else ifneq ($(strip $(ZO_FORCE_NATIVE)),)
    ZO_SELECTED_BACKEND := native
  else ifneq ($(strip $(ZO_DISABLE_NATIVE)),)
    ZO_SELECTED_BACKEND := internal
  endif
endif
# An explicit selection must not silently contradict EXTERNAL_ZLIB.
ifneq ($(strip $(ZO_FORCE_ZLIB)),)
  ifneq ($(ZO_SELECTED_BACKEND),zlib)
    $(error USE_ZLIB conflicts with ZO_DEFLATE_BACKEND=$(ZO_DEFLATE_BACKEND))
  endif
endif
ifneq ($(strip $(ZO_FORCE_NATIVE)),)
  ifneq ($(ZO_SELECTED_BACKEND),native)
    $(error USE_ZLIB_NG conflicts with ZO_DEFLATE_BACKEND=$(ZO_DEFLATE_BACKEND))
  endif
endif
ifneq ($(strip $(ZO_DISABLE_NATIVE)),)
  ifeq ($(ZO_SELECTED_BACKEND),native)
    ifeq ($(strip $(ZO_FORCE_NATIVE)),)
      $(error NO_ZLIB_NG conflicts with ZO_DEFLATE_BACKEND=$(ZO_DEFLATE_BACKEND))
    endif
  endif
endif

# The native probe compiles and links actual zlib-ng entry points rather
# than trusting pkg-config metadata.  Honor the same override variables and
# -lz-ng fallback used by Zip and UnZip's configure scripts.
ifneq ($(filter auto native,$(ZO_SELECTED_BACKEND)),)
  ZO_ZNG_CFLAGS := $(if $(strip $(IZ_ZLIBNG_CFLAGS)),$(IZ_ZLIBNG_CFLAGS),$(shell pkg-config --cflags zlib-ng 2>/dev/null))
  ZO_ZNG_LIBS := $(if $(strip $(IZ_ZLIBNG_LIBS)),$(IZ_ZLIBNG_LIBS),$(shell pkg-config --libs zlib-ng 2>/dev/null))
  ifeq ($(strip $(ZO_ZNG_LIBS)),)
    ZO_ZNG_LIBS := -lz-ng
  endif
  ZO_ZNG_FOUND := $(shell $(CC) $(CPPFLAGS) $(CFLAGS) $(LOCAL_ZIP) $(EXTERNAL_ZLIB) $(ZO_ZNG_CFLAGS) -o /dev/null tests/zng_probe.c $(LOCAL_GLDFLAGS) $(ZO_ZNG_LIBS) >/dev/null 2>&1 && echo yes)
  ifeq ($(ZO_SELECTED_BACKEND),auto)
    ifeq ($(ZO_ZNG_FOUND),yes)
      ZO_SELECTED_BACKEND := native
    else
      ZO_SELECTED_BACKEND := internal
    endif
  endif
endif

# Zip and UnZip enable GNU feature-test declarations with external zlib on
# Linux, for off64_t and related large-file API declarations.
ifeq ($(shell uname -s 2>/dev/null),Linux)
  ZO_EXT_PLATFORM_FLAGS := -D_GNU_SOURCE
endif
ifeq ($(ZO_SELECTED_BACKEND),internal)
  ZO_DEFLATE_FLAGS =
  ZO_DEFLATE_LIBS =
  ZO_INTERNAL_DEFLATE = build/zo-zip-deflate.o
else ifeq ($(ZO_SELECTED_BACKEND),native)
  ifneq ($(ZO_ZNG_FOUND),yes)
    $(error Native zlib-ng selected but its headers/library cannot link)
  endif
  ZO_DEFLATE_FLAGS = $(ZO_EXT_PLATFORM_FLAGS) -DZO_USE_ZLIB_NG $(ZO_ZNG_CFLAGS)
  ZO_DEFLATE_LIBS = $(ZO_ZNG_LIBS)
  ZO_INTERNAL_DEFLATE =
else ifeq ($(ZO_SELECTED_BACKEND),zlib)
  ZO_DEFLATE_FLAGS = $(ZO_EXT_PLATFORM_FLAGS) -DZO_USE_ZLIB $(IZ_ZLIB_CFLAGS)
  ZO_DEFLATE_LIBS = $(if $(strip $(IZ_ZLIB_LIBS)),$(IZ_ZLIB_LIBS),-lz)
  ZO_INTERNAL_DEFLATE =
else
  $(error Unsupported ZO_DEFLATE_BACKEND=$(ZO_DEFLATE_BACKEND); use auto, native, zlib or internal)
endif
ZO_ACCEL_FLAGS = $(filter -DNO_PCLMUL_CRC -DNO_PCLMUL_CRC32 \
    -DNO_ARM_CRC32 -DUSE_ZLIB -DUSE_ZLIB_NG -DASM_CRC \
    -DCRC_TABLE_ONLY -DIZ_CRC_BE_OPTIMIZ,$(LOCAL_UNZIP))
LDLIBS += -lbz2 -llzma -lzstd $(ZO_DEFLATE_LIBS)

# The Zip-side codec adapter is compiled separately to prevent cross-pollution
# of LOCAL_ZIP/LOCAL_UNZIP and to preserve conditional ABI declarations.
ZOCODEC = build/zo-codec-$(ZO_SELECTED_BACKEND).o
ZO_BACKEND_STAMP = build/zo-backend-$(ZO_SELECTED_BACKEND).stamp
all: zipopt zipopt-preflight zipopt-decodecheck
zipopt: $(ZO_BACKEND_STAMP) archive.c archive.h extract.c extract.h writer.c writer.h codec.c codec.h $(CODEC_DEPS) display.h fwkcs_md5.h ../zip30/fwkcs_fast_md5.inc zipopt.c $(ZOCODEC) $(ZO_INTERNAL_DEFLATE) $(UZOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(ZO_ACCEL_FLAGS) archive.c extract.c writer.c zipopt.c $(ZOCODEC) $(ZO_INTERNAL_DEFLATE) $(UZOBJS) $(LDLIBS) -lm -o $@ $(LOCAL_GLDFLAGS)
zipopt-preflight: archive.c archive.h preflight.c
	$(CC) $(CPPFLAGS) $(CFLAGS) archive.c preflight.c -o $@ $(LOCAL_GLDFLAGS)
zipopt-decodecheck: archive.c archive.h extract.c extract.h decodecheck.c $(UZOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) archive.c extract.c decodecheck.c $(UZOBJS) $(LDLIBS) -o $@ $(LOCAL_GLDFLAGS)
build:
	mkdir -p $@
$(ZO_BACKEND_STAMP): | build
	rm -f build/zo-backend-*.stamp
	touch $@
build/zo-zip-deflate.o: zip_deflate.c zip_deflate.h ../zip30/zip.h ../zip30/deflate.c ../zip30/trees.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LOCAL_ZIP) -c zip_deflate.c -o $@
$(ZOCODEC): codec.c codec.h zip_deflate.h archive.h $(CODEC_DEPS) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LOCAL_ZIP) $(EXTERNAL_ZLIB) $(ZO_DEFLATE_FLAGS) -DZO_SHARED_UNZIP_CODECS -c codec.c -o $@
build/uz-unix.o: $(UZDIR)/unix/unix.c | build
	$(CC) $(UZFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c $(UZDIR)/unix/unix.c -o $@
build/uz-%.o: $(UZDIR)/%.c | build
	$(CC) $(UZFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c $(UZDIR)/$*.c -o $@
codec-probe: $(ZO_BACKEND_STAMP) tests/codec_probe.c codec.c codec.h archive.h $(CODEC_DEPS) $(ZO_INTERNAL_DEFLATE)
	$(CC) $(CPPFLAGS) -O2 -std=gnu89 -I../zip30 $(LOCAL_ZIP) $(EXTERNAL_ZLIB) $(ZO_DEFLATE_FLAGS) tests/codec_probe.c codec.c $(ZO_INTERNAL_DEFLATE) -lbz2 -llzma -lzstd $(ZO_DEFLATE_LIBS) -lm -o $@ $(LOCAL_GLDFLAGS)
test-display: tests/test_display.c display.h archive.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_display.c -o $@ $(LOCAL_GLDFLAGS)
test-index: tests/test_index.c archive.c extract.c $(UZOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_index.c archive.c extract.c $(UZOBJS) $(LDLIBS) -o $@ $(LOCAL_GLDFLAGS)
test-structures: tests/test_structures.c
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_structures.c -o $@ $(LOCAL_GLDFLAGS)
test-source-stability: tests/test_source_stability.c archive.c archive.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_source_stability.c archive.c -o $@ $(LOCAL_GLDFLAGS)
test-zip64-offset: tests/test_zip64_offset.c archive.c archive.h writer.c writer.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_zip64_offset.c archive.c writer.c -o $@ $(LOCAL_GLDFLAGS)
test-interrupt: tests/test_interrupt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_interrupt.c -o $@ $(LOCAL_GLDFLAGS)
print-deflate-backend:
	@printf '%s\n' '$(ZO_SELECTED_BACKEND)'
test: test-display test-index test-structures test-zip64-offset test-interrupt test-source-stability codec-probe zipopt zipopt-preflight zipopt-decodecheck
	./test-display
	./test-index
	./test-structures
	./test-zip64-offset
	./test-interrupt
	./tests/test_zipopt.sh
	python3 tests/test_fwkcs_md5.py
	python3 tests/test_level_options.py
	python3 tests/test_backend_selection.py
ifeq ($(ZO_SELECTED_BACKEND),internal)
	python3 tests/test_internal_deflate.py
endif
	./test-source-stability
-include $(UZDEPS)
clean:
	rm -f zipopt zipopt-preflight zipopt-decodecheck test-display test-index test-structures test-interrupt test-source-stability codec-probe test-zip64-offset
	rm -rf build
.PHONY: all clean test print-deflate-backend
