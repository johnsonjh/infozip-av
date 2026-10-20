# SPDX-License-Identifier: MIT-0
# Isolated portable core: no Zip/UnZip production build rules are changed.
CC ?= cc
CFLAGS ?= -O2 -std=c89 -pedantic -Wall -Wextra -Werror
CORE = xtrm.c xtrsha.c xtrv1.c
TESTS = test_xtrm test_large test_v1 test_platform test_policy test_long_limit fuzz_v1 emit_fixture verify_fixture
.PHONY: all check clean
all: $(TESTS)
$(TESTS): %: %.c $(CORE) xtrm.h xtrsha.h xtrv1.h
	$(CC) $(CFLAGS) -o $@ $(CORE) $<
check: all check-reframe check-extra-rewrite check-os2-ea
	sh ./run_m1.sh
clean:
	rm -f $(TESTS) test_os2_ea test_os2_v1 test_os2_ea_mutation test_os2_v1_decode test_linux test_reframe test_extra_rewrite test_win_txn test_win_nt_mock test_win_unzip_mock test_win_nt_native.exe *.san fuzzer_m1

# Optional native Linux adapter tests. Never included in DOS/Windows builds.
.PHONY: check-linux
test_linux: test_linux.c xtrlinux.c xtrlinux.h $(CORE)
	$(CC) $(CFLAGS) -DXTR_TEST_HOOKS -o $@ $(CORE) xtrlinux.c test_linux.c
check-linux: test_linux
	./test_linux

.PHONY: check-guard
check-guard: emit_fixture verify_fixture
	python3 ./test_archive_guard.py
	python3 ./test_archive_graph.py
	python3 ./test_aes_pair_transport.py

# Zip archive association helper is C89 and uses no external metadata library.
.PHONY: check-pairs
test_pair_graph: test_pair_graph.c ../zip30/xtro_pairs.h
	$(CC) $(CFLAGS) -o $@ test_pair_graph.c
check-pairs: test_pair_graph
	./test_pair_graph

.PHONY: check-directory-crypto
check-directory-crypto:
	python3 ./test_encrypted_directory.py

.PHONY: check-zip-capture
check-zip-capture: verify_fixture
	python3 ./test_zip_capture.py

.PHONY: check-unzip-inline
check-unzip-inline:
	python3 ./test_unzip_inline.py

.PHONY: check-unzip-companion
check-unzip-companion:
	python3 ./test_unzip_companion.py

.PHONY: check-overwrite
check-overwrite:
	python3 ./test_linux_overwrite.py

.PHONY: check-directories
check-directories:
	python3 ./test_linux_directories.py

.PHONY: check-replace
check-replace:
	python3 ./test_zip_replace_xattrs.py

.PHONY: check-m6b check-m6b-c89
check-m6b:
	python3 ./test_m6b_transform.py
check-m6b-c89:
	$(CC) $(CFLAGS) -o test_xtrrewrite test_xtrrewrite.c
	./test_xtrrewrite

.PHONY: check-cross-stage
check-cross-stage:
	python3 ./test_cross_stage.py

.PHONY: check-zipnote-xattrs
check-zipnote-xattrs:
	python3 ./test_zipnote_xattrs.py

.PHONY: check-zipsplit-xattrs
check-zipsplit-xattrs:
	python3 ./test_zipsplit_xattrs.py

.PHONY: check-zipcloak-xattrs
check-zipcloak-xattrs:
	python3 ./test_zipcloak_xattrs.py

# Decoded metadata reframe core: no Zip/UnZip feature is enabled here.
.PHONY: check-reframe
test_reframe: test_reframe.c $(CORE) xtrv1.h
	$(CC) $(CFLAGS) -o $@ $(CORE) test_reframe.c
check-reframe: test_reframe
	./test_reframe

# M6E2B: staged, transactional ZIP extra-field rewrite contracts.
.PHONY: check-extra-rewrite
test_extra_rewrite: test_extra_rewrite.c $(CORE) xtrv1.h
	$(CC) $(CFLAGS) -o $@ $(CORE) test_extra_rewrite.c
check-extra-rewrite: test_extra_rewrite
	./test_extra_rewrite

# Live Linux STORE companion ZipCloak transport transition.
.PHONY: check-zipcloak-store
check-zipcloak-store:
	python3 ./test_zipcloak_store_transition.py

# Actual Linux ZipCloak method-8 companion transition coverage.
.PHONY: check-zipcloak-deflate
check-zipcloak-deflate:
	python3 ./test_zipcloak_deflate_transition.py

# Live inline-to-encrypted-companion ZipCloak transition.
.PHONY: check-zipcloak-inline
check-zipcloak-inline:
	python3 ./test_zipcloak_inline_transition.py

# Real M6E2F ZipCrypto reverse owner/companion transition.
.PHONY: check-zipcloak-reverse
check-zipcloak-reverse:
	python3 ./test_zipcloak_reverse.py

# Traditional FreeBSD/NetBSD extattr adapter: mock API contract tests can
# run on Linux. These do NOT certify a native BSD filesystem round trip.
.PHONY: check-bsd-mock
check-bsd-mock:
	$(CC) $(CFLAGS) -DXTR_BSD_TEST -DXTR_TEST_HOOKS -o test_bsd_freebsd $(CORE) xtrbsd.c test_bsd_mock.c
	./test_bsd_freebsd
	$(CC) $(CFLAGS) -DXTR_BSD_TEST -DXTR_BSD_TEST_NETBSD -DXTR_TEST_HOOKS -o test_bsd_netbsd $(CORE) xtrbsd.c test_bsd_mock.c
	./test_bsd_netbsd

# Complete Linux-hosted Zip/UnZip integration using the emulated native
# FreeBSD and NetBSD extattr ABI. This is NOT a native BSD kernel test.
.PHONY: check-bsd-integration
check-bsd-integration:
	python3 ./test_bsd_integration.py

# On-target test for a native FreeBSD or NetBSD filesystem with extattr(2).
.PHONY: check-bsd-native
check-bsd-native:
	python3 ./test_bsd_native.py

# FreeBSD 15 O_NAMEDATTR stream implementation in addition to extattr(2).
# The Linux-hosted test mocks the named-stream API; native validation is separate.
.PHONY: check-bsd-named-mock
check-bsd-named-mock:
	$(CC) $(CFLAGS) -D_GNU_SOURCE -DXTR_BSD_TEST -DXTR_BSD_TEST_NAMED -DXTR_TEST_HOOKS -o test_bsd_named $(CORE) xtrbsd.c test_bsd_named.c
	./test_bsd_named

# Runs only on real FreeBSD 15+ ZFS with xattr=dir (or supporting NFSv4).
.PHONY: check-bsd-named-native
check-bsd-named-native:
	python3 ./test_bsd_named_native.py

# M7D Windows NT EA V1 conversion contract; portable C89, no OS dependency.
# This is NOT the native Zip/UnZip backend or ADS restoration.
.PHONY: check-win-ea
test_win_ea: test_win_ea.c xtrwin_ea.c xtrwin_ea.h $(CORE)
	$(CC) $(CFLAGS) -o $@ $(CORE) xtrwin_ea.c test_win_ea.c
check-win-ea: test_win_ea
	./test_win_ea

# Run on Windows/Wine only after separately cross-compiling the native probe.
# An unsupported Wine filesystem returns 77 rather than a false positive.
.PHONY: build-win-ea-probe
build-win-ea-probe:
	sh ./build-win-ea-probe.sh

# M7D-W2: Windows native handle transaction core (portable mock ABI).
# This target neither requires Windows nor enables native metadata in Zip.
.PHONY: check-win-txn
test_win_txn: test_win_txn.c xtrwin_txn.c xtrwin_txn.h xtrwin_ea.c xtrwin_ea.h $(CORE)
	$(CC) $(CFLAGS) -o $@ $(CORE) xtrwin_ea.c xtrwin_txn.c test_win_txn.c
check-win-txn: test_win_txn
	./test_win_txn

# Standalone Windows native NTFS round-trip with a disposable file.
.PHONY: build-win-ea-w2-test
build-win-ea-w2-test:
	sh ./build-win-ea-w2-test.sh

# Simulated NTAPI ABI, including multi-call query enumeration. This only
# checks source contracts; it does not certify Windows syscalls or NTFS.
.PHONY: check-win-nt-mock
test_win_nt_mock: test_win_nt_mock.c xtrwin_nt.c xtrwin_nt.h xtrwin_nt_abi.h xtrwin_txn.c xtrwin_txn.h mock_win32/windows.h $(CORE)
	$(CC) $(CFLAGS) -D_WIN32 -I./mock_win32 -o $@ $(CORE) xtrwin_ea.c xtrwin_txn.c xtrwin_nt.c test_win_nt_mock.c
check-win-nt-mock: test_win_nt_mock
	./test_win_nt_mock

# Windows W2B2B inline/companion UnZip integration, Linux-hosted simulated Win32 ABI.
# The mock is NOT a substitute for a real MinGW build or NTFS extraction.
.PHONY: check-win-unzip-mock
test_win_unzip_mock: test_win_unzip_mock.c ../unzip60/xtrunzip_win.c mock_unzip_win32/windows.h mock_unzip_win32/io.h $(CORE) xtrwin_ea.c xtrwin_ads.c xtrwin_ads_record.c xtrwin_mixed_verify.c xtrwin_restore_plan.c
	$(CC) $(CFLAGS) -Wno-unused-function -Wno-unused-variable -I./mock_unzip_win32 -o $@ $(CORE) xtrwin_ea.c xtrwin_ads.c xtrwin_ads_record.c xtrwin_mixed_verify.c xtrwin_restore_plan.c test_win_unzip_mock.c
check-win-unzip-mock: test_win_unzip_mock
	./test_win_unzip_mock

# Compile the real private Win32 staging branch (not the test-only tmpfile
# stand-in) against a deliberately minimal simulated ABI. Native MinGW and
# real NTFS testing remain separate gates.
.PHONY: check-win-unzip-stage-syntax
check-win-unzip-stage-syntax:
	$(CC) $(CFLAGS) -Wno-unused-function -Wno-unused-variable -I./mock_unzip_win32 -fsyntax-only test_win_unzip_syntax.c

# Windows ADS Unicode name verification. Separate from native ADS enablement.
.PHONY: check-win-ads
test_win_ads: test_win_ads.c xtrwin_ads.c xtrwin_ads.h
	$(CC) $(CFLAGS) -o $@ xtrwin_ads.c test_win_ads.c
check-win-ads: test_win_ads
	./test_win_ads

.PHONY: check-win-ads-mock
test_win_ads_mock: test_win_ads_mock.c xtrwin_ads_native.c xtrwin_ads.c xtrwin_ads_native.h xtrwin_ads.h mock_ads_win/windows.h
	$(CC) $(CFLAGS) -D_WIN32 -I./mock_ads_win -o $@ xtrwin_ads.c xtrwin_ads_native.c test_win_ads_mock.c
check-win-ads-mock: test_win_ads_mock
	./test_win_ads_mock

# W3B: bounded-memory native ADS stream reading; still no --streams ZIP mode.
.PHONY: check-win-ads-stream-mock build-win-ads-stream-probe
check-win-ads-stream-mock:
	$(CC) $(CFLAGS) -D_WIN32 -I./mock_ads_win -o test_win_ads_stream_mock \
	  xtrwin_ads.c xtrwin_ads_stream.c test_win_ads_stream_mock.c
	./test_win_ads_stream_mock
build-win-ads-stream-probe:
	sh ./build-win-ads-stream-probe.sh

# W3B: portable type-3 ADS record sources; may be combined with EAs later.
.PHONY: check-win-ads-record
check-win-ads-record:
	$(CC) $(CFLAGS) -o test_win_ads_record $(CORE) xtrwin_ads.c \
	  xtrwin_ads_record.c test_win_ads_record.c
	./test_win_ads_record

# Windows mixed EA + NTFS ADS V1 manifest with real serializer and simulated
# native stream/EA syscalls. This tests ZIP metadata semantics, NOT NTFS itself.
.PHONY: check-win-mixed-mock
check-win-mixed-mock:
	$(CC) $(CFLAGS) -D_WIN32 -I mock_mixed_win -o test_win_mixed_mock $(CORE) xtrwin_ea.c xtrwin_ads.c xtrwin_ads_record.c xtrwin_mixed.c test_win_mixed_mock.c
	./test_win_mixed_mock

# W3C2A: authenticated mixed EA/ADS manifest preflight; no native writes.
.PHONY: check-win-mixed-verify
test_win_mixed_verify: test_win_mixed_verify.c xtrwin_mixed_verify.c xtrwin_mixed_verify.h xtrwin_restore_plan.c xtrwin_restore_plan.h xtrwin_ea.c xtrwin_ads.c xtrwin_ads_record.c $(CORE)
	$(CC) $(CFLAGS) -o $@ $(CORE) xtrwin_ea.c xtrwin_ads.c xtrwin_ads_record.c xtrwin_mixed_verify.c xtrwin_restore_plan.c test_win_mixed_verify.c
check-win-mixed-verify: test_win_mixed_verify
	./test_win_mixed_verify

# W3C2A isolated NTFS stream creation primitive and failure cleanup tests.
.PHONY: check-win-ads-write-mock
test_win_ads_write_mock: test_win_ads_write_mock.c xtrwin_ads_write.c xtrwin_ads_write.h xtrwin_ads.c mock_ads_win/windows.h
	$(CC) $(CFLAGS) -I mock_ads_win -D_WIN32 -o $@ xtrwin_ads.c xtrwin_ads_write.c test_win_ads_write_mock.c
check-win-ads-write-mock: test_win_ads_write_mock
	./test_win_ads_write_mock

# W3C2B/C Windows mixed preflight and exact ADS transaction tests.
.PHONY: check-win-ads-restore-syntax
check-win-ads-restore-syntax:
	$(CC) $(CFLAGS) -D_WIN32 -I./mock_ads_win -fsyntax-only xtrwin_ads_restore.c

.PHONY: check-win-restore-plan check-win-ads-txn
check-win-restore-plan:
	$(CC) $(CFLAGS) -o test_win_restore_plan $(CORE) xtrwin_ads.c xtrwin_ads_record.c xtrwin_ea.c xtrwin_mixed_verify.c xtrwin_restore_plan.c test_win_mixed_verify.c
	./test_win_restore_plan
check-win-ads-txn:
	$(CC) $(CFLAGS) -o test_win_ads_txn xtrwin_ads.c xtrwin_ads_txn.c test_win_ads_txn.c
	./test_win_ads_txn

# Windows UTF-8 pathname boundary (simulated ABI, no MinGW certification).
check-win-utf8:
	$(CC) -std=c89 -pedantic -Wall -Wextra -Werror -fdata-sections -ffunction-sections -I./mock_utf8_win -o test_win_utf8_valid xtrwin_utf8path.c test_win_utf8_valid.c -Wl,--gc-sections
	./test_win_utf8_valid

check-win-utf8-boundary:
	$(CC) -std=c89 -pedantic -Wall -Wextra -Werror -I./mock_utf8_win -o test_win_utf8_boundary xtrwin_utf8path.c test_win_utf8_boundary_mock.c
	./test_win_utf8_boundary

# Compile-time selection of fd- vs stream-based Unicode archive openers.
# LOCAL_UNZIP/LOCAL_ZIP flag propagation and other platforms are unchanged.
.PHONY: check-win-utf8-archive
check-win-utf8-archive:
	python3 ./test_win_utf8_archive_contract.py

# W3D2 opt-in Unicode argv converter (simulated Win32 ABI; no MinGW claim).
.PHONY: check-win-utf8-argv
check-win-utf8-argv:
	$(CC) $(CFLAGS) -I./mock_utf8_win -o test_win_utf8_argv xtrwin_utf8argv.c test_win_utf8_argv_mock.c
	./test_win_utf8_argv

# W3D2: metadata preservation must be independent of restoration selection.
# This host-side C89 test compiles the actual production selection macro.
.PHONY: check-win-overwrite-policy
check-win-overwrite-policy:
	python3 ./test_win_overwrite_policy.py

# MinGW Zip existing-archive scan must reposition the buffered CRT stream,
# not only its file descriptor. Host test compiles the production seek code.
.PHONY: check-win-zip-seek
check-win-zip-seek:
	python3 ./test_win_zip_seek_contract.py --cc $(CC)

# OS/2 typed native EA parser and V1 manifest serializer. These use only C89
# and can be run on Linux; NLS system-call compatibility needs native testing.
.PHONY: check-os2-ea
OS2_EA_CORE = $(CORE) xtros2_ea.c
test_os2_ea: test_os2_ea.c xtros2_ea.c xtros2_ea.h $(CORE)
	$(CC) $(CFLAGS) -o $@ $(OS2_EA_CORE) test_os2_ea.c
test_os2_v1: test_os2_v1.c xtros2_ea.c xtros2_ea.h $(CORE)
	$(CC) $(CFLAGS) -o $@ $(OS2_EA_CORE) test_os2_v1.c
test_os2_ea_mutation: test_os2_ea_mutation.c xtros2_ea.c xtros2_ea.h $(CORE)
	$(CC) $(CFLAGS) -o $@ $(OS2_EA_CORE) test_os2_ea_mutation.c
test_os2_v1_decode: test_os2_v1_decode.c xtros2_decode.c xtros2_memory.c xtros2_ea.c $(CORE)
	$(CC) $(CFLAGS) -o $@ xtros2_decode.c xtros2_memory.c xtros2_ea.c $(CORE) test_os2_v1_decode.c
check-os2-ea: test_os2_ea test_os2_v1 test_os2_ea_mutation test_os2_v1_decode
	./test_os2_ea
	./test_os2_v1
	./test_os2_ea_mutation
	./test_os2_v1_decode
