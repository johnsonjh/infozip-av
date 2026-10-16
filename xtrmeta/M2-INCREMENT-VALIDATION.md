# Xtro-ZIP cu68 M2 incremental integration: measured validation

Status: **partial M2 implementation; NOT a complete Zip/UnZip xattr feature**.
Baseline: user-supplied `cu68.tar.xz` with `Xtro-ZIP_cu68_xtrmeta_M1_hardened.patch` already applied.

## Included

- Linux descriptor-based native `user.*` xattr capture and restoration using the portable M1 manifest reader/writer; deterministic capture and binary payloads; separately staged and SHA-256/CRC-checked before any native restoration; 32 MiB manifest / 1 MiB per-value / 1,024-name default limits, explicitly reported rather than silently truncated. Restoration is not atomic if a later `fsetxattr()` fails. Feature is only available as a standalone library adapter and native test, NOT yet exposed via Zip or UnZip options.
- Fix failure propagation in Zip Unix extra-field construction, second-allocation leak and incorrect central-buffer allocation size, with 16-bit extra-field size checks.
- Until owner/companion rewriting is implemented, fail-closed guards prevent unsafe replacement/deletion/selective copy, Zip `-FS`/`-DF`/repair, and rewriting by ZipCloak, ZipNote, ZipSplit. Safe additions/deletions of unrelated members and complete Zip `--out` copies continue to work.
- No changes to README or production DOS/Windows xattr builds.

## Native tests executed

- `make -C xtrmeta check` PASS: the M1 base corpus (88 + 57 + 143 + 45 + 4 assertion groups), 120,000 deterministic mutations, 15 allocation-failure cases, 25,000 libFuzzer executions and the real independent clear/ZipCrypto/Deflate/FWKCS interoperability fixtures.
- `make -C xtrmeta check-linux` PASS: 65 assertions, 0 failures, native tmpfs round-trips for empty/binary values, 60,000 + 14,000 byte metadata, encrypted/public manifest schema, SHA corruption and correctly resigned but unsupported records, no writes on invalid manifest.
- Clang `-std=c89 -pedantic -Wall -Wextra -Werror -fsanitize=address,undefined` on standalone Linux test: PASS, 65 assertions, no reported memory errors or leaks.
- `make -C xtrmeta check-guard` PASS using built native cu68 Zip, ZipCloak, ZipNote and ZipSplit: real Deflate/FWKCS Xtro fixture for unencrypted and ZipCrypto metadata; prohibited operations return nonzero and leave original archive bytes unchanged; permitted unrelated-member addition/deletion, whole archive copy and read-only utility operation preserve metadata; ordinary ZipNote writes and ZipSplit writes still work.
- `make -C zip30 -f unix/Makefile generic_gcc -j6` PASS; produced Zip, ZipCloak, ZipNote and ZipSplit.
- Native Zip and UnZip production CLI smoke tests PASS for STORE, DEFLATE, forced ZIP64, AE-2, AE-3, FWKCS. **No xattr payload is yet attached to those files by production tools**.
- ZipOpt and ZipDedup built. ZipOpt fails closed for unknown Xtro extra field. ZipDedup preserved a no-reference public Xtro fixture, while encrypted Xtro fixture was rejected. These observations DO NOT establish support for arbitrary Xtro dedup rewrites.

## Build limitations

- `./build-unix.sh` reaches UnZip linking but fails on unavailable `-lwavpack` in this environment, even though its configuration reports no WavPack support; `unzip60/unzip` was generated and used for CLI tests. This is not an Xtro-specific runtime failure and was not changed by this patch.
- Native environment has no DOS/MinGW cross-compilers, so the new patch has **not** been compiled under those targets. The user's earlier DOS/Windows build covered only the M1 baseline, not this patch.
- OverlayFS here rejects even moderately large individual xattrs; Linux large-value tests use `/dev/shm` tmpfs, not overlayfs.
- 32-bit native execution, true >4-GiB xattr payloads, real concurrent filesystem races, native FreeBSD/NetBSD/AIX/Solaris/macOS/Windows/OS2, full archive AES companion integration and production Zip/UnZip xattr extraction remain untested/unimplemented.

## Explicit non-goals / release gates still open

1. Production `zip --xattrs` and `unzip --xattrs`, with streaming standard ZIP companion members and correct local/central fields, native safe extraction lifecycle and attribute filters.
2. Owner/companion transaction-aware Zip updates and deletions (versus current fail-closed guards), plus ZipCloak, ZipNote, ZipSplit, ZipOpt and ZipDedup rewrites.
3. Full AES/ZipCrypto/FWKCS encrypted-metadata interaction and ZIP64, output staging, authentication, archive substitution, overlapping member, symlink-target and race tests.
4. On-platform acceptance and build matrix. No supported platform is certified by this partial patch.

Apply this patch **on top of the already applied M1 patch**, not onto pristine `cu68`.

Reproduce: `make -C zip30 -f unix/Makefile generic_gcc`, then `make -C xtrmeta check`, `make -C xtrmeta check-linux`, and `make -C xtrmeta check-guard` from the source root. The Python guards use `zip30/zip` by default.
