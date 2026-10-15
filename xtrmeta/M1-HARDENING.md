# Xtro-ZIP: C89 metadata core — M1 hardening supplement

Baseline: `cu68.tar.xz`, 2026-10-15. Additive new `xtrmeta/` subtree.
This is **not** Zip/UnZip/ZipOpt/ZipDedup native integration. No metadata
will be captured or restored by a production Xtro-ZIP binary as a result
of merely applying this patch. No existing utility build rules are changed.

## Locked encryption / FWKCS rules

1. If an owner uses ZipCrypto, its metadata companion uses ZipCrypto, with
   no additional xattr-specific warning or substitute encryption mode.
2. FWKCS 0x4B46 on ordinary members covers ordinary *uncompressed* contents.
3. FWKCS on public companion members, when explicitly requested, covers
   the *complete* uncompressed ZIP companion payload, not its owner file.
4. A companion whose payload is encrypted MUST NOT have a public FWKCS MD5
   value. If a caller requires FWKCS for every ZIP member, that request is
   incompatible with encrypted companions and MUST be rejected before output.
5. Xtro SHA-256 covers the uncompressed XTMD manifest. For an encrypted
   companion its `XTCS` trailer is *inside* the encrypted ZIP payload. The
   metadata layer does not perform encryption or substitute a hash for the
   ZIP codec's structural and authentication checks.
6. AE-1, AE-2, and experimental AE-3 require actual ZIP transport checks
   AND successful cryptographic authentication where applicable. AE-2's
   ordinary ZIP CRC is zero by design; do not treat a zero CRC as proof that
   AE-2 authentication succeeded.

`xtr1_check_member_policy()` now enforces mode concordance, the absence of
plaintext FWKCS on encrypted companions, and required ZIP integrity status.
The actual ZIP reader must supply reliable verification results; a caller
cannot trust flags copied from an unverified archive header.

## M1 defects corrected

- `xtr1_write_manifest()` rejects all-zero owner IDs before writing bytes.
- `xtr1_check_manifest()` rejects all-zero owner IDs even when supplied by
  an adversarial caller that bypassed `xtr1_extra_decode()`.
- `xtr1_crypto_check()` requires both ZIP transport verification and AES
  authentication for AE-1/2/3, not either one alone.
- `xtr1_check_rewrite_decisions()` rejects accidental retention of stale
  owner IDs on replacement, and disallows cloning a metadata-bearing member
  without rebuilding the manifest under a new owner token.
- `test_long_limit.c` exercises synthetic values larger than 4 GiB without
  allocating or hashing 4 GiB. It confirms preflight LIMIT and the distinct
  midstream IO/rollback responsibility. This is **not** a full >4 GiB test.

The write API is still streaming: a later read/sink failure can occur after
some output is written. The archive writer MUST stage output for strict
publication; the portable library cannot provide filesystem transactionality.

## Identifier status

`0x5854` is a **candidate** third-party Xtro field ID, identified in the
previous M0 audit. It uses the mandatory `XTRO` payload signature and version.
No published collision was identified in the inspected APPNOTE and historical
Info-ZIP lists. Public announcement / possible registration and independent
collision review remain required before production writer enablement. An
unknown `0x5854` payload without this signature is a collision, not Xtro.

## Rewrite safety requirements

`xtr1_check_rewrite_decisions()` is a cheap abstract preflight; it cannot
verify that a member was truly unchanged, and it does not read or rewrite
ZIP bytes. The caller MUST also check the complete original and proposed
archive owner/companion graphs, verify each local/central Xtro extra field,
check all actual payload digests, and stage output before publication.

- Retain and rename: keep Xtro metadata and owner ID unchanged.
- Replace: strip old metadata/companion with explicit warning; regenerate a
  new owner ID and metadata if capture requested.
- Delete: remove owner and companion.
- Clone: assign a fresh owner ID, rebuild manifest and references, or reject.
- Foreign reorder/compress/update tools: must preserve Xtro semantics or
  fail without publishing. Ordinary CRC success is not sufficient.

## Tests executed in this environment

To reproduce: `cd xtrmeta && make check` (requires GCC/Clang and system
`zip`/`unzip` plus Python 3.10+ for the ZIP interoperability test).

Observed on Linux x86-64:

- Strict C89 `-std=c89 -pedantic -Wall -Wextra -Werror`: GCC and Clang passed.
- Original M0 88 checks; M1 57 assertions; platform TLVs 143 assertions.
- New rewrite/encryption policy 45 assertions; 64-bit synthetic limits 4.
- Streaming 65,535 / 65,536 / 1,048,576 values: passed.
- 120,000 deterministic input mutation cases; 15 allocation-failure cases:
  passed, no outstanding allocations reported.
- Clang ASan + UBSan test binaries: passed.
- LLVM libFuzzer 25,000 additional executions: passed, no reported crash.
- Independent Python ZIP Deflate / ZipCrypto / FWKCS fixtures and system
  `unzip -tqq`: passed. Portable parser verified companion SHA-256 separately.

Not tested and **not certified**: 32-bit execution, 16-bit DOS, FreeBSD,
NetBSD, OpenBSD, AIX, Solaris/illumos, macOS, Windows, OS/2, actual native
attribute restore, real AE-1/2/3 integration, ZipCloak, ZipOpt, ZipDedup,
ZipNote, ZipSplit, ZIP64 companions >4 GiB, strict transactional publication,
full fuzz coverage, or production archive rewrites. These remain release
acceptance gates. Do not claim that M2 or later milestones are complete.

## Usage

`make -C xtrmeta all` compiles standalone regression tools only.
`make -C xtrmeta check` performs the available standalone suite.
`make -C xtrmeta clean` removes test binaries.

The core is dependency-free C89 and MIT-0. Python and system Info-ZIP utilities
are only required for tests. This patch does not modify project README files.
