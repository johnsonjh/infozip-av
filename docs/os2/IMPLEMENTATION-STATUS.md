# OS/2 V1 integration status and release gates (2026-10-20)

**Integrated beta candidate, pending native acceptance.** The latest cu102
Open Watcom build now includes the OS/2 Xtro V1 Zip capture and UnZip
restoration adapters. The earlier text below records decisions and earlier
checkpoints; statements that the adapter remains DISABLED describe those
historical checkpoints, not this candidate. Do not treat a Linux cross-build
or a mock EA round-trip as certification of native OS/2 filesystem behavior.

The adapter uses OS/2 Dos* EA enumeration and TLV interface 10, bounded
in-memory companion capture/extraction, encrypted-directory owner policy B,
legacy 0x0009 reconciliation, and deferred SYMLINK activation. It imposes a
32 MiB-per-companion (+ framing) and 128 MiB total companion staging budget;
exceeding these limits is a reported error, not a silent truncation. Open
Watcom binaries cannot depend on kLIBC; the AES salt fallback is deliberately
weak and emits the agreed warning. Compatibility policy still exposes legacy
LAN ACL data in the traditional field where present: do not treat the current
AES metadata mode as a general protection for LAN ACL confidentiality.

Native release blockers: complete `docs/os2/BETA-TEST-REGIMEN.md` across
independently identified host versions and EA-capable filesystems, obtain
before/after raw EA comparisons, and review all observed failures. A wrong
password, incomplete archive, conflicting 0x0009 and Xtro metadata, early
symlink activation, path traversal, or writable plaintext temporary staging
is a release blocker. The fallback entropy source is an approved limitation,
not a source of cryptographic-grade randomness. Archive-wide rollback of
previously written user contents is not promised.

## Evidence available before OS/2 native beta reports

* Optimized and diagnostic Linux-hosted Open Watcom V2 LX builds: passed,
  including Zip, UnZip, traditional utilities, zipopt and zipdedup.
* Portable Xtro V1 tests, encrypted XTCS framing, owner/companion graph,
  existing filesystem adapters, and native OS/2 EA codec mutation tests:
  passed in the engineering environment.
* OS/2 native EA enumeration and native symlink API behavior were tested
  through deterministic host-side mock implementations, not a real OS/2
  kernel. Such tests cannot certify actual HPFS/JFS/FAT semantics.
* A repeatable native `ea-fixture` test executable is built when
  `OS2_TEST_HELPERS=1`; see BETA-TEST-REGIMEN.md.

Unverified: native OS/2 Xtro `--xattrs` round trips; kLIBC links across OS/2
releases; metadata confidentiality on actual target filesystems; failure
behavior on real systems; and zipopt/zipdedup native output publication.
Those are beta acceptance gates, not claims of prior test failure.
