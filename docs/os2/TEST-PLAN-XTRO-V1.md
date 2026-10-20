# OS/2 Xtro EA V1 and kLIBC link multi-version acceptance protocol

**Status: integrated OS/2 `--xattrs` beta acceptance plan, NOT production
certification; do not run this candidate on valuable data.**
See `IMPLEMENTATION-STATUS.md` for implementation gates.
Every run must use expendable paths and separately backed-up media. Follow
`os2-native-test-plan.md` for the basic toolchain/suite tests first.
This protocol must be rerun against the **exact release-candidate build**,
identified by version, source patch SHA-256 and each executable SHA-256.
Cross-linking to LX is not a substitute for native execution.

For exact reproducible commands, native EA fixture utility usage, and
result submission, use [BETA-TEST-REGIMEN.md](BETA-TEST-REGIMEN.md).

## Tester manifest (complete before starting)

Record: tester identifier, date/time, OS family and exact version/fixpack,
ArcaOS/eComStation revision if applicable, kernel, kLIBC version (or absent),
filesystem (HPFS, JFS, FAT, network), codepage/country/NLS settings, available
memory, drive letter, extraction root, shell, and exact binary checksums.
Indicate whether IBM LAN Server/Requester ACL services are installed.
Do not share confidential filesystem attributes or passwords in public logs.

Use a *new, disposable* directory per test. Archive creation and extraction
must occur in separate directories. Copy ZIP files away before manipulating
negative-test fixtures. Record full commands, exit status, screen output,
size/checksum of input and output, and raw EA inventory where possible.
Preferred EA inventory: an existing trusted OS/2 EA inspection tool, or a
small separately compiled `DosEnumAttribute`/`DosQueryPathInfo` probe.
Do not treat ZIP file-content CRC as evidence that EAs were restored.

## Required matrix

| Set | Input / condition | Expected result |
| --- | --- | --- |
| B1 | Store/Deflate regular files, nested directories | complete contents and ZIP CRC |
| B2 | 7 standard executables plus ZipInfo, zipopt, zipdedup | launch, help output; basic operations |
| B3 | ZipCrypto and each selected AES mode | round trip, wrong-password refusal; capture exact failure messages |
| B3a | AES encryption on OS/2 | warning `OS/2 AES uses time/memory-derived salts` appears; process exit successful; test 128/192/256 strength supported by CLI; compare cipher/member sizes |
| B3b | Repeat encryption of identical test data/password at near-identical times | observe salts without claiming uniqueness or cryptographic unpredictability; flag any duplicates for investigation |
| B3c | AES decryption only | succeeds without OS/2 randomness calls; wrong password/tampered authentication fails |
| B3d | OS/2 `DosGetDateTime` or `DosQuerySysInfo` failure (test shim/fault injector) | entropy request fails; no AES output accepted and no silent weak fallback |

| L1 | legacy `0x0009` EAs without `--xattrs` | exactly original native EAs/flags |
| L2 | LAN Server `0x4C41` ACL with and without `-X` | expected ACL option behavior; no silent failure |
| V1 | unencrypted `--xattrs` inline manifest | both legacy and Xtro present; EA values/flags restored once |
| V2 | unencrypted `--xattrs` companion manifest | complete original EA set, companion not extracted |
| V3 | unusually large EA set exceeding legacy capacity | warning, no truncated `0x0009`; Xtro complete |
| V4 | encrypted Xtro metadata | no plaintext legacy EA field; authenticated restoration |
| V5 | encrypted wrong password / tampered AE tag | fail before native metadata write |
| D1 | both formats, identical EA | one native write, identical result |
| D2 | both formats, conflicting EA flags or bytes | fail, leave member's EAs unchanged |
| D3 | case-only duplicate EA names | reject ambiguity by OS/2 NLS rules |
| D4 | existing destination has unrelated EA | unrelated EA remains |
| D5 | `.LONGNAME` on HPFS/JFS and mapped FAT | filename and EA remain consistent |
| S1 | kLIBC relative symlink with `zip -y` | link file + `SYMLINK` EA preserved |
| S0 | Legacy `0x0009` link EA restoration with a later CRC failure | do not activate SYMLINK; non-success exit status |
| S0a | Legacy symlink EA restoration to a pathname already carrying a SYMLINK EA | reject; do not follow or overwrite target |
| S0b | Native `DosSetFileInfo` failure with link pending | non-success; report exact OS/2 rc; no false success |
| S2 | kLIBC absolute or `@UNIXROOT` link with `-y` | byte-exact link target preserved |
| S3 | dangling and circular links with `-y` | preserved without following |
| S4 | same links without `-y` | target EAs/data only, or explicit error if unresolved |
| S5 | symlink to directory | no unintended recursive follow in `-y` mode |
| S6 | existing symlink in destination parent | no redirection outside root |
| S7 | symlink member before malicious traversal member | link activation deferred; no escape |
| S8 | CRC error in later archive member | no premature link activation |
| S9 | malformed `SYMLINK` value length/type | reject native link activation |
| S10 | linked file with another ordinary EA | both source attributes preserved |
| R1 | ZipOpt rewrite of archives with Xtro metadata | identities and companion relations remain sound |
| R2 | ZipDedup rewrite/clone/delete with metadata | no ID collisions, lost companions or unsafe aliases |
| R3 | ZipCloak encrypted transition | correct header/encryption/digest consistency |
| R4 | ZipNote/ZipSplit operations | preserve or explicitly refuse unsupported metadata operation |
| F1 | low disk space, I/O failure, readonly filesystem | accurate non-success and no claimed rollback |
| F2 | malformed manifest, length overflow, bogus ID, reserved member | reject without native changes |
| F3 | encrypted manifest placed in insecure staging | fail closed, never leak plaintext in temp area |
| F4 | systems without EA support | explicit non-success for required EA restoration |

Test negative archives from the trusted harness only. Never place path-escape
or symlink-attack archives on a production volume. Do not attempt to generate
an intentionally corrupted ZIP by editing random offsets manually; harnesses
should mutate known field boundaries and recalculate unrelated ZIP checksums
when the failure is supposed to occur in the Xtro layer.

## Exact procedure for each successful round-trip category

1. Set up a fresh test tree. Create test files/dirs with known contents and
   known native EAs; record the original raw EA values and required flags.
2. Create archives with normal Zip (legacy) and then with `zip --xattrs`;
   for the same input additionally test `zip -y --xattrs` when links exist.
3. Use UnZip list/test modes to verify file-member counts, reserved-companion
   visibility policy, CRC/integrity and correct exit status.
4. Extract normally and with `unzip --xattrs` into separate new roots;
   compare file content and EAs, including 0x80 required bit.
5. Independently inspect each archive's local and central Xtro extra fields;
   use `xtrmeta/verify_fixture` (on a supported host) to check XTMD digest,
   ordering and owner IDs where a companion/inline fixture is available.
6. Repeat on at least HPFS and JFS, and FAT if accessible. Record any native
   size limitations and `.LONGNAME` handling differences.
7. Run negative tests only after successful ordinary round trips. Require
   failure exit status, no filesystem escape, and a truthful error message.

Avoid embedding passwords directly in public command logs. Supply a secure
private mechanism when a password is necessary; redact it from shared reports.

## Cross-platform and host-side regression

On Linux, run strict C89 unit tests (`xtrmeta/test_os2_ea.c` and
`xtrmeta/test_os2_v1.c`) and `make -C xtrmeta check`. Also run the repo's
existing xattr, archive-graph, ZipCloak/ZipNote/ZipSplit, and overwrite-policy
tests, then recompile with high-optimization OW2 and debug OW2. Independently
verify LX headers, imports and SHA-256 checksums, then check other build
scripts for regressions. Run sanitizer/fuzz cases on the portable OS/2 EA
validator; these do not substitute for native OS/2 system call tests.

## Reporting template

```
Tester:              [anonymous code]
OS / version / FP:   [...]
Filesystem / drive: [...]
NLS/codepage:        [...]
kLIBC presence:      [...]
Tools SHA-256:       [...]
Test case ID:        [S6]
Command (redacted):  [...]
Exit code:           [...]
Expected:            [...]
Observed:            [...]
Output/log:          [...]
Before/after EA:     [raw-hex or safe fixture references]
Repeatability:      [...]
No data escaped:     [verified / cannot verify]
```

Release acceptance is blocked by *any* reproducible path escape, premature
symlink activation, missing required EA, conflicting dual-format write,
plaintext metadata leak under explicit encryption, or falsely successful
native attribute failure. Native error results are not automatically regressions
if a filesystem lacks a required capability; they must still be reported.

## Weak-entropy acceptance note

The native OW2 build explicitly permits a weak SHA-1-conditioned salt source
from OS/2 clock, uptime, memory status and process identity. Testers must
record the warning verbatim and should not use real secrets in AES fixtures.
Success does **not** establish cryptographic entropy quality. UnZip's
password-based AES decryption does not require randomness. See `ENTROPY.md`.

## Option B: encrypted directory EA acceptance (mandatory once native adapter enabled)

On each HPFS/JFS host that supports the test EA, create a disposable
`EADIR` directory with a binary native EA and an `FEA_NEEDEA` flag, and
record original EA bytes/flags. Run `zip --xattrs -eP TESTPASSWORD` (using
real test-only passwords) on `EADIR/`. Repeat using ZipCrypto `-P`.
Verify that (1) the directory owner is cleartext and empty; (2) the Xtro
central extra field indicates encrypted companion; (3) the companion is
actually encrypted and password extraction restores identical bytes/flags;
(4) neither the legacy 0x0009 field nor plaintext EA bytes appear; (5) a
wrong password or corrupted companion does not write EAs; (6) ordinary
non-directory owners still require matching encryption; (7) zipopt and
zipdedup do not orphan or expose companions. Save `zipinfo -v`, full logs,
filesystem and codepage details, plus before/after EA enumeration.
Native acceptance is not met by a successful Linux unit test alone.
