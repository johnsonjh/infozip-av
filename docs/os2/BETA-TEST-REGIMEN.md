# Xtro-ZIP cu102 OS/2 — beta acceptance regimen

**Candidate status:** Open Watcom V2 cross-built, Linux-hosted metadata tests
passed. **Not yet qualified for production or irreplaceable files.** This
procedure is for volunteers using a disposable OS/2/ArcaOS/eComStation test
volume. Never test hostile archives on an important volume.

## 0. Every tester must send an environment and results manifest

Record OS/2 Warp/eComStation/ArcaOS full version and fixpack, kernel date,
filesystem and drive of the scratch area (HPFS/JFS/FAT), codepage, country,
terminal/shell, presence of kLIBC and version, available conventional/virtual
memory, and presence of LAN Server ACL components.
Provide full console output, **both the command and exit code**,
any relevant raw EA bytes and the resulting safe sample archive. Do not send
real passwords, confidential EAs, or dumps of production files. Label each
result **PASS / FAIL / UNSUPPORTED / NOT RUN**; do not mark skipped as PASS.

Unpack the supplied OS/2 test binaries into a directory and execute all
commands in **a fresh, disposable scratch tree**, with the executables in PATH.
Use `E:` below to mean a disposable, EA-capable test volume; adjust the drive
explicitly. Do not reuse output directories between test cases. `ea-fixture`
is a purpose-built native OS/2 EA utility included with the beta package. It
uses the actual `DosQueryPathInfo` / `DosSetPathInfo` APIs, not kLIBC.

The standard fixture EA has name `XTROTEST`, value `FFFD0300414243`
(`EAT_ASCII`, length 3, bytes `ABC`), and required flag `80`. Use exactly
those bytes in the following positive tests. `XTRODIR` uses value
`FFFD0300444952` (`DIR`). The `check` operation returns nonzero if **either**
value or required flag differs; preserve the exit status.

## 1. Mandatory native smoke + help

```text
E:
MD XTROBETATEST
CD XTROBETATEST
zip -v
unzip -v
zipinfo -h
zipopt --version
zipdedup --help
zip -h2
unzip -hh
```

If a help/version operation is unrecognized, report the exact output; do not
assume the program is absent. Run the remaining traditional tools' `-h` or
`--help` where supported: zipnote, zipcloak, zipsplit, funzip, unzipsfx.

## 2. EA capture and restoration — unencrypted, inline and companion

```text
MD SOURCE
ECHO Sample test file>SOURCE\ONE.TXT
ea-fixture set SOURCE\ONE.TXT XTROTEST 80 FFFD0300414243
ea-fixture check SOURCE\ONE.TXT XTROTEST 80 FFFD0300414243
zip -r --xattrs XTROEA.ZIP SOURCE
unzip -t XTROEA.ZIP
unzip --xattrs XTROEA.ZIP -d OUTPUT
 ea-fixture check OUTPUT\SOURCE\ONE.TXT XTROTEST 80 FFFD0300414243
```

(The initial whitespace before `ea-fixture` in the final line is optional.)
Record the exact shell command exit codes and the archive member listing. The
archive should contain an Xtro `0x5854` owner field; if inline, no companion
is needed. For companion coverage, create a safe larger EA fixture or obtain a
known-good companion fixture from the test coordinator and repeat. The
maximum single native EA value is 65535 bytes, and OS/2 filesystem EA quotas
may prevent constructing an oversized **aggregate** set; mark such cases
UNSUPPORTED rather than fabricating a pass.

Verify compatibility separately: extract `XTROEA.ZIP` **without**
`--xattrs` into a different empty tree; if the legacy `0x0009` field exists,
its attributes should restore. Compare raw bytes and `FEA_NEEDEA` flags.
Test a file with unrelated preexisting destination EAs; restoring an archived
EA must not remove the unrelated name.

If the `--xattrs` extraction creates a file but exits with code 2, **do not
count that as an EA restore**: staged native EAs are discarded when the archive
does not finish verification. Rerun against a fresh empty `OUTPUT` directory
with the diagnostic build and save stderr as well as stdout. To distinguish
file content from native-EA restoration, use:

```text
unzip -Z -v XTROEA.ZIP
ea-fixture get OUTPUT\SOURCE\ONE.TXT XTROTEST
ea-fixture check OUTPUT\SOURCE\ONE.TXT XTROTEST 80 FFFD0300414243
```

ZipInfo should name `0x5854` as `Xtro metadata`. The `get` result must show
both flag `80` and the exact typed value; `DosQueryPathInfo rc=2` from
`ea-fixture get` means the requested EA was not found. Include the **first**
`unzip: OS/2 Xtro ...` failure line and any `DosQueryPathInfo`,
`DosSetPathInfo`, or `DosSetFileInfo` return code in the report. Keep the
original `XTROEA.ZIP` for independent header and manifest verification.

If the diagnostic UnZip rejects an `unsafe or unqueryable destination`,
also record any preceding `Xtro-ZIP: OS/2 SYMLINK EA path query rc=...`
or `file-handle query rc=...` line and the native path. `oError` is reported
only for EA-list format errors; it has no meaningful value for rc=32.
The safety guard checks the
`SYMLINK` EA independently of the user EA being restored: a valid empty
response or a well-formed zero-length `SYMLINK` value means the destination
is not a link; a genuine query error or malformed record must still block
the write. Retest in a newly created destination on an EA-capable volume.

On a pinned Xtro output file, `DosQueryPathInfo` can return rc=32
(`ERROR_SHARING_VIOLATION`) because the file is still open for writing.
Updated UnZip checks parent path components by name, but checks the final
file via `DosQueryFileInfo` on the pinned native handle. It also applies
ordinary EAs through that handle and releases the pin before deferred
`SYMLINK` EA activation. A file-handle query failure is **not** treated as
proof that the destination is safe. Test the ordinary legacy extraction,
`--xattrs` inline restoration, and an archive with a metadata companion,
including exact `ea-fixture check` values for all three cases.

## 3. Directory attributes and existing directories (Option B)

```text
MD DIRSRC
ea-fixture set DIRSRC XTRODIR 80 FFFD0300444952
zip --xattrs DIRPLAIN.ZIP DIRSRC\
unzip --xattrs DIRPLAIN.ZIP -d DOUT
ea-fixture check DOUT\DIRSRC XTRODIR 80 FFFD0300444952
```

Repeat with `DOUT\DIRSRC` **already existing** and the overwrite-all flag
`unzip -o --xattrs ...` to verify directory registration in that case. The
original unrelated EAs on the existing directory must remain intact. Verify
that the archive's directory owner has no file payload, and that it restores
without `--xattrs` only from the traditional OS/2 field where present.

## 4. AES and ZipCrypto — explicitly encrypted metadata

**Use only passwords created for these disposable fixtures.** Prefer `-eS`
(AES interactive prompt), which avoids printing the password in your command
history; use `-e` for the ordinary ZipCrypto prompt. Example:

```text
zip -r --xattrs -eS --aes-strength 256 PRIVATE.ZIP SOURCE
unzip --xattrs PRIVATE.ZIP -d PRIVOUT
 ea-fixture check PRIVOUT\SOURCE\ONE.TXT XTROTEST 80 FFFD0300414243
zip --xattrs -eS --aes-strength 256 DIRPRIVATE.ZIP DIRSRC\
unzip --xattrs DIRPRIVATE.ZIP -d PRIVDIR
 ea-fixture check PRIVDIR\DIRSRC XTRODIR 80 FFFD0300444952
```

Confirm the exact warning `OS/2 AES uses time/memory-derived salts; secure
entropy is NOT guaranteed.` when AES encryption is performed. Record that the
**directory owner remains unencrypted** while its companion is encrypted.
Neither local nor central headers should contain plaintext `XTROTEST`,
`XTRODIR`, or plaintext EA value bytes. The AES compatibility entropy is
predictable and **not** suitable for valuable secrets. Test AES-128, AES-192,
AES-256, and where supported `--aes-mode quantum` (AE-3) using distinct
scratch archives. Test ZipCrypto using `-e` separately. Wrong passwords and
corrupted companion authentication must fail and must **not** apply new EAs.
For corruption tests use only coordinator-supplied, well-formed mutation
fixtures; do not randomly edit arbitrary ZIP offsets.

## 5. Native kLIBC symlink preservation and extraction safety

These cases require native kLIBC `ln -s` and `readlink` or an independently
trusted equivalent. Record the exact symlink target and original underlying
`SYMLINK` EA before and after extraction. All extraction roots must be
separate disposable directories.

| ID | Fixture | Expected outcome |
| --- | --- | --- |
| SY1 | Relative link, `zip -y --xattrs` | Link's underlying file and `SYMLINK` EA preserved |
| SY2 | Same link **without** `-y` | Target contents/EAs, not link's `SYMLINK` EA |
| SY3 | Dangling/absolute/cyclic links, `-y` | Byte-exact target EA preserved, no following during creation |
| SY4 | Link pointing to a directory | No unexpected traversal during `-y` creation |
| SY5 | `@UNIXROOT` target | Target EA remains unmodified by host-dependent expansion |
| SY6 | Pre-existing destination `SYMLINK` or linked parent | Refuse destination redirection |
| SY7 | Late CRC error following a link member | No early link activation |
| SY8 | Corrupted/malformed `SYMLINK` value | Reject metadata without activating link |
| SY9 | Link with different EAs on target vs link | No mistaken mixing of link and target EAs |

Do not test malicious path-traversal fixtures manually on a filesystem with
valuable files. A tester must verify that no files outside the extraction
root are created or changed. Native link behavior is dependent on the kLIBC
implementation on the machine, but the raw EA must be faithfully preserved.

## 6. Conflict/error and archive-operation matrix

| ID | Operation | Required result |
| --- | --- | --- |
| CF1 | Legacy `0x0009` and Xtro values identical | Apply once, preserve raw bytes |
| CF2 | Same EA name but differing bytes/flags | Non-success, no partial EA update for owner |
| CF3 | Same name with codepage-specific case variation | Reject ambiguous collision |
| CF4 | Missing/duplicate companion or owner ID | Non-success and no native EA writes |
| CF5 | No EA-capable filesystem | Explicit error where preservation required |
| CF6 | Low memory (over 32 MiB companion or 128 MiB aggregate) | Fail; no truncation or claim of success |
| CF7 | Read-only target or native EA write failure | Non-success; report OS/2 status |
| CF8 | Encrypted directory without plaintext EA fallback | Restores through encrypted companion only |
| CF9 | Legacy EA set exceeds ZIP extra-field capacity | Complete Xtro companion and warning, never truncated `0x0009` |
| RW1 | zipopt rewrite | Valid graph and raw EAs; no orphan/duplicate companion |
| RW2 | zipdedup rewrite | Valid graph, unmodified data and EA identity |
| RW3 | ZipNote, ZipSplit, ZipCloak operations | Preserve verified metadata or fail cleanly |
| RW4 | No-clobber, wrong output path, read-only disk | Input/archive unchanged; no false success |
| RW5 | Different extraction include/exclude patterns | No unwanted companion files exposed |

Use the ordinary utility baseline detailed in `os2-native-test-plan.md`
first. Use only synthetic coordinator-supplied conflicting, malformed, and
multi-gigabyte fixtures. A successful `unzip -t` is not proof of correct EAs;
run the native `ea-fixture check` as well.

## 7. Evidence package for the coordinator

For **every** case, record `test-ID`, actual command, exit code, exact
stdout/stderr, expected/actual EA bytes and flags, OS build, filesystem,
codepage, and a reproducibility assessment.
Bundle non-sensitive test fixtures and ZIPs with a README listing failed,
unsupported and unexecuted cases separately. Share passwords only by an
approved private channel; never include them in logs or the bug report.

**Release-blocking failures:** any plaintext EA disclosure from encrypted
Xtro headers or temporary files; modified data outside the target directory;
symlink activation before integrity checks; falsely successful EA failures;
partial write after a pre-detected metadata conflict; failure to preserve
`FEA_NEEDEA`; owner/companion mismatch accepted; or corruption of existing
output by zipopt/zipdedup. One clean host does not establish acceptance for
other OS/2 versions or filesystems. Report unsupported APIs explicitly.

## 8. How to report an issue

Provide an anonymized tester ID, test case ID, OS version/fixpack, filesystem,
codepage, exact command and exit code, full console transcript, before/after
raw EA output, and the smallest non-confidential ZIP that reproduces the
failure. Distinguish **regression** (previous version worked) from **new
feature failure** (native `--xattrs` not previously supported). For a crash,
include the trap location, registers, and executable checksum if available.

See `POLICY.md` for the required metadata semantics, `ENTROPY.md` for the
approved weak-randomness limitation, and `../xtro-ea-v1/FORMAT.md` for the
platform-independent binary specification.
