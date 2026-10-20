# Xtro-ZIP 32-bit OS/2 / ArcaOS native acceptance instructions

Build under Linux with `/opt/watcom` (override with `WATCOM=/path/to/compiler ./build-os2.sh`). Deliver the contents of `os2/` to the tester, not the Linux `.obj` files. The binaries are OS/2 32-bit LX; they have **not** been executed in a native OS/2 system by the cross-builder.

**Current candidate status:** the OS/2 Xtro V1 `--xattrs` capture and
restore adapters are integrated, but still require native beta acceptance.
Use only disposable test files and follow [BETA-TEST-REGIMEN.md](BETA-TEST-REGIMEN.md).
The older tests below remain useful as baseline regressions.

## Environment details to report

- OS/2 version: Warp / eComStation / ArcaOS and build/fixpack.
- Filesystem: HPFS, JFS, FAT as available; identify each test volume.
- Installed kLIBC version, `ln`, `readlink`, and shell (`CMD.EXE` vs kLIBC shell). Test native creation with kLIBC `ln -s`; Xtro-ZIP executable itself does not require a kLIBC DLL.
- Current value of `UNIXROOT`; whether the tested symlinks are relative, absolute, dangling, or `@UNIXROOT`-dependent.
- Presence/absence of LAN Server/Requester for ACL tests.

## Basic smoke test (scratch directory only)

Place the test executables on PATH or run each from its location. In a **new empty scratch directory**, create a small text file. Record the exact commands and console output:

```
zip -v
unzip -v
zipinfo -h
zip -9 BASIC.ZIP TEXT.TXT
unzip -t BASIC.ZIP
unzip -l BASIC.ZIP
unzip BASIC.ZIP -d OUT
```

Verify the extracted bytes match the input (compare with a trusted binary comparison utility). Test `zipnote`, `zipsplit`, `zipcloak`, `funzip`, and `unzipsfx` on **disposable** archives. If testing `unzipsfx` by concatenation, adjust its ZIP offsets with `zip -A` before testing, as described in the upstream REXX script fixes.

## Native EA round-trip

1. On HPFS/JFS create a test file with an ordinary binary EA, an EA whose name uses mixed case, and a file with `.LONGNAME` where supported. If you do not have a native EA editing/listing tool, report which utilities you have; do **not** make up data using a text file with the same name.
2. Record EA names, exact value bytes and required flags (`FEA_NEEDEA`) using an EA-aware tool before archiving.
3. Create an archive with default Zip (without `--xattrs`). Extract into an empty separate scratch directory with default UnZip.
4. Compare all EA names, raw typed EA values and flags. Verify CRC/test output and file content. Repeat with directory EAs and nested directories.
5. Induce a deliberate EA-write failure on a scratch target and confirm UnZip reports an error instead of claiming success.
6. Repeat on FAT if available, documenting `.LONGNAME` and filesystem support limitations.

## kLIBC native symbolic links

For each case below, create the link using a genuine OS/2 kLIBC-aware `ln -s` implementation. First verify it with `readlink` or a comparable known-good utility. Record physical link-file bytes and the raw `SYMLINK` EA when tools permit; do not assume they are identical. Use a scratch archive and empty extraction destination.

| Fixture | Zip creation command principle | Expected condition after extraction |
|---|---|---|
| Relative link to ordinary file | `zip -y LINKS.ZIP target linkname` | `linkname` retains its native `SYMLINK` EA and exact target |
| Absolute link | `zip -y` | Target bytes preserved; no machine-specific path rewriting |
| Dangling link | `zip -y` | Remains a dangling symlink, not dereferenced or silently lost |
| Relative link to directory | `zip -y` | Native link restored; no traversal into referent during creation |
| Circular links | `zip -y` | No infinite loop; link metadata survives |
| `@UNIXROOT` link | `zip -y` | Raw target remains unchanged, and kLIBC resolves it under its configured environment |

In a **separate** archive of a link without `-y`, verify target **data and target EAs** are stored, and the link's `SYMLINK` EA is not mistakenly attached to the ordinary file. Run a symlink fixture whose link and target have *different* ordinary EAs to detect the original Ticket #18 regression.

Test a path containing a symlink in an intermediate component. Try a dangling link and a cyclic link **without** `-y`, and report whether Zip produces a clear failure rather than archiving unrelated data. Try overwriting an existing link in the output scratch directory; the target must not be unintentionally modified.

## Directory time, archive integrity, and operational tests

- Record timestamps of nested directories before and after extract. A directory's final timestamp must not be overwritten by creating its children.
- Test AES and legacy ZipCrypto round-trips with **non-sensitive** passwords and independent ZIP test programs where possible. Note that this build cross-links AES but has not yet been runtime-validated on OS/2.
- Test `-r` with `*`, `*.*`, single filenames, nested wildcard components, paths with spaces, FAT-style names and long names. Record command shell expansion behavior separately from Zip behavior.
- Test a ZIP archive with malformed legacy OS/2 EA extra fields. No crash, no partial symlink activation, and no reported success on failure.
- Test ACL preservation/restoration with `-X` only on a system with the relevant LAN Server/Requester; skip and mark unsupported elsewhere.
- Test archives created by the user-provided bitwiseworks Zip and UnZip to detect compatibility differences. Keep original test archives for examination.

## Return artifacts

Please supply a compressed test-log directory containing: OS/version and filesystem details; exact commands; stdout/stderr and exit codes; `zip -v` and `unzip -v`; archived test files (without private data); and raw EA dumps/fixtures if your utilities can produce them. Distinguish **not tested**, **unsupported environment**, and **failed** rather than marking unavailable checks as passing.

**Not yet certified on native OS/2:** Xtro V1 `--xattrs`, companions,
dual-format collision behavior, and symlink Xtro restoration. These are now
implemented in the engineering candidate but need native test reports. Optional
external libraries remain excluded.

## Experimental zipopt / zipdedup native acceptance (new)

The default optimized build includes `zipopt.exe`, `zipdedup.exe`, `zipopt-preflight.exe`, and `zipopt-decodecheck.exe`. These tools must remain test-only until their native output publication behavior has been verified. They use native Watcom runtime file positioning, not kLIBC, and contain private built-in UnZip decoding. DO NOT test on valuable archives or directories.

On the OS/2 system, use a fresh empty scratch directory containing `TEXT.TXT` with known bytes. Run each command below independently; preserve the complete console output and the exit code after every command. The commands illustrate syntax; use the actual `.exe` pathname if the programs are not on PATH:

```
zip -9 INPUT.ZIP TEXT.TXT
unzip -t INPUT.ZIP
zipopt --version
zipopt --methods=help
zipopt --methods=store INPUT.ZIP OPT.ZIP
unzip -t OPT.ZIP
zipdedup INPUT.ZIP DEDUP.ZIP
unzip -t DEDUP.ZIP
```

Verify archived file bytes using `unzip -p` redirected into separate files, followed by the native `COMP` or an independent byte comparison. Do **not** infer equivalence solely from `unzip -t`. For tools that have only an internal verification API, test them first with `--help`; do not assume the helper executables support full command-line operation.

No-clobber test (experimental tools only): create a sentinel `EXISTS.ZIP` with an independently recorded hash and contents; attempt to produce it with both `zipopt --methods=store INPUT.ZIP EXISTS.ZIP` and `zipdedup INPUT.ZIP EXISTS.ZIP`. Both operations must fail, and the existing file bytes must remain **identical**. Repeat on HPFS and JFS. Inspect the scratch directory for orphan temporary files. Run a broken-output-path/permission-denied test and verify the source ZIP remains unchanged. Also compare outcome when the destination is the same path as the input; no input mutation is permitted.

Large-file test: use a sparse or ordinary ZIP just below and just above the native `long`-seek threshold (approximately 2 GiB), keeping all output scratch-only. `zipdedup` must reject unsupported input offsets cleanly. `zipopt` may use `_fseeki64`, but this is not evidence that every OS/2 filesystem supports such offsets; test and record OS/2 version, filesystem, and failure behavior. Do not spend resources making multi-gigabyte test archives on FAT.

For each utility, record `--version`, exit code, full stdout/stderr, source/output lengths and checksums, and whether the native DOSCALLS import table resolves. Include fixture ZIPs and temporary files (when non-sensitive) in the report. Report crash or unexpected files under a dedicated `FAILED` section rather than treating an LX link success as native acceptance.
