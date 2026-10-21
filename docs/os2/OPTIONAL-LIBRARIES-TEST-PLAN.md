# OS/2 optional codec beta acceptance — report template

**Status:** Native acceptance pending. All tests must be performed on disposable
files and archives. Do not replace production archives with test outputs.

## Tester information

Record OS/2 Warp, eComStation, or ArcaOS full version and patch level;
filesystem (HPFS, JFS, FAT); codepage; available RAM; CPU; exact Zip/UnZip
binary SHA-256 (or another available cryptographic checksum); `zip -v` and
`unzip -v`; and contents of each successfully installed codec's
`build-os2-libs/<codec>/install/built-from-commit.txt`.

Report **PASS**, **FAIL**, **UNSUPPORTED**, or **NOT RUN** for each numbered case,
with exact commands, exit statuses, and full logs. Preserve a failing
archive and the smallest possible input to reproduce a failure.

## Build requirements

1. With no optional libraries installed, `./build-os2.sh` must produce the
   normal optimized 12-executable suite. Verify existing method-12 BZip2.
2. With a Linux-hosted OW2 toolchain, `./build-os2-libs.sh` should build
   all three optional static libraries from the default upstream branch tips,
   while preserving checkouts unmodified (`git status --porcelain` empty).
   First attempt one at a time if diagnosis is needed. `OS2_LIBS=lzma
   ./build-os2-libs.sh` must build a target static liblzma
   and pass its OS/2 LX API link probe; its Git SHA must be recorded.
3. `OS2_LZMA=on ./build-os2.sh` must build all 12 executables. With
   `OS2_DEBUG=1` repeat the diagnostic build. Verify no kLIBC dependencies.
4. Build and activate Zstd with `OS2_LIBS=zstd` / `OS2_ZSTD=on` and then
   WavPack with `OS2_LIBS=wavpack` / `OS2_WAVPACK=on`, independently.
5. `OS2_LZMA=off OS2_ZSTD=off OS2_WAVPACK=off ./build-os2.sh` must still
   build; ordinary `unzipsfx.exe` must not link optional codec libraries.
6. `clean.sh` must remove generated libraries/objects while preserving
   `build-os2-libs/{lzma,zstd,wavpack}/source/.git` and a detached checkout.

## Functional cases

For each selected method, use small text, large binary, empty, repetitive,
random, and multi-file/directory inputs. Keep checksums of originals and
outputs. Run examples from an OS/2 command shell, adapting path quoting only:

```
zip -9 -Z lzma LZMA.ZIP SAMPLE.DAT
unzip -t LZMA.ZIP
unzip LZMA.ZIP -d TESTLZMA

zip -9 -Z xz XZ.ZIP SAMPLE.DAT
unzip -t XZ.ZIP
unzip XZ.ZIP -d TESTXZ

zip -9 -Z zstd ZSTD.ZIP SAMPLE.DAT
unzip -t ZSTD.ZIP
unzip ZSTD.ZIP -d TESTZSTD
```

All extracted contents must match the originals byte-for-byte. Verify
independent extraction with a second implementation supporting the relevant
method (ZIP 14, 95, 20, 93). The legacy Zstd method 20 needs a separate
existing fixture, not an assumption that standard -Z zstd creates it.

7. Method 14 LZMA must handle both EOS-marker and known-size variants,
   including PKZIPC-produced fixtures and property-field edge cases.
8. Method 95 XZ must handle all supported checks, malformed frame headers,
   trailing junk, and truncation without crashes or silent success.
9. Method 96 WinZip JPEG requires a genuine WinZip JPEG ZIP fixture; ordinary
   JPEG content compressed using method 14/95 is not an equivalent test.
10. Methods 20/93 Zstd must decode verified third-party fixtures and reject
    malformed frame/dictionary/checksum data without data corruption.
11. Method 97 WavPack must decode a real WavPack ZIP fixture. Do not assume
    Zip can create method 97; this first integration enables its decoder.
12. Reprocess archives containing each method through `zipopt` and
    `zipdedup`; test candidate rejection, CRC verification, interrupted
    publication, and preservation of all noncandidate members.
13. Repeat a subset with `zip --xattrs` and `unzip --xattrs` on HPFS and JFS
    using native EAs, required-EA flags, directories and kLIBC symlinks.
14. Verify AES, wrong-password behavior, corrupted archives, and archive
    integrity rejection. Do not use weak-entropy OS/2 AES for real secrets.
15. Confirm unsupported methods are skipped/rejected safely by default
    UnZipSFX, without unexpected automatic inclusion of external codecs.
16. Test constrained memory and disk-full extraction with disposable files.

## Acceptance rule

An upstream commit is **not** a known-good OS/2 revision until the full
library build, all Xtro-ZIP target links, and the relevant native tests pass.
A cross-link check alone proves no runtime behavior. Any failed or unrun
case must remain visible in the final report. Update the tested-commit
comments/documentation only after native acceptance.

## OW2 compatibility adapter and no-network checks

- `OS2_LIBS_FETCH=0 OS2_LIBS='lzma zstd wavpack' ./build-os2-libs.sh`
  with the three populated source checkouts must succeed. Verify that
  `build-os2-libs/<codec>/ow2-source` contains the patched throwaway snapshot
  and that `source/.git` stays intact and unchanged.
- Detach each source checkout at the recorded commit and repeat with
  `OS2_LIBS_FETCH=0`. The build must not try to reset or update the checkout.
- Simulate a future incompatible upstream edit in a *disposable clone* and
  verify that a zero-fuzz patch failure exits nonzero and removes the
  incomplete `install/` directory.
- Verify the `-ei` enum-size flag is present in libzstd builds. Check that
  the full archiver and private ZipOpt/ZipDedup decoder build with all three
  libraries, while ordinary `unzipsfx.exe` excludes them.
- Verify on the target OS using `unzip -v` that the intended methods are
  compiled in, then run method-specific compression/extraction fixtures.
  Do not infer native runtime success from an LX link probe.

## Reproduction and report format

For every method and every OS/filesystem pairing record: exact Xtro-ZIP
executable hash, upstream revision, command, process return code, size and
SHA-256 of input and extracted files, expected/actual behavior, and full
stdout/stderr. Include corrupt/truncated streams and archives updated by
`zipopt` and `zipdedup`. Mark cases PASS / FAIL / NOT RUN / UNSUPPORTED.
Use disposable directories; protect existing archives from test overwrites.
