# Xtro-ZIP cu102: Netlabs SVN checkout audit (2026-10-20)

Supplied checkouts: `netlabs-zip-unzip.tar.xz` and `netlabs-unzip.tar.xz`. Both are genuine working-copy snapshots, with `.svn/wc.db` records for repository `https://svn.netlabs.org/repos/ports`, UUID `8d6eb4b1-0faa-de11-b929-00e081727c95`. Both snapshots are at repository revision **2373**. The first archive contains `netlabs/zip/zip/{trunk,vendor}` and `netlabs/unzip/trunk`, but the latter is **zlib 1.2.11**, not Info-ZIP UnZip. The separate second archive contains `netlabs-unzip/unzip/{trunk,vendor}` for Info-ZIP UnZip. Names in the first archive are potentially confusing.

An SVN checkout stores current file text and pristine bases, *not* all revisions or server-side commit messages. Therefore this report audits every active-source difference from the supplied bitwiseworks Git tip, every changed source file between the SVN `vendor` and `trunk` directories, and metadata-reported revisions; it does **not** claim to retrieve every historical SVN changeset. The separately provided bitwiseworks full Git commit-history audit is in `os2-upstream-commit-audit.md`.

## Active SVN trunk versus bitwiseworks Git tree

A bytewise inventory of all non-`.svn` files establishes only:

| Tree | Differing files | Meaning |
|---|---|---|
| Zip | `fileio.c` | SVN still passes `(ulg)-1L` to `fcopy()`; upstream Git fixed to `(uzoff_t)-1L` in `15c2296`. Apply the **newer** fix to cu102 (done). |
| Zip | `os2/os2zip.c` | Compiler/OS-version display strings only; newer Git commit `d24b653`. Do not copy into an OW2 version banner. |
| Zip | `os2/makefile.os2` | Later Git GCC/libcx build adjustment; not applicable to native Watcom. |
| UnZip | `os2/os2.c` | Display strings for compiler and OS/2 variants only (`2c13f24`); native OW2 should identify the actual compiler. |
| UnZip | `os2/makefile.os2` | kLIBC build/link flags; no import into native OW2. |
| UnZip | `os2/rexxtest.cmd`, `os2/zgrepapi.cmd`, `os2/zip2exe.cmd` | REXX script packaging/formatting updates. The `zip2exe.cmd` operational changes are recorded in the Git audit; scripts are not needed to build seven traditional tools or zipopt/dedup. |

There are **zero** source files present only in the SVN trunks and absent from the corresponding Git trees. Therefore the SVN checkouts do not reveal a previously missing OS/2 C-source fix beyond those already reviewed through the complete Git commit histories.

## SVN vendor/3.0 versus Zip trunk

Ten changed source files: `globals.c`, `tailor.h`, `zip.c`, `zip.h`, and six under `os2/`: `makefile.os2`, `os2.c`, `os2acl.c`, `os2zip.c`, `os2zip.h`, `osdep.h`. These comprise kLIBC build selection, wildcard/path traversal, symlink-versus-referent handling, optional OS/2 archive-bit modes, and EA/ACL support. They correspond to the changes in the Git audit. `zip30/os2/os2link.c` is an *independent native OW2* implementation of the compatible `SYMLINK` EA handling rather than an import of kLIBC `realpath`, `lstat`, or GCC code.

## SVN vendor/6.0 versus UnZip trunk

Eight changed source files: `fileio.c`, `unzpriv.h`, `os2/os2.c`, `os2/os2cfg.h`, `os2/makefile.os2`, `os2/os2acl.c`, `os2/zip2exe.cmd`, `os2/zipgrep.cmd`. The important behaviors are OS/2 32-bit file status, deferred directory timestamps, enabling kLIBC/Unix `SYMLINKS` on the GCC build, matching callback ABI, and REXX scripts. A native OW2 build must **not** simply define Unix `SYMLINKS`, since that would introduce unresolved `symlink()` and potentially unwanted Unix-to-native conversion. Retain OS/2 `SYMLINK` EA restoration independently. The deferred-directory-timestamp and 32-bit status fixes have been adapted to native OS/2 APIs in the cu102 patch.

## Separately bundled zlib source

`netlabs/unzip/trunk/zlib.h` declares `ZLIB_VERSION "1.2.11"`. This is an independent zlib packaging checkout, not the Info-ZIP UnZip trunk. The initial Xtro-ZIP OS/2 profile uses built-in DEFLATE and decoders, so linking this zlib would add an unnecessary external dependency and potentially change format/ABI assumptions. **Do not integrate zlib 1.2.11** into the no-external-library baseline. It may be considered as a separate optional library port later, subject to security/support assessment.

## Implementation status / acceptance gates

- Seven traditional programs (and the ZipInfo alias) cross-linked as OS/2 LX using Open Watcom V2, with DOS16-equivalent high optimization flags.
- `zipopt`, `zipdedup`, `zipopt-preflight`, `zipopt-decodecheck` also cross-linked in the baseline configuration, using a private OS/2 UnZip decoder; no kLIBC/EMX/libcx import.
- `zipopt` uses Watcom `_fseeki64`/`_ftelli64` and `_stati64` variants; `zipdedup` deliberately rejects inputs above its signed-long seek limit (2 GiB class) and should not advertise arbitrary-size support.
- OS/2 utility temporary creation is O_EXCL; the native DosMove publish/no-replace behavior and failure cleanup **must** be tested on HPFS and JFS before release. The utilities remain experimental pending these tests.
- Native `SYMLINK` EA parsing and target-resolution unit mock passes on Linux, but actual kLIBC behavior requires native tests. Raw EA/wildcard/ACL tests are separate.
- **Release blockers:** the Xtro V1 OS/2 native `--xattrs` adapter, inline/companion metadata merge/conflict policy, large metadata handling, deferred/safe link activation on extraction, and full native runtime acceptance are *not* implemented by this build patch.

No external Netlabs source was directly copied; it was audited against cu102 and used only as a behavioral/regression reference.
