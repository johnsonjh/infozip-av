# Xtro‑ZIP

<br>
<p align="center">
  <img src=".img/xtro-zip.webp" alt="Xtro‑ZIP" width="100%">
</p>
<br>

---

<!-- toc -->

- [Overview](#overview)
  * [Features](#features)
- [Downloads](#downloads)
- [Building](#building)
- [Usage](#usage)
  * [De-duplication (`zipdedup`)](#de-duplication-zipdedup)
  * [Optimization (`zipopt`)](#optimization-zipopt)
  * [Filesystem metadata preservation](#filesystem-metadata-preservation)
    + [Metadata platform support](#metadata-platform-support)
    + [Metadata preservation notes](#metadata-preservation-notes)
  * [PKAV](#pkav)
    + [PKAV archive creation (`zip`)](#pkav-archive-creation-zip)
    + [PKAV archive testing (`unzip`)](#pkav-archive-testing-unzip)
    + [PKAV archive extraction (`unzip`)](#pkav-archive-extraction-unzip)
    + [PKAV self-extractor creation (`unzipsfx`)](#pkav-self-extractor-creation-unzipsfx)
  * [FWKCS](#fwkcs)
    + [FWKCS archive creation (`zip`)](#fwkcs-archive-creation-zip)
    + [FWKCS archive testing (`unzip`)](#fwkcs-archive-testing-unzip)
    + [FWKCS archive extraction (`unzip`)](#fwkcs-archive-extraction-unzip)
    + [FWKCS self-extractor creation (`unzipsfx`)](#fwkcs-self-extractor-creation-unzipsfx)
  * [PKWARE compatibility](#pkware-compatibility)
    + [PKAV](#pkav-1)
    + [FWKCS](#fwkcs-1)
- [Historical examples](#historical-examples)
  * [PKAV 2.x](#pkav-2x)
  * [PKAV 1.x](#pkav-1x)
- [Developer notes](#developer-notes)
- [Security](#security)
- [Availability](#availability)
- [Licenses](#licenses)
- [External links](#external-links)

<!-- tocstop -->

## Overview

> [!TIP]
> **Xtro‑ZIP** is the **only** permissively‑licensed open‑source ZIP software
> that even comes close to fully supporting the complete ZIP specification!

**Xtro‑ZIP**, derived from **Info‑ZIP**, adds:

* **new algorithms**
* **security** hardening
* **ultra** compression levels
* data **de‑duplication**
* ZIP **optimization**
* filesystem **metadata preservation**
* CRC/SHA/AES/compression **hardware** **acceleration**<sup>1</sup>
* [**PKAV**](https://github.com/johnsonjh/pkstuff#authenticity-verification)
  (create *and* verify for PKAV&nbsp;2.x, verification‑only for PKAV&nbsp;1.x)
* [**FWKCS**](http://justsolve.archiveteam.org/wiki/FWKCS)
  [MD5](https://en.wikipedia.org/wiki/MD5)
* [**AES** cryptography](https://www.winzip.com/en/support/aes-encryption/)
  (**AE‑1**, **AE‑2**, and “quantum‑resistant” **AE‑3**)
* improved **Unicode** support
* innumerable **bug fixes** and other improvements

> [!NOTE]
> [**Precompiled binaries for several popular platforms (Windows, Linux, OS/2, DOS, etc.) are available for download.**](https://github.com/johnsonjh/infozip-av/releases/tag/v0)

### Features

The ability to compress and decompress archive members using **Zstandard**
(method&nbsp;20 and 93), **LZMA** (method&nbsp;14), **XZ**/**LZMA2**
(method&nbsp;95), **ZIP**‑**Implode** (method&nbsp;6),
**DCL**‑**Implode** (method&nbsp;10), **Deflate64** (method&nbsp;9),
**IBM&nbsp;CMPSC** (method&nbsp;16), **Shrink** (method&nbsp;1), **Reduce**
(methods 2 through 5), **PPMd** (method&nbsp;98), and Appleʼs **LZFSE**
(method&nbsp;99) has been added.

New decompression‑only support for the **WZ‑MP3** (method&nbsp;94), **WZ‑JPEG**
(method&nbsp;96), and **WavPack** (method&nbsp;97) “multimedia extensions”,
and Xceedʼs **BWT** (method&nbsp;18) has also been integrated.

WinZip‑style de‑duplication **RefPtr** (method&nbsp;92) is supported.

The usual ZIP **Store** (method&nbsp;0) and **DEFLATE** (method&nbsp;8)
algorithms remain supported.

Additionally, **ultra** compression levels, which take extra time and use more
memory to achieve tighter packing (enabled via `zip ‑11`) are supported for
the **DEFLATE** (using a custom
[Zopfli](https://github.com/google/zopfli)‑derived encoder), **Deflate64™**,
**Zstandard**, IBM z/OS **CMPSC**, **DCL**‑**Implode**, and Apple
**LZFSE** methods.

|   Method | Description                                           | Decompression | Compression |
|---------:|:------------------------------------------------------|:-------------:|:-----------:|
|  **`0`** | Store&nbsp;(no&nbsp;compression)                      |       ✅      |      ✅     |
|  **`1`** | Shrink                                                |       ✅      |      ✅     |
|  **`2`** | Reduce&nbsp;(level&nbsp;1)                            |       ✅      |      ✅     |
|  **`3`** | Reduce&nbsp;(level&nbsp;2)                            |       ✅      |      ✅     |
|  **`4`** | Reduce&nbsp;(level&nbsp;3)                            |       ✅      |      ✅     |
|  **`5`** | Reduce&nbsp;(level&nbsp;4)                            |       ✅      |      ✅     |
|  **`6`** | ZIP‑Implode                                           |       ✅      |      ✅     |
|  **`8`** | DEFLATE                                               |       ✅      |      ✅     |
|  **`9`** | Deflate64™&nbsp;(Enhanced&nbsp;DEFLATE)               |       ✅      |      ✅     |
| **`10`** | DCL‑Implode                                           |       ✅      |      ✅     |
| **`12`** | bzip2<sup>2</sup>                                     |       ✅      |      ✅     |
| **`14`** | LZMA<sup>3</sup>                                      |       ✅      |      ✅     |
| **`16`** | IBM&nbsp;z/OS&nbsp;CMPSC                              |       ✅      |      ✅     |
| **`18`** | BWT<sup>4</sup>                                       |       ✅      |             |
| **`20`** | LPAQ8<sup>5</sup>                                     |       ✅      |      ✅     |
| **`20`** | Zstandard&nbsp;(deprecated)                           |       ✅      |      ✅     |
| **`92`** | Reference&nbsp;Link<sup>6</sup>&nbsp;(de‑duplication) |       ✅      |      ✅     |
| **`93`** | Zstandard<sup>7</sup>                                 |       ✅      |      ✅     |
| **`94`** | WZ‑MP3                                                |       ✅      |             |
| **`95`** | XZ/LZMA2<sup>3</sup>                                  |       ✅      |      ✅     |
| **`96`** | WZ‑JPEG<sup>3</sup>                                   |       ✅      |             |
| **`97`** | WavPack<sup>8</sup>                                   |       ✅      |      ✅     |
| **`98`** | PPMd&nbsp;version&nbsp;I&nbsp;(8)&nbsp;Rev&nbsp;1     |       ✅      |      ✅     |
| **`99`** | <code style="color : red">LZFSE</code><sup>9</sup>                                     |       ✅      |      ✅     |

> [!NOTE]
> Methods 1 through 6 are *legacy algorithms* and are no longer
> recommended for normal use.
>
> <sup>**1**</sup>&nbsp;CRC/SHA/AES/compression hardware acceleration is
> automatically detected at runtime and is currently supported on AMD64 and
> ARM64 systems running Linux, FreeBSD, OpenBSD, macOS, and Windows.
> Additional hardware acceleration may be provided via the (*optional*)
> [`zlib‑ng`](https://github.com/zlib-ng/zlib-ng) or
> [`libdeflate`](https://github.com/ebiggers/libdeflate) libraries where
> available.
>
> <sup>**2**</sup>&nbsp;bzip2 support requires
> [`libbz2`](https://sourceware.org/bzip2/);
> use of [`bz2‑ng`](https://github.com/tfenne/bz2-ng) recommended.
>
> <sup>**3**</sup>&nbsp;LZMA, XZ/LZMA2, and WZ‑JPEG support requires
> [`liblzma`](https://tukaani.org/xz/).
>
> <sup>**4**</sup>&nbsp;BWT is a **non‑standard** Xceed extension that shares
> method `18` with “IBM TERSE”; Xtro‑ZIP automatically determines the proper
> format by identifying valid BWT data.  While the IBM‑specific TERSE and LZ77
> compression technologies referenced in the
> [PKWARE `APPNOTE.TXT`](https://www.pkware.com/documents/casestudies/APPNOTE.TXT)
> unquestionably exist, because there is *no evidence* of formal specifications
> nor any software known to implement these methods, they are excluded from the
> table, as are other specifically reserved (`7`, `11`, `13`, `15`, `17`, etc.)
> identifiers.
>
> <sup>**5**</sup>&nbsp;LPAQ8 is a **non‑standard** PAQZIP extension that
> shares method `20` with the (deprecated) Zstandard (now method&nbsp;93);
> Xtro‑ZIP automatically determines the proper format by analyzing the
> data stream.
>
> <sup>**6**</sup>&nbsp;De‑duplicated archive creation supported via
> [`zipdedup`](#de-duplication-zipdedup).
>
> <sup>**7**</sup>&nbsp;Zstandard support requires
> [`libzstd`](https://facebook.github.io/zstd/).
>
> <sup>**8**</sup>&nbsp;WavPack support requires
> [`libwavpack`](https://www.wavpack.com/); compression supported via
> [`zipopt`](#optimization-zipopt).
>
> <sup>**9**</sup>&nbsp;LZFSE is a **non‑standard** Apple extension that shares
> method `99` with WinZip AES; Xtro‑ZIP automatically determines the proper
> format using metadata analysis.

These changes are built using Fedoraʼs current Info‑ZIP
[`zip`](https://src.fedoraproject.org/rpms/zip) (`3.0‑46`,&nbsp;2026‑07‑17),
and [`unzip`](https://src.fedoraproject.org/rpms/unzip)
(`6.0‑71`,&nbsp;2026‑07‑27) source packages as a base.

If you want, you can compare the changes against the Fedora upstream version
using [GitHub](https://github.com/johnsonjh/infozip-av/compare/fedora...pkav)
or [GitLab](https://gitlab.com/johnsonjh/infozip-av/-/compare/fedora..pkav).

## Downloads

[**Periodically updated builds are available for several operating systems.**](https://github.com/johnsonjh/infozip-av/releases/tag/v0)

## Building

* Use “`./build-unix.sh`” for native builds on most UNIX-like systems.

* Use “`./build-win32.sh`” for Windows builds using
  [mingw-w64](https://www.mingw-w64.org/).

* Use “`./build-dos386.sh`” for DOS 386 DPMI builds using
  [DJGPP](https://www.delorie.com/djgpp/).

* Use “`./build-dos16.sh`” for DOS 16‑bit builds using
  [Open Watcom V2.0](https://github.com/open-watcom/open-watcom-v2).

* Use “`./build-os2.sh`” for OS/2 32‑bit builds using
  [Open Watcom V2.0](https://github.com/open-watcom/open-watcom-v2).
  * *Optionally*, use “`./build-os2-libs.sh`” ***before*** starting the build
  to compile additional OS/2 libraries (LZMA, Zstandard, WavPack).

> To make “reproducible” builds, see
> [`SOURCE_DATE_EPOCH` and (security policy)](docs/SOURCE_DATE_EPOCH.md).

> [!IMPORTANT]
> Examine the actual build scripts (and the “`build-all.sh`” script the
> developer uses to build the binary releases) for more detailed information.

## Usage

### De-duplication (`zipdedup`)

The new `zipdedup` tool creates WinZip‑compatible (“ZIPX” method&nbsp;92)
de‑duplicated archives from existing ZIP source archives.

It hashes all archived files and retains the first (compressed) source file,
without recompressing it, and smartly de‑duplicates entries only if the
operation would result in a *smaller* output archive (*i.e.*, very small files
will be skipped).

```
$ zipdedup original.zip deduplicated.zip
449 new references; approximate savings: 9,010,081 bytes
```

Invoke as `zipdedup --help` for complete `zipdedup` usage information.

### Optimization (`zipopt`)

The new `zipopt` tool optimizes an existing ZIP file by recompressing each
member of the archive using every possible (or every requested) compression
method, keeping the data from the method that produces the smallest output
(which could be the original input).

Relevant archive metadata is preserved and extensive checking is performed to
ensure that the process is completely lossless.

All available *decompression* methods are supported in input files, but output
currently excludes the non‑standard Apple LZFSE and the special‑purpose IBM
z/OS CMPSC methods.

```
$ zipopt original.zip optimized.zip
optimized.zip: complete [1043 members]
zipopt: 13,005,195 bytes -> 3,767,243 bytes -> 3,093,724 bytes
        (71% -> 18% -> 76%) [673,519 bytes saved]
```

Invoke as `zipopt --help` for complete `zipopt` usage information.

### Filesystem metadata preservation

**Xtro‑ZIP** supports optional preservation of UNIX filesystem extended attributes
and NTFS alternate data streams as **Xtro** metadata.

The portable **Xtro** format can store binary attributes, native attribute
metadata, and named data streams.  Small metadata is stored in ZIP extra
fields, and larger metadata is stored as additional ZIP members “companions”.
All metadata is independently verified using SHA‑256, and can be secured with
ZipCrypto or AES encryption.

#### Metadata platform support

| Platform        | Status | Description |
|----------------:|:------:|:------------------------------------------------------------------------------------------------------------------|
| Linux           |   ✅   | Save/restore of Linux [`xattr` extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#Linux) |
| FreeBSD         |   ✅   | Save/restore of FreeBSD [`extattr` extended attributes](https://man.freebsd.org/cgi/man.cgi?query=extattr)        |
| NetBSD          |   ✅   | Save/restore of NetBSD [`extattr` extended attributes](https://man.netbsd.org/extattr.3)                          |
| Windows         |   ✅   | Save/restore of NT [extended attributes and NTFS named data streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) |
| AIX             |        | [Support](https://en.wikipedia.org/wiki/Extended_file_attributes#AIX) is **planned**                              |
| Solaris/illumos |        | [Support](https://en.wikipedia.org/wiki/Extended_file_attributes#Solaris) is **planned**                          |
| macOS           |        | [Support](https://en.wikipedia.org/wiki/Extended_file_attributes#macOS) is **planned**                            |
| Haiku           |        | [Support](https://www.haiku-os.org/docs/userguide/en/attributes.html) is **planned**                              |

* Save/restore extended attributes:

  ```
  zip --xattrs archive.zip file(s)
  unzip --xattrs archive.zip
  ```

On Windows, `--xattrs` indicates NT extended attributes and `--streams`
indicates NTFS named data streams.  The corresponding `--no-xattrs` and
`--no-streams` options can be used to disable these operations.

* Save/restore Windows extended attributes and NTFS data streams

  ```
  zip --xattrs --streams archive.zip file(s)
  unzip --xattrs --streams archive.zip
  ```

#### Metadata preservation notes

* **Xtro metadata** uses the `0x5854` ZIP extra‑field identifier, which is
  provisional and pending final format review.
* Large metadata is stored as “companion” members appear as ordinary ZIP members
  to ZIP extractors that do not recognize the **Xtro‑ZIP** **Xtro** metadata
  extensions.  Such extractors can still process any ordinary files.
* When replacing archive members, **Xtro‑ZIP** recaptures any relevant
  metadata (or reports the removal of obsolete metadata).
* Metadata‑aware archive utilities preserve ownership and “companion”
  relationships where supported (although some encrypted archive
  transformations are currently unsupported).
* ACLs, security descriptors, security labels, capabilities, quarantine
  tags, and NTFS alternate data streams are **not** implicitly restored as
  ordinary extended attributes.

### PKAV

PKAV today is cryptographically useless, but supporting it is *important for
historical preservation and research*, and it unlocks the encrypted AVEXTRA
data present in many original PKZIP archives that would otherwise be completely
inaccessible (or *only* accessible using official PKWARE software).

The `unzip` and `unzipsfx` tools verify both the original PKAV&nbsp;1.x format
used by PKWARE PKZIP 1.x releases as well as the more common PKAV&nbsp;2.x
format.  PKAV archive creation with `zip` supports PKAV&nbsp;2.x only.

#### PKAV archive creation (`zip`)

> [!NOTE]
> Generation of PKAV registration is outside the scope of this project,
> but is [covered elsewhere](https://github.com/johnsonjh/pkstuff#makeav).

```
$ printf '%s\n' '' 'This is the AVEXTRA comment!' '' > avextra.txt

$ zip --pkav-name 'This was made with InfoZip!' \
      --pkav-s1 x --pkav-s2 y \
      --pkav-avextra avextra.txt test.zip ./*.c
  adding: makeav.c (deflated 86%)
  adding: pklaxfix.c (deflated 82%)
  adding: pkpspfix.c (deflated 76%)
  adding: putav.c (deflated 78%)
```

#### PKAV archive testing (`unzip`)

```
$ unzip -t test.zip
Archive:  test.zip
    testing: makeav.c                 OK -AV
    testing: pklaxfix.c               OK -AV
    testing: pkpspfix.c               OK -AV
    testing: putav.c                  OK -AV
Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!

No errors detected in compressed data of test.zip.
```

#### PKAV archive extraction (`unzip`)

```
$ unzip -xa test.zip
Archive:  test.zip
  inflating: makeav.c                -AV [text]
  inflating: pklaxfix.c              -AV [text]
  inflating: pkpspfix.c              -AV [text]
  inflating: putav.c                 -AV [text]
Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!
```

If errors are encountered when testing or extracting an archive, a PKAV
archive provides additional information:

```
$ unzip -t test.zip
Archive:  test.zip
    testing: makeav.c                 OK -AV
    testing: pklaxfix.c               OK -AV
    testing: pkpspfix.c               OK -AV
    testing: putav.c                  bad CRC 437342ff  (should be 9ed0722b) -AV
warning: PKAV Authenticity Verification failed
warning: unverified PKAV AVEXTRA data is present; use --show-avextra-on-fail to display it
At least one error was detected in test.zip.
```

#### PKAV self-extractor creation (`unzipsfx`)

The `unzipsfx` self‑extracting stub handles PKAV automatically.

> [!IMPORTANT]
> When creating a self‑extracting archive, ensure that you correct the entry
> offsets using the `zip ‑A` command.  If you donʼt run `zip ‑A` the archive
> is not a fully conforming ZIP file and other software (especially PKWARE
> software) may reject it as invalid or corrupt.

```
$ cat $(command -v unzipsfx) test.zip > test.sfx

$ chmod a+x test.sfx

$ zip -A test.sfx
Zip entry offsets appear off by 115316 bytes - correcting...

$ ./test.sfx -t
    testing: makeav.c                 OK -AV
    testing: pklaxfix.c               OK -AV
    testing: pkpspfix.c               OK -AV
    testing: putav.c                  OK -AV
Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!

No errors detected in compressed data of ./test.sfx.
```

### FWKCS

The FWKCS extension was originally implemented by
[Frederick W. Kantor](https://en.wikipedia.org/wiki/Frederick_Kantor) as a
way identify duplicate files in archives more reliably than by the filename,
size, and CRC.  It is still useful today as a lightweight integrity checksum,
augmenting the standard ZIP CRC‑32.  FWKCS cooperates with PKAV, and because
older ZIP software can ignore the FWKCS metadata when unsupported, it has
excellent backwards compatibility.

FWKCS support is **not** enabled by default.  To enable FWKCS when archiving,
use the `--fwkcs-md5` option.  To enable FWKCS when listing (`‑l`) or
verbosely listing (`‑v`), use the `--list-fwkcs-md5` option.

It was decided **not** to enable FWKCS support by default (even though it is
officially supported and documented in the current
[`APPNOTE.TXT`](https://www.pkware.com/documents/casestudies/APPNOTE.TXT)) for
a number of reasons:

1. Mainly to avoid *silently* including FWKCS MD5 metadata when most ZIP
   implementations just *silently* ignore it.  This could be catastrophic for
   privacy; a “mostly hidden” MD5 hash may betray the contents of an
   encrypted file.
2. It complicates adding new members to existing archives.  If FWKCS support
   was enabled by default, updating an archive would *silently* create archives
   where newly added or updated members would have FWKCS MD5 hashes and old
   ones would not.
3. Calculating the FWKCS MD5 hashes when archiving is not free in terms of
   CPU time.
4. While the presence of FWKCS MD5 hashes greatly improves the ability to
   detect archive corruption, MD5 is not modern authentication.  Users could
   easily misunderstand FWKCS to be a security feature, and it is not.
5. Requiring opt‑in when listing (`‑l`) and verbosely listing (`‑v`) ensures
   that users who are further processing the output (*e.g.*, `AWK` scripts)
   wonʼt experience regressions.

#### FWKCS archive creation (`zip`)

```
$ zip --fwkcs-md5 pkstuff.zip ./*.com
  adding: makeav.com (deflated 42%)
  adding: pklaxfix.com (deflated 31%)
  adding: pkpspfix.com (deflated 29%)
  adding: putav.com (deflated 29%)
```

#### FWKCS archive testing (`unzip`)

```
$ unzip -v --list-fwkcs-md5 pkstuff.zip
Archive:  pkstuff.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   FWKCS MD5                         Name
--------  ------  ------- ---- ---------- ----- --------  --------------------------------  ----
   30300  Defl:N    17620  42% 10-01-2026 00:39 431fa9a2  3728359993a24bc8329250be8def15ee  makeav.com
   18850  Defl:N    13040  31% 10-01-2026 00:39 902af968  e506191a90b515742d996d4bd74d9ddd  pklaxfix.com
   15888  Defl:N    11210  29% 10-01-2026 00:39 9afdcb69  4077e98e885eeb3860f01e5d730835ac  pkpspfix.com
   16590  Defl:N    11740  29% 10-01-2026 00:39 3b629188  39d3190b88293c17ac93b94818e64468  putav.com
--------          -------  ---                            -------
   81628            53610  34%                            4 files
FWKCS MD5 metadata information present (not verified by listing).
```

```
$ unzip -t pkstuff.zip
Archive:  pkstuff.zip
    testing: makeav.com               OK
    testing: pklaxfix.com             OK
    testing: pkpspfix.com             OK
    testing: putav.com                OK
FWKCS MD5 checksums verified for 4 entries.
No errors detected in compressed data of pkstuff.zip.
```

#### FWKCS archive extraction (`unzip`)

```
$ unzip -xa pkstuff.zip
Archive:  pkstuff.zip
  inflating: makeav.com              [binary]
  inflating: pklaxfix.com            [binary]
  inflating: pkpspfix.com            [binary]
  inflating: putav.com               [binary]
```

If errors are encountered when testing or extracting an archive, an FWKCS
archive provides additional information:

```
$ unzip -t pkstuff.zip
Archive:  pkstuff.zip
    testing: makeav.com               bad CRC 982e9e5e  (should be 431fa9a2)
        FWKCS MD5 mismatch: makeav.com
        9f3d331fc86d703edb022249017ac730 (should be 3728359993a24bc8329250be8def15ee)
    testing: pklaxfix.com             OK
    testing: pkpspfix.com             OK
    testing: putav.com                OK
At least one error was detected in pkstuff.zip.
```

#### FWKCS self-extractor creation (`unzipsfx`)

> [!IMPORTANT]
> When creating a self‑extracting archive, ensure that you correct the entry
> offsets using the `zip ‑A` command.  If you donʼt run `zip ‑A` the archive
> is not a fully conforming ZIP file and other software (especially PKWARE
> software) may reject it as invalid or corrupt.

```
$ cat $(command -v unzipsfx) pkstuff.zip > pkstuff.sfx

$ chmod a+x pkstuff.sfx

$ zip -A pkstuff.sfx
Zip entry offsets appear off by 115316 bytes - correcting...

$ ./pkstuff.sfx -t
    testing: makeav.c                 OK
    testing: pklaxfix.c               OK
    testing: pkpspfix.c               OK
    testing: putav.c                  OK
FWKCS MD5 checksums verified for 4 entries.
No errors detected in compressed data of ./pkstuff.sfx.
```

### PKWARE compatibility

Archives that have been created with this PKAV implementation,
including self‑extracting executables with FWKCS metadata, are fully
compatible with the official PKWARE PKUNZIP software.

#### PKAV

```
$ emu2 pkunzip.exe -t test.sfx

PKUNZIP (R)    FAST!    Extract Utility    Version 2.50    03-01-1999
Copr. 1989-1999 PKWARE Inc.  All Rights Reserved.  Registered version
PKUNZIP Reg. U.S. Pat. and Tm. Off.


Searching ZIP: TEST.SFX
Testing: makeav.c      OK -AV
Testing: pklaxfix.c    OK -AV
Testing: pkpspfix.c    OK -AV
Testing: putav.c       OK -AV

Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!
```

#### FWKCS

While FWKCS metadata is not verified by most classic ZIP tools, it should not
cause compatibility problems (even when used in combination with PKAV).

```
$ emu2 pkunzip.exe -t pkstuff.sfx

PKUNZIP (R)    FAST!    Extract Utility    Version 2.50    03-01-1999
Copr. 1989-1999 PKWARE Inc.  All Rights Reserved.  Registered version
PKUNZIP Reg. U.S. Pat. and Tm. Off.

Searching ZIP: PKSTUFF.SFX
Testing: makeav.com    OK
Testing: pklaxfix.com  OK
Testing: pkpspfix.com  OK
Testing: putav.com     OK
```

## Historical examples

### PKAV 2.x

The [very](http://justsolve.archiveteam.org/wiki/FWKCS)
[famous](https://dn790003.ca.archive.org/0/items/emcfarber_jsstestimony/Sadofsky%2C%20Jason%20Scott.pdf)
[`FWKCS122.ZIP`](https://ftp.sunet.se/mirror/archive/ftp.sunet.se/pub/simtelnet/msdos/bbs/fwkcs122.zip)
archive is a great example of an important historical file that uses
PKAV&nbsp;2.x and includes encrypted AVEXTRA text which needs a complete PKAV
implementation to correctly decode and display.

The decoded PKAV AVEXTRA text from this particular archive was quoted verbatim
and used (amongst other data points) in a USPTO final decision to
[invalidate a software patent](https://dn721608.ca.archive.org/0/items/539FinalDecision73/539%20-%20final%20decision-73.pdf)
(PDF pg. 11) in 2014.
In that case, [Jason Scott](https://en.wikipedia.org/wiki/Jason_Scott)
used the PKWARE PKUNZIP software in a DOS emulator to decode and display the
PKAV AVEXTRA text.

```
$ unzip -t fwkcs122.zip
Archive:  fwkcs122.zip
    testing: FILE_ID.DIZ              OK -AV
    testing: README.TXT               OK -AV
    testing: WHATSNEW.TXT             OK -AV
    testing: REGISTER.DOC             OK -AV
    testing: REGISTER.FRM             OK -AV
    testing: INSTALL.BAT              OK -AV
    testing: REPLACE.BAT              OK -AV
    testing: QIKSTART.BAT             OK -AV
    testing: GETLOOK.BAT              OK -AV
    testing: FWKCS.122                OK -AV
    testing: FWKCS_TM.122             OK -AV
Authentic files Verified!   # OFT466
Frederick W. Kantor (founder/information mechanics)

FWKCS(TM) Contents_Signature System, Ver. 1.22, 1993 Aug 10.
(C)Copyright Frederick W. Kantor 1989-1993. All rights reserved.
Your use of any file or program herein is at solely your own risk:
>--> please have proper backups:
........................ C A V E A T   O P E R A T O R ........................
This zipfile (C)Copyright Frederick W. Kantor 1988-1993. All rights reserved.
No one has any permission from the author_and_copyright_owner to add to,
   subtract from, or otherwise modify, the contents of this copyrighted
   Authenticity Verification Zipfile.
If you distribute this zipfile, use the filename FWKCS122.ZIP.

To use, first do  PKUNZIP FWKCS122.ZIP <enter>
Then, in the same directory with FWKCS122.ZIP,
  to install, do  INSTALL <enter>
  to replace an existing FWKCS system, Ver. 1.12 or later, do  REPLACE <enter>
  to set up the system, without searching files, do  QIKSTART <enter>
  to extract the Lookup programs and selected literature, do  GETLOOK <enter>
and then follow the instructions on the screen...
(For beginning instructions, see README.TXT.)
No errors detected in compressed data of fwkcs122.zip.
```

### PKAV 1.x

The self‑extracting
[`PKZ110.EXE`](http://cd.textfiles.com/rbbsv3n1/pool/pkz110.exe) archive uses
PKAV&nbsp;1.x and includes encrypted AVEXTRA text.

```
$ unzip -t pkz110.exe
Archive:  pkz110.exe
    testing: WHATSNEW.110             OK -AV
    testing: README.DOC               OK -AV
    testing: MANUAL.DOC               OK -AV
    testing: ADDENDUM.DOC             OK -AV
    testing: DEDICATE.DOC             OK -AV
    testing: LICENSE.DOC              OK -AV
    testing: ORDER.DOC                OK -AV
    testing: APPNOTE.TXT              OK -AV
    testing: AUTHVERI.FRM             OK -AV
    testing: OMBUDSMN.ASP             OK -AV
    testing: PKZIP.EXE                OK -AV
    testing: PKUNZIP.EXE              OK -AV
    testing: ZIP2EXE.EXE              OK -AV
    testing: PKZIPFIX.EXE             OK -AV
    testing: PUTAV.EXE                OK -AV
Authentic files Verified!   # PKW655
PKWARE Inc.

Thank you for using PKWARE!  PKWARE Support BBS (414) 352-7176
No errors detected in compressed data of pkz110.exe.
```

## Developer notes

* Usage of AI (artificial intelligence) tools by contributors is permitted,
  subject to the same terms and conditions as the
  [LLVM AI Tool Use Policy](https://llvm.org/docs/AIToolPolicy.html), but
  this permission may be withdrawn at any time and without notice.

## Security

* The canonical home of this software is
  [`https://github.com/johnsonjh/infozip-av`](https://github.com/johnsonjh/infozip-av),
  with a mirror on [GitLab](https://gitlab.com/johnsonjh/infozip-av).
* This software is intended to be **secure** 🛡️.
* If you find any security‑related problems, please don’t hesitate to
  [open a GitHub Issue](https://github.com/johnsonjh/infozip-av/issues/new/choose)
  (or send an [email](mailto:johnsonjh.dev@gmail.com) to the maintainer).

## Availability

* [GitHub](https://github.com/johnsonjh/infozip-av)
* [GitLab](https://gitlab.com/johnsonjh/infozip-av)

## Licenses

* The **Shrink**, **Reduce**, **ZIP**‑**Implode**, and **Deflate64**
  compressors, the **IBM**&nbsp;**CMPSC** compressor and decompressor, the
  **Xceed**&nbsp;**BWT**, **WZ‑JPEG**, and **WZ‑MP3** decompressors, and the
  **PKAV** and **FWKCS** additions to Info‑ZIP are provided under the
  [`MIT‑0`](LICENSE) license, or, at your option, the
  [`Info‑ZIP 2007‑Mar‑04`](zip30/LICENSE) or
  [`Info‑ZIP 2009‑Jan‑02`](unzip60/LICENSE) licenses.

* The **Shrink**, **Reduce**, and **ZIP**‑**Implode** decompression
  implementations are based on MIT licensed code from
  [Jason Summers](https://github.com/jsummers/oldunzip).

* The **LPAQ8** compression and decompression implementations are based on
  [`MIT`](unzip60/LICENSE-TinyZZZ-MIT) licensed code
  from [Dr.W.X WangXuan95](https://gitee.com/wangxuan95).

* The **DCL**‑**Implode** compression and decompression implementations
  use the [`MIT‑0`](LICENSE) licensed
  [PKDCLX](https://github.com/johnsonjh/pkdclx) routines.

* The **PPMd** compression and decompression implementations are derived from
  the public‑domain [7‑Zip PPMd](https://www.7-zip.org/sdk.html) routines.

* The **Zopfli** compression algorithm used is derived from the
  [`Apache‑2.0`](zip30/zopfli.LICENSE) licensed upstream
  [reference implementation](https://github.com/google/zopfli).

* The **LZFSE** compression and decompression implementations are derived from
  the [`BSD‑3‑Clause`](zip30/LZFSE-LICENSE.txt) licensed upstream
  [reference implementation](https://github.com/lzfse/lzfse).

* The Info‑ZIP software suites (Zip and UnZip, with included tools) are
  distributed under their respective [`Info‑ZIP 2007‑Mar‑04`](zip30/LICENSE)
  and [`Info‑ZIP 2009‑Jan‑02`](unzip60/LICENSE) licenses.

## External links

* [`atool`](https://www.nongnu.org/atool/) ‑ Script for managing file archives
* [Common ZIP](https://commonzip.org/) ‑ Open‑source specification for the ZIP file format
* [`hexdump‑zip`](https://github.com/johnsonjh/hexdump-zip) ‑ ANSI C89 implementation of [`thejoshwolfe/hexdump-zip`](https://github.com/thejoshwolfe/hexdump-zip)
* [`johnsonjh/pkstuff`](https://github.com/johnsonjh/pkstuff) ‑ PKZIP/PKUNZIP/PKSFX/PKLITE utilities
* [`patool`](https://wummel.github.io/patool/) ‑ Portable archive file manager
* [PKDCLX](https://github.com/johnsonjh/pkdclx) ‑ PKWARE DCL‑compatible Extended DCL‑Implode and DCL‑Explode
* [PKWARE `APPNOTE.TXT`](https://www.pkware.com/documents/casestudies/APPNOTE.TXT) ‑ Current ZIP file format specification
* [WinZip WZ‑JPEG](https://www.winzip.com/static/wz/docs/wz-jpg-comp.pdf) ‑ Method&nbsp;96 JPEG Compression specification
* [`zipdetails`](https://github.com/pmqs/zipdetails) ‑ Display details about the internal structure of ZIP files
