# Xtro‑ZIP: Enhanced Info‑ZIP

<!-- toc -->

- [Overview](#overview)
- [Usage](#usage)
  * [De-duplication (`zipdedup`)](#de-duplication-zipdedup)
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

**Xtro‑ZIP** adds extensive support for **new algorithms**, **security**
hardening, data **de‑duplication**, CRC/SHA/AES **hardware**
**acceleration**<sup>†</sup>, full
[**PKAV**](https://github.com/johnsonjh/pkstuff#authenticity-verification)
(create *and* verify for PKAV&nbsp;2.x, verification‑only for PKAV&nbsp;1.x),
[**FWKCS**](http://justsolve.archiveteam.org/wiki/FWKCS)
[MD5](https://en.wikipedia.org/wiki/MD5), and
[**AES** cryptography](https://www.winzip.com/en/support/aes-encryption/)
(**AE‑1**, **AE‑2**, and “quantum‑resistant” **AE‑3**) to
[Info‑ZIP](https://infozip.sourceforge.net/).


> [!TIP]
> **Xtro‑ZIP** is the **only** permissively‑licensed open‑source ZIP software
> that even comes close to fully supporting the complete ZIP specification!

The ability to compress and decompress archive members using **Zstandard**
(method&nbsp;20 and 93), **LZMA** (method&nbsp;14), **XZ**/**LZMA2**
(method&nbsp;95), **ZIP**&nbsp;**Implode** (method&nbsp;6),
**DCL**&nbsp;**Implode** (method&nbsp;10), **Deflate64** (method&nbsp;9),
**IBM&nbsp;CMPSC** (method&nbsp;16), **Shrink** (method&nbsp;1), **Reduce**
(methods 2 through 5), and **PPMd** (method&nbsp;98) has been added.

New decompression‑only support for **WZ‑MP3** (method&nbsp;94), **WZ‑JPEG**
(method&nbsp;96), and **WavPack** (method&nbsp;97) has also been added.

WinZip‑style de‑duplication **RefPtr** (method&nbsp;92) is supported.

The usual **Store** (method&nbsp;0) and **DEFLATE** (method&nbsp;8) algorithms
remain supported.

Additionally, new
[Zopfli](https://github.com/google/zopfli)‑enhanced **DEFLATE** (method&nbsp;8)
support is available (when compressing using `zip ‑11`):

|   Method | Description                                           | Decompress | Compress |
|---------:|:------------------------------------------------------|:----------:|:--------:|
|  **`0`** | Store&nbsp;(no&nbsp;compression)                      |     ✅     |    ✅    |
|  **`1`** | Shrink                                                |     ✅     |    ✅    |
|  **`2`** | Reduce&nbsp;(level&nbsp;1)                            |     ✅     |    ✅    |
|  **`3`** | Reduce&nbsp;(level&nbsp;2)                            |     ✅     |    ✅    |
|  **`4`** | Reduce&nbsp;(level&nbsp;3)                            |     ✅     |    ✅    |
|  **`5`** | Reduce&nbsp;(level&nbsp;4)                            |     ✅     |    ✅    |
|  **`6`** | ZIP&nbsp;Implode                                      |     ✅     |    ✅    |
|  **`8`** | DEFLATE&nbsp;(Zopfli&nbsp;optional)                   |     ✅     |    ✅    |
|  **`9`** | Deflate64™&nbsp;(Enhanced&nbsp;DEFLATE)               |     ✅     |    ✅    |
| **`10`** | DCL&nbsp;Implode                                      |     ✅     |    ✅    |
| **`12`** | bzip2<sup>1</sup>                                     |     ✅     |    ✅    |
| **`14`** | LZMA<sup>2</sup>                                      |     ✅     |    ✅    |
| **`16`** | IBM&nbsp;z/OS&nbsp;CMPSC<sup>‡</sup>                  |     ✅     |    ✅    |
| **`18`** | IBM&nbsp;TERSE                                        |            |          |
| **`19`** | IBM&nbsp;LZ77&nbsp;(z/Architecture)                   |            |          |
| **`20`** | Zstandard<sup>3</sup>&nbsp;(deprecated)               |     ✅     |          |
| **`92`** | Reference&nbsp;Link<sup>5</sup>&nbsp;(de‑duplication) |     ✅     |    ✅    |
| **`93`** | Zstandard<sup>3</sup>                                 |     ✅     |    ✅    |
| **`94`** | WZ‑MP3                                                |     ✅     |          |
| **`95`** | XZ/LZMA2<sup>2</sup>                                  |     ✅     |    ✅    |
| **`96`** | WZ‑JPEG<sup>2</sup>                                   |     ✅     |          |
| **`97`** | WavPack<sup>4</sup>                                   |     ✅     |          |
| **`98`** | PPMd&nbsp;version&nbsp;I&nbsp;Rev&nbsp;1              |     ✅     |    ✅    |

> [!NOTE]
> Methods 1 through 6 are legacy algorithms and are no longer
> recommended for use.  <sup>**1**</sup>&nbsp;bzip2 support requires
> [`libbz2`](https://sourceware.org/bzip2/). <sup>**2**</sup>&nbsp;LZMA,
> XZ/LZMA2, and WZ‑JPEG support requires [`liblzma`](https://tukaani.org/xz/).
> <sup>**3**</sup>&nbsp;Zstandard support requires
> [`libzstd`](https://facebook.github.io/zstd/). <sup>**4**</sup>&nbsp;WavPack
> support requires [`libwavpack`](https://www.wavpack.com/).
> <sup>**5**</sup>&nbsp;De‑duplicated archive creation supported via
> [`zipdedup`](#de-duplication-zipdedup). <sup>**†**</sup>&nbsp;CRC/SHA/AES
> hardware acceleration is automatically detected at runtime and is currently
> supported on AMD64 and ARM64 systems running Linux, FreeBSD, OpenBSD, and
> macOS. <sup>**‡**</sup>&nbsp;IBM&nbsp;CMPSC *compression* is an inefficient
> and experimental, but interoperable, work‑in‑progress.

These changes are built using Fedoraʼs current Info‑ZIP
[`zip`](https://src.fedoraproject.org/rpms/zip) (`3.0‑46`,&nbsp;2026‑07‑17),
and [`unzip`](https://src.fedoraproject.org/rpms/unzip)
(`6.0‑71`,&nbsp;2026‑07‑27) source packages as a base.

If you want, you can compare the changes against the Fedora upstream version
using [GitHub](https://github.com/johnsonjh/infozip-av/compare/fedora...pkav)
or [GitLab](https://gitlab.com/johnsonjh/infozip-av/-/compare/fedora..pkav),
or clone the repo and compile it using “`./build.sh`” (on most Unix systems
with GCC).

## Usage

### De-duplication (`zipdedup`)

The new `zipdedup` tool creates WinZip‑compatible (“ZIPX” method&nbsp;92)
de‑duplicated archives from existing ZIP source archives.

It hashes all archived files and retains the first (compressed) source file,
without recompressing it, and smartly de‑duplicates entries only if the
operation would result in a *smaller* output archive (*i.e.*, very small files
will be skipped).

```
$ zipdedup original.zip dedup.zip
449 new references; approximate savings: 9010081 bytes
```

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
UnZipSFX 6.00 of 20 April 2009, by Info-ZIP (http://www.info-zip.org).
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
UnZipSFX 6.00 of 20 April 2009, by Info-ZIP (http://www.info-zip.org).
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

* The **Shrink**, **Reduce**, **ZIP**&nbsp;**Implode**, and **Deflate64**
  compressors, **IBM**&nbsp;**CMPSC** decompressor, **WZ‑JPEG** decompressor,
  **WZ‑MP3** decompressor, and the **PKAV** and **FWKCS** additions to
  Info‑ZIP are provided under the [MIT‑0](LICENSE) license, or, at your
  option, the [`Info‑ZIP 2007‑Mar‑04`](zip30/LICENSE) or
  [`Info‑ZIP 2009‑Jan‑02`](unzip60/LICENSE) licenses.

* The **Shrink**, **Reduce**, and **ZIP Implode** decompression
  implementations are based on MIT licensed code from
  [Jason Summers](https://github.com/jsummers/oldunzip).

* The **DCL**&nbsp;**Implode** compression and decompression implementations
  use the [MIT‑0](LICENSE) licensed
  [PKDCLX](https://github.com/johnsonjh/pkdclx) routines.

* The **PPMd** compression and decompression implementations are derived from
  the public‑domain [7‑Zip PPMd](https://www.7-zip.org/sdk.html) routines.

* The **Zopfli** compression algorithm used is derived from the
  [Apache‑2.0](zip30/zopfli.LICENSE) licensed upstream
  [reference implementation](https://github.com/google/zopfli).

* The Info‑ZIP software suites (Zip and UnZip, with included tools) are
  distributed under their respective [`Info‑ZIP 2007‑Mar‑04`](zip30/LICENSE)
  and [`Info‑ZIP 2009‑Jan‑02`](unzip60/LICENSE) licenses.

## External links

* [Common ZIP](https://commonzip.org/) ‑ Open‑source specification for the ZIP file format
* [`hexdump-zip`](https://github.com/johnsonjh/hexdump-zip) ‑ ANSI C89 implementation of [`thejoshwolfe/hexdump-zip`](https://github.com/thejoshwolfe/hexdump-zip)
* [`johnsonjh/pkstuff`](https://github.com/johnsonjh/pkstuff) ‑ PKZIP/PKUNZIP/PKSFX/PKLITE utilities
* [PKDCLX](https://github.com/johnsonjh/pkdclx) ‑ PKWARE DCL‑compatible Extended DCL‑Implode and DCL‑Explode
* [PKWARE `APPNOTE.TXT`](https://www.pkware.com/documents/casestudies/APPNOTE.TXT) ‑ Current ZIP file format specification
* [WinZip WZ‑JPEG](https://www.winzip.com/static/wz/docs/wz-jpg-comp.pdf) ‑ Method&nbsp;96 JPEG Compression specification
