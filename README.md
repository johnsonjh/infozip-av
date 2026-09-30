# PKAV and FWKCS for Info‑ZIP

<!-- toc -->

- [Overview](#overview)
- [Usage](#usage)
  * [PKAV](#pkav)
    + [PKAV archive creation (`zip`)](#pkav-archive-creation-zip)
    + [PKAV archive testing (`unzip`)](#pkav-archive-testing-unzip)
    + [PKAV archive extraction (`unzip`)](#pkav-archive-extraction-unzip)
    + [PKAV self-extractor creation (`unzipsfx`)](#pkav-self-extractor-creation-unzipsfx)
  * [FWKCS](#fwkcs)
    + [FWKCS archive creation (`unzip`)](#fwkcs-archive-creation-unzip)
    + [FWKCS archive testing (`unzip`)](#fwkcs-archive-testing-unzip)
    + [FWKCS archive extraction (`unzip`)](#fwkcs-archive-extraction-unzip)
    + [FWKCS self-extractor (`unzipsfx`)](#fwkcs-self-extractor-unzipsfx)
  * [PKWARE compatibility](#pkware-compatibility)
    + [PKAV](#pkav-1)
    + [FWKCS](#fwkcs-1)
- [Historical example](#historical-example)
- [Availability](#availability)
- [License](#license)
- [External links](#external-links)

<!-- tocstop -->

## Overview

This project adds full
[PKAV](https://github.com/johnsonjh/pkstuff#authenticity-verification) and
[FWKCS](http://justsolve.archiveteam.org/wiki/FWKCS)
([MD5](https://en.wikipedia.org/wiki/MD5)) support to
[Info‑ZIP](https://infozip.sourceforge.net/).

This support is built on Fedora's current
[`zip`](https://src.fedoraproject.org/rpms/zip) (3.0‑46,&nbsp;2026‑07‑17), and
[`unzip`](https://src.fedoraproject.org/rpms/unzip) (6.0‑71,&nbsp;2026‑07‑27)
source packages.

If you want, you can compare the changes against the Fedora upstream version
using [GitHub](https://github.com/johnsonjh/infozip-av/compare/fedora...pkav)
or [GitLab](https://gitlab.com/johnsonjh/infozip-av/-/compare/fedora..pkav),
or clone the repo and compile it using "`./build.sh`" (on most Unix systems
with GCC).

## Usage

### PKAV

PKAV today is cryptographically useless, but supporting it is *important for
historical preservation and authenticity*, and it unlocks the encrypted AVEXTRA
data present in many original PKZIP archives that would otherwise be completely
inaccessible (or *only* accessible using official PKWARE software).

#### PKAV archive creation (`zip`)

> [!NOTE]
> Generation of PKAV registration is outside the scope of this project,
> but is [covered elsewhere](https://github.com/johnsonjh/pkstuff#makeav).

```
$ printf '%s\n' '' 'This is the AVEXTRA comment!' '' > avextra.txt

$ zip --pkav-name 'This was made with InfoZip!' \
      --pkav-s1 x --pkav-s2 y \
      --pkav-avextra avextra.txt test.zip ./*.c
  adding: makeav.c (deflated 82%)
  adding: pklaxfix.c (deflated 82%)
  adding: pkpspfix.c (deflated 76%)
  adding: putav.c (deflated 77%)
```

#### PKAV archive testing (`unzip`)

```
$ unzip -t test.zip
Archive:  test.zip
    testing: makeav.c                 OK
    testing: pklaxfix.c               OK
    testing: pkpspfix.c               OK
    testing: putav.c                  OK
Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!

No errors detected in compressed data of test.zip.
```

#### PKAV archive extraction (`unzip`)

```
$ unzip -xa test.zip
Archive:  test.zip
  inflating: makeav.c                [text]
  inflating: pklaxfix.c              [text]
  inflating: pkpspfix.c              [text]
  inflating: putav.c                 [text]
Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!
```

#### PKAV self-extractor creation (`unzipsfx`)

The `unzipsfx` self‑extracting stub handles PKAV automatically.

> [!IMPORTANT]
> When creating a self‑extracting archive, ensure that you correct the entry
> offsets using the `zip ‑A` command.  If you don't run `zip ‑A` the archive
> is not a fully conforming ZIP file and other software (especially PKWARE
> software) may reject it as invalid or corrupt.

```
$ cat $(command -v unzipsfx) test.zip > test.sfx

$ chmod a+x test.sfx

$ zip -A test.sfx
Zip entry offsets appear off by 126800 bytes - correcting...

$ ./test.sfx -t
UnZipSFX 6.00 of 20 April 2009, by Info-ZIP (http://www.info-zip.org).
    testing: makeav.c                 OK
    testing: pklaxfix.c               OK
    testing: pkpspfix.c               OK
    testing: putav.c                  OK
Authentic files Verified!   # TDU015
This was made with InfoZip!

This is the AVEXTRA comment!

No errors detected in compressed data of ./test.sfx.
```

### FWKCS

The FWKCS extension was originally implemented by
[Frederick W. Kantor](https://en.wikipedia.org/wiki/Frederick_Kantor) as a
way identify duplicate files in archives more reliably than by the filename,
size, and CRC.  It is still useful today as a reasonably secure, lightweight,
and historically authentic integrity extension.  It cooperates with PKAV, and
because older ZIP software can ignore the FWKCS metadata when unsupported,
it has excellent backwards compatibility.

FWKCS support is **not** enabled by default.  To enable FWKCS when archiving,
use the `--fwkcs-md5` option.  To enable FWKCS when listing (`-l`) or
verbosely listing (`-v`), use the `--list-fwkcs-md5` option.

It was decided **not** to enable FWKCS support by default (even though it is
officially supported and documented in the current
[`APPNOTE.TXT`](https://www.pkware.com/documents/casestudies/APPNOTE.TXT)) for
a number of reasons:

1. Mainly to avoid *silently* including FWKCS MD5 metadata when most ZIP
   implementations just *silently* ignore it.  This could be catastrophic for
   privacy; a "mostly hidden" MD5 hash may betray the contents of an
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
5. Requiring opt-in when listing (`-l`) and verbosely listing (`-v`) ensures
   that users who are further processing the output (*e.g.*, `AWK` scripts)
   won't experience regressions.

#### FWKCS archive creation (`unzip`)

```
$ zip --fwkcs-md5 ./*.com
  adding: makeav.com (deflated 31%)
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
   18774  Defl:N    12902  31% 09-29-2026 04:52 3b2f14a8  63372e2f3cc2d43bb39416537e8b6a13  makeav.com
   18850  Defl:N    13040  31% 09-29-2026 04:52 902af968  e506191a90b515742d996d4bd74d9ddd  pklaxfix.com
   15888  Defl:N    11210  29% 09-29-2026 04:52 9afdcb69  4077e98e885eeb3860f01e5d730835ac  pkpspfix.com
   16094  Defl:N    11449  29% 09-29-2026 04:52 b793cde2  c39f04e9140fbfa7a39ecf25414fa044  putav.com
--------          -------  ---                            -------
   69606            48601  30%                            4 files
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
$ unzip -ta pkstuff.zip
Archive:  ../pkstuff.zip
    testing: makeav.com               OK
    testing: pklaxfix.com             OK
    testing: pkpspfix.com             OK
    testing: putav.com                OK
FWKCS MD5 checksums verified for 4 entries.
No errors detected in compressed data of pkstuff.zip.
```
#### FWKCS self-extractor (`unzipsfx`)

> [!IMPORTANT]
> When creating a self‑extracting archive, ensure that you correct the entry
> offsets using the `zip ‑A` command.  If you don't run `zip ‑A` the archive
> is not a fully conforming ZIP file and other software (especially PKWARE
> software) may reject it as invalid or corrupt.

```
$ cat $(command -v unzipsfx) pkstuff.zip > pkstuff.sfx

$ chmod a+x pkstuff.sfx

$ zip -A pkstuff.sfx
Zip entry offsets appear off by 126800 bytes - correcting...

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

```
$ emu pkunzip.exe -t pkstuff.sfx

PKUNZIP (R)    FAST!    Extract Utility    Version 2.50    03-01-1999
Copr. 1989-1999 PKWARE Inc.  All Rights Reserved.  Registered version
PKUNZIP Reg. U.S. Pat. and Tm. Off.

Searching ZIP: X.SFX
Testing: makeav.com    OK
Testing: pklaxfix.com  OK
Testing: pkpspfix.com  OK
Testing: putav.com     OK
```

## Historical example

The [very](http://justsolve.archiveteam.org/wiki/FWKCS)
[famous](https://dn790003.ca.archive.org/0/items/emcfarber_jsstestimony/Sadofsky%2C%20Jason%20Scott.pdf)
[`FWKCS122.ZIP`](https://ftp.sunet.se/mirror/archive/ftp.sunet.se/pub/simtelnet/msdos/bbs/fwkcs122.zip)
archive is a great example of an important historical file that uses PKAV and
includes encrypted AVEXTRA text which needs a complete PKAV implementation to
correctly decode and display.

The actual decoded PKAV AVEXTRA text from this archive was quoted verbatim and used (amongst
other data points) in a USPTO final decision to
[invalidate a software patent](https://dn721608.ca.archive.org/0/items/539FinalDecision73/539%20-%20final%20decision-73.pdf)
(*PDF pg. 11*) in 2014. In this case, [Jason Scott](https://en.wikipedia.org/wiki/Jason_Scott)
used the historical PKWARE PKUNZIP software in a DOS emulator to decode and
display the PKAV AVEXTRA text.

```
$ unzip -ta fwkcs122.zip
Archive:  fwkcs122.zip
    testing: FILE_ID.DIZ              OK
    testing: README.TXT               OK
    testing: WHATSNEW.TXT             OK
    testing: REGISTER.DOC             OK
    testing: REGISTER.FRM             OK
    testing: INSTALL.BAT              OK
    testing: REPLACE.BAT              OK
    testing: QIKSTART.BAT             OK
    testing: GETLOOK.BAT              OK
    testing: FWKCS.122                OK
    testing: FWKCS_TM.122             OK
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

## Availability

* [GitHub](https://github.com/johnsonjh/infozip-av)
* [GitLab](https://gitlab.com/johnsonjh/infozip-av)

## License

* These PKAV additions to Info‑ZIP are provided under the [MIT‑0 License](LICENSE)
  or, at your option, the [`Info‑ZIP 2007‑Mar‑04`](zip30/LICENSE) or
  [`Info‑ZIP 2009‑Jan‑02`](unzip60/LICENSE) licenses.

* The Info‑ZIP software components (Zip and UnZip) are distributed under their
  respective [`Info‑ZIP 2007‑Mar‑04`](zip30/LICENSE) and
  [`Info‑ZIP 2009‑Jan‑02`](unzip60/LICENSE) licenses.

## External links

* [`johnsonjh/pkstuff`](https://github.com/johnsonjh/pkstuff) ‑ PKZIP/PKUNZIP/PKSFX/PKLITE utilities
* [PKWARE `APPNOTE.TXT`](https://www.pkware.com/documents/casestudies/APPNOTE.TXT) - Current ZIP file format specification
