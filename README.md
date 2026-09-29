# PKAV for Info‑ZIP

## Overview

This project adds full [PKAV](https://github.com/johnsonjh/pkstuff#authenticity-verification) support to [Info‑ZIP](https://infozip.sourceforge.net/).

This support is built on Fedora's current
[`zip`](https://src.fedoraproject.org/rpms/zip) (3.0‑46,&nbsp;2026‑07‑17), and
[`unzip`](https://src.fedoraproject.org/rpms/unzip) (6.0‑71,&nbsp;2026‑07‑27)
source packages.

PKAV today is cryptographically useless, but supporting it is important for
historical preservation and authenticity, and it unlocks the embedded AVEXTRA
comments carried by many original PKZIP archives that would otherwise *only*
be accessible using official but ancient PKWARE software.

If you want, you can compare the changes against the Fedora upstream version
using [GitHub](https://github.com/johnsonjh/infozip-av/compare/fedora...pkav)
or [GitLab](https://gitlab.com/johnsonjh/infozip-av/-/compare/fedora..pkav),
or clone the repo and compile it using "`./build.sh`" (on most Unix systems
with GCC).

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

* [`johnsonjh/pkstuff`](https://github.com/johnsonjh/pkstuff) - PKZIP/PKUNZIP/PKSFX/PKLITE utilities
