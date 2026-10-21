# Vendored upstream bzip2 / libbzip2

Source: https://sourceware.org/bzip2/ and https://gitlab.com/bzip2/bzip2
Upstream Git commit: `f5dfc96063fef2d9c5446d0733867d899ef9b942`.
Upstream version: libbzip2 1.0.8; the checkout contains post-1.0.8
bug fixes (see CHANGES / upstream Git history). The public version remains
`1.0.8, 13-Jul-2019`.

The six codec .c files and both .h files, together with Makefile, LICENSE,
README and CHANGES, are copied **unchanged** from that commit. Only
`bzlib.c` is modified: the long internal-error diagnostic for code 1007 is
split across three `fputs()` calls (identical output) to avoid exceeding
C89 minimum string-literal implementation limits. This
XTRO-VENDOR.md is not an upstream file. Do not relicense upstream code.

Our builds compile the seven library units with separate object directories.
Do not invoke upstream's `all` target, which also builds CLI programs. No
Autotools or autoreconf is needed. OS/2 uses Open Watcom V2 `wcc386`/`wlib`;
Unix uses a static archive compiled with the selected `CC`/`AR`.
Build products must never appear in `vendor/bzip2`.

UnZip's historical Unix configure script rejected a *full* bzlib when
selected from an external directory. Xtro-ZIP permits the selected, tested,
full-API vendored static library rather than compiling it with BZ_NO_STDIO.
The full public API, including stdio functions, remains available.
