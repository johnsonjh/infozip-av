# Reproducible builds and archives (SOURCE_DATE_EPOCH)

**NOTE:** This document is a work in progress.

Xtro-ZIP honors the reproducible-builds `SOURCE_DATE_EPOCH` convention in its
Unix, Windows, OS/2, DOS386 and DOS16 build wrappers **and** in the
actual archive-writing utilities.

**Everything described here is opt-in.** Without setting the
`SOURCE_DATE_EPOCH` variable, archive ordering, timestamps,
encryption randomness, compile-time build strings and utility
behavior retain the default behavior.

## Setting and validating the epoch

Set `SOURCE_DATE_EPOCH` in the **environment**, **not** in a
`make` command-line assignment. For example:

```sh
export SOURCE_DATE_EPOCH=946684801
./build-unix.sh
# or: make -C zip30 -f unix/Makefile generic_gcc
```

The Unix makefiles deliberately reject `make SOURCE_DATE_EPOCH=...` assignments:
their immediate shell probes cannot reliably inherit command-line make
variables, and interpolating an untrusted value into a shell command is unsafe.
The build wrappers and makefiles validate the environment before compilation.
They use only POSIX `sh` and `awk` to produce *numeric-only* preprocessor
definitions. They do not evaluate the epoch as shell or Make code.

Accepted values are nonempty strings of ASCII decimal digits representing UTC
Unix seconds from **315532800 (1980-01-01T00:00:00Z)** through
**2147483647 (2038-01-19T03:14:07Z)**, inclusive. Leading zeros are allowed.
Whitespace, signs, suffixes, non-ASCII digits, overflow and values outside the
range are errors. The C programs check that the value fits their `time_t` and
`gmtime` implementation. An invalid epoch prevents archive creation or
publication; build scripts fail before starting compilation.

The epoch is read and checked once, at process startup. Later environment
changes have no effect. A valid build uses the epoch's **UTC calendar date and
time** in its existing compiler/build-date strings; compiler identification is
retained. When the variable is absent, the original compiler date/time and
`uname -a` values remain. With the variable set, the Unix UnZip makefile uses
`uname -s` to exclude varying kernel/release details from its build string.

## What changes in archives

When this mode is active:

- Newly added or actually replaced members have serialized modification,
  access and creation timestamps *clamped* to the epoch. Older timestamps
  stay older; a source timestamp is never raised to the epoch.

- DOS timestamps are encoded in canonical **UTC**, independent of host `TZ`.
  Their two-second precision always **rounds down**. The timestamp is also
  clamped to the beginning of the DOS calendar when necessary.

- Standard Info-ZIP UT (0x5455), historical UX (0x5855) and known NTFS
  (0x000A) timestamp records are clipped where present. Xtro native named
  attribute access and modification times are clipped during capture.

- Unrecognized/vendor extra fields are preserved as received; Xtro-ZIP does
  not try to interpret undocumented timestamp formats. Existing safety
  checks for malformed or forbidden extra fields still apply.

- Directory and wildcard **discovery** is sorted by unsigned byte values,
  independent of C locale, for repeatable member order. The user's explicit
  command-line operand order is respected.

- Unencrypted Xtro metadata owner identifiers and newly created ZipDedup
  RefPtr group identifiers are deterministic and checked for collisions.
  Existing group identifiers are not regenerated.
  
- Untouched members of a previously existing archive keep their serialized
  timestamp bytes, vendor fields, content and relative order. This includes
  members merely copied through Zip, ZipOpt, ZipDedup or the traditional
  utilities. Selecting `SOURCE_DATE_EPOCH` does **not** rewrite an archive's
  unrelated members just to normalize their timestamps.

PKAV is disabled while `SOURCE_DATE_EPOCH` is active until its deterministic
output can be separately certified for compatibility and safety.

## Encryption: explicit *insecure* double opt-in

With `SOURCE_DATE_EPOCH` set, Xtro-ZIP rejects operations that would create
encrypted archive members unless the environment variable
`SOURCE_DATE_EPOCH_INSECURE` is also set to a **nonempty** value:

```sh
export SOURCE_DATE_EPOCH=946684801
export SOURCE_DATE_EPOCH_INSECURE=yes
# The ordinary Zip encryption options are now accepted.
```

**WARNING: This is cryptographically insecure.**

***YOU REALLY DO NOT WANT TO DO THIS!***

The second variable changes encrypted salts/initialization values and
ZipCrypto headers to deterministic, predictable bytes so repeated builds
yield the same encrypted archive. It seriously reduces the security of the
encryption. This is useful *only* for deliberately insecure, reproducible test
artifacts. A visible warning is printed whenever both variables are set. Using
the insecure variable *alone* is silently ignored. Never use deterministic
encryption for confidential data. Without the double opt-in, Zip retains its
existing normal random generation whenever reproducible mode is not selected.

## Scope and testing

Reproducible input, a fixed compressor version/selection, equivalent
filesystem metadata and the same toolchain are still necessary for complete
archive or executable identity. This feature does not make different codec
implementations produce the same compressed bytes, or make unsigned vendor
extra fields understandable.

Use these regression checks after building the native tools:

```sh
cc -std=c89 -pedantic -Wall -Wextra -Werror \
  tests/test_source_epoch_times.c -o test_source_epoch_times
./test_source_epoch_times
python3 tests/test_source_date_epoch.py --zip zip30/zip \
  --zipopt zipopt/zipopt --zipdedup zipdedup/zipdedup
```

For OS/2, use the supplied Open Watcom V2 toolchain (`WATCOM=/opt/watcom
./build-os2.sh`) and compare hashes from two identical builds. Repeat for
DOS16 and DOS386 with the supported toolchains. Platform-native runtime tests
are still required for release certification; successful cross-linking alone
is insufficient. Add `--baseline-zip /path/to/pristine/cu109/zip30/zip` to
the Python suite to compare unaffected behavior byte-for-byte with cu109 when
the environment variable is absent.
