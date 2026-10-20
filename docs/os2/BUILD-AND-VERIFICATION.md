# Open Watcom V2 OS/2 build and cross-host verification record

Candidate: cu102 plus OS/2 Xtro V1 integration. Host is Linux; output is
32-bit OS/2 LX. The default compiler path is `/opt/watcom`.

## Reproduce from pristine cu102

```sh
mkdir cu102-os2 && cd cu102-os2
tar -xf /path/to/cu102.tar.xz
git apply --check /path/to/xtrozip-cu102-os2-xattrs-release-candidate.patch
git apply /path/to/xtrozip-cu102-os2-xattrs-release-candidate.patch
WATCOM=/opt/watcom OS2_AUX_TOOLS=1 OS2_TEST_HELPERS=1 ./build-os2.sh
WATCOM=/opt/watcom OS2_DEBUG=1 OS2_AUX_TOOLS=1 OS2_TEST_HELPERS=1 ./build-os2.sh
```

`OS2_DEBUG=1` overwrites the release-profile binaries. Re-run without that
setting before packaging or distributing optimized binaries. Specify
`WATCOM=/other/dir` only when the compiler is installed elsewhere; the
release defaults to `/opt/watcom`. No kLIBC, external zlib, WavPack,
libbz2, liblzma, or libzstd linkage is required.

The default build creates `os2/zip.exe`, `unzip.exe`, `zipinfo.exe`,
`zipnote.exe`, `zipcloak.exe`, `zipsplit.exe`, `funzip.exe`, `unzipsfx.exe`,
`zipopt.exe`, `zipdedup.exe`, `zipopt-preflight.exe` and
`zipopt-decodecheck.exe`. `OS2_TEST_HELPERS=1` also produces
`os2/ea-fixture.exe` exclusively for synthetic test data.

## Linux-hosted regression commands

```sh
make -C xtrmeta check
make -C xtrmeta check-guard check-pairs
python3 tests/test_os2_link_mock.py
python3 tests/os2mock/test_os2_entropy.py
python3 tests/test_os2_native_query.py
```

The Xtro test target also executes 200,000 deterministic native-EA mutation
cases and the 120,000-case V1 mutation suite. The 2026-10-20 engineering
run passed these checks, both OW2 profiles, and a clean application to the
original cu102 tree. Open Watcom compile+link does not exercise the generated
LX executables, real HPFS/JFS APIs, NLS/DosMapCase interactions on OS/2,
actual kLIBC behavior or production filesystem security properties.

## Accepted limitations and non-negotiable native gates

* AES salt generation uses explicitly approved SHA-1-conditioned clock,
  memory and process measurements; it is predictable and must print a
  prominent warning when encrypting. Do not use important secrets.
* In-memory metadata staging avoids application-created plaintext temporary
  files, but does not guarantee the OS will never page memory to disk.
* An EA companion is limited to approximately 32 MiB staged bytes, with a
  128 MiB total companion budget. Limit violations must fail, not truncate.
* Legacy `0x0009` and Xtro origin 8/interface 10 are dual representations.
  Conflicts must be rejected before mutation; native SYMLINK EA activation
  must be deferred to the archive's successful final pass.
* An unencrypted directory entry may own an encrypted Xtro companion;
  plaintext legacy directory EA values must not be emitted for that case.
* Historical LAN ACL `0x4C41` handling is separate from Xtro V1 EAs;
  encryption of Xtro EA companions does not itself conceal legacy ACL data.
* Native testing must verify zipopt/zipdedup no-clobber semantics, path
  safety, EA flags, and symlink correctness on disposable volumes.

Native acceptance procedure: `BETA-TEST-REGIMEN.md` and
`TEST-PLAN-XTRO-V1.md`. Do not assert production acceptance until all
applicable cases have independently reported pass with actual OS/2 binaries
and reproducible environment information.
