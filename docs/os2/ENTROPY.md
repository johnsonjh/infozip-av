# OS/2 AES salt compatibility mode (Open Watcom V2)

**Approved compatibility exception; not a cryptographically secure random
number generator.** Decision date 2026-10-20. Applies to Xtro-ZIP's 32-bit
OS/2 native OW2 binaries, not to Unix, Windows, or DOS16.

## Scope

The original cu102 portable AES cipher and PBKDF2 implementation is retained.
For AES encryption, WinZip AE-1/AE-2 and any other calling code using
`iz_aes_entropy()` need fresh salt bytes. On OS/2, Open Watcom has no verified
native cryptographic RNG provider available in this project. To permit
compatibility-mode encryption, `zip30/wzaes.c` uses an explicitly approved,
**weak system-state-derived** fallback. Decryption uses the salt already
stored in the archive and never requires this generator.

The generator feeds a SHA-1 conditioner with:

* OS/2 `DosGetDateTime` (date, clock including hundredths, timezone);
* `DosQuerySysInfo` indices `QSV_MS_COUNT` through `QSV_TOTAVAILMEM`,
  including boot uptime, seconds since epoch, total and available memory;
* the process ID from `DosGetInfoBlocks`, when available, and C `clock()`;
* a per-process sequence number and state updated after each generated block.

The byte encoding used for integer observations is fixed to little-endian
32-bit words. The generator uses separate hash domains for initialization,
output and state evolution, zeroizes temporary digests, returns an error on
failure of either mandatory OS/2 query, and zeroes a requested output buffer
if generation fails. `rand()` is not used. A single explicit warning is sent
to standard error when the generator first successfully supplies bytes:

```
zip warning: OS/2 AES uses time/memory-derived salts; secure entropy is NOT guaranteed.
```

The warning is **not optional** in the initial build. For automated jobs,
collect stderr as well as the exit status; do not treat the warning as an
archive error, and do not suppress it when reporting encryption to users.

## Security limitations

SHA-1 conditioning **does not create entropy**. Time, memory statistics,
uptime, PID and CPU time can be predicted or observed, particularly in a
virtual machine or after clock resets. Chaining reduces trivial repeats
within one invocation but cannot guarantee distinct salt values across
process launches, boots, clones or snapshots. Salt prediction/reuse weakens
password-guessing resistance and may endanger encryption constructions when
uniqueness is required. AES encryption remains functional, but this salt
source must not be advertised as cryptographically secure.

Use test passwords and non-sensitive data for validation. Users protecting
sensitive data should prefer a platform with a vetted CSPRNG until a
suitable OS/2 entropy provider is supported. The future implementation may
investigate an OS/2 entropy gathering daemon, relevant Rexx interfaces, or
existing GnuPG ports, but those are research candidates, not established
interfaces or audited entropy sources.

**Confidentiality policy is separate:** encrypted Xtro EA companions must
never expose plaintext native EAs via legacy extra field `0x0009` or public
scratch files. This weak-entropy compatibility exception does not relax
privacy-safe staging, metadata authentication, link safety, or rollback
requirements. OS/2 `--xattrs` remains disabled until its full adapter and
confidential companion handling are integrated and tested.

## Regression / acceptance

1. Linux-hosted API mock: `python3 tests/os2mock/test_os2_entropy.py` compiles
   the *production* AES backend as C89 with mocked OS/2 queries and tests
   two non-identical outputs, single warning, and failure/zeroization.
2. Cross-compile: `WATCOM=/opt/watcom ./build-os2.sh` (or equivalent
   `WATCOM=...` override), verify LX outputs with no kLIBC dependency.
3. Native OS/2: archive test-only files with supported AES strengths and
   verify extraction, wrong password, integrity failure, and the warning.
4. Repeat the native test on OS/2 Warp, eComStation and ArcaOS, and at least
   HPFS/JFS where available. Record OS versions, salt bytes, error codes,
   full command lines and stderr, without publishing passwords or secrets.
5. Do not interpret simple statistical tests or a few non-repeating salts as
   certification of unpredictability, min-entropy, or cryptographic strength.

All acceptance tests run on disposable data and must be rerun after replacing
or modifying the entropy source.
