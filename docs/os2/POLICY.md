# Xtro-ZIP OS/2 32-bit metadata and symlink policy

Decision record, 2026-10-20. Applies to the integrated OS/2 Xtro V1
engineering candidate. **The requirements are not native acceptance evidence.**
The companion V1 wire format is documented in `../xtro-ea-v1/FORMAT.md`.

## Toolchain and deployment

* Cross-compile 32-bit LX binaries from Linux with Open Watcom V2; default
  `WATCOM=/opt/watcom` (overridable via the environment).
* Match the DOS16 Open Watcom high-optimization release profile; offer a
  diagnostic low-optimization build. All standard Zip and UnZip tools plus
  ZipInfo, ZipOpt and ZipDedup remain part of the build matrix.
* Do not link or load the kLIBC runtime merely to preserve kLIBC symlinks.
  Native `SYMLINK` EAs are accessed through documented OS/2 `Dos*` APIs.
* No required third-party compressor libraries in the initial build. Native
  tests are required on OS/2 Warp, eComStation and ArcaOS where available.

## Capture and encryption

| Zip selection | Traditional OS/2 EA `0x0009` | Xtro V1 origin 8/interface 10 |
| --- | --- | --- |
| No `--xattrs`, unencrypted | normal historical behavior | none |
| `--xattrs`, unencrypted | complete field if it fits | complete selected EAs |
| `--xattrs`, explicitly encrypted | **must omit** plaintext EA field | encrypted companion |
| `--xattrs`, EAs exceed legacy field | **must omit**, never truncate | complete inline/companion representation |

If complete legacy EA data cannot be carried, warn about compatibility loss.
Do not silently treat loss of a required EA as success. For explicitly encrypted
Xtro metadata (including a cleartext directory owner with an encrypted
companion), no legacy plaintext EA *values*, including `SYMLINK` pathnames,
may be disclosed in either ZIP header. Other legacy metadata fields must
also be reviewed for content disclosure. Plain Xtro inline is forbidden with
encryption. Ordinary file owners and companions require matching transport;
**directory owners are the sole exception**. A ZIP directory entry remains
unencrypted and holds no EA value, while its Xtro V1 companion MUST be
encrypted, flagged `XTR_V1_ENCRYPTED`, and verified independently. The
exception does not authorize plaintext fallback, a duplicate legacy EA field,
or a general mismatch between ordinary file owners and companions.

Encrypted Xtro metadata may be staged on disk only if the staging area is
provably private on the actual destination filesystem, or if it is stored
in a secure non-filesystem staging mechanism. Generic `TMP`, a predictable
filename, or HPFS alone does not establish confidentiality. Reject and
leave the output unchanged if privacy cannot be guaranteed. **Explicit OS/2 compatibility exception (approved 2026-10-20):** AES
archive encryption may generate salts from a SHA-1 conditioned mixture of
`DosGetDateTime` and `DosQuerySysInfo` values (including available memory
and uptime), process identity and CPU time. This is *not* a secure entropy
source and does not ensure unpredictability or uniqueness across executions,
particularly under virtual machines. The encoder prints an unmistakable
warning when this fallback is used; AES decryption does not need an entropy
source. The choice is documented in [ENTROPY.md](ENTROPY.md), with
regression requirements. This is a knowingly weaker-than-normal encryption
configuration, not a claim of standard CSPRNG-grade cryptographic security.
A future high-quality OS/2 provider (potentially an entropy-gathering daemon)
should replace the fallback after its interface and security properties are
independently reviewed. Owner-ID collisions must still be rejected; the
fallback is not evidence that an ID is globally unique.

**This entropy exception does not authorize plaintext EA staging or relax
encrypted Xtro metadata confidentiality.** Without verified memory-only or
otherwise privacy-preserving encrypted companion staging, OS/2 `--xattrs`
encrypted workflows remain disabled.

## Native EA representation

OS/2 names and values are byte-exact and native, with origin=8,
type=1, encoding=0, empty namespace, interface TLV 1 = 10. TLV 10
preserves the native FEA2.fEA flag (in particular FEA_NEEDEA=0x80).
Native EA typed-value prefixes are part of the value bytes. Preserve `.LONGNAME`
and `SYMLINK` without re-encoding or rewriting stored symlink destinations.
Restore `.LONGNAME` in a way consistent with FAT destination filename mapping.
The kLIBC `SYMLINK` EA uses a typed ASCII value: u16 0xFFFD, u16
pathname byte length, then that many nonzero pathname bytes, with no
embedded NUL. The underlying link file's own contents must also be retained.

Native names are case-insensitive. Reject semantic duplicates after the OS/2
NLS case-mapping rules have been applied; plain ASCII case folding is only a
subset. Reject malformed EA lists and unsupported required native flags
before attempting changes. When the full EA set cannot fit the receiving
filesystem, fail/report accurately; a larger Xtro manifest does not raise
native filesystem limits.

## Dual representation and native restoration

Without UnZip `--xattrs`, restore conventional `0x0009` EAs only. With
`--xattrs`, merge legacy and Xtro records *before mutation*:

* Same name after native case-folding, identical value and flags -> once.
* Same native identity but different value or flags -> metadata error; reject
  the member's metadata without applying a partially reconciled set.
* Attribute exists only in one enabled source -> restore it.
* Existing destination EAs whose names are not included -> leave unchanged.
* Fail native writes visibly; best-effort bounded rollback is allowed but
  may not be advertised as atomic unless it is guaranteed and tested.

The rule intentionally does not select an arbitrary winner based on source
order, nor does it automatically convert foreign origin records to OS/2 EAs.
The legacy OS/2 LAN Server `0x4C41` ACL mechanism is separate and remains
controlled by its documented extraction option; it is not the V1 native-EA
interface and cannot be mapped to Multics ACLs without a specification.

## Symlink archive creation

With `zip --symlinks` (`-y`) store the underlying native kLIBC link file
*and its own* `SYMLINK` EA, other EAs and applicable ACLs. Without `-y`,
follow the link and archive the target's bytes and attributes, not the
link's `SYMLINK` EA. Refuse dangling/cyclic/unresolvable targets in
follow mode. Preserve relative, absolute and `@UNIXROOT` link target values
byte-for-byte; no host-specific pathname replacement. Do not convert arbitrary
Unix ZIP symlink entries into kLIBC files without a separate specification.

## Safe extraction: mandatory order

1. Preflight all relevant local/central headers, associated companion graph,
   metadata lengths, integrity and protected output paths.
2. Write ordinary contents, not following any pre-existing/native archive
   links. Re-check destination objects before writes, including every parent
   component; path checks alone cannot eliminate all concurrent races.
3. Complete ZIP CRC/decompression and AE authentication, verify XTMD digest,
   record grammar and legacy/Xtro EA identity/flag/value reconciliation.
4. Apply ordinary EAs and ACLs after native path revalidation. Report failed
   native writes; preserve unrelated existing EAs.
5. Apply `SYMLINK` EAs **in a final deferred pass**, after normal contents
   and ordinary metadata have succeeded. Never activate links from an
   unverified companion or malformed EA value. Revalidate every destination
   and parent, and reject unsafe existing links.
6. Set deferred directory timestamps/attributes without inadvertently
   following activated links; report every partial failure. There is no
   unsupported promise of whole-archive transaction rollback.

Native tests must include link-to-parent traversal, preexisting directory
links, CRC failure after a link entry, local/central disagreement, conflicting
legacy/Xtro symlink EAs, relative/absolute/dangling/cyclic links, and symlinks
named by non-ASCII codepage bytes. Preserve link metadata even if no kLIBC
userland runtime is present; link *interpretation* by kLIBC applications is
an additional environment property, not a build dependency.

## Implementation status clarification (beta candidate)

The earlier checkpoint notes in this document predate the wired native
adapter. The present cu102 OS/2 Xtro V1 patch implements memory-backed
capture/restoration and the directory encryption exception in OW2 source.
The OS/2-specific runtime behavior is **unverified** until the matrix in
`BETA-TEST-REGIMEN.md` has passed on native filesystems. Do not interpret
old checklist status notes as a live indication that `--xattrs` remains
compile-time disabled, or interpret an LX link as proof of correct restoration.
