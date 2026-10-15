# Xtro-ZIP binary xattr V1 — M1 protocol and implementation review

**October 15, 2026. Source baseline: cu68.tar.xz. Standalone C89 core only.**
**Status: proposed V1 layout, prototype implementation and regression package.**
No production ZIP/UnZIP integration is permitted by this package. A feature-flagged,
transactional ZIP writer/reader and real OS adapters are M2 and later. Never confuse
an independently checked metadata manifest with a safe native restore operation.

## Extra-field ID: third-party candidate 0x5854

`0x5854`, encoded as `54 58` in ZIP headers, was selected as the Xtro V1
**candidate** after inspecting the documented lists in APPNOTE and Info-ZIP
`proginfo/extrafld.txt`, comparing the cu68 sources, and searching for third-party
uses. There is no known collision in those sources. The four-byte mandatory `XTRO`
signature provides disambiguation. **This is not a proof of exclusive allocation,
a registration, or a claim that no private ZIP implementation uses 0x5854.**
Publish the assignment and solicit collision reports before enabling production
writer output. If a collision emerges before release, change the ID and
regenerate golden fixtures while preserving the internal magic/version.

Historical fields MUST NOT be interpreted as Xtro: 0x4158 XA, 0x4e58 XN,
0x5658 XV, 0x334d Mac3, 0x4453 NT security descriptors, 0x4b46 FWKCS MD5,
0x9901 AES, and all older Unix/ZIP64 IDs. All unknown well-formed fields must
be retained by a compatible pure-copy operation; unrecognized fields must not
be blindly copied onto a *replaced* file. A different party's 0x5854 field
with non-`XTRO` payload is a collision, not a valid Xtro record.

## Entry occurrence and association

Each logical owner archive *occurrence* has a distinct, nonzero 16-byte owner
ID, unchanged by an ordinary rename/copy. Archive-global ownership is checked
by `xtr1_check_archive_index`. Duplicate owner IDs, duplicate companions,
orphan companions and non-companion entries in the reserved namespace are errors.
Companion path is exactly:

`__XTRO_ZIP__/x/` + 32 lowercase hexadecimal owner-ID characters + `.xtm`

The companion is an ordinary ZIP member, never a symlink, and may be exposed by
legacy extractors. It may use STORE (0) or raw Deflate (8) inside ZIP, and may
be ZIP64 sized as permitted by the normal ZIP codec. Xtro-aware extraction
never emits a companion as an ordinary destination file by default. Owner
associations must be reconstructed from CENTRAL and LOCAL headers and exact
member occurrences, not from filename alone, central-directory position or
physical offset. A duplicate `owner_id` is never justified by equal contents.
The library's archive index validation is a schema/graph preflight, NOT a ZIP
parser, archive writer, or a substitute for validating archive offsets/overlaps.

## ZIP extra-field payload (excludes 2-byte ID and 2-byte length)

All integers little-endian. No implicit zero terminators or alignment.

| Off | Len | Field | Value |
|---:|---:|---|---|
|0|4|magic|`XTRO`|
|4|1|major|1|
|5|1|minor|0|
|6|1|mode|1 INLINE, 2 COMPANION|
|7|1|flags|bit 0: encrypted metadata companion; otherwise zero|
|8|16|owner ID|nonzero and unique per archive|
|24|4|record count|for encrypted companion, zero|
|28|8|plain manifest length|for encrypted companion, zero|
|36|4|plain manifest CRC32|for encrypted companion, zero|
|40|variable|central-only body|INLINE manifest or public companion SHA256|

The local field is always exactly 40 payload bytes; the central fixed prefix
must be byte identical to the local. Central INLINE appends the complete
manifest (minimum 36 bytes). Central public COMPANION appends 32 SHA-256 bytes
(72 payload bytes total). Central encrypted COMPANION is exactly 40 bytes:
no plaintext lengths, count, CRC, or digest. INLINE cannot be encrypted.
Excess header-space usage mandates COMPANION, not overwriting other extras.
Metadata-only payload bytes do NOT include the normal ZIP 4-byte field header.

## Plain manifest layout (XTMD)

| Off | Len | Field | Value |
|---:|---:|---|---|
|0|4|magic|`XTMD`|
|4|1|major|1|
|5|1|minor|0|
|6|2|flags|zero|
|8|16|owner ID|matches outer extra|
|24|4|record count|number of records|
|28|8|record bytes length|exact length after header|

The manifest is precisely 36+record-bytes bytes, no padding. For **encrypted**
companions ONLY, the decrypted ZIP member's uncompressed data is this XTMD
manifest followed by a 36-byte `XTCS` trailer: four bytes `XTCS` then SHA-256
of the complete XTMD bytes. That entire payload, including trailer, is
compressed and encrypted together using the owner's requested ZIP encryption
method. For public companions the SHA-256 is in the owner's central extra
field instead; the companion contains only XTMD. CRC-32 and ZIP's own checks
continue to apply to the full uncompressed ZIP companion member data.

A manifest record is: `type:u16, flags:u16, origin:u16, encoding:u16,
namespace_length:u32, name_length:u32, native_TLV_length:u32,
value_length:u64`, followed by exact namespace bytes, exact name bytes,
native TLVs and value bytes. This is a 28-byte fixed prefix. No 64K value
limit. Values are byte-for-byte opaque; UTF-8 and UTF-16LE are merely tagged
encodings, never normalized/re-encoded. A UTF-16LE name must have even length.
Zero-length value is permitted. Known types require nonempty name.

Type values: 1 native KV EA; 2 named attribute file (Solaris/FreeBSD15+);
3 Windows ADS; 4 Mac resource fork; 5 Mac Finder metadata. Additional types
remain preserve-only until explicitly defined. Origins: 1 Linux; 2 FreeBSD;
3 NetBSD; 4 macOS; 5 AIX; 6 Solaris/illumos; 7 Windows; 8 OS/2; 9 OpenBSD.
Origin 0 and unknown tags are preserve-only, not automatically mapped to a
native filesystem. Record flag 1 is critical; other unknown bits block
native interpretation while retaining safely framed data.

### Platform-native TLV encoding

Each TLV is `(type:u16, flags:u16, payload_len:u32, payload bytes)`.
Tags MUST appear in strictly ascending order, with no duplicate tags.
TLV flag bit 0 is critical-to-understand; any unrecognized flag/type must
prevent native application but permit opaque preservation. The current core
reports `schema_supported=0`, not `XTR_OK` with application authorization.

| Tag | Payload bytes | Meaning |
|---:|---:|---|
|1|u16|Required interface discriminator for recognized records|
|2|u32|POSIX mode, including file-type bits if source supplied|
|3|u8|Windows native EA flags; standard `FILE_NEED_EA` bit 7|
|4|u32|Native POSIX UID, source platform implied by origin|
|5|u32|Native POSIX GID, source platform implied by origin|
|6|i64 seconds + u32 nanoseconds|Atime, raw signed two's-complement seconds|
|7|i64 seconds + u32 nanoseconds|Mtime|
|8|i64 seconds + u32 nanoseconds|Ctime (capture only unless backend supports)|
|9|i64 seconds + u32 nanoseconds|Birth/creation time, if supported|
|10|u32|Platform-native flags, preserve-only absent platform-specific mapping|
|11|u32|Windows ADS type, distinct from named EA|
|12|u32|Mac-native flags, preserve-only absent platform mapping|

Nanoseconds 0..999999999. Unknown attributes, types and flags remain
preserve-only. No ACL, file capability or privileged security-label TLV is
native-restorable in V1 by virtue of presence alone. Opaque metadata that
cannot be safely mapped must be retained or exported explicitly rather than
assigned to a foreign namespace. Platform adapters must enforce valid native
names, privileges, symlink-safe operations, POSIX ownership permissions,
and capability detection independently of this serializer.

Interface discriminators (TLV 1): 1 Linux xattr, 2 FreeBSD extattr,
3 FreeBSD named attribute, 4 NetBSD extattr, 5 Darwin xattr, 6 AIX EA,
7 Solaris attribute file, 8 Windows NT EA, 9 Windows ADS, 10 OS/2 EA,
11 Mac resource fork, 12 Finder metadata. This distinction prevents false
FreeBSD aliases; identical namespace/name may be valid across *different*
interfaces. No automatic cross-platform conversion is implied.

### Canonical record ordering and duplicates

New V1 writers MUST sort by `(type, origin, encoding, namespace exact bytes,
name exact bytes, interface TLV value)` using lexicographic raw byte order
(shorter prefix sorts earlier). The portable V1 validator deliberately
**rejects noncanonical order** and identical semantic identities rather than
allocating unbounded storage for deduplicating arbitrary permutations. This
is a tightening from the earlier M0 draft. A pure opaque archive copy of an
unrecognized future format may preserve its bytes, but native restoration
never applies noncanonical or invalid V1 metadata. Unknown attributes can
remain copyable without claiming they are natively restorable.

## Encryption semantics

No Xtro-specific encryption algorithm or new password policy. Selected owner
mode determines companion mode: none, ZipCrypto, WinZip AE-1/AE-2 or experimental
AE-3 (subject to actual ZIP codec support). ZipCrypto is accepted without an
xattr-specific security warning or downgrade. The decrypted encrypted
companion carries `XTCS` SHA-256 internally; the outer Xtro 40-byte fields
do not disclose digest/count/manifest length. Existing ZIP CRC, password check
and actual AE authentication requirements are **outside** the metadata parser;
these must be satisfied *before* any native restoration. The metadata library
`xtr1_crypto_check` enforces consistency based on externally verified status;
it is not a cipher or a ZIP authentication implementation.

### FWKCS MD5 (0x4b46)

FWKCS is central-header-only 19-byte payload: ASCII `MD5` + 16 binary bytes.
It covers the **uncompressed ZIP member contents**, never an automatically
substituted Xtro SHA digest. FWKCS on the ordinary owner covers ordinary owner
file content. For an unencrypted companion and explicit `--fwkcs-md5`, an MD5
may cover the complete public companion uncompressed contents. For an
encrypted companion, central plaintext FWKCS would expose the digest of
protected metadata; do not emit it. A mode that *explicitly* requires FWKCS
for all members and encrypted metadata companions must be rejected before
publishing output, not silently drop a requested digest or reveal it. Existing
FWKCS fields in unrelated ordinary members are retained/handled as before.
ZipOpt presently verifies and normally drops FWKCS upon recompressing; it must
preserve or update associations and apply these rules before Xtro rewriting
is enabled. No MD5 is used as a security/authentication primitive for Xtro.

## Atomicity, error handling, and 32-bit constraints

The C89 portable core does not allocate whole values, abort, or perform
filesystem writes; stream chunks are 4096 bytes in this prototype. Callbacks
can fail and propagate IO errors. Reader stores at most two record identities
and their native TLV bytes for canonical validation, bounded by
`policy.max_field` and `size_t` arithmetic checks. A writer preflights
identities and all declared lengths before emitting any bytes, but a
**midstream failure still requires external staging and rollback** in M2.
Logical lengths are two u32 limbs independent of native `long`. The format
supports full u64, but individual C89 hosts are free to reject unsupported
limits without truncation. No actual >4 GiB runtime stream or 32-bit binary
execution is claimed. On unknown critical records, no native restore.

Archive-level rewriting, ZipCloak, ZipOpt, ZipDedup, ZipNote, archive merges,
local-vs-central reconciliation, symlink safety and transactional publication
are M2/M6 integration gates. The standalone archive-index preflight validates
owner/companion identity graphs but **does not rewrite ZIP archives**. Tests
show that a generic ZIP rewrite may break Xtro local-vs-central field
consistency; it must not be considered lossless just because ZIP CRC passes.

## Security model

CRC and SHA-256 detect corruption and data substitution when unmodified
references are available, but neither unkeyed hash authenticates a hostile
archive. They cannot prevent substitution of an entire coherent owner pair
or erasure of all Xtro fields. ZIP encryption authentication (where present)
must be verified by the ZIP layer. Never modify skipped target files. Do not
follow symlinks to apply metadata. ACLs, quarantine, capabilities, security
labels, and Windows security descriptors require independent opt-in policies.

## M1 code and use

- `xtrm.c/.h`: original M0 raw C89 header and bounded manifest reader.
- `xtrsha.c/.h`: independent pure C89 SHA-256.
- `xtrv1.c/.h`: V1 validated metadata writer/reader, typed TLV schema,
  index association checks, extra-field and FWKCS envelope checks, and
  crypto-mode consistency helper.
- `test_v1.c`, `test_platform.c`, `fuzz_v1.c`: isolated C89 regression.
- `emit_fixture.c`, `verify_fixture.c`, `test_zip_interop.py`: ZIP STORE/Deflate,
  ZipCrypto and FWKCS interoperability checks with independent hashlib and
  `zip`/`unzip`. These tools are test fixtures, not shipping ZIP code.
- `run_m1.sh`, `fuzzer_seeds.py` and `TEST-RESULTS.md`: reproducible command log and limitations.

Relevant historical documentation:
- https://support.pkware.com/pkzip/appnote
- https://sources.debian.org/src/zip/3.0-6/proginfo/extrafld.txt/
- https://www.freebsd.org/releases/15.0R/relnotes/
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id
