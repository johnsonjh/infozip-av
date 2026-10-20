# Xtro-ZIP V1 metadata format: implementer's reference

Status: **implemented V1 wire profile in Xtro-ZIP cu102; not an IANA/PKWARE
registered extra-field assignment or a universal filesystem metadata standard**.
This document describes what cu102's C89 serializer/parser *actually* recognizes.
It does not grant native restoration authority for arbitrary records. The
normative executable reference is `xtrmeta/xtrm.c`, `xtrmeta/xtrv1.c`,
`xtrmeta/xtrsha.c`; consult those sources and regression fixtures if a detail
appears ambiguous. This document does not silently allocate new identifiers.

## Purpose and compatibility model

A normal ZIP entry remains a normal entry: its contents, compression method,
CRC, timestamps and name are governed by ZIP. Xtro stores **additional binary
filesystem metadata** associated with that exact archive-member occurrence.
Legacy ZIP tools can still read ordinary files, but may expose companion
members and may discard, duplicate or detach metadata on archive rewriting.
Xtro-aware rewriters MUST preserve verified owner/companion relationships or
reject the operation without publication. The format is byte-oriented and
independent of the producing platform's pointer size, byte order and text
encoding. It does **not** automatically translate permission models between
operating systems.

All integers below are unsigned little-endian except timestamp seconds (signed
two's-complement). All offsets start at zero within the stated structure.
Byte strings do not include implicit NUL terminators or padding. Lengths
are in **bytes**, not characters.

## Identification and ZIP placement

Xtro uses proposed ZIP extra-field ID `0x5854` (`54 58` in a ZIP header),
followed by ordinary ZIP field length `u16` and the Xtro payload. **Check the
four-byte ASCII `XTRO` signature and version**, not just the numeric ID.
`0x5854` remains a third-party candidate; unique allocation is not proven.
A different payload at the same tag must not be interpreted as Xtro. Every
owner has exactly one local and one central Xtro extra field whose first
40 payload bytes agree. Duplicate fields are rejected.

The owner ID is 16 bytes and must **not be all zero**, unique to an **entry occurrence**, not to a
filename or file content hash. A simple rename may retain that ID. Clone and
replacement require rebuilding metadata under a fresh ID. Two identical
filenames or two identical files do NOT justify reusing an owner ID.

### Xtro ZIP extra payload (not including ZIP's 4-byte ID/length envelope)

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 4 | ASCII `XTRO` | Mandatory |
| 4 | 1 | major version | `1` |
| 5 | 1 | minor version | `0` |
| 6 | 1 | mode | `1` inline; `2` companion |
| 7 | 1 | flags | bit 0 encrypted; all others reserved |
| 8 | 16 | owner ID | nonzero, archive-wide unique |
| 24 | 4 | record count | zero for encrypted companion |
| 28 | 8 | manifest byte length | zero for encrypted companion |
| 36 | 4 | manifest CRC-32 | zero for encrypted companion |
| 40 | variable | central-only body | see below |

The local-header Xtro payload is **exactly 40 bytes** for both modes. The
central field uses the same 40-byte prefix plus:

* Mode 1 (INLINE): the complete plain `XTMD` manifest, at least 36 bytes;
  not encrypted. The advertised length, count and CRC match the manifest.
* Mode 2 (COMPANION), unencrypted: exactly 32 SHA-256 bytes of the complete
  uncompressed manifest (central Xtro payload length 72 bytes).
* Mode 2, encrypted: no appended bytes (central payload length 40 bytes), and
  record count, length, and CRC in the clear prefix are all zero. The SHA-256
  is instead protected inside the encrypted companion, as `XTCS`.

Do not replace other ZIP extra fields when choosing inline versus companion.
The entire central/local ZIP extra-field lists must each fit the ordinary
65,535-byte limit, including all envelopes. If inline does not fit, use the
companion mode. Zero records are allowed by the underlying manifest grammar,
although current capture adapters may omit metadata when there is nothing
eligible to store.

### Companion filename and contents

The exact reserved filename is:

```
__XTRO_ZIP__/x/ + 32 lowercase hex digits of the 16-byte owner ID + .xtm
```

Example for the owner ID bytes `00 01 02 ... 0f`:

```
__XTRO_ZIP__/x/000102030405060708090a0b0c0d0e0f.xtm
```

It is one ordinary ZIP file entry (not a symlink and not a directory). Its
compression is ZIP STORE (method 0) or Deflate (method 8), subject to ZIP's
normal ZIP64 support. The **decoded, uncompressed** contents are the XTMD
manifest for an unencrypted companion; for encrypted companions they are
XTMD followed by XTCS (defined below). Xtro-aware extractors do not extract
companions into user-visible paths by default. Unknown reserved-path entries,
duplicated names, orphan companions, duplicate owner IDs, and ambiguous graph
edges are errors. Do not associate a companion using file name alone: validate
both local and central headers and the archive's complete ownership graph.

## XTMD binary manifest

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 4 | ASCII `XTMD` | Mandatory |
| 4 | 1 | major | 1 |
| 5 | 1 | minor | 0 |
| 6 | 2 | flags | 0 |
| 8 | 16 | owner ID | exactly matches Xtro extra |
| 24 | 4 | record count | u32 |
| 28 | 8 | sum of record bytes | u64, precise |
| 36 | variable | records | exactly count records, no trailing data |

Thus manifest length = `36 + sum(record lengths)`, checked using overflow-safe
64-bit arithmetic. V1 does not impose a 64 KiB limit on a record's value.
A 32-bit implementation may impose documented resource limits, but must reject
oversized inputs rather than truncate lengths or claim successful restoration.

### Individual record header (28 bytes)

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 2 | type | u16; 0 and 65535 prohibited |
| 2 | 2 | flags | bit 0 critical; other bits not currently actionable |
| 4 | 2 | origin | source-platform discriminator |
| 6 | 2 | name encoding | 0 native bytes, 1 UTF-8, 2 UTF-16LE |
| 8 | 4 | namespace length | u32 bytes |
| 12 | 4 | name length | u32 bytes |
| 16 | 4 | native TLV byte length | u32 bytes |
| 20 | 8 | value length | u64 bytes |
| 28 | variable | bytes | namespace, name, native TLVs, value (in order) |

Type 1 = native key/value EA; type 2 = named-attribute file (e.g., Solaris
and FreeBSD 15); type 3 = Windows alternate data stream; type 4 = macOS
resource fork; type 5 = macOS Finder metadata. Other type values are not
natively restorable by cu102. Known types 1–5 require a nonempty name.
Names tagged UTF-16LE have an even byte count. All encodings are stored
**without normalization or transliteration**. Value bytes are opaque, including
NUL and any native typed-value prefix. Zero-length values are legitimate.

Origins in cu102: 1 Linux, 2 FreeBSD, 3 NetBSD, 4 macOS, 5 AIX,
6 Solaris/illumos, 7 Windows, 8 OS/2, 9 OpenBSD. Other origins are
preserve-only until formally specified. Different origins/interfaces with
identical name bytes are different identities, not a reason to overwrite.

### Platform TLVs

Each native TLV uses `tag:u16, flags:u16, length:u32, payload[length]`.
TLVs must be strictly ascending in numeric tag order, each appearing at most
once, with bounds checked before reading data. Flag bit 0 means critical.
Unknown types, flags, and native mappings must not authorize native writes.

| Tag | Payload | Meaning |
| ---: | --- | --- |
| 1 | u16 | required native interface discriminator |
| 2 | u32 | POSIX mode |
| 3 | u8 | Windows EA flags (native `FILE_NEED_EA` is bit 7) |
| 4 | u32 | UID |
| 5 | u32 | GID |
| 6 | i64 + u32 | atime seconds and nanoseconds |
| 7 | i64 + u32 | mtime seconds and nanoseconds |
| 8 | i64 + u32 | ctime seconds and nanoseconds |
| 9 | i64 + u32 | birth/creation seconds and nanoseconds |
| 10 | u32 | platform-native flags (including OS/2 EA required bit) |
| 11 | u32 | Windows ADS stream type |
| 12 | u32 | macOS-native flags |

Nanoseconds must be 0–999,999,999. Current recognized interface values:
1 Linux xattr; 2 FreeBSD extattr; 3 FreeBSD named attribute;
4 NetBSD extattr; 5 Darwin xattr; 6 AIX EA;
7 Solaris attribute file; 8 Windows EA; 9 Windows ADS;
10 OS/2 EA; 11 macOS resource fork; 12 Finder metadata.

The origin/type/interface combinations actually accepted by the C89 core are:

| Type | Origin | Interface |
| --- | --- | --- |
| 1 | 1,2,3,4,5,7,8 | 1,2,4,5,6,8,10 respectively |
| 2 | 2,6 | 3,7 respectively |
| 3 | 7 | 9 |
| 4 | 4 | 11 |
| 5 | 4 | 12 |

An interface TLV must appear on every recognized record. Native restoration
requires a platform adapter that explicitly supports that combination;
passing the portable schema checker is **not** permission to restore. The
native flags for OS/2 must retain `FEA2.fEA` (including `FEA_NEEDEA`).

### Canonical order

Writers sort records using `(type, origin, encoding, namespace raw bytes,
name raw bytes, interface number)` with bytewise lexicographic comparison and
shorter prefix before longer data. The current verifier rejects out-of-order
records and duplicate semantic identities. A platform-specific reader must
also apply the destination filesystem's equivalence rules: OS/2 EA names are
case-insensitive, even where Xtro identities are byte-exact. Reject ambiguous
case-only duplicates on OS/2; do not quietly select one value.

## Checksums and encrypted metadata

Xtro CRC-32 is the same reflected CRC-32 polynomial as conventional ZIP
(`0xEDB88320`). Compute it over **exact complete XTMD bytes**, as does
SHA-256. Do not hash the compressed ciphertext in place of the decoded
manifest. Plain inline metadata uses the central inline XTMD; a plain
companion has the SHA-256 in the owner's central extra field.

An encrypted companion's decoded data ends with:

```
ASCII "XTCS" (4 bytes) | SHA-256(XTMD bytes) (32 bytes)
```

XTCS is inside the encrypted ZIP member. The outer header reveals only the
owner token and encryption mode, not count, byte length, CRC or SHA. The
companion must use the owner entry's ZIP encryption class (unencrypted,
ZipCrypto, WinZip AES AE-1/AE-2 or experimental AE-3) and AES parameters
where relevant, **except for the precisely scoped directory-owner exception**.
A ZIP directory owner has a trailing `/` name, is unencrypted, and contains
no file data. When its EAs are encrypted, the owner remains unencrypted but
has a mode-2 Xtro field with `XTR_V1_ENCRYPTED=1` and all encrypted-field
count/length/CRC fields zero. The companion MUST be encrypted using the
requested ZIP encryption method; its decoded XTMD+XTCS content is verified
exactly as for any other encrypted companion. For AES companions, encryption
strength, AE version, iteration parameters and AE authentication are validated
from the companion's own ZIP transport fields, not inferred from the clear
owner. ZipCrypto has no AE authentication. An ordinary file owner does NOT
qualify, even if it has a directory-like external attribute. The exception
MUST NOT be applied to an inline record, a non-directory member, or any
unencrypted companion. Do not invent a new Xtro V1 flag or extra field. Xtro adds no cipher or key-derivation method: the ZIP reader
must validate ZIP structure, CRC where applicable, decompression, and the
actual AE authentication tag **before** enabling any metadata writes.
ZipCrypto does not provide cryptographic authentication; XTCS is a digest,
not a MAC, and does not make ZipCrypto tamper resistant.

`FWKCS` extra field `0x4B46` is unrelated to Xtro and, if present, checks
ordinary uncompressed ZIP member bytes. For an encrypted metadata companion,
a public FWKCS would leak a metadata digest and must not be written. If
`--fwkcs-md5` is required for *all* entries, that conflicts with an encrypted
companion and archive creation must fail rather than silently leak a digest.

**Platform policy:** on OS/2, an *explicitly encrypted Xtro* creation must
omit cleartext legacy `0x0009` EAs, including `SYMLINK`, to avoid leaking their
contents. For ordinary unencrypted archives emit both legacy `0x0009` and
Xtro V1 when `--xattrs` is requested. A fully represented Xtro companion can
preserve attributes when the legacy format's 65,535-byte field limit is
exceeded; never emit a truncated legacy EA list.

## ACLs, security labels and Multics

**V1 does not define a Multics origin, a Multics ACL interface, a security
label type, a capability record, or a cross-platform ACL translation.** It
would be incorrect for a third-party archiver to invent a V1 type or TLV
number and label it as established Xtro interoperability. A generic raw
record can be copied without interpretation, but a recipient may not know how
to restore it and unknown critical records prevent native application.

For a Honeywell/DPS8 Multics archiver, the following **new specification work**
is necessary before claiming compatible native ACL/label preservation:

1. Choose and publish an unambiguous origin and interface number, and state
   whether existing V1 types suffice or whether a new record type is needed.
   Coordinate any new IDs with Xtro maintainers; do not reuse another OS's
   identifier or overload TLV 10 without an agreed native mapping.
2. Define a byte-exact, versioned native payload for per-segment/per-directory
   access control entries, access names, modes and evaluation order; retain
   distinctions from POSIX ACLs and OS/2 LAN Server ACLs.
3. Specify security labels and other mandatory access-control attributes
   independently of discretionary ACLs, including label normalization,
   category ordering, sensitivity, provenance and authorization to restore.
   An unprivileged extractor must never silently lower a security label.
4. Define object association, names/character encoding, directories versus
   segments, partial failure handling, and canonical identity comparison.
5. Supply authoritative fixtures, a threat model, version negotiation,
   read-only validation tests, and explicit privilege/capability gates before
   enabling a writer or native restoration.

The 16-bit legacy OS/2 `0x4C41` LAN ACL extra field is likewise **not** a
Multics ACL mapping and must not be treated as one. A future metadata schema
revision or carefully specified extension is the appropriate route.

## Security and extraction obligations

A conforming ZIP-integrated implementation should:

1. Preflight the entire owner/companion graph and every local-versus-central
   field; reject orphaned or ambiguous relationships and reserved-path abuse.
2. Enforce size quotas **before** allocating or decompressing an advertised
   manifest, limit aggregate spool bytes, stream values, and reject integer
   overflow and truncated payloads.
3. Authenticate/verify complete ZIP transport and `XTMD`/`XTCS` checksums,
   enforce canonical record order, and reject unsupported critical metadata.
4. Stage destination writes and native metadata application separately;
   guard against path traversal, filesystem symlink/reparse-point redirection,
   root changes, and owner/target races. Never extract an untrusted companion
   to a default destination path.
5. Reconcile traditional and Xtro metadata for the same native identity before
   mutation, rejecting conflicting values or flags, applying equal EAs once.
   Existing *unrelated* destination EAs are not deleted implicitly.
6. Defer filesystem-link activation until all other relevant content and
   metadata have passed verification; report EA failure rather than silently
   treating extraction as a full success.
7. Do not claim archive-wide or filesystem-level atomic rollback unless such
   a guarantee is actually implemented and tested.

## Archive rewrites and portability

- Rename/retain: preserve checked owner token and metadata if the logical
  occurrence remains the same.
- Delete: remove owner and associated companion together.
- Replace: remove old association and generate a fresh owner ID and manifest,
  or explicitly discard metadata with documented warning/policy.
- Clone: allocate a fresh owner ID, rebuild manifest and companion name.
- ZipCloak/encryption transition: update both headers, sidecar transport,
  digest placement, AE parameters and FWKCS atomically after verification.
- ZipOpt/ZipDedup: validate ownership before and after modification; preserve
  payload integrity and prevent sidecar orphaning; any unsupported operation
  must fail closed before publication.

A non-Xtro-aware archiver may preserve ordinary file contents while losing
metadata: ordinary ZIP compatibility is not a promise of metadata fidelity.

## Engineering references and conformance tests

The source of truth is `xtrmeta/xtrm.h`, `xtrm.c`, `xtrv1.h`, `xtrv1.c`,
`xtrsha.c`, with tests `test_v1.c`, `test_policy.c`, `test_pair_graph.c`,
`test_reframe.c`, `test_archive_graph.py`, `test_zip_interop.py`, and the
platform integration tests. Run `make -C xtrmeta check` on supported Unix
build hosts and test ZIP encryption and archive rewriting independently.
A complete foreign implementation should publish golden archives covering
inline, public companion, encrypted companion, malformed lengths/ordering,
unknown critical TLVs, duplicate IDs, hash failures, and wrong crypto modes.
Platform-native round trips must be tested on each receiving OS/filesystem.

All normative V1 sizes and meanings above are grounded in cu102's current
serializer. Implementation-local safety quotas and supported ZIP codecs are
**not** intrinsic limits of the V1 wire format.
