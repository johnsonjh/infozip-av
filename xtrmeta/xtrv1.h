/* SPDX-License-Identifier: MIT-0 */
/* Standalone Xtro-ZIP metadata V1 portable serializer and verifier. C89. */
#ifndef XTRV1_H
# define XTRV1_H
# include "xtrm.h"
# include "xtrsha.h"
# define XTR_V1_EXTRA_ID                                                      \
  0x5854U /* proposed Xtro-ZIP third party allocation                         \
           */
# define XTR_V1_INLINE 1
# define XTR_V1_COMPANION 2U
# define XTR_V1_ENCRYPTED 1U
# define XTR_V1_TLV_INTERFACE 1U
# define XTR_V1_TLV_MODE 2U
# define XTR_V1_TLV_WIN_EA_FLAGS 3U
# define XTR_V1_TLV_UID 4U
# define XTR_V1_TLV_GID 5U
# define XTR_V1_TLV_ATIME 6U
# define XTR_V1_TLV_MTIME 7U
# define XTR_V1_TLV_CTIME 8U
# define XTR_V1_TLV_BTIME 9U
# define XTR_V1_TLV_NATIVE_FLAGS 10U
# define XTR_V1_TLV_WIN_STREAM_TYPE 11U
# define XTR_V1_TLV_MAC_FLAGS 12U
/* Interface values: Linux xattr 1, FreeBSD extattr 2, FreeBSD named 3,
 * NetBSD extattr 4, Darwin xattr 5, AIX EA 6, Solaris file 7,
 * Windows EA 8, Windows ADS 9, OS/2 EA 10, Mac fork 11, Finder 12. */

typedef void *(*xtr1_alloc_cb) (void *, size_t);
typedef void (*xtr1_free_cb) (void *, void *);
typedef struct xtr1_policy
{
  unsigned long max_records, max_field;
  xtr_u64 max_manifest;
  xtr1_alloc_cb alloc;
  xtr1_free_cb release;
  void *context;
} xtr1_policy;
typedef struct xtr1_digest
{
  xtr_u64 manifest_length;
  unsigned long count, crc32;
  unsigned char sha256[32];
  int schema_supported; /* not a grant of filesystem restoration */
} xtr1_digest;
/* Byte exact writer: return 0 on success, other value on failure. */
typedef int (*xtr1_write_cb) (void *, const unsigned char *, size_t);
typedef struct xtr1_sink
{
  xtr1_write_cb write;
  void *context;
} xtr1_sink;
typedef struct xtr1_source
{
  xtr_record record;
  const unsigned char *ns, *name, *native;
  xtr_read_cb read_value;
  void *value_context;
} xtr1_source;

/* Returns XTR_OK/CORRUPT/LIMIT/IO/UNSUPPORTED. Do not perform native
 * writes while validating: finalize digest and transport first. */
int xtr1_check_manifest (xtr_reader *src, xtr_u64 encoded_size,
                         const xtr_extra *outer,
                         const unsigned char *central_sha32,
                         const xtr1_policy *policy, xtr1_digest *result);
int xtr1_write_manifest (const unsigned char owner[16],
                         const xtr1_source *items, size_t count, int encrypted,
                         const xtr1_policy *policy, xtr1_sink *sink,
                         xtr1_digest *result);
/* The 4-byte ZIP ID and size are NOT part of these payloads. */
int xtr1_extra_encode (unsigned char *out, size_t cap, const xtr_extra *e,
                       int central, const unsigned char *inline_payload,
                       size_t inline_size, const unsigned char *sha32,
                       size_t *written);
int xtr1_extra_decode (const unsigned char *p, size_t size, int central,
                       xtr_extra *e, unsigned char sha32[32]);
int xtr1_check_headers (const unsigned char *local, size_t local_len,
                        const unsigned char *central, size_t central_len,
                        xtr_extra *outer, unsigned char sha32[32]);
int xtr1_scan_extra_list (const unsigned char *p, size_t n, int central,
                          int *has_xtr, int *has_fwkcs);
/* FWKCS field covers ordinary uncompressed ZIP member bytes, never XTRO
 * metadata implicitly. Validate schema only here; hash verification belongs
 * to the ZIP codec/FWKCS path. */
int xtr1_check_fwkcs (const unsigned char *p, size_t n, int central);
/* Encryption mode follows the owner's selected ZIP mode (0=clear,
 * 1=ZipCrypto, 2=AE-1,3=AE-2,4=AE-3); policy checks only, no crypto. */
int xtr1_crypto_check (unsigned owner_mode, unsigned companion_mode,
                       int zip_integrity_verified, int authenticated);
/* Generate and check the precisely reserved companion name. */
int xtr1_companion_name (const unsigned char owner[16], char out[52]);
int xtr1_companion_matches (const unsigned char owner[16], const char *name,
                            size_t name_len);
/* ZIP central-directory owner/companion relationship preflight.
 * Reject orphan, ambiguous, duplicated, or reserved-name collisions.
 * This is NOT a ZIP parser or an archive rewriting implementation. */
typedef struct xtr1_index_entry
{
  const char *name;
  size_t name_len;
  const unsigned char *owner_id; /* NULL if ordinary/companion entry */
  unsigned mode;                 /* 0, INLINE, COMPANION */
  int companion;                 /* true only for a metadata payload member */
} xtr1_index_entry;
int xtr1_check_archive_index (const xtr1_index_entry *entries, size_t count,
                              const xtr1_policy *policy);
/* M1 enforcement gate for encrypted metadata companions.
 * zip_ok means the ZIP codec has validated all relevant structural, length,
 * CRC (when present), and stream status; authenticated means the ZIP codec
 * has verified its actual AE authentication tag (if applicable).
 * Neither argument is inferred from an untrusted ZIP header.
 * A companion encrypted with ZipCrypto is accepted without an extra warning.
 * A plaintext FWKCS digest on an encrypted companion is prohibited.
 * If fwkcs_all_required is set, the resulting conflict is UNSUPPORTED. */
int xtr1_check_member_policy (const xtr_extra *e, unsigned owner_crypto,
                              unsigned companion_crypto, int zip_ok,
                              int authenticated, int companion_has_fwkcs,
                              int fwkcs_all_required);

# define XTR1_RETAIN 0U
# define XTR1_RENAME 1U
# define XTR1_REPLACE 2U
# define XTR1_DELETE 3U
# define XTR1_CLONE 4U
/* This validates proposed rewrite decisions, NOT ZIP bytes or publication.
 * For a CLONE with xattrs the caller MUST rebuild the manifest with a new
 * owner ID; copying the old embedded owner ID into the new stream is unsafe.
 * The calling rewrite utility must also separately validate both complete
 * archive indexes before publication with xtr1_check_archive_index. */
typedef struct xtr1_rewrite_entry
{
  unsigned operation;
  unsigned old_mode, new_mode;
  const unsigned char *old_owner, *new_owner;
  int manifest_rebuilt;
} xtr1_rewrite_entry;
int xtr1_check_rewrite_decisions (const xtr1_rewrite_entry *entries,
                                  size_t count);

/* M6E2 portable DECODED-PAYLOAD conversion for future ZipCloak integration.
 * Input is the already decompressed (and if necessary authenticated and
 * decrypted) metadata member, or an inline manifest. Output is the decoded
 * companion payload, NOT a ZIP member or ciphertext. The caller must:
 *   - independently verify the ZIP container, decompressor, encryption and
 *     authentication before calling;
 *   - supply a stable/replayable source; reset returns 0 on success;
 *   - stage output privately and publish neither data nor new extra fields
 *     unless this function and the ZIP rewrite both succeed;
 *   - update both Xtro local/central fields, companions and FWKCS policy
 *     atomically, matching owner/companion encryption modes.
 * The implementation checks the first pass, rewinds, then checks that the
 * bytes copied on the second pass match. It does not allocate by payload
 * size and never touches the filesystem itself. Returns XTR_* status.
 * Public target: plain XTMD payload and central SHA. Encrypted target:
 * XTMD followed by XTCS+SHA inside the member. No cryptography is done. */
typedef int (*xtr1_reset_cb) (void *);
int xtr1_reframe_companion (xtr_reader *source, xtr_u64 source_size,
                            const xtr_extra *old_extra,
                            const unsigned char *old_central_sha,
                            const xtr1_policy *policy, xtr1_reset_cb reset,
                            void *reset_context, xtr1_sink *staged_output,
                            int encrypted_target, xtr_extra *new_extra,
                            xtr1_digest *manifest_digest);

/* M6E2B: transactional extra-list rewrite, for staged ZIP transitions.
 * Buffers MUST be disjoint and MUST NOT overlap either input list or each
 * other. No destination bytes are written until both resulting lists have
 * passed structural validation and capacity checks.  The caller separately
 * validates the entire decoded manifest, ZIP crypto, CRC, authentication,
 * and the complete owner/companion archive graph before publication.
 * If target is inline, payload is the complete validated XTMD manifest;
 * otherwise payload MUST be NULL and public companion targets require SHA.
 * Existing non-Xtro extra fields are preserved byte-for-byte and in order.
 * Both written lengths are set to zero on error. */
int xtr1_rewrite_owner_extras (const unsigned char *old_local, size_t old_ln,
                               const unsigned char *old_central, size_t old_cn,
                               const xtr_extra *new_owner,
                               const unsigned char *inline_payload,
                               size_t inline_len, const unsigned char *sha32,
                               unsigned char *new_local, size_t local_cap,
                               size_t *local_written,
                               unsigned char *new_central, size_t central_cap,
                               size_t *central_written);
/* Rewrite an ordinary metadata companion's extra fields. Never forward an
 *  obsolete FWKCS MD5 digest when the decoded companion payload changes.
 *  If the input carried FWKCS, a new 19-byte MD5 payload is mandatory for a
 *  public output. An encrypted output forbids plaintext FWKCS entirely;
 *  fwkcs_required rejects the conflict, rather than silently dropping it.
 *  The caller must compute regenerated_fwkcs over the complete NEW decoded
 *  payload, not the old payload or compressed bytes. No ZIP crypto occurs.
 *  The caller separately validates owner/companion identity and transport. */
int xtr1_rewrite_companion_extras (
    const unsigned char *old_local, size_t old_ln,
    const unsigned char *old_central, size_t old_cn, int encrypted_target,
    int fwkcs_required, const unsigned char *regenerated_fwkcs,
    unsigned char *new_local, size_t local_cap, size_t *local_written,
    unsigned char *new_central, size_t central_cap, size_t *central_written);
#endif /* ifndef XTRV1_H */
