/* SPDX-License-Identifier: MIT-0 */
#ifndef XTRWIN_ADS_RECORD_H
# define XTRWIN_ADS_RECORD_H
# include "xtrv1.h"
# include "xtrwin_ads.h"
/* Construct one V1 type-3 Windows ADS record, without writing the archive.
 * The returned native TLV storage belongs to the caller, and the stream
 * name refers to the caller's xtr_ads_name. This permits mixed EA/ADS
 * manifests under ONE Xtro owner; it does not authorize ADS restoration.
 * type 3, origin Windows 7, interface ADS 9, NTFS $DATA type 0x80.
 * `read` must supply exactly `length` bytes during final serialization.
 * The caller must maintain stable names and streams until the ZIP transaction
 * completes, and must not release the payload before manifest verification. */
int xtr_ads_record_source (const xtr_ads_name *name, xtr_u64 length,
                           xtr_read_cb read, void *ctx, xtr1_source *out,
                           unsigned char native_tlvs[22]);
#endif /* ifndef XTRWIN_ADS_RECORD_H */
