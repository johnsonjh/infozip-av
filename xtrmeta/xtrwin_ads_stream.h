/* SPDX-License-Identifier: MIT-0 */
#ifndef XTRWIN_ADS_STREAM_H
# define XTRWIN_ADS_STREAM_H
# include "xtrwin_ads_native.h"
# ifdef _WIN32
/* Binary stream-byte callback. A nonzero result aborts the operation.
 * This interface performs no archive publication or filesystem writes.
 * Size is the exact enumeration result (high, low DWORDs).
 * Returns 0 only if all bytes were read and the owner identity survived.
 * 1 = IO, identity change, mismatch or callback abort;
 * 2 = unsupported stream representation/name. */
typedef int (*xtr_ads_bytes_cb) (void *, const unsigned char *, size_t);
int xtr_win_ads_read_stream (HANDLE pinned, const xtr_ads_name *name,
                             unsigned long high, unsigned long low,
                             xtr_ads_bytes_cb consumer, void *ctx);
# endif /* ifdef _WIN32 */
#endif /* ifndef XTRWIN_ADS_STREAM_H */
