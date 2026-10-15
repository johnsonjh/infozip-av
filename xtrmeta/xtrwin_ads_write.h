/* SPDX-License-Identifier: MIT-0 */
#ifndef XTRWIN_ADS_WRITE_H
# define XTRWIN_ADS_WRITE_H
# include "xtrwin_ads_native.h"
# include <stdio.h>
# ifdef _WIN32
/* Create a NEW named $DATA stream on a pinned non-reparse owner.
 * Will NEVER overwrite/delete an existing stream. Stage is decoded bytes.
 * Returns 0 on byte-exact readback, 1 on failure, 2 on unsupported/existing.
 * On failed creation/writes cleanup is attempted; *cleanup_failed indicates
 * that a newly created stream may still be present and requires attention.
 * This primitive is NOT an exact-replacement transaction; not for production
 * UnZip invocation without a separately verified transaction coordinator. */
int xtr_win_ads_create_stream_at (HANDLE owner, const xtr_ads_name *name,
                                  FILE *stage, long offset, unsigned long size,
                                  int *cleanup_failed);
int xtr_win_ads_create_stream (HANDLE owner, const xtr_ads_name *name,
                               FILE *stage, unsigned long size,
                               int *cleanup_failed);
# endif /* ifdef _WIN32 */
#endif /* ifndef XTRWIN_ADS_WRITE_H */
