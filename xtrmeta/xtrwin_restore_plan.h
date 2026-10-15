/* SPDX-License-Identifier: MIT-0 */
/* Verified mixed Windows metadata plan; no native filesystem writes. */
#ifndef XTRWIN_RESTORE_PLAN_H
# define XTRWIN_RESTORE_PLAN_H
# include "xtrwin_ads.h"
# include "xtrwin_ea.h"
# include "xtrwin_mixed_verify.h"
# define XTR_WIN_RESTORE_MAX_ADS 128U
# define XTR_WIN_RESTORE_MAX_BYTES (32UL * 1024UL * 1024UL)
typedef struct xtr_win_ads_part
{
  xtr_ads_name name;
  unsigned long length;
  long offset; /* file offset within fully verified decoded manifest */
} xtr_win_ads_part;
typedef struct xtr_win_restore_plan
{
  xtr_win_ea_list eas;
  xtr_win_ads_part *ads;
  unsigned ads_count;
} xtr_win_restore_plan;
void xtr_win_restore_plan_free (xtr_win_restore_plan *plan);
/* Select bits are independent. A completely malformed record fails even
 * when its class was not selected. SHA/XTCS must verify before return. */
int xtr_win_restore_plan_load (FILE *stage, xtr_u64 encoded,
                               const xtr_extra *outer,
                               const unsigned char *sha, unsigned select,
                               xtr_win_restore_plan *plan);
#endif /* ifndef XTRWIN_RESTORE_PLAN_H */
