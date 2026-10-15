/* SPDX-License-Identifier: MIT-0 */
/* Portable Windows EA/ADS manifest inspection. No filesystem modifications. */
#ifndef XTRWIN_MIXED_VERIFY_H
# define XTRWIN_MIXED_VERIFY_H
# include "xtrv1.h"
# include "xtrwin_ads.h"
# include <stdio.h>
/* Canonical UTF-8 name from a verified record to NTFS UTF-16. */
int xtr_win_ads_from_utf8 (const unsigned char *utf8, size_t n,
                           xtr_ads_name *output);
# define XTR_WIN_SELECT_EA 1U
# define XTR_WIN_SELECT_ADS 2U
typedef struct xtr_win_mixed_summary
{
  unsigned long ea_count, ads_count;
  xtr_u64 ea_bytes, ads_bytes;
  unsigned has_zero_ea;
} xtr_win_mixed_summary;
/* Requires a fully decoded manifest in 'stage'. sha32 is NULL for an
 * encrypted companion; in that case check_manifest verifies the XTCS trailer.
 * This method does NOT authorize native writes or select restoration.
 * Caller must still authenticate ZIP CRC/encryption and owner association.
 */
int xtr_win_mixed_verify (FILE *stage, xtr_u64 encoded, const xtr_extra *outer,
                          const unsigned char *sha32,
                          xtr_win_mixed_summary *summary);
#endif /* ifndef XTRWIN_MIXED_VERIFY_H */
