/* SPDX-License-Identifier: MIT-0 */
/* Opt-in Win32 NTFS named-data-stream enumeration; not ZIP transport. */
#ifndef XTRWIN_ADS_NATIVE_H
# define XTRWIN_ADS_NATIVE_H
# include "xtrwin_ads.h"
# ifdef _WIN32
#  include <windows.h>
typedef int (*xtr_ads_visit_cb) (void *, const xtr_ads_name *, unsigned long,
                                 unsigned long);
/* HANDLE must refer to an already opened, non-reparse filesystem object.
 * No writes. Returns 0 on complete enumeration, 1 on IO/changed identity,
 * 2 when unsupported, 3 for invalid/unsupported stream representation. */
int xtr_win_ads_enumerate_handle (HANDLE pinned, xtr_ads_visit_cb visit,
                                  void *ctx);
# endif /* ifdef _WIN32 */
#endif /* ifndef XTRWIN_ADS_NATIVE_H */
