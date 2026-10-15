/* SPDX-License-Identifier: MIT-0 */
#ifndef XTRWIN_ADS_RESTORE_H
# define XTRWIN_ADS_RESTORE_H
# include "xtrwin_ads_txn.h"
# ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN 1
#  endif /* ifndef WIN32_LEAN_AND_MEAN */
#  include <windows.h>
/* Caller must ensure metadata integrity and owner identity, and provide
 * a private ACL-protected writable backup FILE. Never use public tmpfile(). */
int xtr_win_ads_restore_exact (HANDLE owner, const xtr_win_ads_part *parts,
                               unsigned count, FILE *verified_stage,
                               FILE *secure_backup, int *rollback_failed);
# endif /* ifdef _WIN32 */
#endif /* ifndef XTRWIN_ADS_RESTORE_H */
