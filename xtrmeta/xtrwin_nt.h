/* SPDX-License-Identifier: MIT-0 */
/* Windows NT EA file-handle adapter. The caller must provide an already
 * opened, pinned handle with FILE_READ_EA (and FILE_WRITE_EA for restore).
 * In particular, this API does not accept pathnames or follow reparse points.
 * On non-Windows targets no functions are exposed. */
#ifndef XTRWIN_NT_H
# define XTRWIN_NT_H
# include "xtrwin_ea.h"
# ifdef _WIN32
/* Apply a preverified EA list. Caller owns SHA/XTCS validation and
 * transaction coordination with ADS. */
int xtr_win_nt_apply_list (void *handle, const xtr_win_ea_list *desired,
                           int *rollback_failed);
int xtr_win_nt_snapshot_handle (void *handle, xtr_win_ea_list *output);
int xtr_win_nt_capture_handle (void *handle, const unsigned char owner[16],
                               FILE *stage, int encrypted,
                               xtr1_digest *digest);
int xtr_win_nt_restore_handle (void *handle, FILE *stage, xtr_u64 encoded,
                               const xtr_extra *outer,
                               const unsigned char *sha, int *rollback_failed);
# endif /* ifdef _WIN32 */
#endif /* ifndef XTRWIN_NT_H */
