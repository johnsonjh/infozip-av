/* SPDX-License-Identifier: MIT-0 */
/* Windows NT EA exact-replacement transaction core. ANSI C89.
 * An OS-specific backend owns a pinned, non-reparse file handle. */
#ifndef XTRWIN_TXN_H
# define XTRWIN_TXN_H
# include "xtrwin_ea.h"
typedef struct xtr_win_ea_ops
{
  void *context;
  /* Read a complete, newly allocated snapshot. Empty list is valid. */
  int (*snapshot) (void *, xtr_win_ea_list *);
  /* One upsert, or one deletion (nonzero delete argument). */
  int (*change) (void *, const xtr_win_ea *, int);
} xtr_win_ea_ops;
/* A successful return means readback equals the desired EA set. All
 * metadata must be decoded and verified BEFORE entering this function.
 * On failure, rollback is attempted and verified. rollback_failed is set
 * if the original state could not be recovered (including readback failure).
 * No archive-wide transaction is implied. */
int xtr_win_ea_apply_exact (const xtr_win_ea_ops *ops,
                            const xtr_win_ea_list *desired,
                            int *rollback_failed);
#endif /* ifndef XTRWIN_TXN_H */
