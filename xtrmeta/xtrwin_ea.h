/* SPDX-License-Identifier: MIT-0 */
/* Windows NT EA wire adapter. C89, no Windows header dependency.
 * The caller owns all filesystem operations, full-set replacement,
 * symlink/reparse guards and rollback. This module ONLY converts bounded,
 * validated FILE_FULL_EA_INFORMATION buffers <-> Xtro manifests. */
#ifndef XTRWIN_EA_H
# define XTRWIN_EA_H
# include "xtrv1.h"
# include <stdio.h>
typedef struct xtr_win_ea
{
  unsigned char *name, *value;
  size_t name_len, value_len;
  unsigned flags;
} xtr_win_ea;
typedef struct xtr_win_ea_list
{
  xtr_win_ea *items;
  size_t count;
} xtr_win_ea_list;
void xtr_win_ea_free (xtr_win_ea_list *a);
/* A Windows query's io.Information length, not allocated-buffer length. */
int xtr_win_ea_parse (const unsigned char *buffer, size_t used,
                      xtr_win_ea_list *output);
int xtr_win_ea_pack (const xtr_win_ea_list *a, unsigned char **output,
                     size_t *used);
/* For NtSetEaFile specifically. Reject empty values, which Windows
 * interprets as DELETE rather than creating a zero-length EA. */
int xtr_win_ea_pack_set (const xtr_win_ea_list *a, unsigned char **output,
                         size_t *used);
int xtr_win_ea_to_manifest (const xtr_win_ea_list *a,
                            const unsigned char owner[16], FILE *stage,
                            int encrypted, xtr1_digest *digest);
/* Entire manifest is checked BEFORE exposing any native EA list. Output is
 * a newly allocated list, suitable for a separately transactional applier.
 * This does not call NtSetEaFile or touch any destination filesystem. */
int xtr_win_ea_from_manifest (FILE *stage, xtr_u64 encoded_size,
                              const xtr_extra *outer,
                              const unsigned char *sha32,
                              xtr_win_ea_list *output);
#endif /* ifndef XTRWIN_EA_H */
