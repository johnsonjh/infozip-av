/* SPDX-License-Identifier: MIT-0 */
/* C89 OS/2 FEA2LIST validator and Xtro V1 record adapter.
 * This library does not perform filesystem writes, archive preflight or
 * native symlink activation. Callers must verify ZIP transport first. */
#ifndef XTROS2_EA_H
# define XTROS2_EA_H
# include "xtrv1.h"
# include <stddef.h>
# define XTR_OS2_EA_REQUIRED 0x80U
# define XTR_OS2_EA_NATIVE_LEN 22U
# define XTR_OS2_EA_OK 0
# define XTR_OS2_EA_BAD 1
# define XTR_OS2_EA_LIMIT 2
# define XTR_OS2_EA_CONFLICT 3

typedef struct xtr_os2_ea_item
{
  const unsigned char *name, *value;
  size_t name_len, value_len;
  unsigned flags;
} xtr_os2_ea_item;
typedef struct xtr_os2_ea_source
{
  xtr1_source source;
  unsigned char tlv[XTR_OS2_EA_NATIVE_LEN];
  const unsigned char *value;
  size_t length, position;
} xtr_os2_ea_source;

/* Native codepage/country name comparison callback. Return 1 for equal,
 * 0 for distinct, -1 for an unavailable/failed NLS mapping. The generic
 * no-callback wrappers fold ASCII ONLY and are NOT sufficient for native
 * non-ASCII filesystem identity checks. */
typedef int (*xtr_os2_ea_equal_cb) (const unsigned char *, size_t,
                                    const unsigned char *, size_t, void *);
/* Decode the complete native FEA2LIST, never trusting offsets or cbList.
 * `items` points into the caller-owned immutable bytes. The source must
 * remain live until all items have been consumed. Case-insensitive duplicate
 * names are rejected. Use parse_ex with a native NLS callback on OS/2.
 * A null items pointer with cap=0 counts only; it still validates the list. */
int xtr_os2_ea_parse (const unsigned char *bytes, size_t bytes_len,
                      xtr_os2_ea_item *items, size_t cap, size_t *count);
int xtr_os2_ea_parse_ex (const unsigned char *bytes, size_t bytes_len,
                         xtr_os2_ea_item *items, size_t cap, size_t *count,
                         xtr_os2_ea_equal_cb names_equal, void *context);
/* Compare both fully validated sets. Identical native values/flags are
 * coalescible; different values/flags with the same name are a conflict.
 * Does not mutate existing destination EAs. */
int xtr_os2_ea_reconcile (const xtr_os2_ea_item *legacy, size_t legacy_count,
                          const xtr_os2_ea_item *xtro, size_t xtro_count);
int xtr_os2_ea_reconcile_ex (const xtr_os2_ea_item *legacy,
                             size_t legacy_count, const xtr_os2_ea_item *xtro,
                             size_t xtro_count,
                             xtr_os2_ea_equal_cb names_equal, void *context);
/* Prepare a fully native OS/2 Xtro V1 record. Names and values must remain
 * live and the returned source must not be copied after initialization:
 * read_value stores its context as a pointer to this structure. */
int xtr_os2_ea_source_init (xtr_os2_ea_source *out,
                            const xtr_os2_ea_item *item);
/* Comparator usable with qsort() on xtr_os2_ea_source structs, but
 * initialization MUST be done after sorting the xtr_os2_ea_item array
 * because source contexts point into their own source structs. */
int xtr_os2_ea_item_compare (const void *a, const void *b);
/* Split a validated native EA list into ordinary attributes and the
 * kLIBC SYMLINK marker. The allocations belong to the caller and must be
 * released by xtr_os2_ea_partition_free(). An NLS comparator is mandatory
 * on native OS/2, so non-ASCII native identities are not guessed.
 * The function is all-or-nothing: failures leave both outputs empty. */
typedef struct xtr_os2_ea_partition
{
  unsigned char *ordinary;
  unsigned char *symlink;
  size_t ordinary_len, symlink_len;
} xtr_os2_ea_partition;
int xtr_os2_ea_partition_list (const unsigned char *bytes, size_t length,
                               xtr_os2_ea_partition *result,
                               xtr_os2_ea_equal_cb names_equal, void *context);
void xtr_os2_ea_partition_free (xtr_os2_ea_partition *result);
/* Build a single validated native FEA2LIST from the supplied EA records;
 * caller frees *output. Strict native name equality is supplied by caller. */
int xtr_os2_ea_pack_list (const xtr_os2_ea_item *items, size_t count,
                          unsigned char **output, size_t *length,
                          xtr_os2_ea_equal_cb names_equal, void *context);
#endif /* ifndef XTROS2_EA_H */
