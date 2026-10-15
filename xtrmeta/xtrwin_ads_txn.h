/* SPDX-License-Identifier: MIT-0 */
/* Auditable, bounded, best-effort ADS replacement/rollback coordinator. */
#ifndef XTRWIN_ADS_TXN_H
# define XTRWIN_ADS_TXN_H
# include "xtrwin_restore_plan.h"
typedef struct xtr_win_ads_inventory
{
  xtr_win_ads_part *items;
  unsigned count;
} xtr_win_ads_inventory;
typedef struct xtr_win_ads_ops
{
  void *context;
  /* Snapshot current named $DATA streams into a secure caller-owned FILE.
   * Each item.offset must refer to this file. */
  int (*snapshot) (void *, FILE *, xtr_win_ads_inventory *);
  /* put replaces an existing named stream or creates a new one. */
  int (*put) (void *, const xtr_ads_name *, FILE *, long, unsigned long);
  int (*remove) (void *, const xtr_ads_name *);
  int (*equal_name) (void *, const xtr_ads_name *, const xtr_ads_name *);
} xtr_win_ads_ops;
void xtr_win_ads_inventory_free (xtr_win_ads_inventory *);
/* Returns XTR_OK only after exact readback; rollback_failed is ALWAYS set
 * if failed compensation cannot be fully verified. Not filesystem-atomic. */
int xtr_win_ads_apply_exact (const xtr_win_ads_ops *, const xtr_win_ads_part *,
                             unsigned, FILE *desired_stage,
                             FILE *secure_backup, int *rollback_failed);
#endif /* ifndef XTRWIN_ADS_TXN_H */
