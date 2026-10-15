/* SPDX-License-Identifier: MIT-0 */
/* Fail-closed, separately mockable Windows native EA transaction layer.
 * An NtSetEaFile buffer containing a zero-length value DELETES that EA.
 * This implementation refuses empty-value targets and original snapshots
 * rather than converting preservation to deletion silently. */
#include "xtrwin_txn.h"
#include <stdlib.h>
#include <string.h>

static unsigned
xwt_up (unsigned ch)
{
  return ch >= 'a' && ch <= 'z' ? ch - ('a' - 'A') : ch;
}
static int
xwt_name_equal (const xtr_win_ea *a, const xtr_win_ea *b)
{
  size_t i;

  if (a->name_len != b->name_len)
    {
      return 0;
    }

  for (i = 0; i < a->name_len; i++)
    {
      if (xwt_up (a->name[i]) != xwt_up (b->name[i]))
        {
          return 0;
        }
    }

  return 1;
}
static const xtr_win_ea *
xwt_find (const xtr_win_ea_list *a, const xtr_win_ea *item)
{
  size_t i;

  for (i = 0; i < a->count; i++)
    {
      if (xwt_name_equal (&a->items[i], item))
        {
          return &a->items[i];
        }
    }

  return NULL;
}
static int
xwt_same_entry (const xtr_win_ea *a, const xtr_win_ea *b)
{
  return a && b && xwt_name_equal (a, b) && a->flags == b->flags
         && a->value_len == b->value_len
         && (!a->value_len || !memcmp (a->value, b->value, a->value_len));
}
static int
xwt_equal (const xtr_win_ea_list *a, const xtr_win_ea_list *b)
{
  size_t i;

  if (a->count != b->count)
    {
      return 0;
    }

  for (i = 0; i < a->count; i++)
    {
      if (!xwt_same_entry (&a->items[i], xwt_find (b, &a->items[i])))
        {
          return 0;
        }
    }

  return 1;
}
/* Round-trip the trusted input through the bounded W1 format validator.
 * Also obtains a self-contained immutable snapshot, independent of the
 * caller and the native backend. */
static int
xwt_copy (const xtr_win_ea_list *in, xtr_win_ea_list *out)
{
  unsigned char *raw = NULL;
  size_t len = 0;
  int rc;

  memset (out, 0, sizeof (*out));
  rc = xtr_win_ea_pack (in, &raw, &len);
  if (rc != XTR_OK)
    {
      return rc;
    }

  rc = xtr_win_ea_parse (raw, len, out);
  free (raw);
  return rc;
}
static int
xwt_empty (const xtr_win_ea_list *a)
{
  size_t i;

  for (i = 0; i < a->count; i++)
    {
      if (a->items[i].value_len == 0)
        {
          return 1;
        }
    }

  return 0;
}
/* Updates and deletes are separate operations. On partial failure we
 * query again before compensating, including after a failing native call:
 * the call may have modified the filesystem despite returning failure. */
static int
xwt_reconcile (const xtr_win_ea_ops *ops, const xtr_win_ea_list *present,
               const xtr_win_ea_list *target)
{
  size_t i;
  const xtr_win_ea *other;

  for (i = 0; i < present->count; i++)
    {
      other = xwt_find (target, &present->items[i]);
      if (!other
          && ops->change (ops->context, &present->items[i], 1) != XTR_OK)
        {
          return XTR_IO;
        }
    }

  for (i = 0; i < target->count; i++)
    {
      other = xwt_find (present, &target->items[i]);
      if (!xwt_same_entry (other, &target->items[i])
          && ops->change (ops->context, &target->items[i], 0) != XTR_OK)
        {
          return XTR_IO;
        }
    }

  return XTR_OK;
}
int
xtr_win_ea_apply_exact (const xtr_win_ea_ops *ops,
                        const xtr_win_ea_list *desired, int *rollback_failed)
{
  xtr_win_ea_list target, original, observed, after;
  int rc, mutated = 0, rollback_rc = XTR_IO;

  if (rollback_failed)
    {
      *rollback_failed = 0;
    }

  if (!ops || !ops->snapshot || !ops->change || !desired || !rollback_failed)
    {
      return XTR_CORRUPT;
    }

  memset (&target, 0, sizeof (target));
  memset (&original, 0, sizeof (original));
  memset (&observed, 0, sizeof (observed));
  memset (&after, 0, sizeof (after));
  rc = xwt_copy (desired, &target);
  if (rc != XTR_OK)
    {
      goto done;
    }

  if (xwt_empty (&target))
    {
      rc = XTR_UNSUPPORTED;
      goto done;
    }

  rc = ops->snapshot (ops->context, &observed);
  if (rc != XTR_OK)
    {
      goto done;
    }

  rc = xwt_copy (&observed, &original);
  xtr_win_ea_free (&observed);
  if (rc != XTR_OK)
    {
      goto done;
    }

  if (xwt_empty (&original))
    {
      rc = XTR_UNSUPPORTED;
      goto done;
    }

  if (xwt_equal (&original, &target))
    {
      rc = XTR_OK;
      goto done;
    }

  mutated = 1; /* a failing write may still mutate state */
  rc = xwt_reconcile (ops, &original, &target);
  if (rc == XTR_OK)
    {
      rc = ops->snapshot (ops->context, &observed);
      if (rc == XTR_OK && !xwt_equal (&observed, &target))
        {
          rc = XTR_IO;
        }

      xtr_win_ea_free (&observed);
    }

  if (rc != XTR_OK && mutated)
    {
      int rr = ops->snapshot (ops->context, &after);
      if (rr == XTR_OK)
        {
          /* If unexpected empty-value attributes appeared, deleting
           * them is still necessary when they did not exist originally;
           * however restoration of an originally empty EA was already
           * refused in preflight. */
          rr = xwt_reconcile (ops, &after, &original);
          xtr_win_ea_free (&after);
          if (rr == XTR_OK)
            {
              rr = ops->snapshot (ops->context, &observed);
              if (rr == XTR_OK && !xwt_equal (&observed, &original))
                {
                  rr = XTR_IO;
                }

              xtr_win_ea_free (&observed);
            }
        }

      rollback_rc = rr;
      if (rollback_rc != XTR_OK)
        {
          *rollback_failed = 1;
        }
    }

done:
  xtr_win_ea_free (&after);
  xtr_win_ea_free (&observed);
  xtr_win_ea_free (&original);
  xtr_win_ea_free (&target);
  return rc;
}
