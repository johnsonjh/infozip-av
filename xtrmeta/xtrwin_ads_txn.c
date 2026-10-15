/* SPDX-License-Identifier: MIT-0 */
#include "xtrwin_ads_txn.h"
#include <stdlib.h>
#include <string.h>
#define XAT_MAX 128U
#define XAT_MAX_BYTES (32UL * 1024UL * 1024UL)
void
xtr_win_ads_inventory_free (xtr_win_ads_inventory *a)
{
  if (a)
    {
      free (a->items);
      a->items = NULL;
      a->count = 0;
    }
}
static int
xat_find (const xtr_win_ads_ops *ops, const xtr_win_ads_part *a,
          unsigned count, const xtr_ads_name *n)
{
  unsigned i;

  for (i = 0; i < count; i++)
    {
      if (ops->equal_name (ops->context, &a[i].name, n))
        {
          return (int)i;
        }
    }

  return -1;
}
static int
xat_valid (const xtr_win_ads_ops *ops, const xtr_win_ads_part *a,
           unsigned count)
{
  unsigned i, j;
  unsigned long total = 0;

  if (count > XAT_MAX || (count && !a))
    {
      return 0;
    }

  for (i = 0; i < count; i++)
    {
      if (a[i].offset < 0 || !a[i].name.utf16_len
          || a[i].name.utf16_len > XTR_ADS_MAX_NAME
          || a[i].length > XAT_MAX_BYTES - total)
        {
          return 0;
        }

      total += a[i].length;
      for (j = 0; j < i; j++)
        {
          if (ops->equal_name (ops->context, &a[i].name, &a[j].name))
            {
              return 0;
            }
        }
    }

  return 1;
}
static int
xat_file_equal (FILE *a, long apos, FILE *b, long bpos, unsigned long n)
{
  unsigned char av[8192], bv[8192];

  if (a != b
      && (fseek (a, apos, SEEK_SET) != 0 || fseek (b, bpos, SEEK_SET) != 0))
    {
      return 0;
    }

  while (n)
    {
      size_t take = n > sizeof (av) ? sizeof (av) : (size_t)n;
      if (a == b)
        {
          if (fseek (a, apos, SEEK_SET) != 0 || fread (av, 1, take, a) != take
              || fseek (b, bpos, SEEK_SET) != 0
              || fread (bv, 1, take, b) != take)
            {
              return 0;
            }
        }
      else if (fread (av, 1, take, a) != take
               || fread (bv, 1, take, b) != take)
        {
          return 0;
        }

      if (memcmp (av, bv, take))
        {
          return 0;
        }

      apos += (long)take;
      bpos += (long)take;
      n -= (unsigned long)take;
    }
  return 1;
}
static int
xat_equivalent (const xtr_win_ads_ops *ops, const xtr_win_ads_part *a,
                unsigned na, FILE *af, const xtr_win_ads_part *b, unsigned nb,
                FILE *bf)
{
  unsigned i;
  int j;

  if (na != nb)
    {
      return 0;
    }

  for (i = 0; i < na; i++)
    {
      j = xat_find (ops, b, nb, &a[i].name);
      if (j < 0 || a[i].length != b[j].length
          || !xat_file_equal (af, a[i].offset, bf, b[j].offset, a[i].length))
        {
          return 0;
        }
    }

  return 1;
}
static int
xat_reconcile (const xtr_win_ads_ops *ops, const xtr_win_ads_part *cur,
               unsigned nc, FILE *current_stage,
               const xtr_win_ads_part *target, unsigned nt, FILE *target_stage)
{
  unsigned i;
  int found;

  for (i = 0; i < nc; i++)
    {
      if (xat_find (ops, target, nt, &cur[i].name) < 0)
        {
          if (ops->remove (ops->context, &cur[i].name) != XTR_OK)
            {
              return XTR_IO;
            }
        }
    }

  for (i = 0; i < nt; i++)
    {
      found = xat_find (ops, cur, nc, &target[i].name);
      if (found >= 0 && cur[found].length == target[i].length
          && xat_file_equal (current_stage, cur[found].offset, target_stage,
                             target[i].offset, target[i].length))
        {
          continue;
        }

      if (ops->put (ops->context, &target[i].name, target_stage,
                    target[i].offset, target[i].length)
          != XTR_OK)
        {
          return XTR_IO;
        }
    }

  return XTR_OK;
}
int
xtr_win_ads_apply_exact (const xtr_win_ads_ops *ops,
                         const xtr_win_ads_part *wanted, unsigned nw,
                         FILE *wanted_stage, FILE *backup,
                         int *rollback_failed)
{
  xtr_win_ads_inventory orig, now, after;
  int rc = XTR_CORRUPT, rr, mutated = 0;

  if (rollback_failed)
    {
      *rollback_failed = 0;
    }

  if (!ops || !ops->snapshot || !ops->put || !ops->remove || !ops->equal_name
      || !wanted_stage || !backup || !rollback_failed
      || !xat_valid (ops, wanted, nw))
    {
      return XTR_CORRUPT;
    }

  memset (&orig, 0, sizeof (orig));
  memset (&now, 0, sizeof (now));
  memset (&after, 0, sizeof (after));
  if (fseek (backup, 0, SEEK_SET) != 0)
    {
      return XTR_IO;
    }

  rc = ops->snapshot (ops->context, backup, &orig);
  if (rc != XTR_OK)
    {
      goto done;
    }

  if (!xat_valid (ops, orig.items, orig.count))
    {
      rc = XTR_CORRUPT;
      goto done;
    }

  if (xat_equivalent (ops, orig.items, orig.count, backup, wanted, nw,
                      wanted_stage))
    {
      rc = XTR_OK;
      goto done;
    }

  mutated = 1; /* A failing native operation may already have changed state. */
  rc = xat_reconcile (ops, orig.items, orig.count, backup, wanted, nw,
                      wanted_stage);
  if (rc == XTR_OK)
    {
      if (fseek (backup, 0, SEEK_END) != 0)
        {
          rc = XTR_IO;
          goto rollback;
        }

      rc = ops->snapshot (ops->context, backup, &now);
      if (rc == XTR_OK && !xat_valid (ops, now.items, now.count))
        {
          rc = XTR_CORRUPT;
        }

      if (rc == XTR_OK
          && !xat_equivalent (ops, now.items, now.count, backup, wanted, nw,
                              wanted_stage))
        {
          rc = XTR_IO;
        }
    }

rollback:
  if (rc != XTR_OK && mutated)
    {
      xtr_win_ads_inventory_free (&now);
      if (fseek (backup, 0, SEEK_END) != 0)
        {
          *rollback_failed = 1;
          goto done;
        }

      rr = ops->snapshot (ops->context, backup, &now);
      if (rr == XTR_OK && xat_valid (ops, now.items, now.count))
        {
          rr = xat_reconcile (ops, now.items, now.count, backup, orig.items,
                              orig.count, backup);
        }
      else
        {
          rr = XTR_IO;
        }

      if (rr == XTR_OK)
        {
          if (fseek (backup, 0, SEEK_END) != 0)
            {
              rr = XTR_IO;
            }
          else
            {
              rr = ops->snapshot (ops->context, backup, &after);
            }

          if (rr == XTR_OK
              && (!xat_valid (ops, after.items, after.count)
                  || !xat_equivalent (ops, after.items, after.count, backup,
                                      orig.items, orig.count, backup)))
            {
              rr = XTR_IO;
            }
        }

      if (rr != XTR_OK)
        {
          *rollback_failed = 1;
        }
    }

done:
  xtr_win_ads_inventory_free (&after);
  xtr_win_ads_inventory_free (&now);
  xtr_win_ads_inventory_free (&orig);
  return rc;
}
