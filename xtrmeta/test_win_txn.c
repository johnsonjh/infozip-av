/* SPDX-License-Identifier: MIT-0 */
/* Native-EA transaction contract against independent mock NT operations. */
#include "xtrwin_txn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long checks = 0, failures = 0;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAILED line %d: %s\n", __LINE__, #x);             \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct fixture
{
  xtr_win_ea_list current;
  unsigned calls, reads;
  unsigned fail_on, half_fail_on;
  unsigned read_fail_on;
  int refuse_deletes;
} fixture;
static int
clone (const xtr_win_ea_list *in, xtr_win_ea_list *out)
{
  unsigned char *buf = NULL;
  size_t n = 0;
  int rc = xtr_win_ea_pack (in, &buf, &n);

  memset (out, 0, sizeof (*out));
  if (rc == XTR_OK)
    {
      rc = xtr_win_ea_parse (buf, n, out);
    }

  free (buf);
  return rc;
}
static unsigned
uppercase (unsigned c)
{
  return c >= 'a' && c <= 'z' ? c - 32 : c;
}
static int
eqname (const xtr_win_ea *a, const xtr_win_ea *b)
{
  size_t i;

  if (a->name_len != b->name_len)
    {
      return 0;
    }

  for (i = 0; i < a->name_len; i++)
    {
      if (uppercase (a->name[i]) != uppercase (b->name[i]))
        {
          return 0;
        }
    }

  return 1;
}
static int
itemeq (const xtr_win_ea *a, const xtr_win_ea *b)
{
  return eqname (a, b) && a->flags == b->flags && a->value_len == b->value_len
         && (!a->value_len || !memcmp (a->value, b->value, a->value_len));
}
static int
listeq (const xtr_win_ea_list *a, const xtr_win_ea_list *b)
{
  size_t i, j;
  int found;

  if (a->count != b->count)
    {
      return 0;
    }

  for (i = 0; i < a->count; i++)
    {
      found = 0;
      for (j = 0; j < b->count; j++)
        {
          if (itemeq (&a->items[i], &b->items[j]))
            {
              found = 1;
            }
        }

      if (!found)
        {
          return 0;
        }
    }

  return 1;
}
static int
snapshot (void *ctx, xtr_win_ea_list *out)
{
  fixture *f = (fixture *)ctx;

  f->reads++;
  memset (out, 0, sizeof (*out));
  if (f->read_fail_on && f->reads == f->read_fail_on)
    {
      return XTR_IO;
    }

  return clone (&f->current, out);
}
static int
change (void *ctx, const xtr_win_ea *item, int del)
{
  fixture *f = (fixture *)ctx;
  xtr_win_ea_list after, copy;
  xtr_win_ea *temp = NULL;
  size_t i, count = 0;
  int rc;

  f->calls++;
  if (del && f->refuse_deletes)
    {
      return XTR_IO;
    }

  if (f->fail_on == f->calls)
    {
      return XTR_IO;
    }

  memset (&after, 0, sizeof (after));
  temp = (xtr_win_ea *)calloc (f->current.count + 1U, sizeof (*temp));
  if (!temp)
    {
      return XTR_LIMIT;
    }

  for (i = 0; i < f->current.count; i++)
    {
      if (!eqname (&f->current.items[i], item))
        {
          temp[count++] = f->current.items[i];
        }
    }

  if (!del)
    {
      temp[count++] = *item;
    }

  after.count = count;
  after.items = temp;
  rc = clone (&after, &copy);
  free (temp);
  if (rc != XTR_OK)
    {
      return rc;
    }

  xtr_win_ea_free (&f->current);
  f->current = copy;
  if (f->half_fail_on == f->calls)
    {
      return XTR_IO;
    }

  return XTR_OK;
}
static void
make_item (xtr_win_ea *e, const char *name, unsigned char *val, size_t n,
           unsigned flags)
{
  memset (e, 0, sizeof (*e));
  e->name = (unsigned char *)name;
  e->name_len = strlen (name);
  e->value = val;
  e->value_len = n;
  e->flags = flags;
}
static void
seed (fixture *f, const xtr_win_ea_list *list)
{
  memset (f, 0, sizeof (*f));
  if (clone (list, &f->current) != XTR_OK)
    {
      fprintf (stderr, "seed failed\n");
      exit (1);
    }
}
static void
cleanup (fixture *f)
{
  xtr_win_ea_free (&f->current);
}
static int
run (fixture *f, const xtr_win_ea_list *target, int *rb)
{
  xtr_win_ea_ops ops;

  ops.context = f;
  ops.snapshot = snapshot;
  ops.change = change;
  return xtr_win_ea_apply_exact (&ops, target, rb);
}
int
main (void)
{
  unsigned char v1[] = { 0, 255, 1, 2 }, v2[] = { 5, 7, 9 }, v3[] = { 10 };
  xtr_win_ea initial[2], target[2], empty[1], duplicate[2];
  xtr_win_ea_list start, want, orig, zero, dup;
  fixture f;
  int rb, rc;
  unsigned i;

  make_item (&initial[0], "ALPHA", v1, sizeof (v1), 0);
  make_item (&initial[1], "STALE", v2, sizeof (v2), 128);
  start.items = initial;
  start.count = 2;
  make_item (&target[0], "alpha", v3, sizeof (v3), 0);
  make_item (&target[1], "NEW", v2, sizeof (v2), 128);
  want.items = target;
  want.count = 2;
  seed (&f, &start);
  rc = run (&f, &want, &rb);
  CHECK (rc == XTR_OK && !rb && listeq (&f.current, &want));
  CHECK (f.calls == 3U); /* stale delete, old value update, new add */
  rc = run (&f, &want, &rb);
  CHECK (rc == XTR_OK && !rb && f.calls == 3U); /* idempotent */
  cleanup (&f);
  seed (&f, &start);
  f.fail_on = 2;
  rc = run (&f, &want, &rb);
  CHECK (rc != XTR_OK && !rb && listeq (&f.current, &start));
  cleanup (&f);
  seed (&f, &start);
  f.half_fail_on = 2;
  rc = run (&f, &want, &rb);
  CHECK (rc != XTR_OK && !rb && listeq (&f.current, &start));
  cleanup (&f);
  seed (&f, &start);
  f.fail_on = 2;
  f.read_fail_on = 2;
  rc = run (&f, &want, &rb);
  CHECK (rc != XTR_OK && rb);
  cleanup (&f);
  seed (&f, &start);
  f.fail_on = 2;
  f.half_fail_on = 3;
  rc = run (&f, &want, &rb);
  CHECK (rc != XTR_OK && rb); /* rollback write failed after mutation */
  cleanup (&f);
  seed (&f, &start);
  f.read_fail_on = 1;
  rc = run (&f, &want, &rb);
  CHECK (rc != XTR_OK && !rb && !f.calls && listeq (&f.current, &start));
  cleanup (&f);
  seed (&f, &start);
  f.fail_on = 2;
  f.refuse_deletes = 1;
  rc = run (&f, &want, &rb);
  CHECK (rc != XTR_OK && !rb && listeq (&f.current, &start));
  cleanup (&f);
  make_item (&empty[0], "EMPTY", v1, 0, 0);
  zero.items = empty;
  zero.count = 1;
  seed (&f, &start);
  rc = run (&f, &zero, &rb);
  CHECK (rc == XTR_UNSUPPORTED && !rb && !f.calls
         && listeq (&f.current, &start));
  cleanup (&f);
  seed (&f, &zero);
  rc = run (&f, &want, &rb);
  CHECK (rc == XTR_UNSUPPORTED && !rb && !f.calls
         && listeq (&f.current, &zero));
  cleanup (&f);
  make_item (&duplicate[0], "Alpha", v1, 2, 0);
  make_item (&duplicate[1], "ALPHA", v2, 2, 0);
  dup.items = duplicate;
  dup.count = 2;
  seed (&f, &start);
  rc = run (&f, &dup, &rb);
  CHECK (rc == XTR_CORRUPT && !rb && !f.calls);
  cleanup (&f);
  /* Iterate failures through each reconciliation write (before + after
   * modifying state). Verify every rollback is exact. */
  for (i = 1; i <= 3U; i++)
    {
      seed (&f, &start);
      f.fail_on = i;
      rc = run (&f, &want, &rb);
      CHECK (rc != XTR_OK && !rb && listeq (&f.current, &start));
      cleanup (&f);
      seed (&f, &start);
      f.half_fail_on = i;
      rc = run (&f, &want, &rb);
      CHECK (rc != XTR_OK && !rb && listeq (&f.current, &start));
      cleanup (&f);
    }

  orig.items = initial;
  orig.count = 2;
  for (i = 0; i < 1000U; i++)
    {
      /* Randomized operation and write-failure placement by deterministic
       * arithmetic, reproducible under sanitizers. */
      seed (&f, &orig);
      f.fail_on = (i % 4U) + 1U;
      if ((i % 11U) == 0U)
        {
          f.half_fail_on = f.fail_on;
          f.fail_on = 0;
        }

      rc = run (&f, &want, &rb);
      if (f.fail_on == 4U || f.half_fail_on == 4U)
        {
          CHECK (rc == XTR_OK && !rb && listeq (&f.current, &want));
        }
      else
        {
          CHECK (rc != XTR_OK && !rb && listeq (&f.current, &start));
        }

      cleanup (&f);
    }

  printf ("Windows EA exact-replacement transaction: %lu checks; %lu failed\n",
          checks, failures);
  return failures ? 1 : 0;
}
