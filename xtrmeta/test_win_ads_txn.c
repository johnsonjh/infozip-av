/* SPDX-License-Identifier: MIT-0 */
/* Deterministic native-independent ADS transaction and failure mock. */
#include "xtrwin_ads.h"
#include "xtrwin_ads_txn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MT_CAP 5U
static unsigned checks, failures;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          failures++;                                                         \
          fprintf (stderr, "FAIL at %d: %s\n", __LINE__, #x);                 \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct mock_entry
{
  xtr_ads_name name;
  unsigned char *value;
  size_t len;
} mock_entry;
typedef struct mock_state
{
  mock_entry e[MT_CAP];
  unsigned count;
  unsigned actions, snapshots;
  unsigned fail_action, fail_rollback;
} mock_state;
static int
equal (void *v, const xtr_ads_name *a, const xtr_ads_name *b)
{
  size_t i;

  (void)v;
  if (a->utf16_len != b->utf16_len)
    {
      return 0;
    }

  for (i = 0; i < a->utf16_len; i++)
    {
      unsigned x = a->utf16[i], y = b->utf16[i];
      if (x >= 'a' && x <= 'z')
        {
          x -= 'a' - 'A';
        }

      if (y >= 'a' && y <= 'z')
        {
          y -= 'a' - 'A';
        }

      if (x != y)
        {
          return 0;
        }
    }

  return 1;
}
static int
find (mock_state *m, const xtr_ads_name *n)
{
  unsigned i;

  for (i = 0; i < m->count; i++)
    {
      if (equal (m, &m->e[i].name, n))
        {
          return (int)i;
        }
    }

  return -1;
}
static int
name_set (xtr_ads_name *n, const unsigned short *p, size_t len)
{
  unsigned short raw[80];
  size_t i;

  if (len > 64U)
    {
      return 0;
    }

  raw[0] = ':';
  for (i = 0; i < len; i++)
    {
      raw[i + 1U] = p[i];
    }

  raw[len + 1U] = ':';
  raw[len + 2U] = '$';
  raw[len + 3U] = 'D';
  raw[len + 4U] = 'A';
  raw[len + 5U] = 'T';
  raw[len + 6U] = 'A';
  return xtr_ads_parse_stream (raw, len + 7U, n) == XTR_ADS_OK;
}
static int
put (void *v, const xtr_ads_name *n, FILE *f, long at, unsigned long len)
{
  mock_state *m = (mock_state *)v;
  mock_entry *e;
  unsigned char *buf;
  int index;

  m->actions++;
  index = find (m, n);
  if (index < 0 && m->count >= MT_CAP)
    {
      return XTR_LIMIT;
    }

  buf = (unsigned char *)malloc (len ? len : 1U);
  if (!buf)
    {
      return XTR_LIMIT;
    }

  if (fseek (f, at, SEEK_SET) != 0
      || fread (buf, 1, (size_t)len, f) != (size_t)len)
    {
      free (buf);
      return XTR_IO;
    }

  if (index < 0)
    {
      index = (int)m->count++;
      memset (&m->e[index], 0, sizeof (m->e[index]));
    }

  e = &m->e[index];
  free (e->value);
  e->value = buf;
  e->len = len;
  e->name = *n;
  /* Mimic an API that returns failure AFTER modifying the target. */
  return (m->fail_action && m->actions == m->fail_action)
                 || (m->fail_rollback && m->actions >= m->fail_rollback)
             ? XTR_IO
             : XTR_OK;
}
static int
erase (void *v, const xtr_ads_name *n)
{
  mock_state *m = (mock_state *)v;
  int at = find (m, n);

  m->actions++;
  if (at < 0)
    {
      return XTR_IO;
    }

  free (m->e[at].value);
  m->e[at] = m->e[--m->count];
  return (m->fail_action && m->actions == m->fail_action)
                 || (m->fail_rollback && m->actions >= m->fail_rollback)
             ? XTR_IO
             : XTR_OK;
}
static int
snapshot (void *v, FILE *stage, xtr_win_ads_inventory *inv)
{
  mock_state *m = (mock_state *)v;
  unsigned i;

  m->snapshots++;
  inv->count = 0;
  inv->items = (xtr_win_ads_part *)calloc (m->count ? m->count : 1U,
                                           sizeof (*inv->items));
  if (!inv->items)
    {
      return XTR_LIMIT;
    }

  if (fseek (stage, 0, SEEK_END) != 0)
    {
      return XTR_IO;
    }

  for (i = 0; i < m->count; i++)
    {
      long off = ftell (stage);
      if (off < 0
          || fwrite (m->e[i].value, 1, m->e[i].len, stage) != m->e[i].len)
        {
          return XTR_IO;
        }

      inv->items[i].name = m->e[i].name;
      inv->items[i].length = (unsigned long)m->e[i].len;
      inv->items[i].offset = off;
      inv->count++;
    }

  return fflush (stage) == 0 ? XTR_OK : XTR_IO;
}
static void
clear (mock_state *m)
{
  unsigned i;

  for (i = 0; i < m->count; i++)
    {
      free (m->e[i].value);
    }

  memset (m, 0, sizeof (*m));
}
static int
setup (mock_state *m, xtr_ads_name *a, xtr_ads_name *old, xtr_ads_name *snow)
{
  static const unsigned short A[] = { 'a', 'l', 'p', 'h', 'a' };
  static const unsigned short OLD[] = { 'o', 'l', 'd' };
  static const unsigned short SNOW[] = { 0x96ea, 'x' };
  FILE *f = tmpfile ();
  int ok = 0;

  if (!f)
    {
      return 0;
    }

  memset (m, 0, sizeof (*m));
  if (!name_set (a, A, 5) || !name_set (old, OLD, 3)
      || !name_set (snow, SNOW, 2))
    {
      goto done;
    }

  if (fwrite ("abc123", 1, 6, f) != 6 || fseek (f, 0, SEEK_SET) != 0
      || put (m, a, f, 0, 6) != XTR_OK || put (m, old, f, 0, 3) != XTR_OK)
    {
      goto done;
    }

  m->actions = 0;
  ok = 1;
done:
  fclose (f);
  return ok;
}
static int
evaluate (mock_state *m, const xtr_ads_name *a, const xtr_ads_name *old,
          const xtr_ads_name *snow, int changed)
{
  int ia = find (m, a), io = find (m, old), is = find (m, snow);

  return changed
             ? (ia >= 0 && io < 0 && is >= 0 && m->e[ia].len == 4
                && !memcmp (m->e[ia].value, "NEWW", 4) && m->e[is].len == 0)
             : (ia >= 0 && io >= 0 && is < 0 && m->e[ia].len == 6
                && !memcmp (m->e[ia].value, "abc123", 6));
}
static void
exercise (unsigned fail, unsigned fail_rollback)
{
  xtr_ads_name a, old, snow;
  xtr_win_ads_part requested[2];
  mock_state m;
  xtr_win_ads_ops ops;
  FILE *wanted = tmpfile (), *backup = tmpfile ();
  int rc, rolled = 0;

  CHECK (wanted != NULL && backup != NULL);
  if (!wanted || !backup)
    {
      return;
    }

  CHECK (setup (&m, &a, &old, &snow));
  memset (&ops, 0, sizeof (ops));
  ops.context = &m;
  ops.snapshot = snapshot;
  ops.put = put;
  ops.remove = erase;
  ops.equal_name = equal;
  CHECK (fwrite ("NEWW", 1, 4, wanted) == 4);
  memset (requested, 0, sizeof (requested));
  requested[0].name = a;
  requested[0].length = 4;
  requested[0].offset = 0;
  requested[1].name = snow;
  requested[1].length = 0;
  requested[1].offset = 4;
  m.fail_action = fail;
  m.fail_rollback = fail_rollback;
  rc = xtr_win_ads_apply_exact (&ops, requested, 2, wanted, backup, &rolled);
  if (!fail)
    {
      CHECK (rc == XTR_OK && !rolled);
      CHECK (evaluate (&m, &a, &old, &snow, 1));
      CHECK (
          xtr_win_ads_apply_exact (&ops, requested, 2, wanted, backup, &rolled)
          == XTR_OK);
      CHECK (evaluate (&m, &a, &old, &snow, 1));
    }
  else
    {
      CHECK (rc != XTR_OK);
      if (!fail_rollback)
        {
          CHECK (!rolled);
          CHECK (evaluate (&m, &a, &old, &snow, 0));
        }
      else
        {
          CHECK (rolled != 0);
        }
    }

  requested[1].name = a;
  rolled = 0;
  CHECK (xtr_win_ads_apply_exact (&ops, requested, 2, wanted, backup, &rolled)
         != XTR_OK);
  clear (&m);
  fclose (wanted);
  fclose (backup);
}
int
main (void)
{
  exercise (0, 0);
  exercise (1, 0);
  exercise (2, 0);
  exercise (2, 3);
  printf ("Windows ADS exact transaction mock: %u checks, %u failed\n", checks,
          failures);
  return failures != 0;
}
