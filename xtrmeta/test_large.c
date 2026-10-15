/* SPDX-License-Identifier: MIT-0 */
/* Single 1MiB value generated during reading; zero full-value allocation. */
#include "xtrm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct generator
{
  unsigned char hdr[65];
  unsigned long pos;
  unsigned long value_n;
  unsigned long delivered;
};
static size_t
readgen (void *ctx, unsigned char *out, size_t n)
{
  struct generator *g = (struct generator *)ctx;
  unsigned long limit = 65UL + g->value_n;
  size_t count = 0;

  while (count < n && g->pos < limit)
    {
      if (g->pos < 65UL)
        {
          out[count] = g->hdr[g->pos];
        }
      else
        {
          out[count] = (unsigned char)((g->pos - 65UL) * 17UL + 3UL);
        }

      ++count;
      ++g->pos;
    }
  return count;
}
static int
on_chunk (void *ctx, const xtr_record *rec, unsigned field,
          const unsigned char *p, size_t n)
{
  struct generator *g = (struct generator *)ctx;
  size_t i;

  (void)rec;
  if (field != 3)
    {
      return 0;
    }

  for (i = 0; i < n; i++)
    {
      if (p[i] != (unsigned char)(g->delivered * 17UL + 3UL))
        {
          return 1;
        }

      ++g->delivered;
    }

  return 0;
}
static int
one (unsigned long value_n)
{
  struct generator g;
  xtr_manifest m, out;
  xtr_record rec;
  xtr_reader r;
  xtr_u64 total;
  int rc;

  memset (&g, 0, sizeof (g));
  memset (&m, 0, sizeof (m));
  memset (&rec, 0, sizeof (rec));
  memset (&r, 0, sizeof (r));
  g.value_n = value_n;
  m.count = 1;
  m.records_len.lo = 29UL + value_n;
  m.records_len.hi = 0;
  if (xtr_manifest_header (g.hdr, &m))
    {
      return 1;
    }

  rec.type = 1;
  rec.origin = 1;
  rec.name_len = 1;
  rec.value_len.lo = value_n;
  if (xtr_record_header (g.hdr + 36, &rec))
    {
      return 1;
    }

  g.hdr[64] = 'a';
  r.context = &g;
  r.read = readgen;
  r.sink_context = &g;
  r.data = on_chunk;
  r.max_records = 1;
  r.max_field = 100;
  r.max_total.lo = 0xffffffffUL;
  r.max_total.hi = 0;
  total.lo = 65UL + value_n;
  total.hi = 0;
  rc = xtr_parse_manifest (&r, total, &out);
  if (rc != 0 || g.delivered != value_n)
    {
      fprintf (stderr, "large parser failure: %lu bytes, rc=%d got=%lu\n",
               value_n, rc, g.delivered);
      return 1;
    }

  return 0;
}
int
main (void)
{
  if (one (65535UL) || one (65536UL) || one (1048576UL))
    {
      return EXIT_FAILURE;
    }

  puts (
      "Large streaming: 65535, 65536, and 1048576 byte values round-tripped");
  return EXIT_SUCCESS;
}
