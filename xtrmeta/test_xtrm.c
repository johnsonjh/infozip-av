/* SPDX-License-Identifier: MIT-0 */
#include "xtrm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bufreader
{
  const unsigned char *p;
  size_t size, pos, seen;
  int records;
} bufreader;
static int failures = 0, checks = 0;
#define CHECK(expr)                                                           \
  do                                                                          \
    {                                                                         \
      ++checks;                                                               \
      if (!(expr))                                                            \
        {                                                                     \
          fprintf (stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
          ++failures;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)
static size_t
readbuf (void *opaque, unsigned char *p, size_t n)
{
  bufreader *b = (bufreader *)opaque;

  if (n > b->size - b->pos)
    {
      n = b->size - b->pos;
    }

  if (n > 11)
    {
      n = 11; /* deliberately fragmented input */
    }

  if (n)
    {
      memcpy (p, b->p + b->pos, n);
    }

  b->pos += n;
  return n;
}
static int
begin (void *opaque, const xtr_record *r)
{
  bufreader *b = (bufreader *)opaque;

  CHECK (r->origin == 1);
  ++b->records;
  return 0;
}
static int
data (void *opaque, const xtr_record *r, unsigned field,
      const unsigned char *p, size_t n)
{
  bufreader *b = (bufreader *)opaque;
  size_t i;

  (void)r;
  CHECK (field <= 3);
  for (i = 0; i < n; ++i)
    {
      b->seen += p[i] == 0xffU ? 2U : 1U;
    }

  return 0;
}
static xtr_u64
from_size (size_t n)
{
  xtr_u64 v;

  v.lo = (unsigned long)n;
  v.hi = 0;
  return v;
}
static void
run_parse (unsigned char *mem, size_t len, int expected)
{
  xtr_reader r;
  xtr_manifest m;
  bufreader b;
  int rc;

  memset (&r, 0, sizeof (r));
  memset (&b, 0, sizeof (b));
  b.p = mem;
  b.size = len;
  r.context = &b;
  r.read = readbuf;
  r.sink_context = &b;
  r.begin = begin;
  r.data = data;
  r.max_records = 100;
  r.max_field = 32768;
  r.max_total.lo = 0xffffffffUL;
  r.max_total.hi = 0;
  rc = xtr_parse_manifest (&r, from_size (len), &m);
  CHECK (rc == expected);
  if (rc == 0)
    {
      CHECK (b.pos == len);
    }
}
int
main (void)
{
  unsigned char b[200], h[36], rec[28], ef[200];
  xtr_manifest m;
  xtr_record r;
  xtr_extra x, y;
  size_t used, i;

  memset (&m, 0, sizeof (m));
  memset (&r, 0, sizeof (r));
  memset (&x, 0, sizeof (x));
  for (i = 0; i < 16; ++i)
    {
      m.owner[i] = (unsigned char)i;
    }

  m.count = 0;
  m.records_len = from_size (0);
  CHECK (xtr_manifest_header (h, &m) == XTR_OK);
  CHECK (memcmp (h, "XTMD\001\000\000\000", 8) == 0);
  CHECK (h[24] == 0 && h[28] == 0);
  memcpy (b, h, 36);
  run_parse (b, 36, XTR_OK);
  b[4] = 2;
  run_parse (b, 36, XTR_UNSUPPORTED);
  b[4] = 1;
  b[28] = 1;
  run_parse (b, 36, XTR_CORRUPT);
  b[28] = 0;
  m.count = 1;
  m.records_len = from_size (28 + 4 + 7 + 0 + 4);
  CHECK (xtr_manifest_header (b, &m) == XTR_OK);
  r.type = 1;
  r.origin = 1;
  r.encoding = 0;
  r.ns_len = 4;
  r.name_len = 7;
  r.native_len = 0;
  r.value_len = from_size (4);
  CHECK (xtr_record_header (rec, &r) == XTR_OK);
  memcpy (b + 36, rec, 28);
  memcpy (b + 64, "user", 4);
  memcpy (b + 68, "comment", 7);
  b[75] = 0;
  b[76] = 255;
  b[77] = 128;
  b[78] = 0;
  run_parse (b, 79, XTR_OK);
  b[76] = 1;
  run_parse (b, 79, XTR_OK);
  b[76] = 255;
  b[36 + 6] = 2; /* UTF16 name encoding with odd name byte count */
  run_parse (b, 79, XTR_CORRUPT);
  b[36 + 6] = 0;
  b[36 + 20] = 255; /* value length much bigger than available data */
  run_parse (b, 79, XTR_CORRUPT);
  b[36 + 20] = 4;
  run_parse (b, 78, XTR_CORRUPT);
  m.count = 0;
  m.records_len = from_size (0);
  CHECK (xtr_manifest_header (h, &m) == XTR_OK);
  x.mode = 1;
  x.count = 0;
  x.manifest_len = from_size (36);
  x.crc32 = xtr_crc32_update (0, h, 36);
  memcpy (x.owner, m.owner, 16);
  CHECK (xtr_extra_write (ef, &x, 0, NULL, 0, sizeof (ef), &used) == XTR_OK);
  CHECK (used == 40);
  CHECK (xtr_extra_read (ef, 40, 0, &y) == XTR_OK);
  CHECK (xtr_extra_write (ef, &x, 1, h, 36, sizeof (ef), &used) == XTR_OK);
  CHECK (used == 76);
  CHECK (xtr_extra_read (ef, used, 1, &y) == XTR_OK);
  ef[4] = 8;
  CHECK (xtr_extra_read (ef, used, 1, &y) == XTR_UNSUPPORTED);
  ef[4] = 1;
  ef[6] = 2;
  CHECK (xtr_extra_read (ef, used, 1, &y) == XTR_CORRUPT);
  CHECK (xtr_crc32_update (0, (const unsigned char *)"123456789", 9)
         == 0xcbf43926UL);
  CHECK (
      xtr_crc32_update (xtr_crc32_update (0, (const unsigned char *)"1234", 4),
                        (const unsigned char *)"56789", 5)
      == 0xcbf43926UL);
  /* High unsigned 64-bit bounds are decoded and rejected pre-read. */
  memcpy (b, h, 36);
  b[28] = 0xff;
  b[29] = 0xff;
  b[30] = 0xff;
  b[31] = 0xff;
  b[32] = 0xff;
  b[33] = 0xff;
  b[34] = 0xff;
  b[35] = 0xff;
  run_parse (b, 36, XTR_CORRUPT);
  /* Deterministic malformed byte mutation regression sweep. */
  for (i = 0; i < 36; ++i)
    {
      unsigned char saved = h[i];
      memcpy (b, h, 36);
      b[i] ^= 0xffU;
      /* owner bytes can vary without corruption: any 128-bit ID allowed */
      run_parse (
          b, 36,
          (i >= 8 && i < 24)
              ? XTR_OK
              : ((i == 4 || i == 5)
                     ? XTR_UNSUPPORTED
                     : ((i >= 24 && i < 28) ? XTR_LIMIT : XTR_CORRUPT)));
      h[i] = saved;
    }

  printf ("xtrm experimental C89 tests: %d checks, %d failures\n", checks,
          failures);
  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
