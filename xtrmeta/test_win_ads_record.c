/* SPDX-License-Identifier: MIT-0 */
#include "xtrwin_ads_record.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, errors;
#define CHECK(expr)                                                           \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(expr))                                                            \
        {                                                                     \
          errors++;                                                           \
          fprintf (stderr, "fail line %d\n", __LINE__);                       \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct input
{
  unsigned long at, total;
  unsigned char salt;
} input;
typedef struct sink
{
  unsigned char *p;
  size_t n, cap;
} sink;
static size_t
supply (void *ctx, unsigned char *buf, size_t n)
{
  input *in = (input *)ctx;
  size_t i;

  if (n > in->total - in->at)
    {
      n = (size_t)(in->total - in->at);
    }

  for (i = 0; i < n; i++)
    {
      buf[i] = (unsigned char)(((in->at + i) * 31UL + in->salt) & 255U);
    }

  in->at += (unsigned long)n;
  return n;
}
static int
emit (void *ctx, const unsigned char *p, size_t n)
{
  sink *s = (sink *)ctx;
  unsigned char *next;
  size_t cap;

  if (n > (size_t)-1 - s->n)
    {
      return 1;
    }

  if (s->n + n > s->cap)
    {
      cap = s->cap ? s->cap : 4096U;
      while (cap < s->n + n)
        {
          if (cap > ((size_t)-1) / 2U)
            {
              return 1;
            }

          cap *= 2U;
        }
      next = (unsigned char *)realloc (s->p, cap);
      if (!next)
        {
          return 1;
        }

      s->p = next;
      s->cap = cap;
    }

  memcpy (s->p + s->n, p, n);
  s->n += n;
  return 0;
}
typedef struct rd
{
  const unsigned char *p;
  size_t n, pos;
} rd;
static size_t
consume (void *ctx, unsigned char *dst, size_t n)
{
  rd *r = (rd *)ctx;

  if (n > r->n - r->pos)
    {
      n = r->n - r->pos;
    }

  memcpy (dst, r->p + r->pos, n);
  r->pos += n;
  return n;
}
int
main (void)
{
  unsigned short a[] = { ':', 'a', ':', '$', 'D', 'A', 'T', 'A' };
  unsigned short b[] = { ':', 0x96ea, ':', '$', 'D', 'A', 'T', 'A' };
  xtr_ads_name names[2];
  xtr1_source src[2];
  unsigned char native[2][22];
  input inputs[2];
  xtr1_sink out;
  xtr1_policy policy;
  xtr1_digest dig, verified;
  xtr_extra outer;
  xtr_reader reader;
  unsigned char owner[16];
  sink s;
  rd r;

  memset (owner, 0x51, sizeof (owner));
  memset (&s, 0, sizeof (s));
  memset (&policy, 0, sizeof (policy));
  memset (&dig, 0, sizeof (dig));
  CHECK (xtr_ads_parse_stream (a, sizeof (a) / sizeof (a[0]), names)
         == XTR_ADS_OK);
  CHECK (xtr_ads_parse_stream (b, sizeof (b) / sizeof (b[0]), names + 1)
         == XTR_ADS_OK);
  inputs[0].at = 0;
  inputs[0].total = 0;
  inputs[0].salt = 7;
  inputs[1].at = 0;
  inputs[1].total = 2097152UL;
  inputs[1].salt = 9;
  {
    xtr_u64 n = { 0, 0 };
    CHECK (xtr_ads_record_source (&names[0], n, supply, &inputs[0], &src[0],
                                  native[0])
           == XTR_OK);
    n.lo = 2097152UL;
    CHECK (xtr_ads_record_source (&names[1], n, supply, &inputs[1], &src[1],
                                  native[1])
           == XTR_OK);
  }
  CHECK (src[0].record.type == 3U && src[0].record.origin == 7U
         && src[0].native[8] == 9U && src[0].native[18] == 0x80U);
  policy.max_records = 1024UL;
  policy.max_field = 4096UL;
  policy.max_manifest.lo = 128UL * 1024UL * 1024UL;
  out.context = &s;
  out.write = emit;
  CHECK (xtr1_write_manifest (owner, src, 2, 0, &policy, &out, &dig)
         == XTR_OK);
  CHECK (inputs[1].at == 2097152UL && s.n > 2097152U);
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, owner, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  memset (&r, 0, sizeof (r));
  r.p = s.p;
  r.n = s.n;
  memset (&reader, 0, sizeof (reader));
  reader.read = consume;
  reader.context = &r;
  CHECK (xtr1_check_manifest (&reader, outer.manifest_len, &outer, dig.sha256,
                              &policy, &verified)
         == XTR_OK);
  CHECK (verified.schema_supported && verified.count == 2UL);
  r.pos = 0;
  if (s.n > 100U)
    {
      s.p[s.n - 100U] ^= 1;
    }

  CHECK (xtr1_check_manifest (&reader, outer.manifest_len, &outer, dig.sha256,
                              &policy, &verified)
         != XTR_OK);
  names[0].utf8[0] = '?';
  {
    xtr_u64 n = { 0, 0 };
    CHECK (xtr_ads_record_source (&names[0], n, supply, &inputs[0], &src[0],
                                  native[0])
           == XTR_CORRUPT);
  }
  free (s.p);
  printf ("Windows ADS portable Xtro record tests: %u checks, %u failures\n",
          checks, errors);
  return errors ? 1 : 0;
}
