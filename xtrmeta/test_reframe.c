/* SPDX-License-Identifier: MIT-0 */
/* Portable M6E2 decoded-companion reframe contract regression (C89). */
#include "xtrv1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long checks, errors;
#define T(cond)                                                               \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(cond))                                                            \
        {                                                                     \
          errors++;                                                           \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #cond);            \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct bytes
{
  unsigned char *p;
  size_t len, cap, pos, short_at, write_fail;
  unsigned resets;
  int reset_fail, mutate_at_reset;
} bytes;
static void
release (bytes *b)
{
  free (b->p);
  memset (b, 0, sizeof (*b));
}
static int
append (void *v, const unsigned char *p, size_t n)
{
  bytes *b = (bytes *)v;
  size_t size;
  unsigned char *newp;

  if (n > (size_t)-1 - b->len)
    {
      return 1;
    }

  if (b->write_fail && b->len + n > b->write_fail)
    {
      return 1;
    }

  if (b->len + n > b->cap)
    {
      size = b->cap ? b->cap : 128U;
      while (size < b->len + n)
        {
          if (size > (size_t)-1 / 2U)
            {
              return 1;
            }

          size *= 2U;
        }
      newp = (unsigned char *)realloc (b->p, size);
      if (!newp)
        {
          return 1;
        }

      b->p = newp;
      b->cap = size;
    }

  if (n)
    {
      memcpy (b->p + b->len, p, n);
    }

  b->len += n;
  return 0;
}
static size_t
pull (void *v, unsigned char *p, size_t n)
{
  bytes *b = (bytes *)v;

  if (b->short_at && b->pos >= b->short_at)
    {
      return 0;
    }

  if (b->pos > b->len)
    {
      return 0;
    }

  if (n > b->len - b->pos)
    {
      n = b->len - b->pos;
    }

  if (n > 29U)
    {
      n = 29U;
    }

  if (b->short_at && n > b->short_at - b->pos)
    {
      n = b->short_at - b->pos;
    }

  if (n)
    {
      memcpy (p, b->p + b->pos, n);
    }

  b->pos += n;
  return n;
}
static int
reset_reader (void *v)
{
  bytes *b = (bytes *)v;

  if (b->reset_fail)
    {
      return 1;
    }

  b->resets++;
  b->pos = 0;
  if (b->mutate_at_reset && b->len > 90U)
    {
      b->p[90U] ^= 1;
    }

  return 0;
}
typedef struct pattern
{
  size_t left, pos;
} pattern;
static size_t
source_data (void *v, unsigned char *p, size_t n)
{
  pattern *s = (pattern *)v;
  size_t i;

  if (n > s->left)
    {
      n = s->left;
    }

  if (n > 47U)
    {
      n = 47U;
    }

  for (i = 0; i < n; i++)
    {
      p[i] = (unsigned char)(((s->pos + i) * 17U + 19U) & 255U);
    }

  s->pos += n;
  s->left -= n;
  return n;
}
static xtr_u64
sizepair (size_t n)
{
  xtr_u64 x;

  x.lo = (unsigned long)(n & 0xffffffffUL);
  x.hi = (unsigned long)(((unsigned long)n >> 16) >> 16);
  return x;
}
static void
makepolicy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = 200U;
  p->max_field = 1048576UL;
  p->max_manifest.lo = 8UL * 1024UL * 1024UL;
}
static void
extra_for (const unsigned char id[16], const xtr1_digest *d, int encrypted,
           xtr_extra *e)
{
  memset (e, 0, sizeof (*e));
  memcpy (e->owner, id, 16);
  e->mode = XTR_V1_COMPANION;
  e->flags = encrypted ? XTR_V1_ENCRYPTED : 0;
  if (!encrypted)
    {
      e->count = d->count;
      e->manifest_len = d->manifest_length;
      e->crc32 = d->crc32;
    }
}
static int
checkpayload (bytes *b, const xtr_extra *e, const unsigned char *sha,
              const xtr1_policy *p)
{
  xtr_reader r;
  xtr1_digest d;

  memset (&r, 0, sizeof (r));
  r.read = pull;
  r.context = b;
  b->pos = 0;
  return xtr1_check_manifest (&r, sizepair (b->len), e, sha, p, &d);
}
static int
convert (bytes *in, const xtr_extra *e, const unsigned char *sha,
         const xtr1_policy *p, int to_encrypted, bytes *out, xtr_extra *new_e,
         xtr1_digest *dig)
{
  xtr_reader r;
  xtr1_sink sink;

  memset (&r, 0, sizeof (r));
  r.context = in;
  r.read = pull;
  sink.context = out;
  sink.write = append;
  in->pos = 0;
  return xtr1_reframe_companion (&r, sizepair (in->len), e, sha, p,
                                 reset_reader, in, &sink, to_encrypted, new_e,
                                 dig);
}
static void
rundata (size_t n)
{
  unsigned char id[16], tlv[10], loc[80], cen[130], sha[32];
  xtr1_source one;
  xtr1_policy p;
  xtr1_sink writer;
  xtr1_digest original, after, again;
  xtr_extra pub, enc, back, decoded;
  bytes plain, secret, public_again, out;
  pattern v;
  size_t at, ln, cn;
  int rc;

  memset (&plain, 0, sizeof (plain));
  memset (&secret, 0, sizeof (secret));
  memset (&public_again, 0, sizeof (public_again));
  memset (&out, 0, sizeof (out));
  makepolicy (&p);
  for (at = 0; at < 16U; at++)
    {
      id[at] = (unsigned char)(at + 1U);
    }

  memset (&one, 0, sizeof (one));
  memset (tlv, 0, sizeof (tlv));
  one.record.type = 1U;
  one.record.origin = 1U;
  one.record.name_len = 11U;
  one.record.ns_len = 4U;
  one.record.native_len = 10U;
  one.record.value_len = sizepair (n);
  one.ns = (const unsigned char *)"user";
  one.name = (const unsigned char *)"example.bin";
  tlv[0] = 1U;
  tlv[4] = 2U;
  tlv[8] = 1U;
  one.native = tlv;
  v.left = n;
  v.pos = 0;
  one.read_value = source_data;
  one.value_context = &v;
  writer.context = &plain;
  writer.write = append;
  T (xtr1_write_manifest (id, &one, 1, 0, &p, &writer, &original) == XTR_OK);
  extra_for (id, &original, 0, &pub);
  T (checkpayload (&plain, &pub, original.sha256, &p) == XTR_OK);
  rc = convert (&plain, &pub, original.sha256, &p, 1, &secret, &enc, &after);
  T (rc == XTR_OK);
  T (secret.len == plain.len + 36U);
  T (enc.mode == XTR_V1_COMPANION && enc.flags == 1U);
  T (enc.count == 0 && enc.crc32 == 0 && enc.manifest_len.lo == 0);
  T (!memcmp (secret.p, plain.p, plain.len));
  T (!memcmp (secret.p + plain.len, "XTCS", 4));
  T (!memcmp (secret.p + plain.len + 4U, original.sha256, 32U));
  T (checkpayload (&secret, &enc, NULL, &p) == XTR_OK);
  T (convert (&secret, &enc, NULL, &p, 0, &public_again, &back, &again)
     == XTR_OK);
  T (public_again.len == plain.len);
  T (!memcmp (public_again.p, plain.p, plain.len));
  T (!memcmp (again.sha256, original.sha256, 32));
  T (!memcmp (back.owner, id, 16) && back.flags == 0);
  T (back.count == original.count && back.crc32 == original.crc32);
  T (xtr1_extra_encode (loc, sizeof (loc), &back, 0, NULL, 0, NULL, &ln)
     == XTR_OK);
  T (xtr1_extra_encode (cen, sizeof (cen), &back, 1, NULL, 0, again.sha256,
                        &cn)
     == XTR_OK);
  T (xtr1_check_headers (loc, ln, cen, cn, &decoded, sha) == XTR_OK);
  T (checkpayload (&public_again, &decoded, sha, &p) == XTR_OK);
  if (n == 65536U)
    {
      bytes corrupted, remade;
      xtr_extra saved;
      xtr1_digest dummyd;
      memset (&corrupted, 0, sizeof (corrupted));
      memset (&remade, 0, sizeof (remade));
      T (append (&corrupted, secret.p, secret.len) == 0);
      corrupted.p[corrupted.len - 1] ^= 1U;
      saved = back;
      T (convert (&corrupted, &enc, NULL, &p, 0, &remade, &back, &dummyd)
         == XTR_CORRUPT);
      T (remade.len == 0);
      T (!memcmp (&back, &saved, sizeof (back)));
      release (&corrupted);
      release (&remade);
      /* A public digest mismatch must fail before any staged write. */
      {
        unsigned char wrong_sha[32];
        memcpy (wrong_sha, original.sha256, 32);
        wrong_sha[5] ^= 1U;
        T (convert (&plain, &pub, wrong_sha, &p, 1, &out, &back, &again)
           == XTR_CORRUPT);
        T (out.len == 0);
      }
      /* The input owner identity is authenticated by the manifest bytes. */
      {
        xtr_extra wrong_owner = pub;
        wrong_owner.owner[0] ^= 1U;
        T (convert (&plain, &wrong_owner, original.sha256, &p, 1, &out, &back,
                    &again)
           == XTR_CORRUPT);
        T (out.len == 0);
      }
      /* Bit-flip a value and verify SHA catches it even when framing and
       * XML-like record headers are unchanged. */
      plain.p[plain.len - 5U] ^= 1U;
      T (convert (&plain, &pub, original.sha256, &p, 1, &out, &back, &again)
         == XTR_CORRUPT);
      T (out.len == 0);
      plain.p[plain.len - 5U] ^= 1U;
      out.write_fail = 80U;
      T (convert (&plain, &pub, original.sha256, &p, 1, &out, &back, &again)
         == XTR_IO);
      release (&out);
      plain.mutate_at_reset = 1;
      T (convert (&plain, &pub, original.sha256, &p, 1, &out, &back, &again)
         == XTR_CORRUPT);
      T (out.len > 0); /* caller MUST discard staged partial output */
      plain.mutate_at_reset = 0;
      plain.p[90U] ^= 1U;
      release (&out);
      plain.reset_fail = 1;
      T (convert (&plain, &pub, original.sha256, &p, 1, &out, &back, &again)
         == XTR_IO);
      T (out.len == 0);
      plain.reset_fail = 0;
      plain.short_at = 50U;
      T (convert (&plain, &pub, original.sha256, &p, 1, &out, &back, &again)
         == XTR_IO);
      T (out.len == 0);
      plain.short_at = 0;
      p.max_manifest.lo = 128UL;
      T (convert (&plain, &pub, original.sha256, &p, 1, &out, &back, &again)
         == XTR_LIMIT);
      T (out.len == 0);
    }

  if (n == 4U)
    {
      xtr_extra inline_e;
      inline_e = pub;
      inline_e.mode = XTR_V1_INLINE;
      release (&out);
      T (convert (&plain, &inline_e, NULL, &p, 1, &out, &back, &again)
         == XTR_OK);
      T (back.flags == XTR_V1_ENCRYPTED);
      T (checkpayload (&out, &back, NULL, &p) == XTR_OK);
      release (&out);
      {
        unsigned long seed = 0x73529UL;
        unsigned i;
        for (i = 0; i < 2000U; i++)
          {
            size_t pos;
            unsigned char save;
            seed = (seed * 1664525UL + 1013904223UL) & 0xffffffffUL;
            pos = (size_t)(seed % (unsigned long)plain.len);
            save = plain.p[pos];
            plain.p[pos]
                = (unsigned char)(save ^ (unsigned char)(1U << (i % 8U)));
            T (convert (&plain, &inline_e, NULL, &p, 1, &out, &back, &again)
               != XTR_OK);
            T (out.len == 0);
            plain.p[pos] = save;
          }
      }
    }

  release (&plain);
  release (&secret);
  release (&public_again);
  release (&out);
}
int
main (void)
{
  rundata (0U);
  rundata (4U);
  rundata (65535U);
  rundata (65536U);
  rundata (1048576U);
  printf ("M6E2 portable reframe: %lu checks, %lu failures\n", checks, errors);
  return errors ? 1 : 0;
}
