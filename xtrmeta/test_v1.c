/* SPDX-License-Identifier: MIT-0 */
#include "xtrv1.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int checks = 0, errors = 0;
#define C(x)                                                                  \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x);        \
          errors++;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct buffer
{
  unsigned char *b;
  size_t size, used, pos, fail;
} buffer;
static int
put (void *ctx, const unsigned char *p, size_t n)
{
  buffer *b = (buffer *)ctx;
  unsigned char *v;
  size_t alloc;

  if (b->fail && b->used + n >= b->fail)
    {
      return 1;
    }

  if (n > (size_t)-1 - b->used)
    {
      return 1;
    }

  if (b->used + n > b->size)
    {
      alloc = b->size ? b->size : 512;
      while (alloc < b->used + n)
        {
          if (alloc > (size_t)-1 / 2)
            {
              return 1;
            }

          alloc *= 2;
        }
      v = (unsigned char *)realloc (b->b, alloc);
      if (!v)
        {
          return 1;
        }

      b->b = v;
      b->size = alloc;
    }

  if (n)
    {
      memcpy (b->b + b->used, p, n);
    }

  b->used += n;
  return 0;
}
static size_t
get (void *ctx, unsigned char *out, size_t n)
{
  buffer *b = (buffer *)ctx;

  if (b->fail && b->pos >= b->fail)
    {
      return 0;
    }

  if (n > b->used - b->pos)
    {
      n = b->used - b->pos;
    }

  if (n > 23)
    {
      n = 23; /* partial I/O deliberately */
    }

  if (b->fail && n > b->fail - b->pos)
    {
      n = b->fail - b->pos;
    }

  if (n)
    {
      memcpy (out, b->b + b->pos, n);
    }

  b->pos += n;
  return n;
}
typedef struct pattern
{
  xtr_u64 remaining;
  unsigned long cursor;
} pattern;
static size_t
getpattern (void *ctx, unsigned char *out, size_t n)
{
  pattern *p = (pattern *)ctx;
  size_t i;

  if (!p->remaining.hi && p->remaining.lo < (unsigned long)n)
    {
      n = (size_t)p->remaining.lo;
    }

  if (n > 131)
    {
      n = 131;
    }

  for (i = 0; i < n; i++)
    {
      out[i] = (unsigned char)((p->cursor++ * 13UL + 7UL) & 255UL);
    }

  if (p->remaining.lo < (unsigned long)n)
    {
      p->remaining.hi--;
      p->remaining.lo
          = (p->remaining.lo + (0xffffffffUL - (unsigned long)n) + 1UL)
            & 0xffffffffUL;
    }
  else
    {
      p->remaining.lo -= (unsigned long)n;
    }

  return n;
}
/* On both 32- and 64-bit targets never use 0x100000000 as int arithmetic. */
static xtr_u64
sz (unsigned long v)
{
  xtr_u64 z;

  z.lo = v & 0xffffffffUL;
  z.hi = v >> 16 >> 16;
  return z;
}
static void
policy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = 10000;
  p->max_field = 1048576UL;
  p->max_manifest.lo = 0xffffffffUL;
  p->max_manifest.hi = 0xffUL;
}
static void
setup (xtr1_source *s, unsigned type, unsigned origin, unsigned iface,
       const char *ns, const char *name, unsigned long value,
       unsigned char tlv[10], pattern *source)
{
  memset (s, 0, sizeof (*s));
  s->record.type = type;
  s->record.origin = origin;
  s->record.encoding = 0;
  s->record.ns_len = (unsigned long)strlen (ns);
  s->record.name_len = (unsigned long)strlen (name);
  s->record.native_len = 10;
  s->record.value_len = sz (value);
  s->ns = (const unsigned char *)ns;
  s->name = (const unsigned char *)name;
  tlv[0] = 1;
  tlv[1] = 0;
  tlv[2] = 0;
  tlv[3] = 0;
  tlv[4] = 2;
  tlv[5] = 0;
  tlv[6] = 0;
  tlv[7] = 0;
  tlv[8] = (unsigned char)iface;
  tlv[9] = 0;
  s->native = tlv;
  source->remaining = sz (value);
  source->cursor = 0;
  s->value_context = source;
  s->read_value = getpattern;
}
static int
validate (buffer *b, const xtr_extra *e, const unsigned char *sha,
          const xtr1_policy *p, xtr1_digest *dig)
{
  xtr_reader r;

  memset (&r, 0, sizeof (r));
  b->pos = 0;
  r.context = b;
  r.read = get;
  return xtr1_check_manifest (&r, sz ((unsigned long)b->used), e, sha, p, dig);
}
static void
sha_tests (void)
{
  unsigned char out[32];
  xtr_sha256 h;
  static const unsigned char empty[32]
      = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
          0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
          0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
  static const unsigned char abc[32]
      = { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
          0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
          0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
  static const unsigned char million[32]
      = { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7,
          0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97,
          0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 };
  unsigned char thousand[1000];
  int i;

  xtr_sha256_init (&h);
  xtr_sha256_update (&h, (const unsigned char *)"", 0);
  xtr_sha256_final (&h, out);
  C (!memcmp (out, empty, 32));
  xtr_sha256_init (&h);
  xtr_sha256_update (&h, (const unsigned char *)"ab", 2);
  xtr_sha256_update (&h, (const unsigned char *)"c", 1);
  xtr_sha256_final (&h, out);
  C (!memcmp (out, abc, 32));
  memset (thousand, 'a', sizeof (thousand));
  xtr_sha256_init (&h);
  for (i = 0; i < 1000; i++)
    {
      xtr_sha256_update (&h, thousand, sizeof (thousand));
    }

  xtr_sha256_final (&h, out);
  C (!memcmp (out, million, 32));
}
static void
run (void)
{
  unsigned char owner[16], tlv[6][10], local[128], central[256], sha[32];
  unsigned char scratch[128], dupe[200];
  pattern pats[6];
  xtr1_source src[6];
  xtr1_policy conf;
  xtr1_sink sink;
  xtr1_digest dig, verified;
  xtr_extra x, ex;
  buffer b;
  size_t lenloc, lencen, i;
  int hx, hf;
  char name[52];

  policy (&conf);
  memset (&b, 0, sizeof (b));
  memset (&x, 0, sizeof (x));
  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1U);
    }

  setup (&src[0], 1, 1, 1, "user", "alpha", 4, tlv[0], &pats[0]);
  setup (&src[1], 1, 2, 2, "user", "alpha", 0, tlv[1], &pats[1]);
  setup (&src[2], 1, 7, 8, "nt", "FoO", 12, tlv[2], &pats[2]);
  setup (&src[3], 2, 2, 3, "", "data", 1048576, tlv[3], &pats[3]);
  setup (&src[4], 3, 7, 9, "", "abc:stream", 8, tlv[4], &pats[4]);
  setup (&src[5], 4, 4, 11, "", "com.apple.ResourceFork", 1024, tlv[5],
         &pats[5]);
  sink.write = put;
  sink.context = &b;
  C (xtr1_write_manifest (owner, src, 6, 0, &conf, &sink, &dig) == XTR_OK);
  C (b.used
     == 36 + 6 * 28 + 4 + 5 + 10 + 4 + 4 + 5 + 10 + 0 + 2 + 3 + 10 + 12 + 0 + 4
            + 10 + 1048576 + 0 + 10 + 10 + 8 + 0 + 22 + 10 + 1024);
  C (dig.count == 6 && dig.schema_supported);
  x.mode = 2;
  x.flags = 0;
  memcpy (x.owner, owner, 16);
  x.count = dig.count;
  x.manifest_len = dig.manifest_length;
  x.crc32 = dig.crc32;
  C (xtr1_extra_encode (local, sizeof (local), &x, 0, NULL, 0, NULL, &lenloc)
     == XTR_OK);
  C (xtr1_extra_encode (central, sizeof (central), &x, 1, NULL, 0, dig.sha256,
                        &lencen)
     == XTR_OK);
  C (lenloc == 40 && lencen == 72);
  C (xtr1_check_headers (local, lenloc, central, lencen, &ex, sha) == XTR_OK);
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_OK);
  C (verified.count == 6 && verified.schema_supported);
  C (verified.manifest_length.lo == dig.manifest_length.lo);
  C (!memcmp (verified.sha256, dig.sha256, 32));
  C (xtr1_companion_name (owner, name) == XTR_OK);
  C (strlen (name) == 51
     && xtr1_companion_matches (owner, name, 51) == XTR_OK);
  name[5] = 'x';
  C (xtr1_companion_matches (owner, name, 51) == XTR_CORRUPT);
  {
    xtr1_index_entry graph[3];
    memset (graph, 0, sizeof (graph));
    graph[0].name = "ordinary.txt";
    graph[0].name_len = 12;
    graph[0].owner_id = owner;
    graph[0].mode = 2;
    C (xtr1_companion_name (owner, name) == XTR_OK);
    graph[1].name = name;
    graph[1].name_len = 51;
    graph[1].companion = 1;
    graph[2].name = "other.bin";
    graph[2].name_len = 9;
    C (xtr1_check_archive_index (graph, 3, &conf) == XTR_OK);
    C (xtr1_check_archive_index (graph, 1, &conf) == XTR_CORRUPT);
    graph[2] = graph[0];
    C (xtr1_check_archive_index (graph, 3, &conf) == XTR_CORRUPT);
    graph[2].name = "__XTRO_ZIP__/evil";
    graph[2].name_len = 17;
    graph[2].owner_id = NULL;
    graph[2].mode = 0;
    C (xtr1_check_archive_index (graph, 3, &conf) == XTR_CORRUPT);
    graph[2].name = "other.bin";
    graph[2].name_len = 9;
    C (xtr1_check_archive_index (graph, 3, &conf) == XTR_OK);
    graph[0].mode = 1;
    C (xtr1_check_archive_index (graph, 3, &conf) == XTR_CORRUPT);
    graph[0].mode = 2;
  }
  C (xtr1_crypto_check (1, 1, 1, 0) == XTR_OK);
  C (xtr1_crypto_check (2, 2, 0, 1) == XTR_IO);
  C (xtr1_crypto_check (2, 1, 1, 1) == XTR_CORRUPT);
  C (xtr1_crypto_check (1, 1, 0, 0) == XTR_IO);
  C (xtr1_crypto_check (3, 3, 1, 0) == XTR_IO);
  C (xtr1_check_fwkcs ((const unsigned char *)"MD5abcdefghijklmnop", 19, 1)
     == XTR_OK);
  C (xtr1_check_fwkcs ((const unsigned char *)"MD5abcdefghijklmnop", 19, 0)
     == XTR_CORRUPT);
  /* fwkcs central-only coexists with vendor XTRO */
  dupe[0] = 0x46;
  dupe[1] = 0x4b;
  dupe[2] = 19;
  dupe[3] = 0;
  memcpy (dupe + 4, "MD5abcdefghijklmnop", 19);
  dupe[23] = 0x54;
  dupe[24] = 0x58;
  dupe[25] = 72;
  dupe[26] = 0;
  memcpy (dupe + 27, central, 72);
  C (xtr1_scan_extra_list (dupe, 99, 1, &hx, &hf) == XTR_OK && hx && hf);
  memcpy (dupe + 99, dupe + 23, 76);
  C (xtr1_scan_extra_list (dupe, 175, 1, &hx, &hf) == XTR_CORRUPT);
  dupe[25] = 255;
  C (xtr1_scan_extra_list (dupe, 99, 1, &hx, &hf) == XTR_CORRUPT);
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_OK);
  sha[0] ^= 1;
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_CORRUPT);
  sha[0] ^= 1;
  b.b[8] ^= 0x80;
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_CORRUPT);
  b.b[8] ^= 0x80;
  b.b[36 + 28 + 4 + 5 + 10 + 4 + 28 + 4 + 5 + 10 + 28 + 2 + 3 + 10 + 12 + 28
      + 0 + 4 + 10] ^= 0x1;
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_CORRUPT);
  b.b[36 + 28 + 4 + 5 + 10 + 4 + 28 + 4 + 5 + 10 + 28 + 2 + 3 + 10 + 12 + 28
      + 0 + 4 + 10] ^= 1;
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_OK);
  conf.max_manifest.lo = 1000;
  conf.max_manifest.hi = 0;
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_LIMIT);
  conf.max_manifest.lo = 0xffffffffUL;
  conf.max_manifest.hi = 0xffUL;
  conf.max_records = 2;
  C (validate (&b, &ex, sha, &conf, &verified) == XTR_LIMIT);
  conf.max_records = 10000;
  /* Any future record with same identity under a different TLV is duplicate.
   */
  src[1] = src[0];
  C (xtr1_write_manifest (owner, src, 6, 0, &conf, &sink, &verified)
     == XTR_CORRUPT);
  setup (&src[1], 1, 2, 2, "user", "alpha", 0, tlv[1], &pats[1]);
  /* Unsorted attributes cannot pass canonical writer. */
  {
    xtr1_source t = src[0];
    src[0] = src[1];
    src[1] = t;
    C (xtr1_write_manifest (owner, src, 6, 0, &conf, &sink, &verified)
       == XTR_CORRUPT);
    t = src[0];
    src[0] = src[1];
    src[1] = t;
  }
  /* Preflight detects invalid TLVs without publishing partial bytes. */
  i = b.used;
  tlv[0][4] = 3;
  C (xtr1_write_manifest (owner, src, 6, 0, &conf, &sink, &verified)
     == XTR_CORRUPT);
  C (b.used == i);
  tlv[0][4] = 2;
  /* Encrypted form: values AND SHA footer reside in the encrypted ZIP member.
   */
  free (b.b);
  memset (&b, 0, sizeof (b));
  for (i = 0; i < 6; i++)
    {
      pats[i].cursor = 0;
      pats[i].remaining = src[i].record.value_len;
    }

  C (xtr1_write_manifest (owner, src, 6, 1, &conf, &sink, &dig) == XTR_OK);
  x.flags = 1;
  x.count = 0;
  x.manifest_len = sz (0);
  x.crc32 = 0;
  C (xtr1_extra_encode (local, sizeof (local), &x, 0, NULL, 0, NULL, &lenloc)
     == XTR_OK);
  C (xtr1_extra_encode (central, sizeof (central), &x, 1, NULL, 0, NULL,
                        &lencen)
     == XTR_OK);
  C (lenloc == 40 && lencen == 40);
  C (xtr1_check_headers (local, lenloc, central, lencen, &ex, sha) == XTR_OK);
  C (validate (&b, &ex, NULL, &conf, &verified) == XTR_OK);
  C (verified.count == 6 && verified.schema_supported);
  C (memcmp (b.b + b.used - 36, "XTCS", 4) == 0);
  b.b[b.used - 1] ^= 1;
  C (validate (&b, &ex, NULL, &conf, &verified) == XTR_CORRUPT);
  b.b[b.used - 1] ^= 1;
  /* Truncated streaming read returns explicit IO without overread. */
  b.fail = 100;
  C (validate (&b, &ex, NULL, &conf, &verified) == XTR_IO);
  b.fail = 0;
  /* Buffer writes that fail at an arbitrary point return IO. */
  free (b.b);
  memset (&b, 0, sizeof (b));
  b.fail = 100;
  for (i = 0; i < 6; i++)
    {
      pats[i].cursor = 0;
      pats[i].remaining = src[i].record.value_len;
    }

  C (xtr1_write_manifest (owner, src, 6, 1, &conf, &sink, &verified)
     == XTR_IO);
  b.fail = 0;
  /* Direct hashes never depend on input CRC or FWKCS MD5. */
  memcpy (scratch, dig.sha256, 32);
  C (memcmp (scratch, verified.sha256, 32) == 0 || b.used < 100);
  free (b.b);
}
int
main (void)
{
  sha_tests ();
  run ();
  printf ("xtrv1 tests: %d assertions, %d failures\n", checks, errors);
  return errors ? 1 : 0;
}
