/* MIT-0. C89 typed platform TLV matrices and malformed record tests. */
#include "xtrv1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int errors = 0, checks = 0;
#define C(e)                                                                  \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(e))                                                               \
        {                                                                     \
          fprintf (stderr, "platform failed %d %s\n", __LINE__, #e);          \
          errors++;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct mem
{
  unsigned char b[2048];
  size_t n, pos;
} mem;
static int
put (void *v, const unsigned char *p, size_t n)
{
  mem *m = (mem *)v;

  if (m->n + n > sizeof (m->b))
    {
      return 1;
    }

  if (n)
    {
      memcpy (m->b + m->n, p, n);
    }

  m->n += n;
  return 0;
}
static size_t
get (void *v, unsigned char *p, size_t n)
{
  mem *m = (mem *)v;

  if (n > m->n - m->pos)
    {
      n = m->n - m->pos;
    }

  if (n > 9)
    {
      n = 9;
    }

  if (n)
    {
      memcpy (p, m->b + m->pos, n);
    }

  m->pos += n;
  return n;
}
static void
policy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = 10000;
  p->max_field = 1048576;
  p->max_manifest.lo = 0xffffffffUL;
  p->max_manifest.hi = 0;
}
static void
test (unsigned type, unsigned origin, unsigned interface, unsigned encode,
      const unsigned char *name, unsigned nlen)
{
  xtr1_policy conf;
  xtr1_source rec;
  xtr1_sink sink;
  xtr1_digest dig, out;
  xtr_reader reader;
  xtr_extra x;
  mem b;
  unsigned char owner[16], tlv[32], sha[32];
  unsigned j;
  int rc;

  memset (&b, 0, sizeof (b));
  memset (&rec, 0, sizeof (rec));
  memset (&x, 0, sizeof (x));
  policy (&conf);
  for (j = 0; j < 16; j++)
    {
      owner[j] = (unsigned char)(j + 3);
    }

  tlv[0] = 1;
  tlv[1] = 0;
  tlv[2] = 0;
  tlv[3] = 0;
  tlv[4] = 2;
  tlv[5] = 0;
  tlv[6] = 0;
  tlv[7] = 0;
  tlv[8] = (unsigned char)interface;
  tlv[9] = 0;
  rec.record.type = type;
  rec.record.origin = origin;
  rec.record.encoding = encode;
  rec.record.ns_len = 0;
  rec.record.name_len = nlen;
  rec.record.native_len = 10;
  rec.record.value_len.lo = 0;
  rec.record.value_len.hi = 0;
  rec.name = name;
  rec.native = tlv;
  sink.write = put;
  sink.context = &b;
  rc = xtr1_write_manifest (owner, &rec, 1, 0, &conf, &sink, &dig);
  C (rc == XTR_OK);
  if (rc)
    {
      return;
    }

  C (dig.count == 1 && dig.schema_supported);
  x.mode = 2;
  memcpy (x.owner, owner, 16);
  x.count = 1;
  x.manifest_len = dig.manifest_length;
  x.crc32 = dig.crc32;
  memcpy (sha, dig.sha256, 32);
  memset (&reader, 0, sizeof (reader));
  reader.read = get;
  reader.context = &b;
  rc = xtr1_check_manifest (&reader, dig.manifest_length, &x, sha, &conf,
                            &out);
  C (rc == XTR_OK);
  if (rc == XTR_OK)
    {
      C (out.schema_supported);
    }

  /* Unknown critical TLV: structurally valid, preserve-only. */
  tlv[10] = 13;
  tlv[11] = 0;
  tlv[12] = 1;
  tlv[13] = 0;
  tlv[14] = 1;
  tlv[15] = 0;
  tlv[16] = 0;
  tlv[17] = 0;
  tlv[18] = 0xA5;
  rec.record.native_len = 19;
  b.n = 0;
  b.pos = 0;
  C (xtr1_write_manifest (owner, &rec, 1, 0, &conf, &sink, &dig) == XTR_OK);
  C (!dig.schema_supported);
  x.manifest_len = dig.manifest_length;
  x.crc32 = dig.crc32;
  memcpy (sha, dig.sha256, 32);
  b.pos = 0;
  C (xtr1_check_manifest (&reader, dig.manifest_length, &x, sha, &conf, &out)
     == XTR_OK);
  C (!out.schema_supported);
  /* Duplicate TLV and a truncated value are malformed. */
  tlv[10] = 1;
  b.n = 0;
  C (xtr1_write_manifest (owner, &rec, 1, 0, &conf, &sink, &dig)
     == XTR_CORRUPT);
  tlv[10] = 13;
  tlv[14] = 254;
  C (xtr1_write_manifest (owner, &rec, 1, 0, &conf, &sink, &dig)
     == XTR_CORRUPT);
  tlv[14] = 1;
  rec.record.native_len = 10;
  tlv[2] = 1;
  b.n = 0;
  C (xtr1_write_manifest (owner, &rec, 1, 0, &conf, &sink, &dig) == XTR_OK);
  tlv[2] = 0;
}
int
main (void)
{
  static const unsigned char utf16[] = { 'A', 0, 'B', 0 };
  static const unsigned char binary[] = { 0xff, 0xfe, 0 };
  const unsigned char *name = (const unsigned char *)"name";

  test (1, 1, 1, 0, name, 4);                 /* Linux native kv */
  test (1, 2, 2, 0, name, 4);                 /* FreeBSD traditional extattr */
  test (2, 2, 3, 0, name, 4);                 /* FreeBSD named files */
  test (1, 3, 4, 0, name, 4);                 /* NetBSD */
  test (1, 4, 5, 0, name, 4);                 /* macOS xattr */
  test (1, 5, 6, 0, name, 4);                 /* AIX */
  test (2, 6, 7, 0, name, 4);                 /* Solaris */
  test (1, 7, 8, 0, name, 4);                 /* Windows EA */
  test (3, 7, 9, 2, utf16, sizeof (utf16));   /* Windows ADS */
  test (1, 8, 10, 0, name, 4);                /* OS/2 EA */
  test (4, 4, 11, 0, name, 4);                /* macOS resource fork */
  test (5, 4, 12, 0, name, 4);                /* macOS Finder metadata */
  test (1, 1, 1, 0, binary, sizeof (binary)); /* opaque non-UTF-8 name */
  printf ("platform TLV vectors: %d assertions, %d failures\n", checks,
          errors);
  return errors ? 1 : 0;
}
