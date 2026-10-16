/* MIT-0. Deterministic mutation and allocation-failure regression. C89. */

#include "xtrv1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SZ 256

static unsigned long seed = 0x6384f1dUL, operations = 0, faults = 0;
static unsigned long
next (void)
{
  seed = (seed * 1664525UL + 1013904223UL) & 0xffffffffUL;
  return seed;
}

typedef struct fixture
{
  unsigned char data[SZ];
  size_t len, pos;
} fixture;

static size_t
rd (void *ctx, unsigned char *p, size_t n)
{
  fixture *s = (fixture *)ctx;

  if (n > s->len - s->pos)
    {
      n = s->len - s->pos;
    }

  if (n > 17)
    {
      n = 17;
    }

  if (n)
    {
      memcpy (p, s->data + s->pos, n);
    }

  s->pos += n;
  return n;
}

typedef struct failmem
{
  unsigned calls, alive, fail;
} failmem;
static void *
failalloc (void *ctx, size_t n)
{
  failmem *m = (failmem *)ctx;
  void *p;

  ++m->calls;
  if (m->fail == m->calls)
    {
      return NULL;
    }

  p = malloc (n ? n : 1);
  if (p)
    {
      m->alive++;
    }

  return p;
}

static void
failfree (void *ctx, void *p)
{
  failmem *m = (failmem *)ctx;

  if (p)
    {
      free (p);
      if (!m->alive)
        {
          fprintf (stderr, "invalid free\n");
          exit (3);
        }

      m->alive--;
    }
}

static int
run (fixture *f, xtr_extra *ex, const unsigned char *sha, failmem *mem)
{
  xtr1_policy policy;
  xtr_reader r;
  xtr1_digest result;
  xtr_u64 sz;

  memset (&r, 0, sizeof (r));
  memset (&policy, 0, sizeof (policy));
  policy.max_records = 500;
  policy.max_field = 8192;
  policy.max_manifest.lo = 100000;
  policy.max_manifest.hi = 0;
  policy.alloc = failalloc;
  policy.release = failfree;
  policy.context = mem;
  f->pos = 0;
  r.read = rd;
  r.context = f;
  sz.lo = (unsigned long)f->len;
  sz.hi = 0;
  return xtr1_check_manifest (&r, sz, ex, sha, &policy, &result);
}

int
main (int argc, char **argv)
{
  fixture f, valid;
  unsigned char header[36], rec[28], sha[32], sha2[32], name[] = "test",
                                                        meta[10];
  xtr_manifest m;
  xtr_record rr;
  xtr_extra ex;
  xtr_sha256 hash;
  failmem mem;
  int rc;
  unsigned long i, loops = 120000;

  if (argc > 1)
    {
      loops = strtoul (argv[1], NULL, 10);
    }

  memset (&valid, 0, sizeof (valid));
  memset (&m, 0, sizeof (m));
  memset (&rr, 0, sizeof (rr));
  memset (&ex, 0, sizeof (ex));
  memset (&mem, 0, sizeof (mem));
  for (i = 0; i < 16; i++)
    {
      m.owner[i] = (unsigned char)(i + 1);
    }

  m.count = 1;
  m.records_len.lo = 28 + 4 + 4 + 10 + 8;
  m.records_len.hi = 0;
  if (xtr_manifest_header (header, &m))
    {
      return 5;
    }

  rr.type = 1;
  rr.origin = 1;
  rr.encoding = 0;
  rr.ns_len = 4;
  rr.name_len = 4;
  rr.native_len = 10;
  rr.value_len.lo = 8;
  rr.value_len.hi = 0;
  if (xtr_record_header (rec, &rr))
    {
      return 5;
    }

  meta[0] = 1;
  meta[1] = 0;
  meta[2] = 0;
  meta[3] = 0;
  meta[4] = 2;
  meta[5] = 0;
  meta[6] = 0;
  meta[7] = 0;
  meta[8] = 1;
  meta[9] = 0;
  memcpy (valid.data, header, 36);
  memcpy (valid.data + 36, rec, 28);
  memcpy (valid.data + 64, "user", 4);
  memcpy (valid.data + 68, name, 4);
  memcpy (valid.data + 72, meta, 10);
  memcpy (valid.data + 82, "12345678", 8);
  valid.len = 90;
  ex.mode = 2;
  memcpy (ex.owner, m.owner, 16);
  ex.count = 1;
  ex.manifest_len.lo = 90;
  ex.manifest_len.hi = 0;
  ex.crc32 = xtr_crc32_update (0, valid.data, valid.len);
  xtr_sha256_init (&hash);
  xtr_sha256_update (&hash, valid.data, valid.len);
  xtr_sha256_final (&hash, sha);
  if (run (&valid, &ex, sha, &mem) != XTR_OK || mem.alive)
    {
      return 6;
    }

  /* Exercise each allocator-failure point on otherwise valid data. */
  for (i = 1; i < 16; i++)
    {
      mem.calls = 0;
      mem.fail = (unsigned)i;
      mem.alive = 0;
      rc = run (&valid, &ex, sha, &mem);
      if (mem.alive || (rc != XTR_OK && rc != XTR_LIMIT))
        {
          fprintf (stderr, "allocation failure bug %lu rc=%d\n", i, rc);
          return 7;
        }

      faults++;
    }

  mem.fail = 0;
  for (i = 0; i < loops; i++)
    {
      size_t j, off;
      int nchanges;
      f = valid;
      nchanges = 1 + (int)(next () % 5);
      for (j = 0; j < (size_t)nchanges; j++)
        {
          off = (size_t)(next () % (f.len));
          f.data[off] ^= (unsigned char)(1 + (next () % 255));
        }

      /* A percentage of samples have matching outer CRC/SHA to drive
       * the structural and TLV validators past integrity verification. */
      if ((next () & 3UL) == 0)
        {
          ex.crc32 = xtr_crc32_update (0, f.data, f.len);
          xtr_sha256_init (&hash);
          xtr_sha256_update (&hash, f.data, f.len);
          xtr_sha256_final (&hash, sha2);
        }
      else
        {
          memcpy (sha2, sha, 32);
        }

      mem.calls = 0;
      mem.alive = 0;
      rc = run (&f, &ex, sha2, &mem);
      if (mem.alive || rc < 0 || rc > XTR_UNSUPPORTED)
        {
          fprintf (stderr, "mutation failure iteration=%lu rc=%d\n", i, rc);
          return 8;
        }

      operations++;
      /* Restore the canonical digest and CRC. */
      ex.crc32 = xtr_crc32_update (0, valid.data, valid.len);
    }

  printf ("xtrv1 mutation: %lu cases; allocation checks: %lu; leaks: 0\n",
          operations, faults);
  return 0;
}
