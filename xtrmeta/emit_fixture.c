/* MIT-0. Deterministic, standalone test-fixture generator, C89. */

#include "xtrv1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t
pattern (void *ctx, unsigned char *b, size_t n)
{
  unsigned long *pos = (unsigned long *)ctx;
  size_t i;

  for (i = 0; i < n; i++)
    {
      b[i] = (unsigned char)(((*pos)++ * 7UL + 3UL) & 255UL);
    }

  return n;
}

static int
wr (void *ctx, const unsigned char *p, size_t n)
{
  return fwrite (p, 1, n, (FILE *)ctx) == n ? 0 : 1;
}

static int
path (char *p, size_t cap, const char *dir, const char *name)
{
  size_t a = strlen (dir), b = strlen (name);

  if (a > cap || b > cap - a - 2U)
    {
      return 0;
    }

  memcpy (p, dir, a);
  p[a] = '/';
  memcpy (p + a + 1, name, b + 1);
  return 1;
}

static int
putfile (const char *dir, const char *name, const unsigned char *p, size_t n)
{
  char fn[1024];
  FILE *f;

  if (!path (fn, sizeof (fn), dir, name))
    {
      return 0;
    }

  f = fopen (fn, "wb");
  if (!f)
    {
      return 0;
    }

  if (fwrite (p, 1, n, f) != n)
    {
      fclose (f);
      return 0;
    }

  return fclose (f) == 0;
}

int
main (int argc, char **argv)
{
  unsigned char owner[16], meta[10], local[80], central[128];
  unsigned char content[257];
  unsigned long cursor = 0;
  xtr1_policy p;
  xtr1_source source;
  xtr1_sink sink;
  xtr1_digest d;
  xtr_extra e;
  char name[52], fn[1024];
  size_t len;
  FILE *out;
  int enc, rc;
  unsigned i;

  if (argc != 3)
    {
      return 2;
    }

  enc = strcmp (argv[2], "encrypted") == 0;
  if (!enc && strcmp (argv[2], "plain"))
    {
      return 2;
    }

  memset (&source, 0, sizeof (source));
  memset (&p, 0, sizeof (p));
  memset (&e, 0, sizeof (e));
  p.max_records = 10000;
  p.max_field = 1048576UL;
  p.max_manifest.lo = 0xffffffffUL;
  p.max_manifest.hi = 0;
  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1);
    }

  if (xtr1_companion_name (owner, name))
    {
      return 2;
    }

  if (!putfile (argv[1], "companion_name.txt", (unsigned char *)name, 51))
    {
      return 3;
    }

  for (i = 0; i < sizeof (content); i++)
    {
      content[i] = (unsigned char)(i & 255U);
    }

  if (!putfile (argv[1], "owner.dat", content, sizeof (content)))
    {
      return 3;
    }

  meta[0] = 1;
  meta[1] = 0;
  meta[2] = 0;
  meta[3] = 0;
  meta[4] = 2;
  meta[5] = 0;
  meta[6] = 0;
  meta[7] = 0;
  meta[8] = 3;
  meta[9] = 0;
  source.record.type = 2;
  source.record.origin = 2;
  source.record.encoding = 0;
  source.record.ns_len = 0;
  source.record.name_len = 12;
  source.record.native_len = 10;
  source.record.value_len.lo = 200000UL;
  source.record.value_len.hi = 0;
  source.name = (const unsigned char *)"large-stream";
  source.native = meta;
  source.value_context = &cursor;
  source.read_value = pattern;
  if (!path (fn, sizeof (fn), argv[1], "manifest.xtm"))
    {
      return 3;
    }

  out = fopen (fn, "wb");
  if (!out)
    {
      return 3;
    }

  sink.write = wr;
  sink.context = out;
  rc = xtr1_write_manifest (owner, &source, 1, enc, &p, &sink, &d);
  if (fclose (out) != 0 || rc)
    {
      return 4;
    }

  e.mode = 2;
  e.flags = (unsigned)enc;
  memcpy (e.owner, owner, 16);
  if (!enc)
    {
      e.count = d.count;
      e.manifest_len = d.manifest_length;
      e.crc32 = d.crc32;
    }

  if (xtr1_extra_encode (local, sizeof (local), &e, 0, NULL, 0, NULL, &len))
    {
      return 5;
    }

  if (!putfile (argv[1], "local_xtr.bin", local, len))
    {
      return 5;
    }

  if (xtr1_extra_encode (central, sizeof (central), &e, 1, NULL, 0,
                         enc ? NULL : d.sha256, &len))
    {
      return 5;
    }

  if (!putfile (argv[1], "central_xtr.bin", central, len))
    {
      return 5;
    }

  return 0;
}
