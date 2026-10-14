/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Independent candidate ZIP framing fixture generator (v1 format limits). */

#include "../archive.h"
#include "../codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
w16 (FILE *f, unsigned u)
{
  fputc (u & 255, f);
  fputc ((u >> 8) & 255, f);
}

static void
w32 (FILE *f, unsigned long u)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      fputc ((int)(u & 255UL), f);
      u >>= 8;
    }
}

static unsigned long
crc_step (unsigned long c, const unsigned char *p, unsigned n)
{
  unsigned i;

  while (n--)
    {
      c ^= *p++;

      for (i = 0; i < 8; i++)
        {
          c = (c & 1) ? (c >> 1) ^ 0xedb88320UL : c >> 1;
        }
    }

  return c;
}

int
main (int argc, char **argv)
{
  FILE *in, *comp, *out;
  char buf[32768];
  size_t n;
  unsigned long crc = 0xffffffffUL, usz = 0, csz, pos, cdend;
  zo_u64 size;
  unsigned id, fnlen = 4, version;
  zo_settings settings;
  const zo_candidate *c;

  if (argc != 4)
    {
      return 2;
    }

  id = (unsigned)strtoul (argv[1], NULL, 10);

  if (id >= zo_candidate_count)
    {
      return 2;
    }

  c = &zo_candidates[id];
  version = (c->method <= 6)                       ? 10
            : (c->method == 9)                     ? 21
            : (c->method == 12)                    ? 46
            : (c->method == 14 || c->method == 98) ? 63
                                                   : 20;
  in = fopen (argv[2], "rb");
  comp = tmpfile ();
  out = fopen (argv[3], "wb");

  if (!in || !comp || !out)
    {
      return 2;
    }

  while ((n = fread (buf, 1, sizeof (buf), in)) != 0)
    {
      if ((unsigned long)n > 0xffffffffUL - usz)
        {
          return 3;
        }

      crc = crc_step (crc, (unsigned char *)buf, (unsigned)n);
      usz += (unsigned long)n;
    }

  if (ferror (in))
    {
      return 3;
    }

  crc ^= 0xffffffffUL;

  if (zo_candidate_count > ZO_MAX_CANDIDATES)
    {
      return 2;
    }

  memset (&settings, 0, sizeof (settings));

  for (id = 0; id < zo_candidate_count; id++)
    {
      settings.levels[id] = zo_candidates[id].method == 93U ? 22U
                            : zo_candidates[id].method == 10U
                                ? 9U
                                : zo_candidates[id].parameter;
    }

  id = (unsigned)strtoul (argv[1], NULL, 10);
  settings.zopfli_iterations = 15;
  settings.dcl_optimal = 0;

  if (zo_compress (id, in, comp, &size, &settings) != ZO_COMPRESS_OK
      || size > 0xffffffffUL)
    {
      return 4;
    }

  csz = (unsigned long)size;
  rewind (comp);
  w32 (out, 0x04034b50UL);
  w16 (out, version);
  w16 (out, c->flags);
  w16 (out, c->method);
  w16 (out, 0);
  w16 (out, 0);
  w32 (out, crc);
  w32 (out, csz);
  w32 (out, usz);
  w16 (out, fnlen);
  w16 (out, 0);
  fwrite ("data", 1, fnlen, out);

  while ((n = fread (buf, 1, sizeof (buf), comp)) != 0)
    {
      fwrite (buf, 1, n, out);
    }

  if (ferror (comp) || ferror (out))
    {
      return 5;
    }

  pos = (unsigned long)ftell (out);
  w32 (out, 0x02014b50UL);
  w16 (out, version);
  w16 (out, version);
  w16 (out, c->flags);
  w16 (out, c->method);
  w16 (out, 0);
  w16 (out, 0);
  w32 (out, crc);
  w32 (out, csz);
  w32 (out, usz);
  w16 (out, fnlen);
  w16 (out, 0);
  w16 (out, 0);
  w16 (out, 0);
  w16 (out, 0);
  w32 (out, 0);
  w32 (out, 0);
  fwrite ("data", 1, fnlen, out);
  cdend = (unsigned long)ftell (out);
  w32 (out, 0x06054b50UL);
  w16 (out, 0);
  w16 (out, 0);
  w16 (out, 1);
  w16 (out, 1);
  w32 (out, cdend - pos);
  w32 (out, pos);
  w16 (out, 0);

  if (fclose (out) || fclose (comp) || fclose (in))
    {
      return 5;
    }

  return 0;
}
