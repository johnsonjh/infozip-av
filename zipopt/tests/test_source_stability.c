/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Source mutation/replacement detection */

#include "../archive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
copy (const char *a, const char *b)
{
  unsigned char buf[4096];
  FILE *in = fopen (a, "rb"), *out = fopen (b, "wb");
  size_t n;
  int ok = 1;

  if (!in || !out)
    {
      if (in)
        {
          fclose (in);
        }

      if (out)
        {
          fclose (out);
        }

      return 0;
    }

  while ((n = fread (buf, 1, sizeof (buf), in)) != 0)
    {
      if (fwrite (buf, 1, n, out) != n)
        {
          ok = 0;

          break;
        }
    }

  if (ferror (in))
    {
      ok = 0;
    }

  if (fclose (in) != 0)
    {
      ok = 0;
    }

  if (fclose (out) != 0)
    {
      ok = 0;
    }

  return ok;
}

int
main (void)
{
  const char *src = "build/candidate-0.zip";
  const char *target = "build/stability-mutation.zip";
  const char *replacement = "build/stability-replacement.zip";
  FILE *f;
  zo_archive a;
  int c;

  if (!copy (src, target) || !zo_archive_open (&a, target))
    {
      return 1;
    }

  if (!zo_archive_unchanged (&a))
    {
      return 2;
    }

  f = fopen (target, "rb+");

  if (!f)
    {
      return 3;
    }

  if (fseek (f, 38L, SEEK_SET))
    {
      return 4;
    }

  c = fgetc (f);

  if (c == EOF || fseek (f, 38L, SEEK_SET) || fputc (c ^ 1, f) == EOF
      || fclose (f))
    {
      return 5;
    }

  if (zo_archive_unchanged (&a))
    {
      return 6;
    }

  zo_archive_close (&a);

  if (!copy (src, target) || !zo_archive_open (&a, target))
    {
      return 7;
    }

  if (!copy (src, replacement) || rename (replacement, target))
    {
      return 8;
    }

  if (zo_archive_unchanged (&a))
    {
      return 9;
    }

  zo_archive_close (&a);
  remove (target);
  puts ("PASS: source fingerprint and path-replacement detection");

  return 0;
}
