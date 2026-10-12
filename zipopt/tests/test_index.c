/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Indexed extraction and parsing regression tests */

#include "../archive.h"
#include "../extract.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixture
{
  const char *name;
  const char *data;
  unsigned long local;
  unsigned long crc;
};

static unsigned long central_start;

static struct fixture fixtures[]
    = { { "same.txt", "first archive entry",    0, 0 },
        { "same.txt", "second archive entry",   0, 0 },
        { "[?]*.txt", "literal wildcard entry", 0, 0 } };

static unsigned long
crc32_local (const char *s)
{
  unsigned long crc = 0xffffffffUL;
  unsigned j;

  while (*s)
    {
      crc ^= (unsigned char)*s++;

      for (j = 0; j < 8; j++)
        {
          crc = (crc & 1UL) ? (crc >> 1) ^ 0xedb88320UL : crc >> 1;
        }
    }

  return crc ^ 0xffffffffUL;
}

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

static int
make_fixture (const char *path)
{
  FILE *f;
  unsigned i;
  unsigned long cd, finish;

  f = fopen (path, "wb");

  if (!f)
    {
      return 0;
    }

  for (i = 0; i < 3; i++)
    {
      struct fixture *p = &fixtures[i];
      unsigned nl = (unsigned)strlen (p->name),
               sz = (unsigned)strlen (p->data);
      p->local = (unsigned long)ftell (f);
      p->crc = crc32_local (p->data);

      w32 (f, 0x04034b50UL);
      w16 (f, 20);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, p->crc);
      w32 (f, sz);
      w32 (f, sz);
      w16 (f, nl);
      w16 (f, 0);

      fwrite (p->name, 1, nl, f);
      fwrite (p->data, 1, sz, f);
    }

  cd = (unsigned long)ftell (f);
  central_start = cd;

  for (i = 0; i < 3; i++)
    {
      struct fixture *p = &fixtures[i];
      unsigned nl = (unsigned)strlen (p->name),
               sz = (unsigned)strlen (p->data);

      w32 (f, 0x02014b50UL);
      w16 (f, 20);
      w16 (f, 20);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, p->crc);
      w32 (f, sz);
      w32 (f, sz);
      w16 (f, nl);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, 0);
      w32 (f, p->local);

      fwrite (p->name, 1, nl, f);
    }

  finish = (unsigned long)ftell (f);

  w32 (f, 0x06054b50UL);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 3);
  w16 (f, 3);
  w32 (f, finish - cd);
  w32 (f, cd);
  w16 (f, 0);

  if (fclose (f))
    {
      return 0;
    }

  return 1;
}

int
main (void)
{
  const char *path = "build/test-index.zip";
  zo_archive a;
  FILE *f;
  unsigned i;
  char buffer[100];
  size_t n;

  if (!make_fixture (path))
    {
      fprintf (stderr, "cannot construct test fixture\n");

      return 1;
    }

  if (!zo_archive_open (&a, path))
    {
      fprintf (stderr, "parser failed: %s\n", a.error);

      return 1;
    }

  if (a.count != 3)
    {
      return 2;
    }

  for (i = 0; i < 3; i++)
    {
      f = tmpfile ();

      if (!f || !zo_extract_index (&a, i, f))
        {
          return 3;
        }

      rewind (f);
      n = fread (buffer, 1, sizeof (buffer), f);

      if (n != strlen (fixtures[i].data)
          || memcmp (buffer, fixtures[i].data, n))
        {
          return 4;
        }

      fclose (f);
    }

  zo_archive_close (&a);

  /* A crypt flag without encryption metadata must fail preflight. */
  f = fopen (path, "r+b");

  if (!f)
    {
      return 5;
    }

  if (fseek (f, (long)fixtures[0].local + 6L, SEEK_SET))
    {
      return 6;
    }

  w16 (f, 1);

  if (fseek (f, (long)central_start + 8L, SEEK_SET))
    {
      return 6;
    }

  w16 (f, 1);

  if (fclose (f))
    {
      return 7;
    }

  if (zo_archive_open (&a, path))
    {
      return 8;
    }

  zo_archive_close (&a);
  puts ("PASS: ordinal extraction, duplicate names, literal wildcards, "
        "encryption rejection");

  return 0;
}
