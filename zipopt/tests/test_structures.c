/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* ZIP structural boundary fixtures */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
w16 (FILE *f, unsigned n)
{
  fputc ((int)(n & 255U), f);
  fputc ((int)((n >> 8) & 255U), f);
}

static void
w32 (FILE *f, unsigned long n)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      fputc ((int)(n & 255UL), f);
      n >>= 8;
    }
}

static unsigned long
crc (const unsigned char *s, size_t n)
{
  unsigned long c = 0xffffffffUL;
  unsigned i, j;

  for (i = 0; i < n; i++)
    {
      c ^= s[i];

      for (j = 0; j < 8; j++)
        {
          c = (c & 1UL) ? ((c >> 1) ^ 0xedb88320UL) : (c >> 1);
        }
    }

  return c ^ 0xffffffffUL;
}

static int
make_empty (const char *name, int prefix)
{
  FILE *f = fopen (name, "wb");

  if (!f)
    {
      return 0;
    }

  if (prefix)
    {
      fwrite ("PREFIX", 1, 6, f);
    }

  w32 (f, 0x06054b50UL);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, 0);
  w32 (f, prefix ? 6 : 0);
  w16 (f, 0);

  return fclose (f) == 0;
}

static int
make_desc (const char *name, int signature)
{
  const unsigned char data[] = "Test descriptor payload";
  const unsigned long n = (unsigned long)sizeof (data) - 1;
  unsigned long d = crc (data, (size_t)n), cd, cdend;
  FILE *f = fopen (name, "wb");

  if (!f)
    {
      return 0;
    }

  w32 (f, 0x04034b50UL);
  w16 (f, 20);
  w16 (f, 8);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, 0);
  w32 (f, 0);
  w32 (f, 0);
  w16 (f, 4);
  w16 (f, 0);

  fwrite ("data", 1, 4, f);
  fwrite (data, 1, (size_t)n, f);

  if (signature)
    {
      w32 (f, 0x08074b50UL);
    }

  w32 (f, d);
  w32 (f, n);
  w32 (f, n);

  cd = (unsigned long)ftell (f);

  w32 (f, 0x02014b50UL);
  w16 (f, 20);
  w16 (f, 20);
  w16 (f, 8);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, d);
  w32 (f, n);
  w32 (f, n);
  w16 (f, 4);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, 0);
  w32 (f, 0);

  fwrite ("data", 1, 4, f);
  cdend = (unsigned long)ftell (f);

  w32 (f, 0x06054b50UL);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 1);
  w16 (f, 1);
  w32 (f, cdend - cd);
  w32 (f, cd);
  w16 (f, 0);

  return fclose (f) == 0;
}

/* A directory is a structural entry, don't recompress */
static int
make_stored (const char *path, const char *name, unsigned long n,
             int directory)
{
  FILE *f;
  unsigned char *data = NULL;
  unsigned long j, cd, cdend, d = 0, seed = 0x13579bdfUL;
  size_t name_len = strlen (name);

  if (n)
    {
      data = (unsigned char *)malloc ((size_t)n);

      if (!data)
        {
          return 0;
        }

      for (j = 0; j < n; j++)
        {
          seed = (seed * 1664525UL + 1013904223UL) & 0xffffffffUL;
          data[j] = (unsigned char)(seed >> 20);
        }

      d = crc (data, (size_t)n);
    }

  f = fopen (path, "wb");

  if (!f)
    {
      free (data);

      return 0;
    }

  w32 (f, 0x04034b50UL);
  w16 (f, 20);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, d);
  w32 (f, n);
  w32 (f, n);
  w16 (f, (unsigned)name_len);
  w16 (f, 0);

  fwrite (name, 1, name_len, f);

  if (n)
    {
      fwrite (data, 1, (size_t)n, f);
    }

  cd = (unsigned long)ftell (f);

  w32 (f, 0x02014b50UL);
  w16 (f, 20);
  w16 (f, 20);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, d);
  w32 (f, n);
  w32 (f, n);
  w16 (f, (unsigned)name_len);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 0);
  w32 (f, directory ? 0x10UL : 0UL);
  w32 (f, 0);

  fwrite (name, 1, name_len, f);

  cdend = (unsigned long)ftell (f);

  w32 (f, 0x06054b50UL);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 1);
  w16 (f, 1);
  w32 (f, cdend - cd);
  w32 (f, cd);
  w16 (f, 0);

  free (data);

  return fclose (f) == 0;
}

/*
 * Multiple members, including a directory between files, for verbose
 * display/record-separation regressions without relying on external Zip.
 */

static int
make_three (const char *path, int compressible_first)
{
  const char *names[3] = { "first.txt", "folder/", "folder/last.txt" };
  const char *values[3] = { "FIRST", "", "LAST" };
  char long_first[4096];
  unsigned long offsets[3], central, end;
  unsigned i;
  FILE *f;

  if (compressible_first)
    {
      memset (long_first, 'A', sizeof (long_first) - 1U);
      long_first[sizeof (long_first) - 1U] = '\0';
      values[0] = long_first;
    }

  f = fopen (path, "wb");

  if (!f)
    {
      return 0;
    }

  for (i = 0; i < 3; i++)
    {
      unsigned long n = (unsigned long)strlen (values[i]);
      unsigned long d = crc ((const unsigned char *)values[i], (size_t)n);
      unsigned len = (unsigned)strlen (names[i]);

      offsets[i] = (unsigned long)ftell (f);

      w32 (f, 0x04034b50UL);
      w16 (f, 20);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, d);
      w32 (f, n);
      w32 (f, n);
      w16 (f, len);
      w16 (f, 0);

      fwrite (names[i], 1, len, f);
      fwrite (values[i], 1, (size_t)n, f);
    }

  central = (unsigned long)ftell (f);

  for (i = 0; i < 3; i++)
    {
      unsigned long n = (unsigned long)strlen (values[i]);
      unsigned long d = crc ((const unsigned char *)values[i], (size_t)n);
      unsigned len = (unsigned)strlen (names[i]);

      w32 (f, 0x02014b50UL);
      w16 (f, 20);
      w16 (f, 20);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, d);
      w32 (f, n);
      w32 (f, n);
      w16 (f, len);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, i == 1 ? 0x10UL : 0UL);
      w32 (f, offsets[i]);

      fwrite (names[i], 1, len, f);
    }

  end = (unsigned long)ftell (f);

  w32 (f, 0x06054b50UL);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 3);
  w16 (f, 3);
  w32 (f, end - central);
  w32 (f, central);
  w16 (f, 0);

  return fclose (f) == 0;
}

/*
 * A 12-entry directory archive exercises multi-digit progress alignment
 * without relying on an installed Zip executable or external scripts.
 */

static int
make_twelve (const char *path)
{
  unsigned long offsets[12], cd, end;
  unsigned i;
  char name[5] = "d00/";
  FILE *f = fopen (path, "wb");

  if (!f)
    {
      return 0;
    }

  for (i = 0; i < 12; i++)
    {
      name[1] = (char)('0' + i / 10U);
      name[2] = (char)('0' + i % 10U);

      offsets[i] = (unsigned long)ftell (f);

      w32 (f, 0x04034b50UL);
      w16 (f, 20);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, 0);
      w32 (f, 0);
      w32 (f, 0);
      w16 (f, 4);
      w16 (f, 0);

      fwrite (name, 1, 4, f);
    }

  cd = (unsigned long)ftell (f);

  for (i = 0; i < 12; i++)
    {
      name[1] = (char)('0' + i / 10U);
      name[2] = (char)('0' + i % 10U);

      w32 (f, 0x02014b50UL);
      w16 (f, 20);
      w16 (f, 20);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, 0);
      w32 (f, 0);
      w32 (f, 0);
      w16 (f, 4);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w16 (f, 0);
      w32 (f, 0x10UL);
      w32 (f, offsets[i]);

      fwrite (name, 1, 4, f);
    }

  end = (unsigned long)ftell (f);

  w32 (f, 0x06054b50UL);
  w16 (f, 0);
  w16 (f, 0);
  w16 (f, 12);
  w16 (f, 12);
  w32 (f, end - cd);
  w32 (f, cd);
  w16 (f, 0);

  return fclose (f) == 0;
}

static int
make_bad_local_time (const char *target)
{
  FILE *f;

  if (!make_stored (target, "data", 0, 0))
    {
      return 0;
    }

  f = fopen (target, "rb+");

  if (!f)
    {
      return 0;
    }

  if (fseek (f, 10L, SEEK_SET) != 0 || fputc (0x57, f) == EOF)
    {
      fclose (f);
      return 0;
    }

  return fclose (f) == 0;
}

static int
make_bad_local_version (const char *target)
{
  FILE *f;

  if (!make_stored (target, "data", 0, 0))
    {
      return 0;
    }

  f = fopen (target, "rb+");

  if (!f)
    {
      return 0;
    }

  if (fseek (f, 4L, SEEK_SET) != 0 || fputc (21, f) == EOF
      || fputc (0, f) == EOF)
    {
      fclose (f);
      return 0;
    }

  return fclose (f) == 0;
}

int
main (void)
{
  if (!make_empty ("build/empty-structure.zip", 0)
      || !make_empty ("build/bad-empty-prefix.zip", 1)
      || !make_desc ("build/signed-desc.zip", 1)
      || !make_desc ("build/unsigned-desc.zip", 0)
      || !make_stored ("build/directory-structure.zip", "folder/", 0, 1)
      || !make_three ("build/three-structure.zip", 0)
      || !make_three ("build/three-mixed.zip", 1)
      || !make_twelve ("build/twelve-structure.zip")
      || !make_stored ("build/bad-directory.zip", "folder/", 1, 1)
      || !make_bad_local_version ("build/bad-local-version.zip")
      || !make_bad_local_time ("build/bad-local-timestamp.zip")
      || !make_stored ("build/interrupt-structure.zip", "slow.bin", 2000000UL,
                       0))
    {
      return 1;
    }

  return 0;
}
