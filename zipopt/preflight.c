/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Internal preflight harness (not final optimizer) */

#include "archive.h"
#include <stdio.h>

int
main (int argc, char **argv)
{
  zo_archive a;
  zo_u64 n;

  if (argc != 2)
    {
      fprintf (stderr, "usage: zipopt-preflight archive.zip\n");

      return 2;
    }

  if (!zo_archive_open (&a, argv[1]))
    {
      fprintf (stderr, "zipopt: rejected: %s\n", a.error);
      zo_archive_close (&a);

      return 1;
    }

  for (n = 0; n < a.count; n++)
    {
      printf ("%lu: method %u compressed %lu uncompressed %lu\n",
              (unsigned long)n, a.entries[(size_t)n].method,
              (unsigned long)a.entries[(size_t)n].csize,
              (unsigned long)a.entries[(size_t)n].usize);
    }

  zo_archive_close (&a);

  return 0;
}
