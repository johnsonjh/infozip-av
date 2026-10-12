/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Non-publishing index-based verification driver. */

#include "archive.h"
#include "extract.h"
#include <stdio.h>

int
main (int argc, char **argv)
{
  zo_archive a;
  zo_u64 i;

  if (argc != 2)
    {
      fprintf (stderr, "usage: zipopt-decodecheck input.zip\n");

      return 2;
    }

  if (!zo_archive_open (&a, argv[1]))
    {
      fprintf (stderr, "zipopt: rejected: %s\n", a.error);
      zo_archive_close (&a);

      return 1;
    }

  for (i = 0; i < a.count; i++)
    {
      FILE *tmp = tmpfile ();

      if (!tmp)
        {
          fprintf (stderr, "zipopt: cannot create temporary stream\n");
          zo_archive_close (&a);

          return 1;
        }

      if (!zo_extract_index (&a, i, tmp))
        {
          fprintf (stderr,
                   "zipopt: decode or integrity failure at index %lu\n",
                   (unsigned long)i);
          fclose (tmp);
          zo_archive_close (&a);

          return 1;
        }

      fclose (tmp);
    }

  fprintf (stderr, "zipopt: verified %lu members\n", (unsigned long)a.count);
  zo_archive_close (&a);

  return 0;
}
