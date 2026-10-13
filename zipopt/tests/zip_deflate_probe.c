/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* probe for the bundled raw Deflate adapter */

#include "../zip_deflate.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct io_state
{
  FILE *src;
  FILE *dst;
  unsigned chunk;
  int fail_output;
} io_state;

static unsigned
read_cb (void *opaque, unsigned char *buffer, unsigned size)
{
  io_state *s = (io_state *)opaque;

  if (size > s->chunk)
    {
      size = s->chunk;
    }

  return (unsigned)fread (buffer, 1, size, s->src);
}

static int
write_cb (void *opaque, const unsigned char *buffer, unsigned size)
{
  io_state *s = (io_state *)opaque;

  if (s->fail_output && size)
    {
      return 1;
    }

  return fwrite (buffer, 1, size, s->dst) != size;
}

int
main (int argc, char **argv)
{
  io_state s;
  unsigned n, repeat;
  int level;

  if (argc != 6)
    {
      return 2;
    }

  level = atoi (argv[1]);
  s.chunk = (unsigned)atoi (argv[4]);
  repeat = (unsigned)atoi (argv[5]);

  if (s.chunk == 0 || repeat == 0 || level < 1 || level > 9)
    {
      return 2;
    }

  s.fail_output = 0;

  while (repeat--)
    {
      s.src = fopen (argv[2], "rb");
      s.dst = fopen (argv[3], "wb");

      if (!s.src || !s.dst)
        {
          return 3;
        }

      n = zo_zip_internal_deflate (read_cb, write_cb, &s, (unsigned)level);

      if (ferror (s.src) || ferror (s.dst))
        {
          n = 0;
        }

      if (fclose (s.dst) || fclose (s.src) || !n)
        {
          return 4;
        }
    }

  return 0;
}
