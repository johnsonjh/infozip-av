/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* ZIP64 offset-only extraction version regression */

#ifndef _FILE_OFFSET_BITS
# define _FILE_OFFSET_BITS 64
#endif /* ifndef _FILE_OFFSET_BITS */
#if !defined(_POSIX_C_SOURCE)
# define _POSIX_C_SOURCE 200809L
#endif /* if !defined( _POSIX_C_SOURCE ) */

#include "../archive.h"
#include "../writer.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static unsigned
u16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned long
u32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

int
main (void)
{
  zo_archive src;
  zo_writer w;
  zo_u64 start = ((zo_u64)1 << 32) + 8192U;
  zo_u64 central = 0;
  unsigned char local[30], cen[46];
  int ok = 0;

  memset (&src, 0, sizeof (src));
  memset (&w, 0, sizeof (w));

  if (!zo_archive_open (&src, "build/directory-structure.zip"))
    {
      goto done;
    }

  if (!zo_writer_begin (&w, &src, "build/zip64-offset-probe.zip"))
    {
      goto done;
    }

  /*
   * Create a sparse >4 GiB offset without writing gigabytes of data.
   * This directly exercises writer header consistency; the prefix is
   * intentionally a hole and not a second ZIP member.
   */

  if (fseeko (w.stream, (off_t)start, SEEK_SET) != 0
      || !zo_writer_add (&w, 0, NULL, 0, 0, 0))
    {
      goto done;
    }

  if ((central = (zo_u64)ftello (w.stream)) < start
      || !zo_writer_complete (&w))
    {
      goto done;
    }

  if (fflush (w.stream) != 0 || fseeko (w.stream, (off_t)start, SEEK_SET) != 0
      || fread (local, 1, sizeof (local), w.stream) != sizeof (local)
      || fseeko (w.stream, (off_t)central, SEEK_SET) != 0
      || fread (cen, 1, sizeof (cen), w.stream) != sizeof (cen))
    {
      goto done;
    }

  if (u32 (local) != 0x04034b50UL || u32 (cen) != 0x02014b50UL
      || u16 (local + 4) != 45 || u16 (cen + 6) != 45
      || u32 (cen + 42) != 0xffffffffUL || u32 (local + 18) != 0
      || u32 (local + 22) != 0)
    {
      goto done;
    }

  ok = 1;

done:
  zo_writer_abort (&w);
  zo_archive_close (&src);

  if (ok)
    {
      puts ("PASS: ZIP64 offset-only extraction versions agree");
    }
  else
    {
      fputs ("FAIL: ZIP64 offset-only extraction version mismatch\n", stderr);
    }

  return ok ? 0 : 1;
}
