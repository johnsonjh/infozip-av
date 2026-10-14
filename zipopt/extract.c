/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* private zipopt embedded UnZip adapter */

#if !defined(_WIN32) && !defined(__DJGPP__)
#define UNIX 1
#endif
#define DLL 1
#define ZIPOPT_EMBED 1

#include "../unzip60/unzip.h"
#include "extract.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Match the CRC provider used by the private UnZip objects.  External
 * Deflate backends suppress UnZip's standalone crc32() symbol. */
#if defined(ZO_USE_ZLIB_NG)
# include <zlib-ng.h>
#elif defined(ZO_USE_ZLIB)
# include <zlib.h>
#else
extern ulg crc32 (ulg crc, const uch *buf, size_t len);
#endif

struct zo_sink
{
  FILE *file;
  zo_u64 count;
  unsigned long crc;
  int failed;
};

static struct zo_sink *zo_active_sink;

static unsigned long
zo_crc (unsigned long crc, const unsigned char *p, ulg n)
{
  while (n != 0)
    {
      unsigned int take = n > (ulg)UINT_MAX ? UINT_MAX : (unsigned int)n;
#if defined(ZO_USE_ZLIB_NG)
      crc = (unsigned long)zng_crc32_z ((uint32_t)(crc ^ 0xffffffffUL),
                                       (const uint8_t *)p, (size_t)take)
            ^ 0xffffffffUL;
#elif defined(ZO_USE_ZLIB)
      crc = (unsigned long)crc32 ((uLong)(crc ^ 0xffffffffUL),
                                 (const Bytef *)p, (uInt)take)
            ^ 0xffffffffUL;
#else
      crc = (unsigned long)crc32 ((ulg)(crc ^ 0xffffffffUL), p,
                                 (size_t)take) ^ 0xffffffffUL;
#endif
      crc &= 0xffffffffUL;
      p += take;
      n -= take;
    }

  return crc & 0xffffffffUL;
}

static int
zo_unzip_msg (zvoid *g, uch *p, ulg n, int flag)
{
  struct zo_sink *s = zo_active_sink;

  (void)g;

  if (flag != 0)
    {
      return 0;
    }

  if (s == NULL || s->failed)
    {
      return 1;
    }

  if ((zo_u64)n > ((zo_u64)-1) - s->count
      || fwrite (p, 1, (size_t)n, s->file) != (size_t)n)
    {
      s->failed = 1;

      return 1;
    }

  s->count += (zo_u64)n;
  s->crc = zo_crc (s->crc, p, n);

  return 0;
}

int
zo_extract_index (const zo_archive *a, zo_u64 i, FILE *out)
{
  UzpInit init;
  struct zo_sink sink;
  char *args[4];
  int rc;

  if (!a || !out || i >= a->count || i > (zo_u64)ULONG_MAX || zo_active_sink)
    {
      return 0;
    }

  memset (&init, 0, sizeof (init));
  init.structlen = sizeof (init);
  init.msgfn = zo_unzip_msg;
  memset (&sink, 0, sizeof (sink));
  sink.file = out;
  sink.crc = 0xffffffffUL;
  zo_active_sink = &sink;
  args[0] = "unzip";
  args[1] = "-p";
  args[2] = (char *)a->path;
  args[3] = NULL;
  rc = UzpAltMainIndex (3, args, &init, (unsigned long)i);
  zo_active_sink = NULL;

  if (rc != 0 || sink.failed || sink.count != a->entries[(size_t)i].usize
      || (sink.crc ^ 0xffffffffUL) != a->entries[(size_t)i].crc
      || fflush (out) != 0)
    {
      return 0;
    }

  return 1;
}
