/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* private zipopt embedded UnZip adapter */

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(OS2)
#define UNIX 1
#endif
#define DLL 1
#define ZIPOPT_EMBED 1

#include "../unzip60/unzip.h"

#ifdef ZO_WITH_LIBDEFLATE
/* The private UnZip parser resets its decoder settings on *every* invocation.
 * Carry zipopt's last size argument through to each indexed extraction. */
const char *zo_unzip_libdeflate_size_arg;
#endif
#include "extract.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Match the CRC provider used by the private UnZip objects.  External
 * Deflate backends suppress UnZip's standalone crc32() symbol. */
#if defined(ZO_USE_ZLIB_NG)
# include <zlib-ng.h>
#elif defined(ZO_USE_ZLIB)
# include <zlib.h>
#else
extern ulg crc32 (ulg crc, const uch *buf, size_t len);
#if defined(OS2) && defined(__WATCOMC__)
#pragma aux crc32 "_*" parm caller [] value [eax] modify [eax]
#endif
#endif

struct zo_sink
{
  FILE *file;
  zo_u64 count;
  unsigned long crc;
  int failed;
  int size_overflow, write_failed, write_errno;
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
UZ_EXP zo_unzip_msg (zvoid *g, uch *p, ulg n, int flag)
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

  if ((zo_u64)n > ((zo_u64)-1) - s->count)
    {
      s->size_overflow = 1;
      s->failed = 1;
      return 1;
    }
  if (fwrite (p, 1, (size_t)n, s->file) != (size_t)n)
    {
      s->write_failed = 1;
      s->write_errno = errno;
      s->failed = 1;
      return 1;
    }

  s->count += (zo_u64)n;
  s->crc = zo_crc (s->crc, p, n);

  return 0;
}

int
zo_extract_index_report (const zo_archive *a, zo_u64 i, FILE *out,
                         zo_extract_report *report)
{
  UzpInit init;
  struct zo_sink sink;
  char *args[7];
  int argc;
  int rc;

  if (report)
    {
      memset (report, 0, sizeof (*report));
      report->unzip_status = -1;
    }

  if (!a || !out || i >= a->count || i > (zo_u64)ULONG_MAX || zo_active_sink)
    {
      return 0;
    }

#ifdef ZO_TEST_PPMD_VERIFY_OOM
  /* Test-only fault injection: the original input is STORE, so a failure
   * here proves that final verification rejects a PPMd candidate and
   * retries the entire output without publishing the rejected archive. */
  if (a->entries[(size_t)i].method == 98U
      && getenv ("ZO_TEST_PPMD_VERIFY_OOM") != NULL)
    {
      if (report)
        report->unzip_status = 6;
      return 0;
    }
#endif

  memset (&init, 0, sizeof (init));
  init.structlen = sizeof (init);
  init.msgfn = zo_unzip_msg;
  memset (&sink, 0, sizeof (sink));
  sink.file = out;
  sink.crc = 0xffffffffUL;
  zo_active_sink = &sink;
  argc = 0;
  args[argc++] = "unzip";
  args[argc++] = "-p";
#ifdef ZO_WITH_LIBDEFLATE
  args[argc++] = "--use-libdeflate";
  if (zo_unzip_libdeflate_size_arg)
    {
      args[argc++] = "--libdeflate-size";
      args[argc++] = (char *)zo_unzip_libdeflate_size_arg;
    }
#endif
  args[argc++] = (char *)a->path;
  args[argc] = NULL;
  errno = 0;
  rc = UzpAltMainIndex (argc, args, &init, (unsigned long)i);
  if (report)
    {
      report->unzip_status = rc;
      report->unzip_errno = errno;
      report->written = sink.count;
      report->crc = sink.crc ^ 0xffffffffUL;
      report->size_overflow = sink.size_overflow;
      report->write_failed = sink.write_failed;
      report->write_errno = sink.write_errno;
    }
  zo_active_sink = NULL;

  if (rc != 0 || sink.failed || sink.count != a->entries[(size_t)i].usize
      || (sink.crc ^ 0xffffffffUL) != a->entries[(size_t)i].crc)
    {
      return 0;
    }

  if (fflush (out) != 0)
    {
      if (report)
        {
          report->flush_failed = 1;
          report->flush_errno = errno;
        }
      return 0;
    }

  return 1;
}

int
zo_extract_index (const zo_archive *a, zo_u64 i, FILE *out)
{
  return zo_extract_index_report (a, i, out, NULL);
}
