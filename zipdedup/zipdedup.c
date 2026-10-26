/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#undef ZD_VER
#define ZD_VER "0.7"

#undef ZD_DATE
#define ZD_DATE "2026-10-26"

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(ZD_DOS16) && !defined(OS2) && !defined(_FILE_OFFSET_BITS)
# define _FILE_OFFSET_BITS 64
#endif /* _FILE_OFFSET_BITS */

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(ZD_DOS16) && !defined(OS2) && !defined(_POSIX_C_SOURCE)
# define _POSIX_C_SOURCE 200809L
#endif /* ifndef _POSIX_C_SOURCE */

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(ZD_DOS16) && !defined(OS2)
#define UNIX 1
#endif
#define DLL 1

#include "../unzip60/izsha1.h"
#include "fwkcs_md5.h"
#include "../unzip60/unzip.h"
#include "../common/xtrlibdeflate_size.h"

#if defined(USE_ZLIB_NG)
# include "../unzip60/iz_native_zlibng.h"
#elif defined(USE_ZLIB)
# include <zlib.h>
#else
#if defined(ZD_DOS16)
/* UnZip's CRC routine is compiled with the Watcom cdecl/stack ABI. */
extern unsigned long __cdecl crc32 (unsigned long, const unsigned char *, size_t);
#else
extern unsigned long crc32 (unsigned long, const unsigned char *, size_t);
#if defined(OS2) && defined(__WATCOMC__)
#pragma aux crc32 "_*" parm caller [] value [eax] modify [eax]
#endif
#endif
#endif

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XTR_REWRITE_IMPLEMENTATION
#include "../xtrmeta/xtrrewrite.h"
#include "../xtrmeta/xtrv1.h"
#include "../xtrmeta/xtrverify_inline.h"
#include "../xtrmeta/source_epoch.h"
#define XTR_SDE_NEED_DOS 1
#define XTR_SDE_NEED_EXTRAS 1
#include "../xtrmeta/source_epoch_times.h"
#include <time.h>
#ifdef _WIN32
# include <io.h>
# include <fcntl.h>
# include "../zipopt/win32_port.h"
# define unlink _unlink
# define close _close
# define fdopen _fdopen
# define mkstemp iz_win_mkstemp
# define link(a,b) iz_win_publish_noreplace((a),(b))
#elif defined(ZD_DOS16)
# include "dos16_port.h"
# include <io.h>
#elif defined(OS2)
# include <io.h>
# include <fcntl.h>
# include "../zipopt/os2_port.h"
# define mkstemp iz_os2_mkstemp
# define link(a,b) iz_os2_publish_noreplace((a),(b))
#elif defined(__DJGPP__)
# include <unistd.h>
# include "../zipopt/dos386_port.h"
#else
# include <unistd.h>
#endif

extern unsigned long refptr9903_crc (unsigned long, unsigned int, unsigned int,
                                     unsigned long, const unsigned char[16]);

#define ZD_CEN 0x02014b50UL
#define ZD_LOC 0x04034b50UL
#define ZD_END 0x06054b50UL
#define ZD_Z64 0x06064b50UL
#define ZD_ZLOC 0x07064b50UL
#define ZD_DIGSIG 0x05054b50UL
#define ZD_REFPTR 92U
#define ZD_APKALIGN 0xd935U
#define ZD_APACHEALIGN 0xa11eU

/* Small limit for TESTING ONLY - production builds always use LONG_MAX */
#ifndef ZD_POS_MAX
# define ZD_POS_MAX LONG_MAX
#endif

/* zipdedup uses UnZip's public API, so unzip.h unfortunately does not define
 * the internal USE_XCEED_BWT macro for this compilation unit so copy here. */
#if !defined(NO_XCEED_BWT) && !defined(__16BIT__) && \
    !defined(MEMORY16) && !defined(SMALL_MEM) && !defined(MED_MEM) && \
    !defined(FUNZIP) && !defined(NO_LIMITS_H) && \
    !(defined(MSDOS) && !defined(__DJGPP__) && !defined(__GO32__)) && \
    UINT_MAX >= 0xffffffffUL && ULONG_MAX >= 0xffffffffUL && CHAR_BIT == 8
# define ZD_HAVE_XCEED_BWT 1
#endif


struct zd_entry
{
  unsigned char *cen;
  unsigned long cenlen;
  unsigned char *loc;
  unsigned long loclen;
  char *name;
  unsigned long off, next_off, usize, csize, crc;
  unsigned long new_off;
  unsigned method, flags, dostime, dosdate;
  unsigned csz64, usz64, off64, lcsz64, lusz64;
  unsigned char sha1[20], uuid[16];
  int digest_valid, has_ref, selected, is_source, source_index;
  xr_node xtr;
  int add_md5;
  unsigned char md5[16];
};

struct zd_archive
{
  FILE *in;
  unsigned long bytes, cd_off, cd_size, count, commentlen;
  unsigned char *comment;
  struct zd_entry *members;
  unsigned long *order;
  const char *input, *output;
  int force, verbose, quiet, fwkcs_md5;
};

static const char *zd_error;
static int zd_verbose;
static int zd_xld_enabled;
static const char *zd_xld_size_arg;

/* Every internal UnZip API invocation receives the same opt-in.  Do not
 * preserve an UnZip global across calls: uz_opts() resets it per invocation. */
static int zd_unzip_arguments(char *args[8], const char *archive,
                              const char *member)
{
  int argc = 0;
  args[argc++] = "unzip";
  args[argc++] = "-p";
  if (zd_xld_enabled) args[argc++] = "--use-libdeflate";
  if (zd_xld_size_arg) {
    args[argc++] = "--libdeflate-size";
    args[argc++] = (char *)zd_xld_size_arg;
  }
  args[argc++] = (char *)archive;
  args[argc++] = (char *)member;
  args[argc] = NULL;
  return argc;
}
static int zd_sde_active;
static unsigned long zd_sde_epoch;

static int
zd_sde_init (void)
{
  const char *s = getenv ("SOURCE_DATE_EPOCH");
  time_t converted;
  if (s == NULL)
    return 1;
  if (!xtr_source_epoch_parse (s, &zd_sde_epoch))
    {
      fputs ("zipdedup: invalid SOURCE_DATE_EPOCH (required range "
             "315532800..2147483647)\n", stderr);
      return 0;
    }
  converted = (time_t)zd_sde_epoch;
  if ((unsigned long)converted != zd_sde_epoch || gmtime (&converted) == NULL)
    {
      fputs ("zipdedup: SOURCE_DATE_EPOCH not supported by time_t\n", stderr);
      return 0;
    }
  zd_sde_active = 1;
  s = getenv ("SOURCE_DATE_EPOCH_INSECURE");
  if (s != NULL && *s != '\0')
    fputs ("WARNING: SOURCE_DATE_EPOCH_INSECURE permits deterministic, "
           "CRYPTOGRAPHICALLY INSECURE encryption randomness!\n", stderr);
  return 1;
}

/*
 * Reject oversized in-core structures before any narrowing
 * cast. Data payload copying remains streaming
 */

#if defined(ZD_DOS16)
# define ZD_DOS16_MAX_ALLOC 60000UL
#endif

static void
zd_fail (const char *s)
{
  if (zd_error == NULL)
    {
      zd_error = s;
    }
}

static unsigned
zd_u16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned long
zd_u32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static void
zd_w16 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char)v;
  p[1] = (unsigned char)(v >> 8);
}

static void
zd_w32 (unsigned char *p, unsigned long v)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      p[i] = (unsigned char)(v & 255UL);
      v >>= 8;
    }
}

static void
zd_w64 (unsigned char *p, unsigned long v)
{
  unsigned i;

  for (i = 0; i < 8; i++)
    {
      p[i] = (unsigned char)(v & 255UL);
      v >>= 8;
    }
}

static int
zd_r64 (const unsigned char *p, unsigned long *v)
{
  unsigned i;
  unsigned long a = 0;

  for (i = 8; i > 0; i--)
    {
      if (a > (ULONG_MAX - (unsigned long)p[i - 1]) / 256UL)
        {
          return 0;
        }

      a = a * 256UL + (unsigned long)p[i - 1];
    }

  *v = a;
  return 1;
}

static int
zd_at (FILE *f, unsigned long off)
{
  if (off > (unsigned long)LONG_MAX || fseek (f, (long)off, SEEK_SET) != 0)
    {
      zd_fail ("file offset is unsupported by this platform or seek failed");
      return 0;
    }

  return 1;
}

static int
zd_read (FILE *f, void *p, size_t n)
{
  if (fread (p, 1, n, f) != n)
    {
      zd_fail ("truncated ZIP input");
      return 0;
    }

  return 1;
}

static int
zd_write (FILE *f, const void *p, size_t n)
{
  long pos = ftell (f);

  if (pos < 0 || pos > ZD_POS_MAX
      || (unsigned long)n > (unsigned long)(ZD_POS_MAX - pos))
    {
      zd_fail ("output ZIP exceeds this build's LONG_MAX file-offset limit");
      return 0;
    }

  if (fwrite (p, 1, n, f) != n)
    {
      zd_fail ("write failed");
      return 0;
    }

  return 1;
}

/* Check large inputs before entering the long-based ftell/fseek */
static int
zd_input_representable (FILE *in)
{
#if defined(_WIN32) || defined(OS2)
  __int64 size = _filelengthi64 (_fileno (in));
  if (size < 0)
#else
  struct stat sb;
  if (fstat (fileno (in), &sb) != 0 || sb.st_size < 0)
#endif
    {
      zd_fail ("internal error: unable to determine input size");
      return 0;
    }

#if defined(_WIN32) || defined(OS2)
  if ((unsigned __int64)size > (unsigned long)ZD_POS_MAX)
#else
  if (sb.st_size > (off_t)ZD_POS_MAX)
#endif
    {
      zd_fail ("input ZIP exceeds the builds support file offset limit");

      return 0;
    }

  return 1;
}

static int
zd_has (const unsigned char *p, unsigned n, unsigned tag, unsigned *offset,
        unsigned *length)
{
  unsigned pos = 0, k, l;

  while (pos < n)
    {
      if (n - pos < 4)
        {
          zd_fail ("malformed extra-field header");
          return -1;
        }

      k = zd_u16 (p + pos);
      l = zd_u16 (p + pos + 2);
      if (l > n - pos - 4)
        {
          zd_fail ("malformed extra-field size");
          return -1;
        }

      if (k == tag)
        {
          if (offset)
            {
              *offset = pos;
            }

          if (length)
            {
              *length = l;
            }

          return 1;
        }

      pos += (unsigned)(4 + l);
    }
  return 0;
}

static int
zd_parse_z64 (struct zd_entry *e)
{
  unsigned pos = 0, n = 0, ret;
  unsigned char *p = e->cen + 46 + zd_u16 (e->cen + 28);
  unsigned exlen = zd_u16 (e->cen + 30);

  ret = (unsigned)zd_has (p, exlen, 1, &pos, &n);
  if (ret == (unsigned)-1)
    {
      return 0;
    }

  if ((e->usz64 || e->csz64 || e->off64) && ret != 1)
    {
      zd_fail ("missing ZIP64 central-directory extra");
      return 0;
    }

  if (ret == 1)
    {
      unsigned char *d = p + pos + 4;
      if (e->usz64)
        {
          if (n < 8 || !zd_r64 (d, &e->usize))
            {
              goto invalid;
            }

          d += 8;
          n -= 8;
        }

      if (e->csz64)
        {
          if (n < 8 || !zd_r64 (d, &e->csize))
            {
              goto invalid;
            }

          d += 8;
          n -= 8;
        }

      if (e->off64)
        {
          if (n < 8 || !zd_r64 (d, &e->off))
            {
              goto invalid;
            }

          d += 8;
          n -= 8;
        }
    }

  return 1;

invalid:
  zd_fail ("invalid ZIP64 central-directory extra");
  return 0;
}

static int
zd_find_end (struct zd_archive *a)
{
  unsigned char *buf;
  unsigned long start, len, j, off = 0;
  unsigned n, disk, cdisk, entries, entries_disk;
  unsigned char hdr[56];

  if (fseek (a->in, 0, SEEK_END) != 0 || ftell (a->in) < 0)
    {
      zd_fail ("cannot determine ZIP length");
      return 0;
    }

  a->bytes = (unsigned long)ftell (a->in);
  len = a->bytes < 65557UL ? a->bytes : 65557UL;
#ifdef ZD_DOS16
  /* Limit in-core EOCD scan; comments requiring a larger tail are not
   * supported in the DOS16 experimental build. */
  if (len > ZD_DOS16_MAX_ALLOC) len = ZD_DOS16_MAX_ALLOC;
#endif
  start = a->bytes - len;
  buf = (unsigned char *)malloc ((size_t)(len ? len : 1));
  if (!buf)
    {
      zd_fail ("out of memory");
      return 0;
    }

  if (!zd_at (a->in, start) || !zd_read (a->in, buf, (size_t)len))
    {
      free (buf);
      return 0;
    }

  for (j = len; j >= 22; j--)
    {
      if (zd_u32 (buf + j - 22) != ZD_END)
        {
          continue;
        }

      n = zd_u16 (buf + j - 22 + 20);
      if (j - 22 + 22 + (unsigned long)n == len)
        {
          off = start + j - 22;
          break;
        }
    }

  if (j < 22)
    {
      free (buf);
#ifdef ZD_DOS16
      zd_fail ("ZIP end record not found within DOS 60000-byte scan limit");
#else
      zd_fail ("end of central directory not found");
#endif
      return 0;
    }

  disk = zd_u16 (buf + j - 22 + 4);
  cdisk = zd_u16 (buf + j - 22 + 6);
  entries_disk = zd_u16 (buf + j - 22 + 8);
  entries = zd_u16 (buf + j - 22 + 10);
  a->count = entries;
  a->cd_size = zd_u32 (buf + j - 22 + 12);
  a->cd_off = zd_u32 (buf + j - 22 + 16);
  a->commentlen = zd_u16 (buf + j - 22 + 20);
  a->comment
      = (unsigned char *)malloc ((size_t)(a->commentlen ? a->commentlen : 1));
  if (!a->comment)
    {
      free (buf);
      zd_fail ("out of memory");
      return 0;
    }

  memcpy (a->comment, buf + j, a->commentlen);
  free (buf);
  if (disk || cdisk || (entries != entries_disk && entries_disk != 65535U))
    {
      zd_fail ("split/multi-disk ZIP archives are not supported");
      return 0;
    }

  if (a->count == 65535UL || a->cd_size == 0xffffffffUL
      || a->cd_off == 0xffffffffUL)
    {
      unsigned long p64, count2;
      if (off < 20 || !zd_at (a->in, off - 20) || !zd_read (a->in, hdr, 20))
        {
          return 0;
        }

      if (zd_u32 (hdr) != ZD_ZLOC || zd_u32 (hdr + 4) != 0
          || zd_u32 (hdr + 16) != 1 || !zd_r64 (hdr + 8, &p64))
        {
          zd_fail ("invalid ZIP64 locator");
          return 0;
        }

      if (!zd_at (a->in, p64) || !zd_read (a->in, hdr, 56))
        {
          return 0;
        }

      if (zd_u32 (hdr) != ZD_Z64 || zd_u32 (hdr + 4) != 44UL
          || zd_u32 (hdr + 8) != 0 || zd_u32 (hdr + 16) != 0
          || zd_u32 (hdr + 20) != 0 || !zd_r64 (hdr + 24, &count2)
          || !zd_r64 (hdr + 32, &a->count) || count2 != a->count
          || !zd_r64 (hdr + 40, &a->cd_size))
        {
          zd_fail ("invalid ZIP64 end record");
          return 0;
        }

      /* ZIP64 CD offset is at byte 48? ZIP64 EOCD: size[8],vermade2,
       * verneed2,disk4,cdisk4,entriesdisk8,totalentries8,size8,offset8 */
      if (!zd_at (a->in, p64 + 48) || !zd_read (a->in, hdr, 8)
          || !zd_r64 (hdr, &a->cd_off))
        {
          return 0;
        }
    }

  if (a->cd_off > a->bytes || a->cd_size > a->bytes - a->cd_off
      || a->count > 10000000UL
      || a->count > ULONG_MAX / sizeof (struct zd_entry))
    {
      zd_fail ("invalid central-directory bounds");
      return 0;
    }

  return 1;
}

static int
zd_load (struct zd_archive *a)
{
  unsigned long i, here, limit;
  unsigned char hdr[46];

  if (!zd_find_end (a))
    {
      return 0;
    }

  if (a->count == 0)
    {
      return 1;
    }

#ifdef ZD_DOS16
  if (a->count > ZD_DOS16_MAX_ALLOC / sizeof (*a->members)
      || a->count > ZD_DOS16_MAX_ALLOC / sizeof (*a->order))
    {
      zd_fail ("DOS member table exceeds segment allocation limit");
      return 0;
    }
#endif
  a->members
      = (struct zd_entry *)calloc ((size_t)a->count, sizeof (*a->members));
  a->order = (unsigned long *)malloc ((size_t)a->count * sizeof (*a->order));
  if (!a->members || !a->order)
    {
      zd_fail ("out of memory");
      return 0;
    }

  here = a->cd_off;
  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + i;
      unsigned long n;
      unsigned nam, extr, com, off, xlen;
      int r;
      if (!zd_at (a->in, here) || !zd_read (a->in, hdr, sizeof (hdr)))
        {
          return 0;
        }

      if (zd_u32 (hdr) != ZD_CEN)
        {
          zd_fail ("invalid central-directory signature");
          return 0;
        }

      nam = zd_u16 (hdr + 28);
      extr = zd_u16 (hdr + 30);
      com = zd_u16 (hdr + 32);
      n = 46UL + (unsigned long)nam + extr + com;
      if (n > a->cd_size || here > a->cd_off + a->cd_size - n)
        {
          zd_fail ("central-directory entry exceeds bounds");
          return 0;
        }

#ifdef ZD_DOS16
      if (n > ZD_DOS16_MAX_ALLOC || (unsigned long)nam + 1UL > ZD_DOS16_MAX_ALLOC)
        {
          zd_fail ("DOS central-directory record exceeds segment limit");
          return 0;
        }
#endif
      e->cen = (unsigned char *)malloc ((size_t)n);
      e->name = (char *)malloc ((size_t)nam + 1);
      if (!e->cen || !e->name)
        {
          zd_fail ("out of memory");
          return 0;
        }

      memcpy (e->cen, hdr, 46);
      if (!zd_read (a->in, e->cen + 46, (size_t)(n - 46)))
        {
          return 0;
        }

      memcpy (e->name, e->cen + 46, nam);
      e->name[nam] = '\0';
      if (memchr (e->name, 0, nam) != NULL)
        {
          zd_fail ("NUL in ZIP member name");
          return 0;
        }

      e->cenlen = n;
      e->method = zd_u16 (hdr + 10);
      e->flags = zd_u16 (hdr + 8);
      e->dostime = zd_u16 (hdr + 12);
      e->dosdate = zd_u16 (hdr + 14);
      e->crc = zd_u32 (hdr + 16);
      e->csize = zd_u32 (hdr + 20);
      e->usize = zd_u32 (hdr + 24);
      e->off = zd_u32 (hdr + 42);
      e->csz64 = (e->csize == 0xffffffffUL);
      e->usz64 = (e->usize == 0xffffffffUL);
      e->off64 = (e->off == 0xffffffffUL);

      if (zd_u16 (hdr + 34) != 0 || (e->flags & 0x41U))
        {
          zd_fail ("split or encrypted archive/member rejected");
          return 0;
        }

      if ((zd_u16 (hdr + 4) >> 8) == 0x08 && (e->flags & 1))
        {
          zd_fail ("encrypted member rejected");
          return 0;
        }

      if (zd_has (e->cen + 46 + nam, extr, 7, NULL, NULL) != 0
          || zd_has (e->cen + 46 + nam, extr, 0x9901, NULL, NULL) != 0
          || zd_has (e->cen + 46 + nam, extr, 0x0014, NULL, NULL) != 0)
        {
          zd_fail ("PKAV, AES, or authenticated signature metadata rejected");
          return 0;
        }

      /* Xtro owner metadata must remain attached to the original member.
       * Validate the complete extra list; owners and sidecars will be
       * excluded from RefPtr selection while unrelated members can dedup. */
      if (!xr_scan(e->cen + 46 + nam, extr, 1, &e->xtr)) {
        zd_fail("malformed or duplicated Xtro central extra");return 0;
      }
      {
        unsigned char sideid[16];
        int kind=xr_name((const unsigned char *)e->name,nam,sideid);
        if (e->xtr.role && e->xtr.header[7]) {
          zd_fail("encrypted Xtro metadata unsupported in ZipDedup");return 0;
        }
        if (kind<0 || (kind==1 && e->xtr.role)) {
          zd_fail("invalid Xtro reserved name");return 0;
        }
        if (kind==1) {
          if (e->method!=0U && e->method!=8U) {
            zd_fail("unsupported Xtro companion compression");return 0;
          }
          e->xtr.role=3;
          memcpy(e->xtr.id,sideid,16);
        }
      }

      r = zd_has (e->cen + 46 + nam, extr, 0x9903, &off, &xlen);

      if (r < 0)
        {
          return 0;
        }

      if (r)
        {
          if (xlen != 20)
            {
              zd_fail ("malformed 0x9903 reference extra");
              return 0;
            }

          e->has_ref = 1;
          memcpy (e->uuid, e->cen + 46 + nam + off + 8, 16);

          if (zd_u32 (e->cen + 46 + nam + off + 4)
              != refptr9903_crc ((unsigned long)e->method, e->dostime,
                                 e->dosdate, e->crc, e->uuid))
            {
              zd_fail ("invalid existing WinZip 0x9903 checksum");
              return 0;
            }
        }

      if (!zd_parse_z64 (e))
        {
          return 0;
        }

      if (e->method == ZD_REFPTR && e->csize != 20)
        {
          zd_fail ("method 92 members must have a 20-byte SHA-1 payload");
          return 0;
        }

      a->order[i] = i;
      if (here > ULONG_MAX - n)
        {
          zd_fail ("ZIP directory position overflow");
          return 0;
        }

      here += n;
    }

  limit = a->cd_off + a->cd_size;
  if (here < limit)
    {
      unsigned char tail[6];
      if (limit - here < 6 || !zd_at (a->in, here) || !zd_read (a->in, tail, 6)
          || zd_u32 (tail) != ZD_DIGSIG)
        {
          zd_fail ("unexpected central directory trailing data");
          return 0;
        }

      zd_fail ("digitally signed central directory cannot be rewritten");
      return 0;
    }

  if (here != limit)
    {
      zd_fail ("central-directory size mismatch");
      return 0;
    }

  /* Sort local header offset because central order must remain unchanged! */
  for (i = 1; i < a->count; i++)
    {
      unsigned long idx = a->order[i], j = i;
      while (j > 0 && a->members[a->order[j - 1]].off > a->members[idx].off)
        {
          a->order[j] = a->order[j - 1];
          j--;
        }
      a->order[j] = idx;
    }

  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + a->order[i];
      unsigned long next
          = (i + 1 < a->count) ? a->members[a->order[i + 1]].off : a->cd_off;
      unsigned char lhdr[30];
      unsigned ln, lex, lpos = 0, lcount = 0;
      int r;
      if (e->off >= next || next > a->cd_off || e->off > ULONG_MAX - 30
          || e->off + 30 > next)
        {
          zd_fail ("overlapping or invalid local entries");
          return 0;
        }

      if (!zd_at (a->in, e->off) || !zd_read (a->in, lhdr, 30))
        {
          return 0;
        }

      if (zd_u32 (lhdr) != ZD_LOC || zd_u16 (lhdr + 8) != e->method
          || zd_u16 (lhdr + 6) != e->flags)
        {
          zd_fail ("local/central header mismatch");
          return 0;
        }

      ln = zd_u16 (lhdr + 26);
      lex = zd_u16 (lhdr + 28);
      if (30UL + ln + lex > next - e->off || ln != zd_u16 (e->cen + 28))
        {
          zd_fail ("invalid local header bounds or name mismatch");
          return 0;
        }

      e->loclen = 30UL + ln + lex;
      e->next_off = next;
      if (e->csize > next - e->off - e->loclen)
        {
          zd_fail ("compressed member extends past next entry");
          return 0;
        }

#ifdef ZD_DOS16
      if (e->loclen > ZD_DOS16_MAX_ALLOC)
        {
          zd_fail ("DOS local-header record exceeds segment limit");
          return 0;
        }
#endif
      e->loc = (unsigned char *)malloc ((size_t)e->loclen);
      if (!e->loc)
        {
          zd_fail ("out of memory");
          return 0;
        }

      memcpy (e->loc, lhdr, 30);
      if (!zd_read (a->in, e->loc + 30, (size_t)(e->loclen - 30)))
        {
          return 0;
        }

      if (memcmp (e->loc + 30, e->cen + 46, ln) != 0)
        {
          zd_fail ("local and central member names differ");
          return 0;
        }

      if (e->xtr.role==3) {
        xr_node local;
        memset(&local,0,sizeof(local));
        if (!xr_scan(e->loc + 30 + ln,lex,0,&local)) {
          zd_fail("unexpected Xtro local field on companion");return 0;
        }
      } else if (!xr_scan(e->loc + 30 + ln,lex,0,&e->xtr)) {
        zd_fail("Xtro local/central metadata mismatch");return 0;
      }

      if (zd_has (e->loc + 30 + ln, lex, 7, NULL, NULL) != 0
          || zd_has (e->loc + 30 + ln, lex, 0x9901, NULL, NULL) != 0)
        {
          zd_fail ("authenticated or AES local record rejected");
          return 0;
        }

      e->lcsz64 = (zd_u32 (lhdr + 18) == 0xffffffffUL);
      e->lusz64 = (zd_u32 (lhdr + 22) == 0xffffffffUL);
      r = zd_has (e->loc + 30 + ln, lex, 1, &lpos, &lcount);
      if (r < 0)
        {
          return 0;
        }

      if ((e->lcsz64 || e->lusz64)
          && (!r || lcount < (unsigned)(8 * (e->lcsz64 + e->lusz64))))
        {
          zd_fail ("malformed local ZIP64 size extra");
          return 0;
        }

      if (e->method == ZD_REFPTR && !e->has_ref)
        {
          zd_fail ("existing method 92 member missing 0x9903 extra");
          return 0;
        }
    }

  /* Owner identity graph must be complete before creating output. */
  {
    xr_node *nodes;
    if (a->count>(unsigned long)((size_t)-1/sizeof(*nodes))) {
      zd_fail("Xtro graph too large");return 0;
    }
    nodes=(xr_node *)malloc((size_t)(a->count?a->count:1)*sizeof(*nodes));
    if (!nodes) {zd_fail("out of memory for Xtro graph");return 0;}
    for (i=0;i<a->count;i++) nodes[i]=a->members[i].xtr;
    { int graphok=xr_graph(nodes,(size_t)a->count);
      if (graphok) for (i=0;i<a->count;i++) a->members[i].xtr=nodes[i];
      free(nodes);
      if (!graphok) {zd_fail("invalid Xtro owner/companion graph");return 0;}
    }
  }
  return 1;
}

/* Only access callback output belonging to the specific UnZip extraction.
 * UnZip -p emits decoded file bytes with flag zero and diags otherwise */
static iz_sha1 zd_hash_state;
static unsigned long zd_hash_bytes, zd_hash_crc;
static int zd_hash_failed;
static unsigned long
zd_crc32_step (unsigned long crc, const unsigned char *p, unsigned long n)
{
  while (n != 0)
    {
      unsigned int take = n > (unsigned long)UINT_MAX
                          ? UINT_MAX : (unsigned int)n;
      crc = (unsigned long)crc32 (crc ^ 0xffffffffUL, p, take)
            ^ 0xffffffffUL;
      crc &= 0xffffffffUL;
      p += take;
      n -= take;
    }
  return crc & 0xffffffffUL;
}

static int
UZ_EXP zd_unzip_cb (zvoid *g, uch *p, ulg len, int flag)
{
  (void)g;
  if (flag != 0)
    {
      return 0;
    }

  if (zd_hash_bytes > ULONG_MAX - len)
    {
      zd_hash_failed = 1;
      return 1;
    }

#ifdef ZD_DOS16
  if (len > ZD_DOS16_MAX_ALLOC) {
    zd_hash_failed = 1;
    return 1;
  }
#endif
  iz_sha1_update (&zd_hash_state, p, (size_t)len);
  zd_hash_bytes += (unsigned long)len;
  zd_hash_crc = zd_crc32_step (zd_hash_crc, p, (unsigned long)len);
  return 0;
}

static int zd_has_metachar (const char *p);

/*
 * Opt-in FWKCS mode checking all non-directory entries by name
 * RefPtr (m92) gives the referenced plaintext bytes and
 * not the 20-byte reference pointer!
 */

static xm_md5_ctx zd_md5_state;
static unsigned long zd_md5_bytes, zd_md5_crc;
static int zd_md5_failed;

static int
UZ_EXP zd_md5_cb (zvoid *g, uch *p, ulg len, int flag)
{
  (void)g;
  if (flag != 0)
    {
      return 0;
    }

  if (len > ULONG_MAX - zd_md5_bytes)
    {
      zd_md5_failed = 1;

      return 1;
    }

#ifdef ZD_DOS16
  if (len > ZD_DOS16_MAX_ALLOC) {
    zd_md5_failed = 1;
    return 1;
  }
#endif
  {
    ulg remain = len;
    const uch *buf = p;

    while (remain)
      {
        unsigned take = remain > 32768UL ? 32768U : (unsigned)remain;

        xm_md5_update (&zd_md5_state, buf, take);
        buf += take;
        remain -= take;
      }
  }

  zd_md5_bytes += (unsigned long)len;
  zd_md5_crc = zd_crc32_step (zd_md5_crc, p, (unsigned long)len);

  return 0;
}

static int
zd_md5_member (struct zd_archive *a, unsigned long idx,
               unsigned char digest[16])
{
  struct zd_entry *e = &a->members[idx];
  UzpInit u;
  char *argv[8];
  unsigned long j;
  int rc;

  if (e->name[0] && e->name[strlen (e->name) - 1] == '/')
    {
      if (e->usize != 0 || e->crc != 0)
        {
          zd_fail ("directory with nonempty contents cannot be FWKCS validated");

          return 0;
        }

      xm_md5_init (&zd_md5_state);
      xm_md5_final (digest, &zd_md5_state);

      return 1;
    }

  /*
   * The public UnZip API selects by pattern and not central index
   * reject selecting multiple entries rather than hash wrong data.
   */

  if (!e->name[0] || zd_has_metachar (e->name))
    {
      zd_fail ("FWKCS cannot select member with empty or pattern name");

      return 0;
    }

  for (j = 0; j < a->count; j++)
    if (j != idx && !strcmp (e->name, a->members[j].name))
      {
        zd_fail ("duplicate names prevent unambiguous FWKCS verification");
        return 0;
      }

  memset (&u, 0, sizeof (u));
  u.structlen = sizeof (u);
  u.msgfn = zd_md5_cb;
  zd_md5_failed = 0;
  zd_md5_bytes = 0;
  zd_md5_crc = 0xffffffffUL;
  xm_md5_init (&zd_md5_state);
  rc = UzpAltMain (zd_unzip_arguments(argv, a->input, e->name), argv, &u);

  if (rc != 0 || zd_md5_failed || zd_md5_bytes != e->usize
      || (zd_md5_crc ^ 0xffffffffUL) != e->crc)
    {
      zd_fail ("FWKCS requested but member cannot be decoded or verified");

      return 0;
    }

  xm_md5_final (digest, &zd_md5_state);

  return 1;
}

/*
 * Parse central FWKCS records without rewriting them
 * Any malformed or repeated FWKCS is an error only
 * with --fwkcs-md5 mode
 */

static int
zd_prepare_fwkcs (struct zd_archive *a, unsigned long *missing)
{
  unsigned long i;
  *missing = 0;

  for (i = 0; i < a->count; ++i)
    {
      struct zd_entry *e = &a->members[i];
      unsigned name = zd_u16 (e->cen + 28);
      unsigned ex = zd_u16 (e->cen + 30);
      const unsigned char *extras = e->cen + 46 + name;
      unsigned pos = 0, n, id, got = 0;
      unsigned char digest[16];
      int isdir = e->name[0]
                  && e->name[strlen (e->name) - 1] == '/';
      while (pos < ex)
        {
          if (ex - pos < 4)
            {
              zd_fail ("malformed central extra field");

              return 0;
            }

          id = zd_u16 (extras + pos);
          n = zd_u16 (extras + pos + 2);

          if (n > ex - pos - 4)
            {
              zd_fail ("malformed central extra field length");

              return 0;
            }

          if (id == 0x4b46U)
            {
              if (got || n != 19 || memcmp (extras + pos + 4, "MD5", 3))
                {
                  zd_fail ("duplicate or invalid existing FWKCS MD5 extra");

                  return 0;
                }

              got = 1;
              memcpy (digest, extras + pos + 7, 16);
            }

          pos += n + 4;
        }

      if (!isdir || got)
        {
          if (!zd_md5_member (a, i, e->md5))
            {
              return 0;
            }

          if (got && memcmp (digest, e->md5, 16))
            {
              zd_fail ("existing FWKCS MD5 checksum mismatch");

              return 0;
            }
        }

      if (!got && !isdir)
        {
          e->add_md5 = 1;
          ++*missing;
        }
    }

  return 1;
}

static int
zd_has_metachar (const char *p)
{
  while (*p)
    {
      if (*p == '*' || *p == '?' || *p == '[' || *p == ']' || *p == '\\')
        {
          return 1;
        }

      p++;
    }
  return 0;
}

/* Preflight every Xtro companion before the deduplication plan.  The
 * embedded UnZip decoder validates member CRC and FWKCS.  The portable C89
 * verifier then validates the full native metadata schema and SHA-256.
 * No native filesystem mutation or output publication is possible here. */
static FILE *zd_xtr_stage;
static unsigned long zd_xtr_bytes;
static int zd_xtr_failed;
static int
UZ_EXP zd_xtr_cb(zvoid *g,uch *p,ulg len,int flag)
{
  (void)g;
  if (flag!=0) return 0;
  if (!zd_xtr_stage || len>33554432UL-zd_xtr_bytes) {
    zd_xtr_failed=1;return 1;
  }
#if defined(ZD_DOS16)
  /* A callback is backed by one segment-sized buffer.  Do not narrow an
   * overlong length or advance an unbounded near/far buffer pointer. */
  if (len > ZD_DOS16_MAX_ALLOC) {
    zd_xtr_failed=1;return 1;
  }
#endif
  if (fwrite(p,1,(size_t)len,zd_xtr_stage)!=(size_t)len) {
    zd_xtr_failed=1;return 1;
  }
  zd_xtr_bytes+=(unsigned long)len;
  return 0;
}
static size_t
zd_xtr_read(void *context,unsigned char *p,size_t n)
{
  return fread(p,1,n,(FILE *)context);
}
static int
zd_verify_xtr(struct zd_archive *a,struct zd_entry *e)
{
  UzpInit u;
  char *args[8];
  unsigned long j;
  xtr_extra outer;
  xtr1_policy policy;
  xtr1_digest digest;
  xtr_reader reader;
  xtr_u64 total;
  const unsigned char *p=e->xtr.header;
  int code,valid;
  if (e->xtr.role!=3) return 1;
  if (e->usize>33554432UL || !e->name[0] ||
      zd_has_metachar(e->name)) {
    zd_fail("Xtro metadata exceeds bounded validation policy");return 0;
  }
  for (j=0;j<a->count;j++) {
    if (&a->members[j]!=e && !strcmp(a->members[j].name,e->name)) {
      zd_fail("ambiguous Xtro companion filename");return 0;
    }
  }
  zd_xtr_stage=tmpfile();
  if (!zd_xtr_stage) {zd_fail("cannot stage Xtro metadata");return 0;}
  memset(&u,0,sizeof(u));u.structlen=sizeof(u);u.msgfn=zd_xtr_cb;
  zd_xtr_bytes=0;zd_xtr_failed=0;
  code=UzpAltMain(zd_unzip_arguments(args,a->input,e->name),args,&u);
  valid=(code==0 && !zd_xtr_failed && zd_xtr_bytes==e->usize &&
         !fseek(zd_xtr_stage,0,SEEK_SET));
  if (valid) {
    memset(&outer,0,sizeof(outer));
    memset(&policy,0,sizeof(policy));
    memset(&reader,0,sizeof(reader));
    outer.mode=p[6];outer.flags=p[7];
    memcpy(outer.owner,p+8,16);
    outer.count=xr_le32(p+24);
    outer.manifest_len.lo=xr_le32(p+28);
    outer.manifest_len.hi=xr_le32(p+32);
    outer.crc32=xr_le32(p+36);
    total.lo=zd_xtr_bytes;total.hi=0;
    policy.max_records=65536UL;policy.max_field=1048576UL;
    policy.max_manifest.lo=33554432UL;policy.max_manifest.hi=0;
    reader.context=zd_xtr_stage;reader.read=zd_xtr_read;
    valid=(xtr1_check_manifest(&reader,total,&outer,e->xtr.sha,
                                &policy,&digest)==XTR_OK);
  }
  fclose(zd_xtr_stage);zd_xtr_stage=NULL;
  if (!valid) zd_fail("Xtro companion failed ZIP or manifest integrity");
  return valid;
}
static int
zd_verify_xtr_all(struct zd_archive *a)
{
  unsigned long i;
  for (i=0;i<a->count;i++) {
    struct zd_entry *e=&a->members[i];
    if (e->xtr.role==1) {
      unsigned name=zd_u16(e->cen+28),extra=zd_u16(e->cen+30);
      unsigned off=0,len=0;
      int found=zd_has(e->cen+46+name,extra,0x5854,&off,&len);
      if (found!=1 || !xr_inline_verify(e->cen+46+name+off+4,len)) {
        zd_fail("invalid inline Xtro manifest");return 0;
      }
    } else if (e->xtr.role==3 && !zd_verify_xtr(a,e)) return 0;
  }
  return 1;
}

static int
zd_hash_file (struct zd_archive *a, struct zd_entry *e)
{
  UzpInit u;
  char *argv[8];
  int rc;

  if (e->method == ZD_REFPTR || e->name[0] == '\0')
    {
      return 0;
    }

  if (zd_has_metachar (e->name))
    {
      zd_fail ("member name contains UnZip pattern syntax; cannot hash by "
               "exact name");
      return 0;
    }

  memset (&u, 0, sizeof (u));
  u.structlen = sizeof (u);
  u.msgfn = zd_unzip_cb;
  zd_hash_failed = 0;
  zd_hash_bytes = 0;
  zd_hash_crc = 0xffffffffUL;
  iz_sha1_init (&zd_hash_state);
  rc = UzpAltMain (zd_unzip_arguments(argv, a->input, e->name), argv, &u);
  iz_sha1_finish (&zd_hash_state, e->sha1);
  if (rc != 0 || zd_hash_failed || zd_hash_bytes != e->usize
      || (zd_hash_crc ^ 0xffffffffUL) != e->crc)
    {
      zd_fail ("UnZip decoding failed or uncompressed size/CRC mismatch");
      return 0;
    }

  e->digest_valid = 1;
  return 1;
}

static int
zd_trailer_is_descriptor (struct zd_archive *a, const struct zd_entry *e)
{
  unsigned long extra = e->next_off - e->off - e->loclen - e->csize;
  unsigned char b[24];
  unsigned pos = 0, n;
  unsigned long cc = 0, uu = 0;
  int is64 = (e->csz64 || e->usz64 || e->lcsz64 || e->lusz64);

  if (!(e->flags & 8U))
    {
      return extra == 0;
    }

  if (extra != (unsigned long)(is64 ? 20 : 12)
      && extra != (unsigned long)(is64 ? 24 : 16))
    {
      return 0;
    }

  if (!zd_at (a->in, e->off + e->loclen + e->csize)
      || !zd_read (a->in, b, (size_t)extra))
    {
      return 0;
    }

  if (extra == (unsigned long)(is64 ? 24 : 16))
    {
      if (zd_u32 (b) != 0x08074b50UL)
        {
          return 0;
        }

      pos = 4;
    }

  if (zd_u32 (b + pos) != e->crc)
    {
      return 0;
    }

  pos += 4;
  if (is64)
    {
      if (!zd_r64 (b + pos, &cc) || !zd_r64 (b + pos + 8, &uu))
        {
          return 0;
        }

      n = 16;
    }
  else
    {
      cc = zd_u32 (b + pos);
      uu = zd_u32 (b + pos + 4);
      n = 8;
    }

  (void)n;
  return cc == e->csize && uu == e->usize;
}

static int
zd_supported (unsigned m)
{
  switch (m)
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 8:
    case 10:
    case 31340:
      return 1;

#ifdef USE_DEFLATE64
    case 9:
      return 1;
#endif /* ifdef USE_DEFLATE64 */

#ifdef USE_BZIP2
    case 12:
      return 1;
#endif /* ifdef USE_BZIP2 */

#ifdef USE_CMPSC16
    case 16:
      return 1;
#endif /* USE_CMPSC16 */

#ifdef ZD_HAVE_XCEED_BWT
    case 18:
      return 1;
#endif /* ZD_HAVE_XCEED_BWT */

#ifdef USE_LZFSE
    /* AES (also method 99) was rejected above by its 0x9901 extra field.
     * Encryption is independently disallowed for all zipdedup input. */
    case 99:
      return 1;
#endif /* USE_LZFSE */

#ifdef USE_LZMA
    case 14:
      return 1;
#endif /* ifdef USE_LZMA */

#if defined(USE_ZSTD) || (defined(USE_LPAQ8) && !defined(NO_LPAQ8))
    case 20:
      return 1;
#endif /* if defined(USE_ZSTD) || (defined(USE_LPAQ8) && !defined(NO_LPAQ8)) */

#ifdef USE_ZSTD
    case 93:
      return 1;
#endif /* fdef USE_ZSTD */

#ifdef USE_PPMD
    case 98:
      return 1;
#endif /* ifdef USE_PPMD */

#ifdef USE_XZ
    case 95:
      return 1;
#endif /* ifdef USE_XZ */

#ifdef USE_WAVP
    case 97:
      return 1;
#endif /* ifdef USE_WAVP */

#ifdef USE_WZMP3
    case 94:
      return 1;
#endif /* ifdef USE_WZMP3 */

#ifdef USE_WZJPEG
    case 96:
      return 1;
#endif /* ifdef USE_WZJPEG */

    default:
      return 0;
    }
}

static int
zd_random_uuid (struct zd_archive *a, struct zd_entry *source,
                unsigned char b[16])
{
  FILE *f;
  size_t n = 0;

  if (zd_sde_active)
    {
      unsigned long attempt;
      for (attempt = 0; attempt < 65536UL; attempt++)
        {
          iz_sha1 state;
          unsigned char digest[20], number[8];
          unsigned long j;
          unsigned i;
          int collision = 0;
          unsigned long values[2];

          values[0] = zd_sde_epoch;
          values[1] = attempt;
          for (i = 0; i < 2; i++)
            {
              unsigned k;
              for (k = 0; k < 4; k++)
                {
                  number[i * 4U + k] = (unsigned char)(values[i] & 255UL);
                  values[i] >>= 8;
                }
            }
          iz_sha1_init (&state);
          iz_sha1_update (&state,
                          (const unsigned char *)"XtroZip:RefPtr:v1", 17);
          iz_sha1_update (&state, number, sizeof (number));
          iz_sha1_update (&state, source->sha1, 20);
          iz_sha1_update (&state, (const unsigned char *)source->name,
                          strlen (source->name));
          iz_sha1_finish (&state, digest);
          memcpy (b, digest, 16);
          b[6] = (unsigned char)((b[6] & 15U) | 64U);
          b[8] = (unsigned char)((b[8] & 63U) | 128U);

          for (j = 0; j < a->count; j++)
            {
              struct zd_entry *e = &a->members[j];
              if ((e->is_source || e->has_ref)
                  && memcmp (b, e->uuid, 16) == 0)
                {
                  collision = 1;
                  break;
                }
            }
          if (!collision)
            return 1;
        }
      zd_fail ("deterministic RefPtr UUID collision limit exceeded");
      return 0;
    }

  f = fopen ("/dev/urandom", "rb");

  if (f)
    {
      n = fread (b, 1, 16, f);
      fclose (f);
    }

  if (n != 16)
    {
      zd_fail (
          "randomness not available; cannot create reference UUID");
      return 0;
    }

  /* RFC4122 UUID bits stored without string formatting */
  b[6] = (unsigned char)((b[6] & 15U) | 64U);
  b[8] = (unsigned char)((b[8] & 63U) | 128U);
  return 1;
}

static int
zd_plan (struct zd_archive *a, unsigned long *number, unsigned long *saved)
{
  unsigned long i, j, s, k;

  *number = 0;
  *saved = 0;
  /* Decode all accessible physical members, once, through the UnZip API. */
  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + i;
      if (e->xtr.role || e->method == ZD_REFPTR || e->usize == 0 || !zd_supported (e->method))
        {
          continue;
        }

      for (j = 0; j < a->count; j++)
        {
          if (j != i && !strcmp (e->name, a->members[j].name))
            {
              zd_fail ("duplicate archive names prevent unambiguous UnZip "
                       "extraction");
              return 0;
            }
        }

      if (!zd_hash_file (a, e))
        {
          return 0;
        }
    }

  /* Choose the first PHYSICAL source, not the first central-directory
   * listing. ZIP central-directory entries may be in a different order. */
  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + a->order[i];
      if (e->xtr.role || !e->digest_valid || e->has_ref || e->method == ZD_REFPTR)
        {
          continue;
        }

      for (j = 0; j < i; j++)
        {
          unsigned long idx = a->order[j];
          struct zd_entry *src = a->members + idx;
          if (src->xtr.role || !src->digest_valid || src->selected || src->usize != e->usize
              || src->crc != e->crc || memcmp (src->sha1, e->sha1, 20) != 0)
            {
              continue;
            }

          /* Calculation includes removed compressed stream and trailing
           * descriptor, and the new source 0x9903 field once per group. */
          if (!zd_trailer_is_descriptor (a, e))
            {
              break;
            }

          s = e->next_off - e->off;
          k = e->loclen + 20UL + 24UL
              + (!src->is_source && !src->has_ref ? 24UL : 0UL);
          if (s <= k)
            {
              break;
            }

          if (!src->is_source && !src->has_ref)
            {
              if (!zd_random_uuid (a, src, src->uuid))
                {
                  return 0;
                }
            }

          src->is_source = 1;
          e->selected = 1;
          e->source_index = (int)idx;
          memcpy (e->uuid, src->uuid, 16);
          *saved += s - e->loclen - 20UL - 24UL;
          (*number)++;
          if (zd_verbose)
            {
              printf ("dedup: %s -> %s (%lu payload bytes)\n", e->name,
                      src->name, e->csize);
            }

          break;
        }
    }

  /* Count extra field once for each newly marked physical source. */
  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + i;
      if (e->is_source && !e->has_ref)
        {
          if (*saved < 24UL)
            {
              zd_fail ("internal saving underflow");
              return 0;
            }

          *saved -= 24UL;
        }
    }

  return 1;
}

static int
zd_patch64 (unsigned char *p, unsigned len, unsigned need_usz,
            unsigned need_csz, unsigned need_off, unsigned long usz,
            unsigned long csz, unsigned long off)
{
  unsigned pos = 0, n = 0, r;
  unsigned char *d;

  r = (unsigned)zd_has (p, len, 1, &pos, &n);
  if (r == (unsigned)-1)
    {
      return 0;
    }

  if ((need_usz || need_csz || need_off) && r != 1)
    {
      zd_fail ("missing ZIP64 extra during update");
      return 0;
    }

  if (r == 1)
    {
      d = p + pos + 4;
      if (need_usz)
        {
          if (n < 8)
            {
              goto err;
            }

          zd_w64 (d, usz);
          d += 8;
          n -= 8;
        }

      if (need_csz)
        {
          if (n < 8)
            {
              goto err;
            }

          zd_w64 (d, csz);
          d += 8;
          n -= 8;
        }

      if (need_off)
        {
          if (n < 8)
            {
              goto err;
            }

          zd_w64 (d, off);
          d += 8;
          n -= 8;
        }
    }

  return 1;

err:
  zd_fail ("short ZIP64 extra during rewrite");
  return 0;
}

static int
zd_rewrite_central (struct zd_entry *e, FILE *out)
{
  unsigned name = zd_u16 (e->cen + 28), ex = zd_u16 (e->cen + 30);
  unsigned com = zd_u16 (e->cen + 32), nex = ex;
  unsigned char *c;
  unsigned char *p;
  unsigned long len = e->cenlen;
  int add = (e->selected || (e->is_source && !e->has_ref));
  int add_md5 = e->add_md5;
  unsigned v = zd_u16 (e->cen + 6);
  unsigned long crc;

  if (add)
    {
      if (ex > 65535U - 24U)
        {
          zd_fail ("central extra field cannot accommodate RefPtr");
          return 0;
        }

      nex += 24;
      len += 24;
    }

  if (add_md5)
    {
      if (nex > 65535U - 23U)
        {
          zd_fail ("central extra field cannot accommodate FWKCS MD5");
          return 0;
        }

      nex += 23U;
      len += 23UL;
    }

#ifdef ZD_DOS16
  if (len > ZD_DOS16_MAX_ALLOC)
    {
      zd_fail ("DOS rewritten central record exceeds segment limit");
      return 0;
    }
#endif
  c = (unsigned char *)malloc ((size_t)len);
  if (!c)
    {
      zd_fail ("out of memory");
      return 0;
    }

  memcpy (c, e->cen, 46UL + name + ex);

  if (add || add_md5)
    {
      memset (c + 46UL + name + ex, 0,
              (add ? 24U : 0U) + (add_md5 ? 23U : 0U));
    }

  memcpy (c + 46UL + name + nex, e->cen + 46UL + name + ex, com);
  zd_w16 (c + 30, nex);
  if (e->selected)
    {
      zd_w16 (c + 10, 92);
      zd_w16 (c + 8, e->flags & ~8U);
      if (!e->csz64)
        {
          zd_w32 (c + 20, 20UL);
        }

      if (v < 20)
        {
          v = 20;
        }
    }

  if (e->is_source && v < 20)
    {
      v = 20;
    }

  if (e->usz64 || e->csz64 || e->off64 || e->lcsz64 || e->lusz64)
    {
      if (v < 45)
        {
          v = 45;
        }
    }

  zd_w16 (c + 6, v);
  if (e->off64)
    {
      zd_w32 (c + 42, 0xffffffffUL);
    }
  else
    {
      zd_w32 (c + 42, e->new_off);
    }

  if (add_md5)
    {
      p = c + 46 + name + ex + (add ? 24U : 0U);
      zd_w16 (p, 0x4b46U);
      zd_w16 (p + 2, 19U);
      memcpy (p + 4, "MD5", 3);
      memcpy (p + 7, e->md5, 16);
    }

  if (!zd_patch64 (c + 46 + name, nex, e->usz64, e->csz64, e->off64, e->usize,
                   e->selected ? 20UL : e->csize, e->new_off))
    {
      free (c);
      return 0;
    }

  if (add)
    {
      p = c + 46 + name + ex;
      zd_w16 (p, 0x9903);
      zd_w16 (p + 2, 20);
      crc = refptr9903_crc (e->selected ? 92UL : (unsigned long)e->method,
                            e->dostime, e->dosdate, e->crc, e->uuid);
      zd_w32 (p + 4, crc);
      memcpy (p + 8, e->uuid, 16);
    }

  if (!zd_write (out, c, (size_t)len))
    {
      free (c);
      return 0;
    }

  free (c);
  return 1;
}

static int
zd_copy (FILE *in, FILE *out, unsigned long at, unsigned long len)
{
  unsigned char buf[65536];

  if (!zd_at (in, at))
    {
      return 0;
    }

  while (len)
    {
      size_t take = len > sizeof (buf) ? sizeof (buf) : (size_t)len;
      if (!zd_read (in, buf, take) || !zd_write (out, buf, take))
        {
          return 0;
        }

      len -= (unsigned long)take;
    }
  return 1;
}

static int
zd_rewrite_local (struct zd_entry *e, FILE *out)
{
  unsigned char *l;
  unsigned n = zd_u16 (e->loc + 26), x = zd_u16 (e->loc + 28);
  unsigned v = zd_u16 (e->loc + 4);

  l = (unsigned char *)malloc ((size_t)e->loclen);
  if (!l)
    {
      zd_fail ("out of memory");
      return 0;
    }

  memcpy (l, e->loc, (size_t)e->loclen);
  if (e->selected)
    {
      zd_w16 (l + 8, 92);
      zd_w16 (l + 6, e->flags & ~8U);
      zd_w32 (l + 14, e->crc);
      zd_w32 (l + 18, e->lcsz64 ? 0xffffffffUL : 20UL);
      zd_w32 (l + 22, e->lusz64 ? 0xffffffffUL : e->usize);
      if (!zd_patch64 (l + 30 + n, x, e->lusz64, e->lcsz64, 0, e->usize, 20UL,
                       0UL))
        {
          free (l);
          return 0;
        }

      if (v < 20)
        {
          v = 20;
        }
    }

  if (e->is_source && v < 20)
    {
      v = 20;
    }

  if (e->usz64 || e->csz64 || e->lcsz64 || e->lusz64)
    {
      if (v < 45)
        {
          v = 45;
        }
    }

  zd_w16 (l + 4, v);
  if (!zd_write (out, l, (size_t)e->loclen))
    {
      free (l);
      return 0;
    }

  free (l);
  return 1;
}

static int
zd_end (FILE *out, unsigned long count, unsigned long cd_start,
        unsigned long cd_len, const unsigned char *comment, unsigned comlen,
        int zip64)
{
  unsigned char b[56];
  unsigned long at;

  memset (b, 0, sizeof (b));
  if (count > 65535UL || cd_start > 0xffffffffUL || cd_len > 0xffffffffUL)
    {
      zip64 = 1;
    }

  if (zip64)
    {
      if (ftell (out) < 0)
        {
          zd_fail ("cannot determine ZIP64 end position");
          return 0;
        }

      at = (unsigned long)ftell (out);
      zd_w32 (b, ZD_Z64);
      zd_w64 (b + 4, 44UL);
      zd_w16 (b + 12, 45);
      zd_w16 (b + 14, 45);
      zd_w64 (b + 24, count);
      zd_w64 (b + 32, count);
      zd_w64 (b + 40, cd_len);
      zd_w64 (b + 48, cd_start);
      if (!zd_write (out, b, 56))
        {
          return 0;
        }

      memset (b, 0, sizeof (b));
      zd_w32 (b, ZD_ZLOC);
      zd_w64 (b + 8, at);
      zd_w32 (b + 16, 1);
      if (!zd_write (out, b, 20))
        {
          return 0;
        }
    }

  memset (b, 0, sizeof (b));
  zd_w32 (b, ZD_END);
  zd_w16 (b + 8, count > 65535UL ? 65535U : (unsigned)count);
  zd_w16 (b + 10, count > 65535UL ? 65535U : (unsigned)count);
  zd_w32 (b + 12, cd_len > 0xffffffffUL ? 0xffffffffUL : cd_len);
  zd_w32 (b + 16, cd_start > 0xffffffffUL ? 0xffffffffUL : cd_start);
  zd_w16 (b + 20, comlen);
  return zd_write (out, b, 22) && zd_write (out, comment, comlen);
}

/*
 * Detect the APK Signing Block envelope before the CD>
 * It is independent of the archive extension so not a claim that the
 * signatures are valid.  A broken sequence is still protected if the
 * trailing magic exists.
 *
 * Return 0 for missing, 1 for well-formed, 2 for malformed/broken.
 */

static int
zd_apk_signing_block (struct zd_archive *a)
{
  static const unsigned char magic[] = "APK Sig Block 42";
  unsigned char foot[24], head[8], pair[8];
  unsigned long size, begin, pos, end, n;

  if (a->cd_off < 24 || !zd_at (a->in, a->cd_off - 24)
      || !zd_read (a->in, foot, sizeof (foot)))
    return 0;
  if (memcmp (foot + 8, magic, sizeof (magic) - 1U) != 0)
    return 0;
  if (!zd_r64 (foot, &size) || size < 24 || size > a->cd_off - 8)
    return 2;
  begin = a->cd_off - 8 - size;
  if (!zd_at (a->in, begin) || !zd_read (a->in, head, sizeof (head))
      || memcmp (head, foot, 8) != 0)
    return 2;

  pos = begin + 8;
  end = a->cd_off - 24;
  while (pos < end)
    {
      if (end - pos < 12 || !zd_at (a->in, pos)
          || !zd_read (a->in, pair, 8) || !zd_r64 (pair, &n)
          || n < 4 || n > end - pos - 8)
        return 2;
      pos += 8 + n;
    }
  return pos == end ? 1 : 2;
}

/* Check only the two documented alignment extra formats.  This validates
 * the promised data offset, without changing any metadata or header bytes.
 * Unknown/malformed alignment values are not interpreted optimistically. */
static int
zd_alignment_fields (const unsigned char *p, unsigned n,
                     unsigned long data_off, int *seen)
{
  unsigned pos = 0, id, len, alignment;
  while (pos < n)
    {
      if (n - pos < 4)
        return 0;
      id = zd_u16 (p + pos);
      len = zd_u16 (p + pos + 2);
      if (len > n - pos - 4)
        return 0;
      if (id == ZD_APKALIGN || id == ZD_APACHEALIGN)
        {
          *seen = 1;
          if (len < 2)
            return 0;
          alignment = zd_u16 (p + pos + 4);
          if (id == ZD_APACHEALIGN)
            {
              /* Highest bit is Apache's allow-method-change flag. */
              alignment &= 0x7fffU;
              if (!alignment || (alignment & (alignment - 1U)))
                return 0;
            }
          else if (!alignment)
            return 0;
          if (data_off % alignment != 0)
            return 0;
        }
      pos += 4 + len;
    }
  return 1;
}

/* Predict physical local-header offsets using precisely the same lengths as
 * zd_emit().  This is called only if an actual deduplication is planned. */
static int
zd_alignment_preserved (struct zd_archive *a, int *seen)
{
  unsigned long i, at;
  *seen = 0;
  /* Do not impose a new output-offset preflight on archives which contain
   * neither of the two explicitly protected alignment extra fields. */
  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + i;
      unsigned cn = zd_u16 (e->cen + 28), cx = zd_u16 (e->cen + 30);
      unsigned ln = zd_u16 (e->loc + 26), lx = zd_u16 (e->loc + 28);
      const unsigned char *c = e->cen + 46 + cn;
      const unsigned char *l = e->loc + 30 + ln;
      if (zd_has (c, cx, ZD_APKALIGN, NULL, NULL) == 1
          || zd_has (c, cx, ZD_APACHEALIGN, NULL, NULL) == 1
          || zd_has (l, lx, ZD_APKALIGN, NULL, NULL) == 1
          || zd_has (l, lx, ZD_APACHEALIGN, NULL, NULL) == 1)
        {
          *seen = 1;
          break;
        }
    }
  if (!*seen)
    return 1;

  at = a->count ? a->members[a->order[0]].off : a->cd_off;
  for (i = 0; i < a->count; i++)
    {
      struct zd_entry *e = a->members + a->order[i];
      unsigned cn = zd_u16 (e->cen + 28), cx = zd_u16 (e->cen + 30);
      unsigned ln = zd_u16 (e->loc + 26), lx = zd_u16 (e->loc + 28);
      unsigned long size = e->selected ? e->loclen + 20UL
                         : e->next_off - e->off;
      if (at > ULONG_MAX - e->loclen)
        return 0;
      if (!zd_alignment_fields (e->cen + 46 + cn, cx,
                                at + e->loclen, seen)
          || !zd_alignment_fields (e->loc + 30 + ln, lx,
                                   at + e->loclen, seen))
        return 0;
      if (at > ULONG_MAX - size)
        return 0;
      at += size;
    }
  return 1;
}

static int
zd_emit (struct zd_archive *a, FILE *out)
{
  unsigned long i, at, cdstart, cdlen, limit;
  int zip64 = 0, ok = 1;

  /* Only members explicitly changed by deduplication/FWKCS may acquire
   * normalized timestamps. Every other member keeps its original fields. */
  if (zd_sde_active)
    for (i = 0; i < a->count; i++)
      {
        struct zd_entry *e = a->members + i;
        unsigned char *c, *l;
        unsigned cn, cx, ln, lx;
        unsigned long cutoff;
        if (!e->selected && !e->is_source && !e->add_md5)
          continue;
        cn = zd_u16(e->cen + 28);
        cx = zd_u16(e->cen + 30);
        ln = zd_u16(e->loc + 26);
        lx = zd_u16(e->loc + 28);
        c = e->cen + 46UL + cn;
        l = e->loc + 30UL + ln;
        cutoff = xtr_sde_dos(zd_sde_epoch);
        xtr_sde_clip_dos(e->cen + 12,cutoff);
        xtr_sde_clip_dos(e->loc + 10,cutoff);
        e->dostime = zd_u16(e->cen + 12);
        e->dosdate = zd_u16(e->cen + 14);
        if (!xtr_sde_clip_extras(c,cx,zd_sde_epoch) ||
            !xtr_sde_clip_extras(l,lx,zd_sde_epoch))
          {
            zd_fail("malformed timestamp extra in replaced member");
            return 0;
          }
      }

  limit = a->count ? a->members[a->order[0]].off : a->cd_off;
  if (limit && !zd_copy (a->in, out, 0, limit))
    {
      ok = 0;
    }

  for (i = 0; i < a->count && ok; i++)
    {
      struct zd_entry *e = a->members + a->order[i];
      if (ftell (out) < 0)
        {
          zd_fail ("output offset not representable");
          ok = 0;
          break;
        }

      at = (unsigned long)ftell (out);
      e->new_off = at;
      if (e->selected || e->is_source || (zd_sde_active && e->add_md5))
        {
          if (!zd_rewrite_local (e, out))
            {
              ok = 0;
              break;
            }

          if (e->selected)
            {
              if (!zd_write (out, e->sha1, 20))
                {
                  ok = 0;
                  break;
                }
            }
          else
            {
              if (!zd_copy (a->in, out, e->off + e->loclen,
                            e->next_off - e->off - e->loclen))
                {
                  ok = 0;
                  break;
                }
            }
        }
      else if (!zd_copy (a->in, out, e->off, e->next_off - e->off))
        {
          ok = 0;
          break;
        }
    }

  if (ok && ftell (out) < 0)
    {
      zd_fail ("output size not representable");
      ok = 0;
    }

  cdstart = ok ? (unsigned long)ftell (out) : 0;
  for (i = 0; i < a->count && ok; i++)
    {
      struct zd_entry *e = a->members + i;
      if (!zd_rewrite_central (e, out))
        {
          ok = 0;
        }
    }

  if (ok && ftell (out) < 0)
    {
      zd_fail ("central directory size not representable");
      ok = 0;
    }

  cdlen = ok ? (unsigned long)ftell (out) - cdstart : 0;
  if (ok
      && !zd_end (out, a->count, cdstart, cdlen, a->comment,
                  (unsigned)a->commentlen, zip64))
    {
      ok = 0;
    }

  if (ok && fflush (out) != 0)
    {
      zd_fail ("cannot flush output archive");
      ok = 0;
    }

  return ok;
}

static void
zd_cleanup (struct zd_archive *a)
{
  unsigned long i;

  if (a->in)
    {
      fclose (a->in);
    }

  for (i = 0; i < a->count && a->members; i++)
    {
      free (a->members[i].cen);
      free (a->members[i].loc);
      free (a->members[i].name);
    }

  free (a->members);
  free (a->order);
  free (a->comment);
}

static void
zd_usage (FILE *out)
{
(void)fprintf (out,
/******************************************************************************/
"Xtro-ZIP - ZipDeDup - WinZip-compatible (\"ZIPX\" method 92) de-duplication\n"
"Release %s - %s - https://github.com/johnsonjh/infozip-av\n"
"Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>\n"
"\n", ZD_VER, ZD_DATE);
(void)fprintf (out,
"Usage: zipdedup [option(s)...] <in.zip> <out.zip>\n"
"  -f, --force          allow dangerous operations\n"
"  -5, --fwkcs-md5      write FWKCS MD5 metadata to output\n"
"  --use-libdeflate[-]  optional small-member Deflate decoder\n"
"  --libdeflate-size N  maximum compressed/uncompressed member size (1MiB)\n"
"  -q, --quiet          suppress non-essential output\n"
"  -v, --verbose        verbose output display mode\n"
"  -V, --version        display version information\n"
"  -h, --help           display this help text\n");
/******************************************************************************/
}

int
main (int argc, char **argv)
{
  struct zd_archive a;
  int i, nargs = 0, ok = 0, apk_block, align_ok, align_seen;
  unsigned long count = 0, saved = 0, missing = 0;
  int rewrite;
  const char *paths[2];
  char *tmp = NULL;
  FILE *out = NULL;
  int fd = -1;

  if (!zd_sde_init ())
    return 2;

  memset (&a, 0, sizeof (a));

  for (i = 1; i < argc; i++)
    {
      if (!strcmp (argv[i], "--fwkcs-md5") || !strcmp (argv[i], "-5"))
        {
          a.fwkcs_md5 = 1;

          continue;
        }

      if (!strcmp(argv[i], "--use-libdeflate") ||
          !strcmp(argv[i], "--use-libdeflate-"))
        {
          zd_xld_enabled = argv[i][strlen(argv[i])-1] != '-';
          continue;
        }
      if (!strncmp(argv[i], "--libdeflate-size=", 18) ||
          !strcmp(argv[i], "--libdeflate-size"))
        {
          size_t size;
          zd_xld_size_arg = !strncmp(argv[i], "--libdeflate-size=", 18)
                            ? argv[i]+18 : (i+1 < argc ? argv[++i] : "");
          if (!xld_parse_limit(zd_xld_size_arg, &size)) {
            fprintf(stderr,"zipdedup: invalid --libdeflate-size\n");
            return 2;
          }
          continue;
        }

      if (!strcmp (argv[i], "--force") || !strcmp (argv[i], "-f"))
        {
          a.force = 1;

          continue;
        }

      if (!strcmp (argv[i], "--verbose") || !strcmp (argv[i], "-v"))
        {
          a.verbose = 1;

          continue;
        }

      if (!strcmp (argv[i], "--quiet") || !strcmp (argv[i], "-q"))
        {
          a.quiet = 1;

          continue;
        }

      if (!strcmp (argv[i], "--help") || !strcmp (argv[i], "-h"))
        {
          zd_usage (stdout);

          return 0;
        }

      if (!strcmp (argv[i], "--version") || !strcmp (argv[i], "-V"))
        {
          fprintf (stdout,
                   "Xtro-ZIP - Advanced ZipDedup archive utility - derived from Info-ZIP\n"
                   "Release %s - %s - https://github.com/johnsonjh/infozip-av\n"
                   "Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>\n",
                   ZD_VER, ZD_DATE);
          if (iz_sha1_hardware_active ())
            puts ("Hardware SHA acceleration enabled");

          return 0;
        }

      if (argv[i][0] == '-' || nargs >= 2)
        {
          zd_usage (stderr);

          return 2;
        }

      paths[nargs++] = argv[i];
    }

  if (nargs != 2)
    {
      zd_usage (stderr);

      return 2;
    }

  if (zd_xld_size_arg && !zd_xld_enabled) {
    fprintf(stderr,"zipdedup: --libdeflate-size requires --use-libdeflate\n");
    return 2;
  }
#ifndef USE_LIBDEFLATE
  if (zd_xld_enabled) {
    fprintf(stderr,"zipdedup: libdeflate support not compiled in\n");
    return 2;
  }
#endif

  a.input = paths[0];
  a.output = paths[1];
  zd_verbose = a.verbose;

  if (!strcmp (a.input, a.output))
    {
      fprintf (stderr, "zipdedup: input and output must differ\n");
      return 2;
    }

  a.in = fopen (a.input, "rb");

  if (!a.in)
    {
      fprintf (stderr, "zipdedup: cannot open input '%s'\n", a.input);
      return 1;
    }

  if (!zd_input_representable (a.in)
      || !zd_load (&a) || !zd_verify_xtr_all (&a)
      || !zd_plan (&a, &count, &saved)
      || (a.fwkcs_md5 && !zd_prepare_fwkcs (&a, &missing)))
    {
      goto done;
    }

  rewrite = (count != 0 || missing != 0);
  apk_block = zd_apk_signing_block (&a);

  if (apk_block)
    {
      fprintf (stderr, "zipdedup: warning: APK Signing Block detected%s\n",
               apk_block == 2 ? " (malformed envelope)" : "");

      if (rewrite && !a.force)
        {
          zd_fail ("APK Signing Block prevents rewrite (use --force to override)");

          goto done;
        }

      if (rewrite)
        {
          fprintf (stderr, "zipdedup: warning: --force may invalidate APK signatures\n");
        }
    }

  if (rewrite)
    {
      align_ok = zd_alignment_preserved (&a, &align_seen);

      if (!align_ok)
        {
          fprintf (stderr, "zipdedup: warning: 0xD935/0xA11E alignment cannot be preserved or interpreted\n");

          if (!a.force)
            {
              zd_fail ("alignment metadata prevents rewrite (use --force to override)");

              goto done;
            }

          fprintf (stderr, "zipdedup: warning: --force may invalidate alignment requirements\n");
        }
    }

  if (!a.quiet)
    {
      printf (
          "%lu new references; approximate savings: %lu bytes\n",
          count, saved);
    }

  if (strlen (a.output) > ((size_t)-1) - 32)
    {
      zd_fail ("output name too long");
      goto done;
    }

  tmp = (char *)malloc (strlen (a.output) + 32);
  if (!tmp)
    {
      zd_fail ("out of memory");
      goto done;
    }

  sprintf (tmp, "%s.zipdedup.XXXXXX", a.output);
  fd = mkstemp (tmp);
  if (fd < 0)
    {
      zd_fail ("cannot create exclusive output temporary");
      goto done;
    }

  out = fdopen (fd, "wb");
  if (!out)
    {
      zd_fail ("cannot stream to output temporary");
      close (fd);
      fd = -1;
      goto done;
    }

  fd = -1;
  if (!rewrite)
    {
      if (!zd_copy (a.in, out, 0, a.bytes))
        {
          goto done;
        }
    }
  else if (!zd_emit (&a, out))
    {
      goto done;
    }

  if (fclose (out) != 0)
    {
      out = NULL;
      zd_fail ("cannot finalize output archive");
      goto done;
    }

  out = NULL;
#if defined(ZD_DOS16)
  if (iz_dos16_publish_noreplace (tmp, a.output) != 0)
#elif defined(__DJGPP__)
  if (iz_dos386_publish_noreplace (tmp, a.output) != 0)
#else
  if (link (tmp, a.output) != 0)
#endif
    {
#if defined(__DJGPP__) || defined(ZD_DOS16)
      zd_fail ("cannot publish output (destination exists or DOS copy failed)");
#else
      zd_fail (
          "cannot publish output (already exists or hard links unsupported)");
#endif
      goto done;
    }

#ifndef OS2
  /* POSIX/Win32/DOS publication copies or hardlinks and leaves the
   * temporary name behind. The native OS/2 backend uses DosMove(),
   * which consumes the temporary pathname on success. */
  if (unlink (tmp) != 0)
    {
      zd_fail ("published output but could not remove temporary");
      goto done;
    }
#endif

  ok = 1;
done:
  if (out && fclose (out) != 0)
    {
      zd_fail ("cannot close failed output");
    }

  if (fd >= 0)
    {
      close (fd);
    }

  if (!ok && tmp)
    {
      unlink (tmp);
    }

  if (!ok)
    {
      fprintf (stderr, "zipdedup: %s\n",
               zd_error ? zd_error : "unknown error");
    }

  free (tmp);
  zd_cleanup (&a);
  return ok ? 0 : 1;
}
