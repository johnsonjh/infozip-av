/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200809L
#endif /* ifndef _POSIX_C_SOURCE */

#define UNIX 1
#define DLL 1

#include "../unzip60/izsha1.h"
#include "../unzip60/unzip.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern unsigned long refptr9903_crc (unsigned long, unsigned int, unsigned int,
                                     unsigned long, const unsigned char[16]);

#define ZD_CEN 0x02014b50UL
#define ZD_LOC 0x04034b50UL
#define ZD_END 0x06054b50UL
#define ZD_Z64 0x06064b50UL
#define ZD_ZLOC 0x07064b50UL
#define ZD_DIGSIG 0x05054b50UL
#define ZD_REFPTR 92U

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
};

struct zd_archive
{
  FILE *in;
  unsigned long bytes, cd_off, cd_size, count, commentlen;
  unsigned char *comment;
  struct zd_entry *members;
  unsigned long *order;
  const char *input, *output;
  int dry, verbose, quiet;
};

static const char *zd_error;
static int zd_verbose;

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
  if (fwrite (p, 1, n, f) != n)
    {
      zd_fail ("write failed");
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
      zd_fail ("end of central directory not found");
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
      if (zd_u16 (hdr + 34) != 0 || (e->flags & 0x41U) || e->method == 99)
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
          zd_fail ("Method 92 member must have a 20-byte SHA-1 payload");
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

      if (zd_has (e->loc + 30 + ln, lex, 7, NULL, NULL) != 0)
        {
          zd_fail ("authenticated local record rejected");
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
          zd_fail ("existing Method 92 member missing 0x9903 extra");
          return 0;
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
  unsigned j;

  while (n--)
    {
      crc ^= (unsigned long)*p++;
      for (j = 0; j < 8; j++)
        {
          crc = (crc & 1UL) ? ((crc >> 1) ^ 0xedb88320UL) : (crc >> 1);
        }
    }
  return crc & 0xffffffffUL;
}

static int
zd_unzip_cb (zvoid *g, uch *p, ulg len, int flag)
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

  iz_sha1_update (&zd_hash_state, p, (size_t)len);
  zd_hash_bytes += (unsigned long)len;
  zd_hash_crc = zd_crc32_step (zd_hash_crc, p, (unsigned long)len);
  return 0;
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

static int
zd_hash_file (struct zd_archive *a, struct zd_entry *e)
{
  UzpInit u;
  char *argv[5];
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
  argv[0] = "unzip";
  argv[1] = "-p";
  argv[2] = (char *)a->input;
  argv[3] = e->name;
  argv[4] = NULL;
  zd_hash_failed = 0;
  zd_hash_bytes = 0;
  zd_hash_crc = 0xffffffffUL;
  iz_sha1_init (&zd_hash_state);
  rc = UzpAltMain (4, argv, &u);
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
      return 1;

#ifdef USE_DEFLATE64
    case 9:
      return 1;
#endif /* ifdef USE_DEFLATE64 */

#ifdef USE_BZIP2
    case 12:
      return 1;
#endif /* ifdef USE_BZIP2 */

#ifdef USE_LZMA
    case 14:
      return 1;
#endif /* ifdef USE_LZMA */

#ifdef USE_ZSTD
    case 20:
    case 93:
      return 1;
#endif /* ifdef USE_ZSTD */

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
zd_random_uuid (unsigned char b[16])
{
  FILE *f = fopen ("/dev/urandom", "rb");
  size_t n = 0;

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
      if (e->method == ZD_REFPTR || e->usize == 0 || !zd_supported (e->method))
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
      if (!e->digest_valid || e->has_ref || e->method == ZD_REFPTR)
        {
          continue;
        }

      for (j = 0; j < i; j++)
        {
          unsigned long idx = a->order[j];
          struct zd_entry *src = a->members + idx;
          if (!src->digest_valid || src->selected || src->usize != e->usize
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
              if (!zd_random_uuid (src->uuid))
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

  c = (unsigned char *)malloc ((size_t)len);
  if (!c)
    {
      zd_fail ("out of memory");
      return 0;
    }

  memcpy (c, e->cen, 46UL + name + ex);
  if (add)
    {
      memset (c + 46UL + name + ex, 0, 24);
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

static int
zd_emit (struct zd_archive *a, FILE *out)
{
  unsigned long i, at, cdstart, cdlen, limit;
  int zip64 = 0, ok = 1;

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
      if (e->selected || e->is_source)
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
  fprintf (out, "zipdedup 0.1\n"
                "Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>\n\n"
                "Usage: zipdedup [--dry-run] [-v|--verbose] [-q|--quiet] "
                "INPUT.zip OUTPUT.zip\n"
                "       zipdedup --help | --version\n");
}

int
main (int argc, char **argv)
{
  struct zd_archive a;
  int i, nargs = 0, ok = 0;
  unsigned long count = 0, saved = 0;
  const char *paths[2];
  char *tmp = NULL;
  FILE *out = NULL;
  int fd = -1;

  memset (&a, 0, sizeof (a));
  for (i = 1; i < argc; i++)
    {
      if (!strcmp (argv[i], "--dry-run"))
        {
          a.dry = 1;
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

      if (!strcmp (argv[i], "--version"))
        {
          puts ("zipdedup 0.1");
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

  if (!zd_load (&a) || !zd_plan (&a, &count, &saved))
    {
      goto done;
    }

  if (!a.quiet)
    {
      printf (
          "%lu new Method 92 references; estimated net savings: %lu bytes\n",
          count, saved);
    }

  if (a.dry)
    {
      ok = 1;
      goto done;
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
  if (count == 0)
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
  if (link (tmp, a.output) != 0)
    {
      zd_fail (
          "cannot publish output (already exists or hard links unsupported)");
      goto done;
    }

  if (unlink (tmp) != 0)
    {
      zd_fail ("published output but could not remove temporary");
      goto done;
    }

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
