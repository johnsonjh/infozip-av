/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/*
 * This code intentionally rejects any ambiguous archive structure. It does
 * not perform extraction, and cannot itself publish an output archive.
 */

#ifndef _FILE_OFFSET_BITS
# define _FILE_OFFSET_BITS 64
#endif /* ifndef _FILE_OFFSET_BITS */

#if !defined(_POSIX_C_SOURCE) && !defined(_WIN32)
# define _POSIX_C_SOURCE 200809L
#endif /* if !defined( _POSIX_C_SOURCE ) && !defined( _WIN32 ) */

#include "archive.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef _WIN32
# include <sys/stat.h>
# include <unistd.h>
#endif /* ifndef _WIN32 */

#define ZO_EOCD 0x06054b50UL
#define ZO_Z64END 0x06064b50UL
#define ZO_Z64LOC 0x07064b50UL
#define ZO_CENTRAL 0x02014b50UL
#define ZO_LOCAL 0x04034b50UL
#define ZO_DATA 0x08074b50UL
#define ZO_FW 0x4b46U
#define ZO_MAX_U16 65535U
#define ZO_MAX_U32 0xffffffffUL
#define ZO_U64_MAX ((zo_u64) - 1)

static int
zo_bad (zo_archive *a, const char *msg)
{
  if (!a->error[0])
    {
      strncpy (a->error, msg, sizeof (a->error) - 1);
      a->error[sizeof (a->error) - 1] = '\0';
    }

  return 0;
}

static unsigned
zo_16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned long
zo_32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static zo_u64
zo_64 (const unsigned char *p)
{
  return (zo_u64)zo_32 (p) | ((zo_u64)zo_32 (p + 4) << 32);
}

static int
zo_sum (zo_u64 a, zo_u64 b, zo_u64 *out)
{
  if (a > ZO_U64_MAX - b)
    {
      return 0;
    }

  *out = a + b;

  return 1;
}

static int
zo_seek (zo_archive *a, zo_u64 off)
{
  if (off > a->filesize)
    {
      return zo_bad (a, "file offset beyond end");
    }

#ifdef _WIN32
  if (_fseeki64 (a->fp, (__int64)off, SEEK_SET) != 0)
#else  /* ifdef _WIN32 */
  if (off > (ZO_U64_MAX >> 1) || (zo_u64)(off_t)off != off
      || fseeko (a->fp, (off_t)off, SEEK_SET) != 0)
#endif /* ifdef _WIN32 */
    {
      return zo_bad (a, "seek failed or unsupported 64-bit offset");
    }

  return 1;
}

static int
zo_read (zo_archive *a, void *p, size_t n)
{
  if (fread (p, 1, n, a->fp) != n)
    {
      return zo_bad (a, "truncated ZIP input");
    }

  return 1;
}

int
zo_archive_at (zo_archive *a, zo_u64 off, void *p, size_t n)
{
  if (off > a->filesize || (zo_u64)n > a->filesize - off)
    {
      return zo_bad (a, "record exceeds archive boundary");
    }

  return zo_seek (a, off) && zo_read (a, p, n);
}

/* Whitelist field types that have well-defined independent metadata semantics.
 * Reject opaque vendor fields and their potentially invalid references. */
static int
zo_extras (zo_archive *a, const unsigned char *p, unsigned n, int central,
           zo_entry *e, int want_usize, int want_csize, int want_offset,
           int want_disk, zo_u64 *usize, zo_u64 *csize, zo_u64 *offset)
{
  unsigned i = 0, typ, len;
  unsigned fwseen = 0, zseen = 0;

  while (i < n)
    {
      if (n - i < 4)
        {
          return zo_bad (a, "truncated extra-field header");
        }

      typ = zo_16 (p + i);
      len = zo_16 (p + i + 2);
      i += 4;

      if (len > n - i)
        {
          return zo_bad (a, "extra field exceeds record");
        }

      switch (typ)
        {
        case 0x0001:
          {
            unsigned at = 0;
            if (zseen++)
              {
                return zo_bad (a, "duplicate ZIP64 extra field");
              }

            if (want_usize)
              {
                if (len - at < 8)
                  {
                    return zo_bad (a, "missing ZIP64 size");
                  }

                *usize = zo_64 (p + i + at);
                at += 8;
              }

            if (want_csize)
              {
                if (len - at < 8)
                  {
                    return zo_bad (a, "missing ZIP64 compressed size");
                  }

                *csize = zo_64 (p + i + at);
                at += 8;
              }

            if (want_offset)
              {
                if (len - at < 8)
                  {
                    return zo_bad (a, "missing ZIP64 local offset");
                  }

                *offset = zo_64 (p + i + at);
                at += 8;
              }

            if (want_disk)
              {
                if (len - at < 4 || zo_32 (p + i + at) != 0)
                  {
                    return zo_bad (a, "unsupported split ZIP64 archive");
                  }
              }

            break;
          }

        case ZO_FW:
          if (!central || fwseen++ || len != 19 || memcmp (p + i, "MD5", 3))
            {
              return zo_bad (a, "invalid FWKCS metadata");
            }

          e->has_fwkcs = 1;

          break;

        case 0x0007:
          return zo_bad (a, "PKAV authentication metadata prohibited");

        case 0x9901:
          return zo_bad (a, "WinZip AES metadata prohibited");

        case 0x9903:
          return zo_bad (a, "RefPtr metadata prohibited");

        case 0x5455: /* Extended UTC timestamps.  1 flag byte + timestamps. */
          /*
           * The central copy commonly stores only mtime even when its
           * flags advertise other timestamps present in the local copy.
           * Info-ZIP itself writes this legitimate compact form.
           */

          if (len < 1 || (p[i] & ~7U)
              || (len
                      != 1U
                             + 4U
                                   * (((p[i] & 1U) != 0) + ((p[i] & 2U) != 0)
                                      + ((p[i] & 4U) != 0))
                  && !(central && len == ((p[i] & 1U) ? 5U : 1U))))
            {
              return zo_bad (a, "malformed extended timestamp field");
            }

          break;

        case 0x554e: /* Xceed's Unicode name/comment field. */
          {
            unsigned chars, charoff, k;
            /* Safe to discard ONLY when it EXACTLY duplicates the ASCII
             * central-directory pathname, without any Unicode comment.
             * Xceed local records omit the comment length word. */
            if (len < (central ? 8U : 6U)
                || memcmp(p + i, "NUCX", 4) != 0)
              return zo_bad(a, "unsupported Unicode extra field");
            chars = zo_16(p + i + 4);
            charoff = central ? 8U : 6U;
            if ((central && zo_16(p + i + 6) != 0)
                || chars != e->name_len
                || chars > (len - charoff) / 2U
                || len - charoff != chars * 2U)
              return zo_bad(a, "Unicode name/comment not safely representable");
            for (k = 0U; k < chars; k++)
              {
                unsigned ch = zo_16(p + i + charoff + 2U * k);
                if (ch > 127U ||
                    (unsigned char)(ch == '\\' ? '/' : ch) != e->name[k])
                  return zo_bad(a, "Unicode pathname differs from ZIP name");
              }
            break;
          }

        case 0x7075: /* Unicode path: version, name CRC32, UTF-8 bytes. */
        case 0x6375: /* Unicode comment */
          if (len < 5 || p[i] != 1)
            {
              return zo_bad (a, "malformed Unicode metadata field");
            }

          break;

        case 0x7875: /* Unix UID/GID size-prefixed values. */
          if (len < 3 || p[i] != 1 || p[i + 1] == 0 || p[i + 1] > 8
              || len < 2U + (unsigned)p[i + 1] + 1U
              || p[i + 2U + (unsigned)p[i + 1]] == 0
              || p[i + 2U + (unsigned)p[i + 1]] > 8
              || len
                     != 3U + (unsigned)p[i + 1]
                            + (unsigned)p[i + 2U + (unsigned)p[i + 1]])
            {
              return zo_bad (a, "malformed Unix UID/GID field");
            }

          break;

        case 0x000a: /* NTFS timestamps */
          if (len < 4)
            {
              return zo_bad (a, "malformed NTFS timestamp field");
            }

          break;

        case 0x5855: /* old Info-ZIP Unix timestamps */
        case 0x7855: /* old Info-ZIP Unix UID/GID */
        case 0x000d: /* PKWARE Unix */
          break;

        default:
          return zo_bad (a,
                         "unrecognized extra field: safety not established");
        }
      i += len;
    }

  return 1;
}

static int
zo_read_extra (zo_archive *a, zo_u64 off, unsigned n, int central, zo_entry *e,
               int wu, int wc, int wo, int wd, zo_u64 *u, zo_u64 *c, zo_u64 *o)
{
  unsigned char *p;
  int ok;

  if (!n)
    {
      if (wu || wc || wo || wd)
        {
          return zo_bad (a, "missing ZIP64 extra field");
        }

      return 1;
    }

  p = (unsigned char *)malloc (n);

  if (!p)
    {
      return zo_bad (a, "out of memory for ZIP extra field");
    }

  ok = zo_archive_at (a, off, p, n)
       && zo_extras (a, p, n, central, e, wu, wc, wo, wd, u, c, o);
  free (p);

  return ok;
}

static int
zo_end (zo_archive *a, zo_u64 *cd_off, zo_u64 *cd_len, zo_u64 *members)
{
  size_t tail, i;
  unsigned char *b;
  zo_u64 base, eocd, temp, loc;
  unsigned char zloc[20], ze[56];
  int found = 0, has_z64 = 0;
  zo_u64 zsize;
  zo_u64 legacy_count, legacy_cd_len, legacy_cd_off;

  tail = (size_t)(a->filesize < 65557 ? a->filesize : 65557);

  if (tail < 22)
    {
      return zo_bad (a, "no ZIP end record");
    }

  base = a->filesize - (zo_u64)tail;
  b = (unsigned char *)malloc (tail);

  if (!b)
    {
      return zo_bad (a, "out of memory for ZIP end search");
    }

  if (!zo_archive_at (a, base, b, tail))
    {
      free (b);

      return 0;
    }

  for (i = tail - 22;; --i)
    {
      if (zo_32 (b + i) == ZO_EOCD && zo_16 (b + i + 20) == tail - i - 22)
        {
          found = 1;

          break;
        }

      if (i == 0)
        {
          break;
        }
    }

  if (!found)
    {
      free (b);

      return zo_bad (a, "ZIP EOCD missing or trailing data");
    }

  eocd = base + (zo_u64)i;
  a->eocd_offset = eocd;
  a->archive_comment_len = zo_16 (b + i + 20);

  if (zo_16 (b + i + 4) || zo_16 (b + i + 6)
      || zo_16 (b + i + 8) != zo_16 (b + i + 10))
    {
      free (b);

      return zo_bad (a, "split archive not supported");
    }

  *members = (zo_u64)zo_16 (b + i + 10);
  *cd_len = (zo_u64)zo_32 (b + i + 12);
  *cd_off = (zo_u64)zo_32 (b + i + 16);
  free (b);
  legacy_count = *members;
  legacy_cd_len = *cd_len;
  legacy_cd_off = *cd_off;

  if (eocd >= 20 && zo_archive_at (a, eocd - 20, zloc, 20)
      && zo_32 (zloc) == ZO_Z64LOC)
    {
      has_z64 = 1;
    }

  /*
   * EOF-search seeks for the optional locator.  No error if there is no
   * locator, provided the legacy directory is contiguous with EOCD.
   */

  a->error[0] = '\0';

  if (has_z64)
    {
      loc = eocd - 20;

      if (zo_32 (zloc + 4) || zo_32 (zloc + 16) != 1)
        {
          return zo_bad (a, "invalid ZIP64 locator");
        }

      temp = zo_64 (zloc + 8);

      if (!zo_archive_at (a, temp, ze, 56))
        {
          return 0;
        }

      if (zo_32 (ze) != ZO_Z64END || (zsize = zo_64 (ze + 4)) < 44
          || zsize > (ZO_U64_MAX - 12) || !zo_sum (temp, zsize + 12, &loc)
          || loc != eocd - 20 || zo_32 (ze + 16) || zo_32 (ze + 20)
          || zo_64 (ze + 24) != zo_64 (ze + 32))
        {
          return zo_bad (a, "unsupported or inconsistent ZIP64 end record");
        }

      *members = zo_64 (ze + 32);
      *cd_len = zo_64 (ze + 40);
      *cd_off = zo_64 (ze + 48);

      if ((legacy_count != 65535 && legacy_count != *members)
          || (legacy_cd_len != ZO_MAX_U32 && legacy_cd_len != *cd_len)
          || (legacy_cd_off != ZO_MAX_U32 && legacy_cd_off != *cd_off)
          || !zo_sum (*cd_off, *cd_len, &loc) || loc != temp)
        {
          return zo_bad (a, "ZIP64 directory disagrees with EOCD");
        }
    }
  else
    {
      if (*members == 65535 || *cd_off == ZO_MAX_U32 || *cd_len == ZO_MAX_U32)
        {
          return zo_bad (a, "missing ZIP64 locator");
        }

      if (!zo_sum (*cd_off, *cd_len, &temp) || temp != eocd)
        {
          return zo_bad (
              a, "central directory offsets inconsistent or SFX prefix");
        }
    }

  if (*cd_off == 0 && *members)
    {
      return zo_bad (a, "invalid central-directory start");
    }

  return 1;
}

static int
zo_cmp_entry (const void *a, const void *b)
{
  const zo_entry *x = *(const zo_entry *const *)a;
  const zo_entry *y = *(const zo_entry *const *)b;

  return   x->local_offset < y->local_offset ? -1
         : x->local_offset > y->local_offset ?  1
                                             :  0;
}

static int
zo_method_supported (unsigned m)
{
  if (m <= 6  || m == 8  || m == 9  || m == 10 || m == 12 || m == 14 || m == 16
   || m == 18 || m == 20 || m == 93 || m == 94 || m == 95 || m == 96 || m == 98
   || m == 99)
    {
      return 1;
    }

  return 0;
}

static int
zo_descriptor_match (const unsigned char *p, unsigned width64, zo_entry *e)
{
  if (zo_32 (p) != e->crc)
    {
      return 0;
    }

  if (width64)
    {
      return zo_64 (p + 4) == e->csize && zo_64 (p + 12) == e->usize;
    }

  return (zo_u64)zo_32 (p + 4) == e->csize
         && (zo_u64)zo_32 (p + 8) == e->usize;
}

static int
zo_parse (zo_archive *a)
{
  zo_u64 pos, next, u, c, off, t;
  zo_u64 i;
  zo_entry *e;
  unsigned char cen[46], loc[30], mark[24];
  zo_entry **sorted;
  unsigned nl, el, cl, ln, lx, method, flags;
  int wu, wc, wo, wd;

  if (!zo_end (a, &a->cd_offset, &a->cd_size, &a->count))
    {
      return 0;
    }

  if (a->count > (zo_u64)(((size_t)-1) / sizeof (*a->entries)))
    {
      return zo_bad (a, "too many ZIP entries");
    }

  if (a->count && (a->cd_size / 46) < a->count)
    {
      return zo_bad (a, "central directory too small");
    }

  a->entries = (zo_entry *)calloc ((size_t)(a->count ? a->count : 1),
                                   sizeof (zo_entry));
  if (!a->entries)
    {
      return zo_bad (a, "out of memory for entries");
    }

  pos = a->cd_offset;

  for (i = 0; i < a->count; i++)
    {
      e = &a->entries[(size_t)i];

      if (!zo_sum (pos, 46, &next) || next > a->cd_offset + a->cd_size
          || !zo_archive_at (a, pos, cen, 46))
        {
          return zo_bad (a, "truncated central directory");
        }

      if (zo_32 (cen) != ZO_CENTRAL)
        {
          return zo_bad (a, "invalid central-header signature");
        }

      nl = zo_16 (cen + 28);
      el = zo_16 (cen + 30);
      cl = zo_16 (cen + 32);

      if (!zo_sum (next, (zo_u64)nl + el + cl, &next)
          || next > a->cd_offset + a->cd_size || nl == 0)
        {
          return zo_bad (a, "central record bounds invalid");
        }

      e->central_offset = pos;
      e->central_extra_len = el;
      e->central_comment_len = cl;
      e->version_needed = zo_16 (cen + 6);
      e->flags = flags = zo_16 (cen + 8);
      e->method = method = zo_16 (cen + 10);
      e->crc = zo_32 (cen + 16);
      e->csize = c = zo_32 (cen + 20);
      e->usize = u = zo_32 (cen + 24);
      e->local_offset = off = zo_32 (cen + 42);
      e->name_len = nl;

      if ((flags & (1U | 0x40U | 0x2000U)) || method == 92)
        {
          return zo_bad (a, "encrypted or RefPtr member prohibited");
        }

      if ((flags & ~0x080eU) != 0)
        {
          return zo_bad (a, "unsupported general-purpose ZIP flags");
        }

      if (!zo_method_supported (method))
        {
          return zo_bad (a, "unsupported input compression method");
        }

      if (zo_16 (cen + 34) != 0 && zo_16 (cen + 34) != 65535)
        {
          return zo_bad (a, "nonzero disk-start index");
        }

      if (zo_16 (cen + 36) & 6U)
        {
          return zo_bad (a, "PKAV internal attributes prohibited");
        }

      if (zo_16 (cen + 34) == 65535)
        {
          wd = 1;
        }
      else
        {
          wd = 0;
        }

      wu = (u == ZO_MAX_U32);
      wc = (c == ZO_MAX_U32);
      wo = (off == ZO_MAX_U32);
      e->name = (unsigned char *)malloc (nl + 1);

      if (!e->name)
        {
          return zo_bad (a, "out of memory for name");
        }

      if (!zo_archive_at (a, pos + 46, e->name, nl))
        {
          return 0;
        }

      e->name[nl] = 0;

      if (memchr (e->name, 0, nl))
        {
          return zo_bad (a, "embedded NUL in ZIP member name");
        }

      if (!zo_read_extra (a, pos + 46 + nl, el, 1, e, wu, wc, wo, wd, &u, &c,
                          &off))
        {
          return 0;
        }

      e->usize = u;
      e->csize = c;
      e->local_offset = off;

      if (e->local_offset >= a->cd_offset)
        {
          return zo_bad (a, "local header overlaps central directory");
        }

      pos = next;
    }

  if (pos != a->cd_offset + a->cd_size)
    {
      return zo_bad (a, "central directory contains unexpected records");
    }

  for (i = 0; i < a->count; i++)
    {
      e = &a->entries[(size_t)i];

      if (!zo_archive_at (a, e->local_offset, loc, 30))
        {
          return 0;
        }

      if (zo_32 (loc) != ZO_LOCAL)
        {
          return zo_bad (a, "invalid local-header signature");
        }

      flags = zo_16 (loc + 6);
      method = zo_16 (loc + 8);

      if (zo_16 (loc + 4) != e->version_needed)
        {
          return zo_bad (a, "local/central extraction versions disagree");
        }

      if (flags != e->flags || method != e->method)
        {
          return zo_bad (a, "local/central method or flags disagree");
        }

      /*
       * DOS last-modification time/date are duplicated by the ZIP format.
       * A mismatch would otherwise be silently preserved by the writer.
       */
      {
        unsigned char central_stamp[4];

        if (!zo_archive_at (a, e->central_offset + 12, central_stamp, 4))
          {
            return 0;
          }

        if (memcmp (loc + 10, central_stamp, 4) != 0)
          {
            return zo_bad (a, "local/central DOS timestamps disagree");
          }
      }

      ln = zo_16 (loc + 26);
      lx = zo_16 (loc + 28);
      e->local_extra_len = lx;

      if (ln != e->name_len)
        {
          return zo_bad (a, "local/central filename length differs");
        }

      if (!zo_sum (e->local_offset, 30UL + ln + lx, &e->data_offset)
          || e->data_offset > a->cd_offset)
        {
          return zo_bad (a, "invalid local header length");
        }

      {
        unsigned char *name = (unsigned char *)malloc (ln);
        int ok;

        if (!name)
          {
            return zo_bad (a, "out of memory for local name");
          }

        ok = zo_archive_at (a, e->local_offset + 30, name, ln)
             && memcmp (name, e->name, ln) == 0;
        free (name);

        if (!ok)
          {
            return zo_bad (a, "local/central filename mismatch");
          }
      }

      if (!(flags & 8))
        {
          if (zo_32 (loc + 14) != e->crc
              || (zo_32 (loc + 18) != e->csize
                  && zo_32 (loc + 18) != ZO_MAX_U32)
              || (zo_32 (loc + 22) != e->usize
                  && zo_32 (loc + 22) != ZO_MAX_U32))
            {
              return zo_bad (a, "local size or CRC mismatch");
            }
        }

      u = zo_32 (loc + 22);
      c = zo_32 (loc + 18);
      off = 0;
      wu = (u == ZO_MAX_U32);
      wc = (c == ZO_MAX_U32);

      if (!zo_read_extra (a, e->local_offset + 30 + ln, lx, 0, e, wu, wc, 0, 0,
                          &u, &c, &off))
        {
          return 0;
        }

      if (!(flags & 8) && (u != e->usize || c != e->csize))
        {
          return zo_bad (a, "local ZIP64 sizes mismatch");
        }

      if (!zo_sum (e->data_offset, e->csize, &e->data_end)
          || e->data_end > a->cd_offset)
        {
          return zo_bad (a, "compressed data overlaps central directory");
        }

      e->record_end = e->data_end;

      if (flags & 8)
        {
          /* Candidate signature-less/with-signature descriptors, 32/64-bit. */
          unsigned want64
              = (e->csize > ZO_MAX_U32 || e->usize > ZO_MAX_U32 || wu || wc);
          unsigned len = want64 ? 20 : 12;
          int plain = 0, signed_desc = 0;

          if (e->data_end > a->cd_offset
              || a->cd_offset - e->data_end < (zo_u64)len)
            {
              return zo_bad (a, "short ZIP data descriptor");
            }

          if (!zo_archive_at (a, e->data_end, mark, len))
            {
              return 0;
            }

          plain = zo_descriptor_match (mark, want64, e);

          if (a->cd_offset - e->data_end >= (zo_u64)(len + 4))
            {
              if (!zo_archive_at (a, e->data_end, mark, len + 4))
                {
                  return 0;
                }

              if (zo_32 (mark) == ZO_DATA)
                {
                  signed_desc = zo_descriptor_match (mark + 4, want64, e);
                }
            }

          if (plain == signed_desc)
            {
              return zo_bad (a, "invalid or ambiguous ZIP data descriptor");
            }

          e->record_end += (zo_u64)(len + (signed_desc ? 4 : 0));
        }

      if (e->record_end > a->cd_offset)
        {
          return zo_bad (a, "local record extends beyond central directory");
        }

      if (e->method == 99)
        {
          unsigned long magic;

          if (e->csize < 4 || !zo_archive_at (a, e->data_offset, mark, 4))
            {
              return zo_bad (a, "invalid LZFSE method-99 header");
            }

          magic = zo_32 (mark);

          if (magic != 0x24787662UL && magic != 0x2d787662UL
           && magic != 0x31787662UL && magic != 0x32787662UL
           && magic != 0x6e787662UL)
            {
              return zo_bad (a, "method-99 stream is not unencrypted LZFSE");
            }
        }
    }

  if (a->count == 0)
    {
      if (a->cd_offset != 0)
        {
          return zo_bad (
              a, "empty archive contains an unsupported prefix or gap");
        }

      return 1;
    }

  sorted = (zo_entry **)malloc ((size_t)a->count * sizeof (*sorted));

  if (!sorted)
    {
      return zo_bad (a, "out of memory validating record spans");
    }

  for (i = 0; i < a->count; i++)
    {
      sorted[(size_t)i] = &a->entries[(size_t)i];
    }

  qsort (sorted, (size_t)a->count, sizeof (*sorted), zo_cmp_entry);
  t = 0;

  for (i = 0; i < a->count; i++)
    {
      if (sorted[(size_t)i]->local_offset != t)
        {
          free (sorted);

          return zo_bad (
              a, "SFX prefix, inter-record gap, or overlapping local records");
        }

      t = sorted[(size_t)i]->record_end;
    }

  free (sorted);

  if (t != a->cd_offset)
    {
      return zo_bad (a, "gap before central directory");
    }

  return 1;
}

/*
 * The fingerprint detects changes even when the resulting file has the
 * same size and timestamp. The stat identity also detects pathname swaps.
 * These checks detect ordinary concurrent mutation, not an adversary who
 * can restore both file contents and metadata between checks.
 */

static int
zo_archive_hash (zo_archive *a, zo_u64 *result)
{
  unsigned char buf[32768];
  zo_u64 hash = ((zo_u64)0xcbf29ce4UL << 32) | 0x84222325UL;
  zo_u64 prime = ((zo_u64)1 << 40) | 0x1b3UL;
  zo_u64 left = a->filesize;
  unsigned i;

  if (!zo_seek (a, 0))
    {
      return 0;
    }

  while (left)
    {
      size_t n = left > sizeof (buf) ? sizeof (buf) : (size_t)left;

      if (fread (buf, 1, n, a->fp) != n)
        {
          return zo_bad (a, "input changed or truncated during fingerprint");
        }

      for (i = 0; i < (unsigned)n; i++)
        {
          hash = (hash ^ (zo_u64)buf[i]) * prime;
        }

      left -= (zo_u64)n;
    }

  *result = hash;

  return 1;
}

#ifndef _WIN32
static int
zo_archive_stat (zo_archive *a, int save)
{
  struct stat fdst, pathst;
  zo_u64 mn = 0, cn = 0;

  if (fstat (fileno (a->fp), &fdst) != 0 || stat (a->path, &pathst) != 0
      || !S_ISREG (fdst.st_mode) || !S_ISREG (pathst.st_mode)
      || fdst.st_dev != pathst.st_dev || fdst.st_ino != pathst.st_ino
      || fdst.st_size < 0 || (zo_u64)fdst.st_size != a->filesize)
    {
      return zo_bad (a, "input replaced or changed during optimization");
    }

# if defined(__APPLE__)
  mn = (zo_u64)fdst.st_mtimespec.tv_nsec;
  cn = (zo_u64)fdst.st_ctimespec.tv_nsec;
# elif defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
  mn = (zo_u64)fdst.st_mtim.tv_nsec;
  cn = (zo_u64)fdst.st_ctim.tv_nsec;
# endif /* if defined( __APPLE__ ) */

  if (save)
    {
      a->source_device = (zo_u64)fdst.st_dev;
      a->source_inode = (zo_u64)fdst.st_ino;
      a->source_size = (zo_u64)fdst.st_size;
      a->source_mtime = (zo_u64)fdst.st_mtime;
      a->source_ctime = (zo_u64)fdst.st_ctime;
      a->source_mtime_nsec = mn;
      a->source_ctime_nsec = cn;
    }
  else if (a->source_device != (zo_u64)fdst.st_dev
           || a->source_inode != (zo_u64)fdst.st_ino
           || a->source_size != (zo_u64)fdst.st_size
           || a->source_mtime != (zo_u64)fdst.st_mtime
           || a->source_ctime != (zo_u64)fdst.st_ctime
           || a->source_mtime_nsec != mn || a->source_ctime_nsec != cn)
    {
      return zo_bad (a, "input metadata changed during optimization");
    }

  return 1;
}
#endif /* ifndef _WIN32 */

int
zo_archive_unchanged (zo_archive *a)
{
  zo_u64 hash;

#ifndef _WIN32
  if (!zo_archive_stat (a, 0))
    {
      return 0;
    }
#endif /* ifndef _WIN32 */

  if (!zo_archive_hash (a, &hash))
    {
      return 0;
    }

#ifndef _WIN32
  if (!zo_archive_stat (a, 0))
    {
      return 0;
    }
#endif /* ifndef _WIN32 */

  if (hash != a->initial_hash)
    {
      return zo_bad (a, "input contents changed during optimization");
    }

  return 1;
}

int
zo_archive_open (zo_archive *a, const char *path)
{
  memset (a, 0, sizeof (*a));
  a->path = path;
  a->fp = fopen (path, "rb");

  if (!a->fp)
    {
      return zo_bad (a, "cannot open input ZIP");
    }

#ifdef _WIN32
  if (_fseeki64 (a->fp, 0, SEEK_END)
      || (a->filesize = (zo_u64)_ftelli64 (a->fp)) == ZO_U64_MAX)
#else  /* ifdef _WIN32 */
  if (fseeko (a->fp, 0, SEEK_END)
      || (a->filesize = (zo_u64)ftello (a->fp)) == ZO_U64_MAX)
#endif /* ifdef _WIN32 */
    {
      return zo_bad (a, "cannot establish ZIP file size");
    }

#ifndef _WIN32
  if (!zo_archive_stat (a, 1))
    {
      return 0;
    }
#endif /* ifndef _WIN32 */

  if (!zo_parse (a) || !zo_archive_hash (a, &a->initial_hash))
    {
      return 0;
    }

#ifndef _WIN32
  if (!zo_archive_stat (a, 0))
    {
      return 0;
    }
#endif /* ifndef _WIN32 */

  return 1;
}

void
zo_archive_close (zo_archive *a)
{
  zo_u64 i;

  if (a->entries)
    {
      for (i = 0; i < a->count; i++)
        {
          free (a->entries[(size_t)i].name);
        }

      free (a->entries);
    }

  if (a->fp)
    {
      fclose (a->fp);
    }

  memset (a, 0, sizeof (*a));
}
