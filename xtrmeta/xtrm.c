/* Experimental portable parser/serializer for M0 format review.
 * NOT PRODUCTION WIRE FORMAT. SPDX-License-Identifier: MIT-0 */
#include "xtrm.h"
#include <limits.h>
#include <string.h>
/* Reuse the native CRC32/IEEE PCLMUL and ARMv8 accelerators where supported.
 * Normal ZIP CRC and xattr CRC both use polynomial 0xedb88320. */
#if !defined(SFX) && defined(__GNUC__)  \
    && (defined(__x86_64__) || defined(__amd64__))
# define ZCONST const
# define uch unsigned char
# define z_uint4 unsigned int
# define extent size_t
/* The existing assembly header has an extended string literal.  Clang
 * rejects it under -pedantic -Werror although it is compiler-supported. */
# if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Woverlength-strings"
# endif
# include "../zip30/crc32_pclmul.h"
# if defined(__clang__)
#  pragma clang diagnostic pop
# endif
# undef extent
# undef z_uint4
# undef uch
# undef ZCONST
#endif
#if !defined(SFX) && !defined(NO_ARM_CRC32) && !defined(USE_ZLIB) \
    && !defined(ASM_CRC) && !defined(CRC_TABLE_ONLY) \
    && !defined(IZ_CRC_BE_OPTIMIZ)
#include "../zip30/crc32_arm.h"
#endif

#if CHAR_BIT != 8
# error ZIP wire encoding requires 8-bit bytes
#endif /* if CHAR_BIT != 8 */
#if ULONG_MAX < 0xffffffffUL
# error xtrm requires unsigned long of at least 32 bits
#endif /* if ULONG_MAX < 0xffffffffUL */
#define XTR_MASK 0xffffffffUL

static unsigned
xtr_16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}
static unsigned long
xtr_32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static xtr_u64
xtr_64 (const unsigned char *p)
{
  xtr_u64 v;

  v.lo = xtr_32 (p);
  v.hi = xtr_32 (p + 4);
  return v;
}
static void
xtr_put16 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char)v;
  p[1] = (unsigned char)(v >> 8);
}
static void
xtr_put32 (unsigned char *p, unsigned long v)
{
  p[0] = (unsigned char)v;
  p[1] = (unsigned char)(v >> 8);
  p[2] = (unsigned char)(v >> 16);
  p[3] = (unsigned char)(v >> 24);
}
static void
xtr_put64 (unsigned char *p, xtr_u64 v)
{
  xtr_put32 (p, v.lo);
  xtr_put32 (p + 4, v.hi);
}
static int
xtr_u64_valid (xtr_u64 v)
{
  return v.lo <= XTR_MASK && v.hi <= XTR_MASK;
}
static int
xtr_lt (xtr_u64 a, xtr_u64 b)
{
  return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo);
}
static int
xtr_sub (xtr_u64 *a, xtr_u64 b)
{
  if (xtr_lt (*a, b))
    {
      return 0;
    }

  if (a->lo < b.lo)
    {
      a->lo = (a->lo + (XTR_MASK - b.lo) + 1UL) & XTR_MASK;
      a->hi = (a->hi - b.hi - 1UL) & XTR_MASK;
    }
  else
    {
      a->lo -= b.lo;
      a->hi -= b.hi;
    }

  return 1;
}
static int
xtr_equal (xtr_u64 a, xtr_u64 b)
{
  return a.lo == b.lo && a.hi == b.hi;
}
static xtr_u64
xtr_from_ulong (unsigned long v)
{
  xtr_u64 ret;

  ret.lo = v & XTR_MASK;
  ret.hi = (v >> 16 >> 16) & XTR_MASK;
  return ret;
}
static int
xtr_read_exact (xtr_reader *r, xtr_u64 *remain, unsigned char *buf, size_t n)
{
  size_t at = 0;
  xtr_u64 need = xtr_from_ulong ((unsigned long)n);

  if (!xtr_sub (remain, need))
    {
      return XTR_CORRUPT;
    }

  while (at < n)
    {
      size_t got = r->read (r->context, buf + at, n - at);
      if (got == 0 || got > n - at)
        {
          return XTR_IO;
        }

      at += got;
    }
  return XTR_OK;
}
int
xtr_manifest_header (unsigned char out[36], const xtr_manifest *m)
{
  if (out == NULL || m == NULL || m->count > XTR_MASK
      || !xtr_u64_valid (m->records_len))
    {
      return XTR_CORRUPT;
    }

  memcpy (out, "XTMD", 4);
  out[4] = 1;
  out[5] = 0;
  out[6] = 0;
  out[7] = 0;
  memcpy (out + 8, m->owner, 16);
  xtr_put32 (out + 24, m->count);
  xtr_put64 (out + 28, m->records_len);
  return XTR_OK;
}
int
xtr_record_header (unsigned char out[28], const xtr_record *r)
{
  if (out == NULL || r == NULL || r->type == 0 || r->type == 65535U
      || r->type > 65535U || r->flags > 65535U || r->origin > 65535U
      || r->encoding > 2 || r->ns_len > XTR_MASK || r->name_len > XTR_MASK
      || r->native_len > XTR_MASK || (r->encoding == 2 && (r->name_len & 1UL))
      || !xtr_u64_valid (r->value_len))
    {
      return XTR_CORRUPT;
    }

  xtr_put16 (out, r->type);
  xtr_put16 (out + 2, r->flags);
  xtr_put16 (out + 4, r->origin);
  xtr_put16 (out + 6, r->encoding);
  xtr_put32 (out + 8, r->ns_len);
  xtr_put32 (out + 12, r->name_len);
  xtr_put32 (out + 16, r->native_len);
  xtr_put64 (out + 20, r->value_len);
  return XTR_OK;
}
static int
xtr_read_field (xtr_reader *r, xtr_u64 *remain, const xtr_record *rec,
                unsigned field, xtr_u64 len)
{
  unsigned char buf[4096];
  int err;
  xtr_u64 chunk;

  if (!xtr_sub (remain, len))
    {
      return XTR_CORRUPT;
    }

  while (len.lo || len.hi)
    {
      size_t want = sizeof (buf);
      size_t at = 0;
      if (!len.hi && len.lo < (unsigned long)want)
        {
          want = (size_t)len.lo;
        }

      while (at < want)
        {
          size_t got = r->read (r->context, buf + at, want - at);
          if (got == 0 || got > want - at)
            {
              return XTR_IO;
            }

          at += got;
        }
      if (r->data != NULL && r->data (r->sink_context, rec, field, buf, want))
        {
          return XTR_IO;
        }

      chunk = xtr_from_ulong ((unsigned long)want);
      err = xtr_sub (&len, chunk);
      if (!err)
        {
          return XTR_CORRUPT;
        }
    }
  return XTR_OK;
}
int
xtr_parse_manifest (xtr_reader *r, xtr_u64 total, xtr_manifest *m)
{
  unsigned char buf[36];
  xtr_record rec;
  xtr_u64 remain, records, want, len;
  unsigned long i;
  int err;

  if (r == NULL || r->read == NULL || m == NULL || !xtr_u64_valid (total)
      || !xtr_u64_valid (r->max_total))
    {
      return XTR_CORRUPT;
    }

  if (xtr_lt (r->max_total, total))
    {
      return XTR_LIMIT;
    }

  remain = total;
  err = xtr_read_exact (r, &remain, buf, 36);
  if (err)
    {
      return err;
    }

  if (memcmp (buf, "XTMD", 4) || buf[6] || buf[7])
    {
      return XTR_CORRUPT;
    }

  if (buf[4] != 1 || buf[5] != 0)
    {
      return XTR_UNSUPPORTED;
    }

  memcpy (m->owner, buf + 8, 16);
  m->count = xtr_32 (buf + 24);
  m->records_len = xtr_64 (buf + 28);
  if (m->count > r->max_records)
    {
      return XTR_LIMIT;
    }

  if (!xtr_equal (m->records_len, remain))
    {
      return XTR_CORRUPT;
    }

  records = remain;
  for (i = 0; i < m->count; ++i)
    {
      err = xtr_read_exact (r, &records, buf, 28);
      if (err)
        {
          return err;
        }

      if (!xtr_sub (&remain, xtr_from_ulong (28UL)))
        {
          return XTR_CORRUPT;
        }

      rec.type = xtr_16 (buf);
      rec.flags = xtr_16 (buf + 2);
      rec.origin = xtr_16 (buf + 4);
      rec.encoding = xtr_16 (buf + 6);
      rec.ns_len = xtr_32 (buf + 8);
      rec.name_len = xtr_32 (buf + 12);
      rec.native_len = xtr_32 (buf + 16);
      rec.value_len = xtr_64 (buf + 20);
      if (rec.type == 0 || rec.type == 65535U || rec.encoding > 2
          || (rec.encoding == 2 && (rec.name_len & 1UL)))
        {
          return XTR_CORRUPT;
        }

      if (rec.ns_len > r->max_field || rec.name_len > r->max_field
          || rec.native_len > r->max_field)
        {
          return XTR_LIMIT;
        }

      len = xtr_from_ulong (rec.ns_len);
      if (!xtr_sub (&records, len))
        {
          return XTR_CORRUPT;
        }

      len = xtr_from_ulong (rec.name_len);
      if (!xtr_sub (&records, len))
        {
          return XTR_CORRUPT;
        }

      len = xtr_from_ulong (rec.native_len);
      if (!xtr_sub (&records, len))
        {
          return XTR_CORRUPT;
        }

      if (!xtr_sub (&records, rec.value_len))
        {
          return XTR_CORRUPT;
        }

      /* All bounds established; read callbacks see only checked bytes. */
      if (r->begin != NULL && r->begin (r->sink_context, &rec))
        {
          return XTR_IO;
        }

      want = xtr_from_ulong (rec.ns_len);
      err = xtr_read_field (r, &remain, &rec, 0, want);
      if (err)
        {
          return err;
        }

      want = xtr_from_ulong (rec.name_len);
      err = xtr_read_field (r, &remain, &rec, 1, want);
      if (err)
        {
          return err;
        }

      want = xtr_from_ulong (rec.native_len);
      err = xtr_read_field (r, &remain, &rec, 2, want);
      if (err)
        {
          return err;
        }

      err = xtr_read_field (r, &remain, &rec, 3, rec.value_len);
      if (err)
        {
          return err;
        }
    }

  if (records.lo != 0 || records.hi != 0 || remain.lo != 0 || remain.hi != 0)
    {
      return XTR_CORRUPT;
    }

  return XTR_OK;
}
#ifndef SFX
static const unsigned long xtr_crc_byte[256] = {
    0x00000000UL, 0x77073096UL, 0xee0e612cUL, 0x990951baUL,
    0x076dc419UL, 0x706af48fUL, 0xe963a535UL, 0x9e6495a3UL,
    0x0edb8832UL, 0x79dcb8a4UL, 0xe0d5e91eUL, 0x97d2d988UL,
    0x09b64c2bUL, 0x7eb17cbdUL, 0xe7b82d07UL, 0x90bf1d91UL,
    0x1db71064UL, 0x6ab020f2UL, 0xf3b97148UL, 0x84be41deUL,
    0x1adad47dUL, 0x6ddde4ebUL, 0xf4d4b551UL, 0x83d385c7UL,
    0x136c9856UL, 0x646ba8c0UL, 0xfd62f97aUL, 0x8a65c9ecUL,
    0x14015c4fUL, 0x63066cd9UL, 0xfa0f3d63UL, 0x8d080df5UL,
    0x3b6e20c8UL, 0x4c69105eUL, 0xd56041e4UL, 0xa2677172UL,
    0x3c03e4d1UL, 0x4b04d447UL, 0xd20d85fdUL, 0xa50ab56bUL,
    0x35b5a8faUL, 0x42b2986cUL, 0xdbbbc9d6UL, 0xacbcf940UL,
    0x32d86ce3UL, 0x45df5c75UL, 0xdcd60dcfUL, 0xabd13d59UL,
    0x26d930acUL, 0x51de003aUL, 0xc8d75180UL, 0xbfd06116UL,
    0x21b4f4b5UL, 0x56b3c423UL, 0xcfba9599UL, 0xb8bda50fUL,
    0x2802b89eUL, 0x5f058808UL, 0xc60cd9b2UL, 0xb10be924UL,
    0x2f6f7c87UL, 0x58684c11UL, 0xc1611dabUL, 0xb6662d3dUL,
    0x76dc4190UL, 0x01db7106UL, 0x98d220bcUL, 0xefd5102aUL,
    0x71b18589UL, 0x06b6b51fUL, 0x9fbfe4a5UL, 0xe8b8d433UL,
    0x7807c9a2UL, 0x0f00f934UL, 0x9609a88eUL, 0xe10e9818UL,
    0x7f6a0dbbUL, 0x086d3d2dUL, 0x91646c97UL, 0xe6635c01UL,
    0x6b6b51f4UL, 0x1c6c6162UL, 0x856530d8UL, 0xf262004eUL,
    0x6c0695edUL, 0x1b01a57bUL, 0x8208f4c1UL, 0xf50fc457UL,
    0x65b0d9c6UL, 0x12b7e950UL, 0x8bbeb8eaUL, 0xfcb9887cUL,
    0x62dd1ddfUL, 0x15da2d49UL, 0x8cd37cf3UL, 0xfbd44c65UL,
    0x4db26158UL, 0x3ab551ceUL, 0xa3bc0074UL, 0xd4bb30e2UL,
    0x4adfa541UL, 0x3dd895d7UL, 0xa4d1c46dUL, 0xd3d6f4fbUL,
    0x4369e96aUL, 0x346ed9fcUL, 0xad678846UL, 0xda60b8d0UL,
    0x44042d73UL, 0x33031de5UL, 0xaa0a4c5fUL, 0xdd0d7cc9UL,
    0x5005713cUL, 0x270241aaUL, 0xbe0b1010UL, 0xc90c2086UL,
    0x5768b525UL, 0x206f85b3UL, 0xb966d409UL, 0xce61e49fUL,
    0x5edef90eUL, 0x29d9c998UL, 0xb0d09822UL, 0xc7d7a8b4UL,
    0x59b33d17UL, 0x2eb40d81UL, 0xb7bd5c3bUL, 0xc0ba6cadUL,
    0xedb88320UL, 0x9abfb3b6UL, 0x03b6e20cUL, 0x74b1d29aUL,
    0xead54739UL, 0x9dd277afUL, 0x04db2615UL, 0x73dc1683UL,
    0xe3630b12UL, 0x94643b84UL, 0x0d6d6a3eUL, 0x7a6a5aa8UL,
    0xe40ecf0bUL, 0x9309ff9dUL, 0x0a00ae27UL, 0x7d079eb1UL,
    0xf00f9344UL, 0x8708a3d2UL, 0x1e01f268UL, 0x6906c2feUL,
    0xf762575dUL, 0x806567cbUL, 0x196c3671UL, 0x6e6b06e7UL,
    0xfed41b76UL, 0x89d32be0UL, 0x10da7a5aUL, 0x67dd4accUL,
    0xf9b9df6fUL, 0x8ebeeff9UL, 0x17b7be43UL, 0x60b08ed5UL,
    0xd6d6a3e8UL, 0xa1d1937eUL, 0x38d8c2c4UL, 0x4fdff252UL,
    0xd1bb67f1UL, 0xa6bc5767UL, 0x3fb506ddUL, 0x48b2364bUL,
    0xd80d2bdaUL, 0xaf0a1b4cUL, 0x36034af6UL, 0x41047a60UL,
    0xdf60efc3UL, 0xa867df55UL, 0x316e8eefUL, 0x4669be79UL,
    0xcb61b38cUL, 0xbc66831aUL, 0x256fd2a0UL, 0x5268e236UL,
    0xcc0c7795UL, 0xbb0b4703UL, 0x220216b9UL, 0x5505262fUL,
    0xc5ba3bbeUL, 0xb2bd0b28UL, 0x2bb45a92UL, 0x5cb36a04UL,
    0xc2d7ffa7UL, 0xb5d0cf31UL, 0x2cd99e8bUL, 0x5bdeae1dUL,
    0x9b64c2b0UL, 0xec63f226UL, 0x756aa39cUL, 0x026d930aUL,
    0x9c0906a9UL, 0xeb0e363fUL, 0x72076785UL, 0x05005713UL,
    0x95bf4a82UL, 0xe2b87a14UL, 0x7bb12baeUL, 0x0cb61b38UL,
    0x92d28e9bUL, 0xe5d5be0dUL, 0x7cdcefb7UL, 0x0bdbdf21UL,
    0x86d3d2d4UL, 0xf1d4e242UL, 0x68ddb3f8UL, 0x1fda836eUL,
    0x81be16cdUL, 0xf6b9265bUL, 0x6fb077e1UL, 0x18b74777UL,
    0x88085ae6UL, 0xff0f6a70UL, 0x66063bcaUL, 0x11010b5cUL,
    0x8f659effUL, 0xf862ae69UL, 0x616bffd3UL, 0x166ccf45UL,
    0xa00ae278UL, 0xd70dd2eeUL, 0x4e048354UL, 0x3903b3c2UL,
    0xa7672661UL, 0xd06016f7UL, 0x4969474dUL, 0x3e6e77dbUL,
    0xaed16a4aUL, 0xd9d65adcUL, 0x40df0b66UL, 0x37d83bf0UL,
    0xa9bcae53UL, 0xdebb9ec5UL, 0x47b2cf7fUL, 0x30b5ffe9UL,
    0xbdbdf21cUL, 0xcabac28aUL, 0x53b39330UL, 0x24b4a3a6UL,
    0xbad03605UL, 0xcdd70693UL, 0x54de5729UL, 0x23d967bfUL,
    0xb3667a2eUL, 0xc4614ab8UL, 0x5d681b02UL, 0x2a6f2b94UL,
    0xb40bbe37UL, 0xc30c8ea1UL, 0x5a05df1bUL, 0x2d02ef8dUL
};
#endif
unsigned long
xtr_crc32_update (unsigned long crc, const unsigned char *p, size_t n)
{
  unsigned long c;
  size_t i;
  if (p == NULL && n != 0)
    return 0;
#ifdef IZ_CRC32_PCLMUL
  if (n >= 256U && (crc & ~XTR_MASK) == 0
      && iz_pclmul_available ())
    {
      size_t bulk = n & ~(size_t)15U;
      crc = iz_crc32_pclmul ((unsigned int)crc, p, bulk);
      p += bulk;
      n -= bulk;
    }
#endif
#ifdef IZ_ARM_CRC32_ENABLED
  if (n >= 128U && iz_arm_has (IZ_ARM_CRC_BIT))
    return (unsigned long)iz_arm_crc32 ((unsigned int)crc, p, n);
#endif
  c = (crc ^ XTR_MASK) & XTR_MASK;
#ifdef SFX
  for (i = 0; i < n; ++i)
    {
      unsigned j;
      c ^= p[i];
      for (j = 0; j < 8; ++j)
        c = (c & 1UL) ? ((c >> 1) ^ 0xedb88320UL) : (c >> 1);
    }
#else
# define XTR_CRC_BYTE_STEP(b) do { \
    c = (c >> 8) ^ xtr_crc_byte[(c ^ (b)) & 255UL]; \
  } while (0)
  for (i = 0; n - i >= 4U; i += 4U)
    {
      XTR_CRC_BYTE_STEP (p[i]);
      XTR_CRC_BYTE_STEP (p[i + 1]);
      XTR_CRC_BYTE_STEP (p[i + 2]);
      XTR_CRC_BYTE_STEP (p[i + 3]);
    }
  for (; i < n; ++i)
    XTR_CRC_BYTE_STEP (p[i]);
# undef XTR_CRC_BYTE_STEP
#endif
  return (c ^ XTR_MASK) & XTR_MASK;
}

int
xtr_extra_write (unsigned char out[], const xtr_extra *e, int central,
                 const unsigned char *inline_data, size_t inline_len,
                 size_t capacity, size_t *written)
{
  size_t n;

  if (out == NULL || e == NULL || written == NULL
      || !xtr_u64_valid (e->manifest_len) || e->count > XTR_MASK
      || e->crc32 > XTR_MASK || (e->mode != 1 && e->mode != 2) || e->flags > 1
      || (e->flags
          && (e->mode != 2 || e->count || e->manifest_len.lo
              || e->manifest_len.hi || e->crc32)))
    {
      return XTR_CORRUPT;
    }

  if (!central && (inline_len || inline_data != NULL))
    {
      return XTR_CORRUPT;
    }

  if (e->mode == 1 && e->flags)
    {
      return XTR_CORRUPT;
    }

  n = 40;
  if (central && e->mode == 1)
    {
      if (e->manifest_len.hi || e->manifest_len.lo != (unsigned long)inline_len
          || (inline_len && inline_data == NULL))
        {
          return XTR_CORRUPT;
        }

      if (inline_len > 65535U - 40U)
        {
          return XTR_LIMIT;
        }

      if (inline_len < 36 || memcmp (inline_data, "XTMD\001\000\000\000", 8)
          || memcmp (inline_data + 8, e->owner, 16)
          || xtr_32 (inline_data + 24) != e->count
          || xtr_64 (inline_data + 28).hi
                 != ((unsigned long)(inline_len - 36) >> 16 >> 16)
          || xtr_64 (inline_data + 28).lo
                 != ((unsigned long)(inline_len - 36) & XTR_MASK)
          || xtr_crc32_update (0, inline_data, inline_len) != e->crc32)
        {
          return XTR_CORRUPT;
        }

      n += inline_len;
    }

  /* Digest for public COMPANION is intentionally not generated here. */
  if (central && e->mode == 2 && e->flags == 0)
    {
      return XTR_UNSUPPORTED;
    }

  if (n > 65535U || n > capacity)
    {
      return XTR_LIMIT;
    }

  memcpy (out, "XTRO", 4);
  out[4] = 1;
  out[5] = 0;
  out[6] = (unsigned char)e->mode;
  out[7] = (unsigned char)e->flags;
  memcpy (out + 8, e->owner, 16);
  xtr_put32 (out + 24, e->count);
  xtr_put64 (out + 28, e->manifest_len);
  xtr_put32 (out + 36, e->crc32);
  if (central && e->mode == 1 && inline_len)
    {
      memcpy (out + 40, inline_data, inline_len);
    }

  *written = n;
  return XTR_OK;
}
int
xtr_extra_read (const unsigned char *p, size_t n, int central, xtr_extra *e)
{
  if (p == NULL || e == NULL || n < 40 || n > 65535U || memcmp (p, "XTRO", 4))
    {
      return XTR_CORRUPT;
    }

  if (p[4] != 1 || p[5] != 0)
    {
      return XTR_UNSUPPORTED;
    }

  e->mode = p[6];
  e->flags = p[7];
  memcpy (e->owner, p + 8, 16);
  e->count = xtr_32 (p + 24);
  e->manifest_len = xtr_64 (p + 28);
  e->crc32 = xtr_32 (p + 36);
  if (e->mode == 1)
    {
      if (e->flags || (!central && n != 40)
          || (central
              && (e->manifest_len.hi
                  || e->manifest_len.lo != (unsigned long)(n - 40))))
        {
          return XTR_CORRUPT;
        }
    }
  else if (e->mode == 2)
    {
      if (e->flags > 1 || n != (size_t)((central && !e->flags) ? 72 : 40))
        {
          return XTR_CORRUPT;
        }

      if (e->flags
          && (e->count || e->manifest_len.lo || e->manifest_len.hi
              || e->crc32))
        {
          return XTR_CORRUPT;
        }
    }
  else
    {
      return XTR_CORRUPT;
    }

  return XTR_OK;
}
