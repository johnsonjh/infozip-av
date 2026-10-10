/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#include "cmpsc16.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define CM_MAX_DICT 65536UL
#define CM_MAX_PHRASE 260U
#define CM_HUFF_MAX 640U

/* Byte-addressed, bit-LSB-first input for RFC1951 only. */
typedef struct cm_bits
{
  const unsigned char *data;
  size_t size;
  size_t pos;
  unsigned bit;
} cm_bits;

static int
cm_bit (cm_bits *b, unsigned *v)
{
  if (b->pos >= b->size)
    {
      return -1;
    }

  *v = ((unsigned)b->data[b->pos] >> b->bit) & 1U;
  if (++b->bit == 8U)
    {
      b->bit = 0U;
      ++b->pos;
    }

  return 0;
}

static int
cm_get (cm_bits *b, unsigned n, unsigned *v)
{
  unsigned i, x, k = 0U;

  if (n > 16U)
    {
      return -1;
    }

  for (i = 0U; i < n; ++i)
    {
      if (cm_bit (b, &x))
        {
          return -1;
        }

      k |= x << i;
    }

  *v = k;
  return 0;
}

typedef struct cm_huff
{
  short child[CM_HUFF_MAX][2];
  short value[CM_HUFF_MAX];
  unsigned nodes;
} cm_huff;

static int
cm_tree (cm_huff *t, const unsigned char *lengths, unsigned nsym)
{
  unsigned freq[16], next[16];
  unsigned n, len, i, c, node, bit;
  long remaining = 1L;
  unsigned active = 0U;

  if (nsym > 320U)
    {
      return -1;
    }

  for (i = 0U; i < 16U; ++i)
    {
      freq[i] = next[i] = 0U;
    }

  for (i = 0U; i < CM_HUFF_MAX; ++i)
    {
      t->child[i][0] = t->child[i][1] = -1;
      t->value[i] = -1;
    }

  t->nodes = 1U;
  for (i = 0U; i < nsym; ++i)
    {
      if (lengths[i] > 15U)
        {
          return -1;
        }

      if (lengths[i])
        {
          ++freq[lengths[i]];
          ++active;
        }
    }

  if (!active)
    {
      t->nodes = 0U;
      return 0;
    }

  for (i = 1U; i < 16U; ++i)
    {
      remaining = 2L * remaining - (long)freq[i];
      if (remaining < 0L)
        {
          return -1;
        }
    }

  c = 0U;
  for (i = 1U; i < 16U; ++i)
    {
      c = (c + freq[i - 1U]) << 1;
      next[i] = c;
    }

  for (n = 0U; n < nsym; ++n)
    {
      len = lengths[n];
      if (!len)
        {
          continue;
        }

      c = next[len]++;
      node = 0U;
      for (i = len; i != 0U; --i)
        {
          if (t->value[node] >= 0)
            {
              return -1;
            }

          bit = (c >> (i - 1U)) & 1U;
          if (t->child[node][bit] == -1)
            {
              if (t->nodes >= CM_HUFF_MAX)
                {
                  return -1;
                }

              t->child[node][bit] = (short)t->nodes++;
            }

          node = (unsigned)t->child[node][bit];
        }

      if (t->value[node] >= 0 || t->child[node][0] >= 0
          || t->child[node][1] >= 0)
        {
          return -1;
        }

      t->value[node] = (short)n;
    }

  return 0;
}

static int
cm_symbol (cm_bits *b, const cm_huff *t, unsigned *sym)
{
  unsigned i, node = 0U, bit;

  if (!t->nodes)
    {
      return -1;
    }

  for (i = 0U; i <= 15U; ++i)
    {
      if (t->value[node] >= 0)
        {
          *sym = (unsigned)t->value[node];
          return 0;
        }

      if (cm_bit (b, &bit))
        {
          return -1;
        }

      if (t->child[node][bit] < 0)
        {
          return -1;
        }

      node = (unsigned)t->child[node][bit];
    }

  return -1;
}

static const unsigned cm_len_base[29]
    = { 3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
        31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
static const unsigned char cm_len_extra[29]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
static const unsigned cm_dist_base[30]
    = { 1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
        33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
static const unsigned char cm_dist_extra[30]
    = { 0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
        6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

/* RFC1951 stream; rejects overrun, incomplete stream, or wrong output size.
 * `used` is ceil(bits consumed / 8); caller can check dictionary delimiting.
 */
static int
cm_inflate (const unsigned char *src, size_t src_len, unsigned char *dst,
            size_t dst_len, size_t *used)
{
  static const unsigned char order[19]
      = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
  cm_huff lt, dt, ct;
  cm_bits b;
  unsigned char ll[288], dl[32], cl[19], both[320];
  unsigned last = 0U, type, x, y, n, hlit, hdist, hclen;
  unsigned sym, dist_sym, extra, distance, count, total;
  size_t written = 0U, j;

  b.data = src;
  b.size = src_len;
  b.pos = 0U;
  b.bit = 0U;
  while (!last)
    {
      if (cm_get (&b, 1U, &last) || cm_get (&b, 2U, &type))
        {
          return -1;
        }

      if (type == 0U)
        {
          if (b.bit)
            {
              b.bit = 0U;
              ++b.pos;
            }

          if (cm_get (&b, 16U, &x) || cm_get (&b, 16U, &y))
            {
              return -1;
            }

          if ((x ^ 65535U) != y || x > dst_len - written)
            {
              return -1;
            }

          for (j = 0U; j < (size_t)x; ++j)
            {
              if (cm_get (&b, 8U, &n))
                {
                  return -1;
                }

              dst[written++] = (unsigned char)n;
            }

          continue;
        }

      if (type == 3U)
        {
          return -1;
        }

      memset (ll, 0, sizeof ll);
      memset (dl, 0, sizeof dl);
      if (type == 1U)
        {
          for (x = 0U; x <= 143U; ++x)
            {
              ll[x] = 8U;
            }

          for (; x <= 255U; ++x)
            {
              ll[x] = 9U;
            }

          for (; x <= 279U; ++x)
            {
              ll[x] = 7U;
            }

          for (; x < 288U; ++x)
            {
              ll[x] = 8U;
            }

          for (x = 0U; x < 32U; ++x)
            {
              dl[x] = 5U;
            }
        }
      else
        {
          if (cm_get (&b, 5U, &x) || cm_get (&b, 5U, &y)
              || cm_get (&b, 4U, &n))
            {
              return -1;
            }

          hlit = x + 257U;
          hdist = y + 1U;
          hclen = n + 4U;
          if (hlit > 286U || hdist > 32U)
            {
              return -1;
            }

          memset (cl, 0, sizeof cl);
          for (x = 0U; x < hclen; ++x)
            {
              if (cm_get (&b, 3U, &y))
                {
                  return -1;
                }

              cl[order[x]] = (unsigned char)y;
            }

          if (cm_tree (&ct, cl, 19U))
            {
              return -1;
            }

          total = hlit + hdist;
          for (x = 0U; x < total;)
            {
              if (cm_symbol (&b, &ct, &sym))
                {
                  return -1;
                }

              if (sym <= 15U)
                {
                  both[x++] = (unsigned char)sym;
                  continue;
                }

              if (sym == 16U)
                {
                  if (!x || cm_get (&b, 2U, &y))
                    {
                      return -1;
                    }

                  count = 3U + y;
                  sym = both[x - 1U];
                }
              else if (sym == 17U)
                {
                  if (cm_get (&b, 3U, &y))
                    {
                      return -1;
                    }

                  count = 3U + y;
                  sym = 0U;
                }
              else if (sym == 18U)
                {
                  if (cm_get (&b, 7U, &y))
                    {
                      return -1;
                    }

                  count = 11U + y;
                  sym = 0U;
                }
              else
                {
                  return -1;
                }

              if (count > total - x)
                {
                  return -1;
                }

              while (count--)
                {
                  both[x++] = (unsigned char)sym;
                }
            }

          memcpy (ll, both, hlit);
          memcpy (dl, both + hlit, hdist);
        }

      if (ll[256U] == 0U || cm_tree (&lt, ll, 288U) || cm_tree (&dt, dl, 32U))
        {
          return -1;
        }

      for (;;)
        {
          if (cm_symbol (&b, &lt, &sym))
            {
              return -1;
            }

          if (sym < 256U)
            {
              if (written == dst_len)
                {
                  return -1;
                }

              dst[written++] = (unsigned char)sym;
            }
          else if (sym == 256U)
            {
              break;
            }
          else
            {
              if (sym > 285U || dt.nodes == 0U)
                {
                  return -1;
                }

              x = sym - 257U;
              if (cm_get (&b, cm_len_extra[x], &extra))
                {
                  return -1;
                }

              count = cm_len_base[x] + extra;
              if (cm_symbol (&b, &dt, &dist_sym) || dist_sym >= 30U)
                {
                  return -1;
                }

              if (cm_get (&b, cm_dist_extra[dist_sym], &extra))
                {
                  return -1;
                }

              distance = cm_dist_base[dist_sym] + extra;
              if (distance > 32768U || (size_t)distance > written
                  || (size_t)count > dst_len - written)
                {
                  return -1;
                }

              for (j = 0U; j < (size_t)count; ++j)
                {
                  dst[written] = dst[written - (size_t)distance];
                  ++written;
                }
            }
        }
    }
  if (written != dst_len)
    {
      return -1;
    }

  *used = b.pos + (b.bit != 0U ? 1U : 0U);
  return 0;
}

/* Dictionary expansion: 8-byte IBM expansion dictionary entry format. */
static int
cm_expand (const unsigned char *dict, unsigned width, unsigned symbol,
           unsigned char out[CM_MAX_PHRASE], unsigned *length)
{
  unsigned entries = 1U << width;
  unsigned index, psl, csl, offset, i, n = 0U, steps = 0U;
  unsigned char filled[CM_MAX_PHRASE];
  const unsigned char *e;

  if (symbol < 256U)
    {
      out[0] = (unsigned char)symbol;
      *length = 1U;
      return 0;
    }

  if (symbol >= entries)
    {
      return -1;
    }

  memset (filled, 0, sizeof filled);
  index = symbol;
  for (;;)
    {
      if (++steps > CM_MAX_PHRASE)
        {
          return -1;
        }

      e = dict + (size_t)index * 8U;
      psl = (unsigned)(e[0] >> 5);
      if (psl)
        {
          if (psl > 5U)
            {
              return -1;
            }

          offset = (unsigned)e[7];
          if (offset > CM_MAX_PHRASE - psl)
            {
              return -1;
            }

          for (i = 0U; i < psl; ++i)
            {
              if (filled[offset + i])
                {
                  return -1;
                }

              out[offset + i] = e[2U + i];
              filled[offset + i] = 1U;
            }

          if (offset + psl > n)
            {
              n = offset + psl;
            }

          index = (((unsigned)e[0] & 31U) << 8) | (unsigned)e[1];
          if (index >= entries)
            {
              return -1;
            }
        }
      else
        {
          if ((e[0] & 0x18U) != 0U)
            {
              return -1;
            }

          csl = (unsigned)e[0] & 7U;
          if (!csl)
            {
              return -1;
            }

          for (i = 0U; i < csl; ++i)
            {
              if (filled[i])
                {
                  return -1;
                }

              out[i] = e[1U + i];
              filled[i] = 1U;
            }

          if (csl > n)
            {
              n = csl;
            }

          break;
        }
    }

  for (i = 0U; i < n; ++i)
    {
      if (!filled[i])
        {
          return -1;
        }
    }

  *length = n;
  return 0;
}

/* SIZE is a 64-bit byte count supplied in two base-2^32 limbs, so this
 * interface remains strict C89 without requiring a compiler long long. */
int
cmpsc16_stream_decode (cmpsc16_read_fn reader, cmpsc16_write_fn writer,
                       void *opaque, unsigned long size_hi,
                       unsigned long size_lo)
{
  unsigned char header[6], *stored = NULL, *dict = NULL;
  unsigned char phrase[CM_MAX_PHRASE], out[4096];
  unsigned width, flags, sym, bits = 0U, current = 0U, need, n, i;
  unsigned long stored_len;
  unsigned long lo = size_lo, hi = size_hi;
  size_t dict_len, pos = 0U, used = 0U, t;
  int c, rc = -1;

  for (i = 0U; i < 6U; ++i)
    {
      c = reader (opaque);
      if (c < 0)
        {
          return -1;
        }

      header[i] = (unsigned char)c;
    }

  width = (unsigned)header[1] & 15U;
  flags = (unsigned)header[1] & 0xf0U;
  if (header[0] != 1U || width < 9U || width > 13U
      || (flags != 0x80U && flags != 0xc0U))
    {
      return -1;
    }

  stored_len = (unsigned long)header[2] | ((unsigned long)header[3] << 8)
               | ((unsigned long)header[4] << 16)
               | ((unsigned long)header[5] << 24);
  dict_len = (size_t)(1U << width) * 8U;
  /* The maximum dictionary has 64 KiB of uncompressed data.  A 1 MiB
   * compressed-dictionary cap prevents hostile allocations and excessive
   * zero padding; normally Deflate requires less than 66 KiB here. */
  if (stored_len == 0UL || stored_len > 1048576UL
      || (unsigned long)(size_t)stored_len != stored_len
      || (flags == 0x80U && stored_len != (unsigned long)dict_len))
    {
      return -1;
    }

  stored = (unsigned char *)malloc ((size_t)stored_len);
  dict = (unsigned char *)malloc (dict_len);
  if (!stored || !dict)
    {
      rc = -2;
      goto done;
    }

  for (t = 0U; t < (size_t)stored_len; ++t)
    {
      c = reader (opaque);
      if (c < 0)
        {
          goto done;
        }

      stored[t] = (unsigned char)c;
    }

  if (flags == 0x80U)
    {
      memcpy (dict, stored, dict_len);
    }
  else
    {
      if (cm_inflate (stored, (size_t)stored_len, dict, dict_len, &used))
        {
          goto done;
        }

      for (t = used; t < (size_t)stored_len; ++t)
        {
          if (stored[t] != 0U)
            {
              goto done;
            }
        }
    }

  /* Codes are MSB-first and the ZIP uncompressed size supplies EOF. */
  while (hi || lo)
    {
      sym = 0U;
      need = width;
      while (need--)
        {
          if (bits == 0U)
            {
              c = reader (opaque);
              if (c < 0)
                {
                  goto done;
                }

              current = (unsigned)c;
              bits = 8U;
            }

          sym = (sym << 1) | ((current >> (--bits)) & 1U);
        }
      if (cm_expand (dict, width, sym, phrase, &n))
        {
          goto done;
        }

      if (!hi && (unsigned long)n > lo)
        {
          goto done;
        }

      if (lo < (unsigned long)n)
        {
          /* Borrow one 32-bit limb without relying on 64-bit integer types. */
          --hi;
          lo = 0xffffffffUL - ((unsigned long)n - lo) + 1UL;
        }
      else
        {
          lo -= (unsigned long)n;
        }

      for (i = 0U; i < n; ++i)
        {
          out[pos++] = phrase[i];
          if (pos == sizeof out)
            {
              if (writer (opaque, out, pos))
                {
                  goto done;
                }

              pos = 0U;
            }
        }
    }
  if (pos && writer (opaque, out, pos))
    {
      goto done;
    }

  /* Accept nonzero unused bits (PKZIP behavior), but only zero bytes
   * after the final complete symbol.  The callback is bounded to the
   * current ZIP member, including encryption overhead handling. */
  while ((c = reader (opaque)) >= 0)
    {
      if (c != 0)
        {
          goto done;
        }
    }
  rc = 0;
done:
  free (stored);
  free (dict);
  return rc;
}
