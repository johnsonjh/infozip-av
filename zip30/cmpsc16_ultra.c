/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/*
 * Experimental CMPSC dictionary-aware multi-candidate trainer.
 * Validated against CMPSCTST and PKUNZIP v14.
 */

/*
 * The expansion dictionary uses the architectural 8-byte unpreceded
 * entry format. Dictionary DEFLATE is independent raw RFC 1951 DEFLATE.
 * The per-member input spool makes stdin and non-seekable inputs work.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if UINT_MAX < 65536UL
# error CMPSC encoder requires at least 32-bit unsigned integers
#endif /* if UINT_MAX < 65536UL */

#define IZCMU_MAXSYM 8192U
#define IZCMU_PHRASE 64U
#define IZCMU_MAXDSIZE (IZCMU_MAXSYM * 8U)
#define IZCMU_SLOTS 262144UL
#define IZCMU_MASK (IZCMU_SLOTS - 1UL)
#define IZCMU_LONG_SLOTS 65536UL
#define IZCMU_LONG_MASK (IZCMU_LONG_SLOTS - 1UL)
#define IZCMU_MAXPROBE 24U

typedef unsigned (*izcmu_read_fn) (void *, unsigned char *, unsigned);
typedef int (*izcmu_write_fn) (void *, const unsigned char *, unsigned);
typedef struct
{
  unsigned char phrase[IZCMU_MAXSYM][IZCMU_PHRASE];
  unsigned short length[IZCMU_MAXSYM];
  unsigned short next[IZCMU_MAXSYM];
  unsigned short heads[256];
} izcmu_enc;

typedef struct
{
  unsigned char bytes[IZCMU_PHRASE];
  unsigned char length;
  unsigned long count;
  unsigned long score;
} izcmu_gram;

static unsigned long
izcmu_hash (const unsigned char *p, unsigned n)
{
  unsigned long h = 2166136261UL;
  unsigned i;

  for (i = 0; i < n; ++i)
    {
      h = (h ^ (unsigned long)p[i]) * 16777619UL;
    }

  return h ^ (unsigned long)n;
}

static void
izcmu_observe (izcmu_gram *grams, unsigned long mask, const unsigned char *p,
               unsigned n)
{
  unsigned long pos = izcmu_hash (p, n) & mask;
  unsigned i;
  izcmu_gram *g;

  for (i = 0; i < IZCMU_MAXPROBE; ++i)
    {
      g = grams + ((pos + (unsigned long)i) & mask);

      if (!g->length)
        {
          g->length = (unsigned char)n;
          memcpy (g->bytes, p, n);
          g->count = 1UL;

          return;
        }

      if (g->length == n && memcmp (g->bytes, p, n) == 0)
        {
          if (g->count < ULONG_MAX)
            {
              ++g->count;
            }

          return;
        }
    }
}

/*
 * Scores are stored with each observation.
 * qsort therefore has no global comparison state
 * and is safe for concurrent independent encoders
 */

static unsigned long
izcmu_score (const izcmu_gram *g, unsigned width, unsigned bias)
{
  unsigned gain = 8U * (unsigned)g->length - width;

  if (g->count > ULONG_MAX / (unsigned long)gain)
    {
      return ULONG_MAX;
    }

  {
    unsigned long score = g->count * (unsigned long)gain;

    if (g->length > 7U)
      {
        unsigned div = 1U + ((unsigned)g->length - 7U + 4U) / 5U;
        score /= div;

        if (bias == 0U)
          {
            return 0UL;
          }

        if (score > ULONG_MAX / (unsigned long)bias)
          {
            return ULONG_MAX;
          }

        return score * (unsigned long)bias / 100UL;
      }

    return score;
  }
}

static int
izcmu_compare (const void *a, const void *b)
{
  const izcmu_gram *x = *(const izcmu_gram *const *)a;
  const izcmu_gram *y = *(const izcmu_gram *const *)b;
  int c;

  if (x->score != y->score)
    {
      return x->score > y->score ? -1 : 1;
    }

  if (x->count != y->count)
    {
      return x->count > y->count ? -1 : 1;
    }

  c = memcmp (x->bytes, y->bytes,
              x->length < y->length ? x->length : y->length);
  if (c)
    {
      return -c;
    }

  if (x->length != y->length)
    {
      return x->length > y->length ? -1 : 1;
    }

  return 0;
}

/*
 * Read Zip input exactly once, preserve accounting.
 * The resulting phrase observations are shared by all auto-width candidates.
 */

static int
izcmu_collect (izcmu_read_fn reader, void *ctx, FILE *spool, izcmu_gram *grams,
               izcmu_gram *lgrams, izcmu_gram **rank, unsigned long *used)
{
  unsigned char block[8192], tail[IZCMU_PHRASE];
  unsigned tail_len = 0U, n, i, l;
  unsigned long k;

  *used = 0UL;

  for (;;)
    {
      n = reader (ctx, block, (unsigned)sizeof block);

      if (n == (unsigned)EOF)
        {
          return -1;
        }

      if (!n)
        {
          break;
        }

      if (fwrite (block, 1U, n, spool) != (size_t)n)
        {
          return -3;
        }

      for (i = 0U; i < n; ++i)
        {
          if (tail_len == sizeof tail)
            {
              memmove (tail, tail + 1U, sizeof tail - 1U);
              --tail_len;
            }

          tail[tail_len++] = block[i];

          for (l = 2U; l <= 7U && l <= tail_len; ++l)
            {
              izcmu_observe (grams, IZCMU_MASK, tail + tail_len - l, l);
            }

          /* Experimental sparse long-gram training */
          {
            static const unsigned lens[7]
                = { 8U, 12U, 16U, 24U, 32U, 48U, 64U };
            unsigned k;

            for (k = 0U; k < 7U; ++k)
              {
                if (tail_len >= lens[k])
                  {
                    izcmu_observe (lgrams, IZCMU_LONG_MASK,
                                   tail + tail_len - lens[k], lens[k]);
                  }
              }
          }
        }
    }

  if (fflush (spool) || fseek (spool, 0L, SEEK_SET))
    {
      return -3;
    }

  for (k = 0UL; k < IZCMU_SLOTS; ++k)
    {
      if (grams[k].length > 1U && grams[k].count >= 2UL)
        {
          rank[(*used)++] = grams + k;
        }
    }

  for (k = 0UL; k < IZCMU_LONG_SLOTS; ++k)
    {
      if (lgrams[k].length > 7U && lgrams[k].count >= 2UL)
        {
          rank[(*used)++] = lgrams + k;
        }
    }

  return 0;
}

/*
 * Prototype: prefix-sharing dictionary builder
 * with architectural preceded 8-byte expansion entries.
 */

#define IZCMU_INDEX_SIZE 65536UL
#define IZCMU_INDEX_MASK (IZCMU_INDEX_SIZE - 1UL)

static unsigned
izcmu_findphrase (const izcmu_enc *state, const unsigned short *index,
                  const unsigned char *p, unsigned n)
{
  unsigned long h = izcmu_hash (p, n) & IZCMU_INDEX_MASK;
  unsigned k;

  for (k = 0U; k < IZCMU_INDEX_SIZE; ++k)
    {
      unsigned v = (unsigned)index[(h + k) & IZCMU_INDEX_MASK];
      unsigned s;

      if (!v)
        {
          return 0xffffU;
        }

      s = v - 1U;

      if (state->length[s] == n && memcmp (state->phrase[s], p, n) == 0)
        {
          return s;
        }
    }

  return 0xffffU;
}

static void
izcmu_register (izcmu_enc *state, unsigned short *index, unsigned code,
                const unsigned char *p, unsigned n)
{
  unsigned long h = izcmu_hash (p, n) & IZCMU_INDEX_MASK;
  unsigned k;

  for (k = 0U; k < IZCMU_INDEX_SIZE; ++k)
    {
      unsigned long slot = (h + k) & IZCMU_INDEX_MASK;

      if (!index[slot])
        {
          index[slot] = (unsigned short)(code + 1U);

          break;
        }
    }

  state->length[code] = (unsigned short)n;
  memcpy (state->phrase[code], p, n);
}

static void
izcmu_make_dict (unsigned width, unsigned char *dict, izcmu_gram **rank,
                 unsigned long used, izcmu_enc *state, unsigned short *index,
                 unsigned bias)
{
  unsigned nsym = 1U << width;
  unsigned dsize = nsym * 8U;
  unsigned next = 256U, i;
  unsigned long k;

  memset (state, 0, sizeof *state);
  memset (index, 0, IZCMU_INDEX_SIZE * sizeof *index);

  for (k = 0UL; k < used; ++k)
    {
      rank[k]->score = izcmu_score (rank[k], width, bias);
    }

  qsort (rank, (size_t)used, sizeof *rank, izcmu_compare);
  memset (dict, 0, dsize);

  for (i = 0U; i < 256U; ++i)
    {
      unsigned char byte = (unsigned char)i;
      dict[i * 8U] = 1U;
      dict[i * 8U + 1U] = byte;
      izcmu_register (state, index, i, &byte, 1U);
    }

  for (k = 0UL; k < used && next < nsym; ++k)
    {
      const izcmu_gram *g = rank[k];

      unsigned prev = 0xffffU, prevlen = 0U, chunk, j, needed = 0U;

      if (!g->score)
        {
          continue;
        }

      /* Skip duplicate candidates and never partially install chains. */
      if (izcmu_findphrase (state, index, g->bytes, g->length) != 0xffffU)
        {
          continue;
        }

      for (j = (g->length > 7U ? 7U : (unsigned)g->length);;
           j += (g->length - j > 5U ? 5U : (unsigned)g->length - j))
        {
          if (izcmu_findphrase (state, index, g->bytes, j) == 0xffffU)
            {
              ++needed;
            }

          if (j == g->length)
            {
              break;
            }
        }

      if (needed > nsym - next)
        {
          continue;
        }

      for (j = (g->length > 7U ? 7U : (unsigned)g->length);;
           j += (g->length - j > 5U ? 5U : (unsigned)g->length - j))
        {
          unsigned found = izcmu_findphrase (state, index, g->bytes, j);

          if (found == 0xffffU)
            {
              unsigned char *e = dict + next * 8U;

              if (prev == 0xffffU)
                {
                  e[0] = (unsigned char)j;
                  memcpy (e + 1U, g->bytes, j);
                }
              else
                {
                  chunk = j - prevlen;
                  e[0] = (unsigned char)((chunk << 5U) | (prev >> 8U));
                  e[1] = (unsigned char)prev;
                  memcpy (e + 2U, g->bytes + prevlen, chunk);
                  e[7] = (unsigned char)prevlen;
                }

              izcmu_register (state, index, next, g->bytes, j);
              found = next++;
            }

          prev = found;
          prevlen = j;

          if (j == g->length)
            {
              break;
            }
        }
    }

  for (i = next; i < nsym; ++i)
    {
      dict[i * 8U] = 1U;
    }
}

/*
 * Bit writer used for a single
 * fixed-Huffman raw-Deflate block
 */

typedef struct
{
  unsigned char *out;
  unsigned used, cap;
  unsigned long bits;
  unsigned count;
  int error;
} izcmu_bits;

static void
izcmu_putbits (izcmu_bits *b, unsigned value, unsigned width)
{
  if (b->error)
    {
      return;
    }

  b->bits |= (unsigned long)value << b->count;
  b->count += width;

  while (b->count >= 8U)
    {
      if (b->used >= b->cap)
        {
          b->error = 1;

          return;
        }

      b->out[b->used++] = (unsigned char)b->bits;
      b->bits >>= 8;
      b->count -= 8U;
    }
}

static unsigned
izcmu_rev (unsigned v, unsigned bits)
{
  unsigned n = 0U;

  while (bits--)
    {
      n = (n << 1) | (v & 1U);
      v >>= 1;
    }

  return n;
}

static void
izcmu_fixed (izcmu_bits *b, unsigned sym)
{
  unsigned v, n;

  if (sym <= 143U)
    {
      v = sym + 0x30U;
      n = 8U;
    }
  else if (sym <= 255U)
    {
      v = sym - 144U + 0x190U;
      n = 9U;
    }
  else if (sym <= 279U)
    {
      v = sym - 256U;
      n = 7U;
    }
  else
    {
      v = sym - 280U + 0xc0U;
      n = 8U;
    }

  izcmu_putbits (b, izcmu_rev (v, n), n);
}

static const unsigned short izcmu_lbase[29]
    = { 3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
        31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };

static const unsigned char izcmu_lextra[29]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };

static const unsigned short izcmu_dbase[30]
    = { 1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
        33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };

static const unsigned char izcmu_dextra[30]
    = { 0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
        6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

static void
izcmu_match (izcmu_bits *b, unsigned len, unsigned dist)
{
  unsigned i;

  for (i = 0; i < 29U; ++i)
    {
      if (len < izcmu_lbase[i] + (1U << izcmu_lextra[i]))
        {
          break;
        }
    }

  if (i >= 29U)
    {
      b->error = 1;

      return;
    }

  izcmu_fixed (b, 257U + i);
  izcmu_putbits (b, len - izcmu_lbase[i], izcmu_lextra[i]);

  for (i = 0; i < 30U; ++i)
    {
      if (dist < izcmu_dbase[i] + (1U << izcmu_dextra[i]))
        {
          break;
        }
    }

  if (i >= 30U)
    {
      b->error = 1;

      return;
    }

  izcmu_putbits (b, izcmu_rev (i, 5U), 5U);
  izcmu_putbits (b, dist - izcmu_dbase[i], izcmu_dextra[i]);
}

#define IZCMU_HASH3 4096U

static unsigned
izcmu_h3 (const unsigned char *p)
{
  return (((unsigned)p[0] * 251U) ^ ((unsigned)p[1] * 31U) ^ (unsigned)p[2])
         & (IZCMU_HASH3 - 1U);
}

/*
 * Encode the fixed-size dictionary with raw DEFLATE.
 */

static unsigned
izcmu_defdict (const unsigned char *dict, unsigned dsize, unsigned char *dst)
{
  int *head = NULL, *prev = NULL;
  izcmu_bits b;
  unsigned i = 0U, j, steps, bestlen, bestdist, limit;
  int chain, pos;

  b.out = dst;
  b.cap = dsize;
  b.used = 0U;
  b.bits = 0UL;
  b.count = 0U;
  b.error = 0;
  head = (int *)malloc (IZCMU_HASH3 * sizeof *head);
  prev = (int *)malloc ((size_t)dsize * sizeof *prev);

  if (!head || !prev)
    {
      free (head);
      free (prev);

      return 0U;
    }

  for (j = 0; j < IZCMU_HASH3; ++j)
    {
      head[j] = -1;
    }

  izcmu_putbits (&b, 3U, 3U); /* BFINAL=1, BTYPE=01 (fixed Huffman) */

  while (i < dsize && !b.error)
    {
      bestlen = 0U;
      bestdist = 0U;

      if (i + 2U < dsize)
        {
          unsigned h = izcmu_h3 (dict + i);
          chain = head[h];
          steps = 0U;
          limit = dsize - i;

          if (limit > 258U)
            {
              limit = 258U;
            }

          while (chain >= 0 && steps++ < 64U)
            {
              unsigned cp = (unsigned)chain;
              unsigned n = 0U;

              if (dict[cp] == dict[i] && dict[cp + 1U] == dict[i + 1U]
                  && dict[cp + 2U] == dict[i + 2U])
                {
                  n = 3U;

                  while (n < limit && dict[cp + n] == dict[i + n])
                    {
                      ++n;
                    }

                  if (n > bestlen)
                    {
                      bestlen = n;
                      bestdist = i - cp;
                    }

                  if (n == limit)
                    {
                      break;
                    }
                }

              chain = prev[cp];
            }
        }

      if (bestlen >= 3U)
        {
          izcmu_match (&b, bestlen, bestdist);
          j = bestlen;
        }
      else
        {
          izcmu_fixed (&b, dict[i]);
          j = 1U;
        }

      while (j--)
        {
          if (i + 2U < dsize)
            {
              unsigned h = izcmu_h3 (dict + i);
              pos = head[h];
              prev[i] = pos;
              head[h] = (int)i;
            }

          ++i;
        }
    }
  izcmu_fixed (&b, 256U);

  if (b.count && !b.error)
    {
      if (b.used >= b.cap)
        {
          b.error = 1;
        }
      else
        {
          b.out[b.used++] = (unsigned char)b.bits;
        }
    }

  free (head);
  free (prev);

  return b.error ? 0U : b.used;
}

static void
izcmu_buildindex (izcmu_enc *state, unsigned nsym)
{
  unsigned s, k;

  for (s = 0U; s < 256U; ++s)
    {
      state->heads[s] = 0xffffU;
    }

  for (s = 0U; s < nsym; ++s)
    {
      if (!state->length[s])
        {
          continue;
        }

      k = (unsigned)state->phrase[s][0];
      state->next[s] = state->heads[k];
      state->heads[k] = (unsigned short)s;
    }
}

/*
 * Count without relying on 64-bit arithmetic!
 * hi increases only when unsigned long wraps
 */

typedef struct
{
  unsigned long hi, lo;
} izcmu_size;

static void
izcmu_add (izcmu_size *z, unsigned n)
{
  unsigned long old = z->lo;

  z->lo += (unsigned long)n;

  if (z->lo < old)
    {
      ++z->hi;
    }
}

static int
izcmu_smaller (const izcmu_size *a, const izcmu_size *b)
{
  return a->hi < b->hi || (a->hi == b->hi && a->lo < b->lo);
}

/*
 * LLM/AI helped here:
 * Rewind the input spool and emit packed symbols, or count
 * the exact bytes when writer is NULL. In both modes, decoding
 * uses identical matching. The counter deliberately excludes the
 * six-byte header and dictionary.
 */

static int
izcmu_stream (FILE *spool, const izcmu_enc *state, unsigned width,
              izcmu_write_fn writer, void *ctx, izcmu_size *bytes)
{
  unsigned char look[IZCMU_PHRASE], out[4096];
  unsigned len = 0U, n, j, best, bestlen, s, used = 0U;
  unsigned accum = 0U, have = 0U, remaining;
  int eof = 0;

  bytes->hi = 0UL;
  bytes->lo = 0UL;

  if (fseek (spool, 0L, SEEK_SET))
    {
      return -3;
    }

  while (!eof || len)
    {
      while (len < IZCMU_PHRASE && !eof)
        {
          n = (unsigned)fread (look + len, 1U, IZCMU_PHRASE - len, spool);

          if (!n)
            {
              if (ferror (spool))
                {
                  return -3;
                }

              eof = 1;
            }
          else
            {
              len += n;
            }
        }

      if (!len)
        {
          break;
        }

      best = (unsigned)look[0];
      bestlen = 1U;

      for (s = state->heads[best]; s != 0xffffU; s = state->next[s])
        {
          unsigned sl = (unsigned)state->length[s];

          if (sl > bestlen && sl <= len
              && memcmp (state->phrase[s], look, sl) == 0)
            {
              best = s;
              bestlen = sl;
            }
        }

      for (j = 0U; j < width; ++j)
        {
          accum = (accum << 1U) | ((best >> (width - 1U - j)) & 1U);

          if (++have == 8U)
            {
              out[used++] = (unsigned char)accum;
              accum = 0U;
              have = 0U;

              if (used == (unsigned)sizeof out)
                {
                  if (writer && writer (ctx, out, used))
                    {
                      return -1;
                    }

                  izcmu_add (bytes, used);
                  used = 0U;
                }
            }
        }

      remaining = len - bestlen;

      if (remaining)
        {
          memmove (look, look + bestlen, remaining);
        }

      len = remaining;
    }

  if (have)
    {
      out[used++] = (unsigned char)(accum << (8U - have));
    }

  if (used)
    {
      if (writer && writer (ctx, out, used))
        {
          return -1;
        }

      izcmu_add (bytes, used);
    }

  return 0;
}

/*
 * This -11 path always includes bias=0, which preserves the legacy
 * dictionary and symbol selection, as a full-payload fallback.  Each
 * candidate uses the exact raw/Deflate dictionary and packed-stream size.
 */

/*
 * Return 0 success, -1 input/write callback error, -2 allocation error,
 * -3 temporary file read/write/open error.
 * Width 0 selects the smallest complete candidate (including dictionary).
 * Widths 9..13 force a specific format for interoperability testing.
 */

static int
izcmu_encode (izcmu_read_fn reader, izcmu_write_fn writer, void *ctx,
              unsigned requested_width)
{
  izcmu_enc *state = NULL;
  unsigned short *index = NULL;
  izcmu_gram *grams = NULL, *lgrams = NULL, **rank = NULL;
  unsigned char *dict = NULL, *compressed = NULL;
  FILE *spool = NULL;
  unsigned char head[6];
  unsigned long used = 0UL;
  unsigned width, begin, end, bestwidth = 0U, n, dictlen, dsize;
  unsigned bestbias = 0U, trial, bias;
  static const unsigned biases[]
      = { 0U, 5U, 8U, 10U, 15U, 18U, 20U, 25U, 30U, 45U, 70U, 150U };
  izcmu_size candidate, bestsize, outputbytes;
  int rc = -2;

  if (requested_width && (requested_width < 9U || requested_width > 13U))
    {
      return -2;
    }

  begin = requested_width ? requested_width : 9U;
  end = requested_width ? requested_width : 13U;
  spool = tmpfile ();

  if (!spool)
    {
      return -3;
    }

  dict = (unsigned char *)malloc (IZCMU_MAXDSIZE);
  compressed = (unsigned char *)malloc (IZCMU_MAXDSIZE);
  state = (izcmu_enc *)calloc (1U, sizeof *state);
  grams = (izcmu_gram *)calloc ((size_t)IZCMU_SLOTS, sizeof *grams);
  lgrams = (izcmu_gram *)calloc ((size_t)IZCMU_LONG_SLOTS, sizeof *lgrams);
  rank = (izcmu_gram **)malloc ((size_t)(IZCMU_SLOTS + IZCMU_LONG_SLOTS)
                                * sizeof *rank);
  index = (unsigned short *)malloc (IZCMU_INDEX_SIZE * sizeof *index);

  if (!dict || !compressed || !state || !grams || !lgrams || !rank || !index)
    {
      goto done;
    }

  rc = izcmu_collect (reader, ctx, spool, grams, lgrams, rank, &used);

  if (rc)
    {
      goto done;
    }

  rc = -3;
  bestsize.hi = ULONG_MAX;
  bestsize.lo = ULONG_MAX;

  for (width = begin; width <= end; ++width)
    {
      dsize = (1U << width) * 8U;

      for (trial = 0U; trial < sizeof biases / sizeof biases[0]; ++trial)
        {
          bias = biases[trial];
          izcmu_make_dict (width, dict, rank, used, state, index, bias);
          izcmu_buildindex (state, 1U << width);
          dictlen = izcmu_defdict (dict, dsize, compressed);
          n = (dictlen && dictlen < dsize) ? dictlen : dsize;

          if (izcmu_stream (spool, state, width, NULL, NULL, &candidate))
            {
              goto done;
            }

          izcmu_add (&candidate, n + 6U);

          if (bestwidth == 0U || izcmu_smaller (&candidate, &bestsize))
            {
              bestwidth = width;
              bestbias = bias;
              bestsize = candidate;
            }
        }
    }

  width = bestwidth;
  dsize = (1U << width) * 8U;
  izcmu_make_dict (width, dict, rank, used, state, index, bestbias);
  izcmu_buildindex (state, 1U << width);
  dictlen = izcmu_defdict (dict, dsize, compressed);
  n = (dictlen && dictlen < dsize) ? dictlen : dsize;
  head[0] = 1U;
  head[1] = (unsigned char)((dictlen && dictlen < dsize) ? (0xc0U | width)
                                                         : (0x80U | width));
  head[2] = (unsigned char)n;
  head[3] = (unsigned char)(n >> 8);
  head[4] = (unsigned char)(n >> 16);
  head[5] = (unsigned char)(n >> 24);
  rc = -1;

  if (writer (ctx, head, 6U)
      || writer (ctx, (dictlen && dictlen < dsize) ? compressed : dict, n))
    {
      goto done;
    }

  rc = izcmu_stream (spool, state, width, writer, ctx, &outputbytes);

done:
  if (spool)
    {
      fclose (spool);
    }

  free (index);
  free (rank);
  free (lgrams);
  free (grams);
  free (state);
  free (compressed);
  free (dict);

  return rc;
}
