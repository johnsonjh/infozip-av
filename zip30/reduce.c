/*
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

/*
 * Reduce first encodes LZ77 references as DLE (144) sequences; a second
 * pass applies per-previous-byte follower coding. A temporary C stdio file
 * holds the DLE stream so the follower tables can be trained without requiring
 * seekable input or keeping an entire member in memory. A bounded Misra-Gries
 * pass identifies frequent followers; a subsequent exact-count pass selects
 * profitable sets. The encoder intentionally never references pre-file zeros.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED_RING 8192U
#define RED_HASH 4096U
#define RED_FOLLOW 16U
#define RED_OUT 512U
#define RED_NONE 65535U
#define RED_DLE 144U

typedef unsigned (*red_read_fn) (void *, unsigned char *, unsigned);
typedef int (*red_write_fn) (void *, const unsigned char *, unsigned);

struct red_ctx
{
  red_read_fn read;
  red_write_fn write;
  void *opaque;
  FILE *spool;
  unsigned char *ring;
  unsigned short *head;
  unsigned short *chain;
  unsigned long *stamp;
  unsigned char *follower;
  unsigned short *estimate;
  unsigned long *exact;
  unsigned long total[256];
  unsigned char sizes[256];
  unsigned char out[RED_OUT];
  unsigned outused;
  unsigned long bits;
  unsigned nbits;
  unsigned previous;
  unsigned long pos, end;
  int eof;
  unsigned factor;
};

static void
red_destroy (struct red_ctx *s)
{
  if (s == NULL)
    {
      return;
    }

  if (s->spool != NULL)
    {
      fclose (s->spool);
    }

  free (s->ring);
  free (s->head);
  free (s->chain);
  free (s->stamp);
  free (s->follower);
  free (s->estimate);
  free (s->exact);
  free (s);
}

static struct red_ctx *
red_create (red_read_fn readfn, red_write_fn writefn, void *opaque,
            unsigned factor)
{
  struct red_ctx *s;
  unsigned i;

  s = (struct red_ctx *)malloc (sizeof (*s));

  if (s == NULL)
    {
      return NULL;
    }

  memset (s, 0, sizeof (*s));
  s->read = readfn;
  s->write = writefn;
  s->opaque = opaque;
  s->factor = factor;
  s->ring = (unsigned char *)malloc (RED_RING);
  s->head = (unsigned short *)malloc (RED_HASH * sizeof (unsigned short));
  s->chain = (unsigned short *)malloc (RED_RING * sizeof (unsigned short));
  s->stamp = (unsigned long *)malloc (RED_RING * sizeof (unsigned long));
  s->follower = (unsigned char *)malloc (256U * RED_FOLLOW);
  s->estimate
      = (unsigned short *)malloc (256U * RED_FOLLOW * sizeof (unsigned short));
  s->exact
      = (unsigned long *)malloc (256U * RED_FOLLOW * sizeof (unsigned long));

  if (s->ring == NULL || s->head == NULL || s->chain == NULL
      || s->stamp == NULL || s->follower == NULL || s->estimate == NULL
      || s->exact == NULL)
    {
      red_destroy (s);
      return NULL;
    }

  s->spool = tmpfile ();

  if (s->spool == NULL)
    {
      red_destroy (s);
      return NULL;
    }

  for (i = 0; i < RED_HASH; ++i)
    {
      s->head[i] = RED_NONE;
    }

  memset (s->estimate, 0, 256U * RED_FOLLOW * sizeof (unsigned short));
  memset (s->exact, 0, 256U * RED_FOLLOW * sizeof (unsigned long));

  return s;
}

/* Input lookahead never exceeds 385 bytes; the 8K circular buffer retains
 * the 4K history for any compression factor without overwriting it. */
static int
red_fill (struct red_ctx *s, unsigned want)
{
  unsigned char buf[512];
  unsigned i, n, space;

  while (!s->eof && s->end - s->pos < (unsigned long)want)
    {
      space = want - (unsigned)(s->end - s->pos);

      if (space > sizeof (buf))
        {
          space = sizeof (buf);
        }

      n = s->read (s->opaque, buf, space);

      if (n == (unsigned)EOF || n > space)
        {
          return 0;
        }

      if (n == 0U)
        {
          s->eof = 1;
          break;
        }

      for (i = 0; i < n; ++i)
        {
          s->ring[(unsigned)(s->end++ & (RED_RING - 1U))] = buf[i];
        }
    }

  return 1;
}

static unsigned
red_at (const struct red_ctx *s, unsigned long pos)
{
  return s->ring[(unsigned)(pos & (RED_RING - 1U))];
}

static unsigned
red_hash3 (const struct red_ctx *s, unsigned long pos)
{
  unsigned a, b, c;

  a = red_at (s, pos);
  b = red_at (s, pos + 1UL);
  c = red_at (s, pos + 2UL);

  return (a * 251U + b * 31U + c) & (RED_HASH - 1U);
}

static void
red_insert (struct red_ctx *s, unsigned long pos)
{
  unsigned h, slot;

  if (s->end - pos < 3UL)
    {
      return;
    }

  h = red_hash3 (s, pos);
  slot = (unsigned)(pos & (RED_RING - 1U));
  s->chain[slot] = s->head[h];
  s->head[h] = (unsigned short)slot;
  s->stamp[slot] = pos;
}

static void
red_match (const struct red_ctx *s, unsigned maxlen, unsigned *bestlen,
           unsigned *bestdist)
{
  unsigned slot, tries, n, dist, maxdist;
  unsigned long at;

  maxdist = 1U << (8U + s->factor);
  slot = s->head[red_hash3 (s, s->pos)];

  for (tries = 0; slot != RED_NONE && tries < 48U; ++tries)
    {
      at = s->stamp[slot];

      /* Unsigned subtraction also handles absolute positions passing 4 GiB. */
      if (s->pos - at == 0UL || s->pos - at > (unsigned long)maxdist)
        {
          break;
        }

      dist = (unsigned)(s->pos - at);
      n = 0;

      /* No overlapping backreferences: conservative PKZIP convention. */
      while (n < maxlen && n < dist
             && red_at (s, at + (unsigned long)n)
                    == red_at (s, s->pos + (unsigned long)n))
        {
          ++n;
        }

      /* V=0 has the special meaning 'escaped DLE'; never emit it. */
      if (n == 3U && dist <= 256U)
        {
          n = 0;
        }

      if (n > *bestlen)
        {
          *bestlen = n;
          *bestdist = dist;
        }

      slot = s->chain[slot];
    }
}

/* Misra-Gries tracks up to 16 likely successors per previous byte. */
static void
red_observe (struct red_ctx *s, unsigned prev, unsigned val)
{
  unsigned base, j, empty;

  base = prev * RED_FOLLOW;
  empty = RED_FOLLOW;
  for (j = 0; j < RED_FOLLOW; ++j)
    {
      if (s->estimate[base + j] != 0U)
        {
          if (s->follower[base + j] == val)
            {
              if (s->estimate[base + j] != USHRT_MAX)
                {
                  ++s->estimate[base + j];
                }

              return;
            }
        }
      else if (empty == RED_FOLLOW)
        {
          empty = j;
        }
    }

  if (empty != RED_FOLLOW)
    {
      s->follower[base + empty] = (unsigned char)val;
      s->estimate[base + empty] = 1;
    }
  else
    {
      for (j = 0; j < RED_FOLLOW; ++j)
        {
          --s->estimate[base + j];
        }
    }
}

static int
red_spool_byte (struct red_ctx *s, unsigned val)
{
  if (fputc ((int)val, s->spool) == EOF)
    {
      return 0;
    }

  red_observe (s, s->previous, val);
  s->previous = val;

  return 1;
}

static int
red_spool_input (struct red_ctx *s)
{
  unsigned maxlen, available, bestlen, bestdist, lengthbits, small;
  unsigned v, len, n, j, dist;

  maxlen = ((1U << (8U - s->factor)) - 1U) + 255U + 3U;
  lengthbits = (1U << (8U - s->factor)) - 1U;

  for (;;)
    {
      if (!red_fill (s, maxlen))
        {
          return 0;
        }

      available = (unsigned)(s->end - s->pos);

      if (available == 0U)
        {
          break;
        }

      bestlen = 0;
      bestdist = 0;

      if (available >= 3U)
        {
          red_match (s, available, &bestlen, &bestdist);
        }

      /* The DLE sequence costs 3 or 4 bytes, plus follower encoding.
       * A len>=5 match is always profitable compared to literals. */
      if (bestlen < 5U)
        {
          bestlen = 0U;
        }

      if (bestlen != 0U)
        {
          len = bestlen - 3U;
          dist = bestdist - 1U;
          small = len < lengthbits ? len : lengthbits;
          v = ((dist >> 8) << (8U - s->factor)) | small;

          if (v == 0U || !red_spool_byte (s, RED_DLE)
              || !red_spool_byte (s, v))
            {
              return 0;
            }

          if (small == lengthbits && !red_spool_byte (s, len - lengthbits))
            {
              return 0;
            }

          if (!red_spool_byte (s, dist & 255U))
            {
              return 0;
            }

          n = bestlen;
        }
      else
        {
          v = red_at (s, s->pos);

          if (!red_spool_byte (s, v))
            {
              return 0;
            }

          if (v == RED_DLE && !red_spool_byte (s, 0U))
            {
              return 0;
            }

          n = 1U;
        }

      for (j = 0; j < n; ++j)
        {
          red_insert (s, s->pos + (unsigned long)j);
        }

      s->pos += (unsigned long)n;
    }

  return fflush (s->spool) == 0;
}

/* Accurate second pass over just the candidate followers, followed by
 * optimal-prefix selection using the actual bit cost including table bytes. */
static int
red_build_followers (struct red_ctx *s)
{
  int c;
  unsigned prev, base, j, i, k, n, best, bestn, idxbits;
  unsigned long hits, total, gain, bestgain, tmp, cost;
  unsigned char tchar;

  prev = 0;

  if (fseek (s->spool, 0L, SEEK_SET) != 0)
    {
      return 0;
    }

  while ((c = fgetc (s->spool)) != EOF)
    {
      base = prev * RED_FOLLOW;

      if (s->total[prev] != ULONG_MAX)
        {
          ++s->total[prev];
        }

      for (j = 0; j < RED_FOLLOW; ++j)
        {
          if (s->estimate[base + j] != 0U
              && s->follower[base + j] == (unsigned char)c)
            {
              if (s->exact[base + j] != ULONG_MAX)
                {
                  ++s->exact[base + j];
                }

              break;
            }
        }

      prev = (unsigned char)c;
    }
  if (ferror (s->spool))
    {
      return 0;
    }

  for (i = 0; i < 256U; ++i)
    {
      base = i * RED_FOLLOW;

      /* Highest actual frequencies first, zero candidates at the end. */
      for (j = 0; j < RED_FOLLOW; ++j)
        {
          best = j;

          for (k = j + 1U; k < RED_FOLLOW; ++k)
            {
              if (s->exact[base + k] > s->exact[base + best])
                {
                  best = k;
                }
            }

          tmp = s->exact[base + j];
          s->exact[base + j] = s->exact[base + best];
          s->exact[base + best] = tmp;
          tchar = s->follower[base + j];
          s->follower[base + j] = s->follower[base + best];
          s->follower[base + best] = tchar;
        }

      hits = 0UL;
      total = s->total[i];
      bestgain = 0UL;
      bestn = 0;

      for (n = 1; n <= RED_FOLLOW; ++n)
        {
          tmp = s->exact[base + n - 1U];

          if (tmp == 0UL)
            {
              break;
            }

          hits += tmp;
          idxbits = 1;

          while ((1U << idxbits) < n)
            {
              ++idxbits;
            }

          /* Saved bits: each hit saves (7-indexbits), each miss
           * adds one flag bit, and each follower costs 8 header bits. */

          /* Prevent score arithmetic wrapping on a 32-bit unsigned long.
           * Saturation changes only the heuristic, never the bitstream. */
          gain = hits > ULONG_MAX / (7U - idxbits) ? ULONG_MAX
                                                   : hits * (7U - idxbits);
          cost = total - hits;

          if (cost > ULONG_MAX - 8UL * n)
            {
              cost = ULONG_MAX;
            }
          else
            {
              cost += 8UL * n;
            }

          if (gain > cost)
            {
              gain -= cost;
              if (gain > bestgain)
                {
                  bestgain = gain;
                  bestn = n;
                }
            }
        }

      s->sizes[i] = (unsigned char)bestn;
    }

  return fseek (s->spool, 0L, SEEK_SET) == 0;
}

static int
red_flush (struct red_ctx *s)
{
  if (s->outused != 0U)
    {
      if (s->write (s->opaque, s->out, s->outused) != 0)
        {
          return 0;
        }

      s->outused = 0;
    }

  return 1;
}

static int
red_bits (struct red_ctx *s, unsigned val, unsigned n)
{
  s->bits |= (unsigned long)val << s->nbits;
  s->nbits += n;

  while (s->nbits >= 8U)
    {
      s->out[s->outused++] = (unsigned char)(s->bits & 255UL);

      if (s->outused == RED_OUT && !red_flush (s))
        {
          return 0;
        }

      s->bits >>= 8;
      s->nbits -= 8;
    }

  return 1;
}

static int
red_output (struct red_ctx *s)
{
  unsigned i, n, j, idxbits, prev;
  int c;

  for (i = 256U; i != 0U;)
    {
      --i;
      n = s->sizes[i];

      if (!red_bits (s, n, 6U))
        {
          return 0;
        }

      for (j = 0; j < n; ++j)
        {
          if (!red_bits (s, s->follower[i * RED_FOLLOW + j], 8U))
            {
              return 0;
            }
        }
    }

  prev = 0;

  while ((c = fgetc (s->spool)) != EOF)
    {
      n = s->sizes[prev];

      if (n == 0U)
        {
          if (!red_bits (s, (unsigned)c, 8U))
            {
              return 0;
            }
        }
      else
        {
          idxbits = 1;

          while ((1U << idxbits) < n)
            {
              ++idxbits;
            }
          for (j = 0; j < n; ++j)
            {
              if (s->follower[prev * RED_FOLLOW + j] == (unsigned char)c)
                {
                  break;
                }
            }

          if (j == n)
            {
              if (!red_bits (s, 1U, 1U) || !red_bits (s, (unsigned)c, 8U))
                {
                  return 0;
                }
            }
          else if (!red_bits (s, 0U, 1U) || !red_bits (s, j, idxbits))
            {
              return 0;
            }
        }

      prev = (unsigned char)c;
    }

  if (ferror (s->spool))
    {
      return 0;
    }

  if (s->nbits != 0U && !red_bits (s, 0U, 8U - s->nbits))
    {
      return 0;
    }

  return red_flush (s);
}

/* Return 0 success, 1 unavailable memory/temp file, 2 input/output error. */
static int
red_encode (red_read_fn rd, red_write_fn wr, void *opaque, unsigned factor)
{
  struct red_ctx *s;
  int ok;

  if (factor < 1U || factor > 4U)
    {
      return 2;
    }

  s = red_create (rd, wr, opaque, factor);

  if (s == NULL)
    {
      return 1;
    }

  ok = red_spool_input (s) && red_build_followers (s) && red_output (s);
  red_destroy (s);

  return ok ? 0 : 2;
}
