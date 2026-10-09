/*
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

/*
 * The four PKZIP formats use 4K/8K dictionaries and two/three
 * Shannon-Fano (canonical prefix) trees.  This module deliberately does
 * not share code with the decoder or PKWARE DCL Implode (method 10).
 * Tokens are spooled to a temporary file to train the per-member trees.
 * All allocations are smaller than a 64K 16-bit memory segment.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IM6_RING 16384U
#define IM6_HASH 4096U
#define IM6_NONE 65535U
#define IM6_OUT 512U

typedef unsigned (*im6_read_fn) (void *, unsigned char *, unsigned);
typedef int (*im6_write_fn) (void *, const unsigned char *, unsigned);

struct im6_tree
{
  unsigned long freq[256];
  unsigned char len[256];
  unsigned short code[256];
  unsigned size;
};

struct im6_state
{
  im6_read_fn read;
  im6_write_fn write;
  void *opaque;
  FILE *tokens;
  unsigned char *ring;
  unsigned short *head, *chain;
  unsigned long *stamp_lo, *stamp_hi;
  unsigned long pos, end;
  int eof;
  unsigned window, trees, minimum, maxlen;
  struct im6_tree literal, length, distance;
  unsigned long bits;
  unsigned nbits, outused;
  unsigned char out[IM6_OUT];
};

static void
im6_destroy (struct im6_state *s)
{
  if (s == NULL)
    {
      return;
    }

  if (s->tokens != NULL)
    {
      fclose (s->tokens);
    }

  free (s->ring);
  free (s->head);
  free (s->chain);
  free (s->stamp_lo);
  free (s->stamp_hi);
  free (s);
}

static struct im6_state *
im6_create (im6_read_fn rd, im6_write_fn wr, void *opaque, unsigned window,
            unsigned trees)
{
  struct im6_state *s;
  unsigned i;

  s = (struct im6_state *)malloc (sizeof (*s));

  if (s == NULL)
    {
      return NULL;
    }

  memset (s, 0, sizeof (*s));
  s->read = rd;
  s->write = wr;
  s->opaque = opaque;
  s->window = window;
  s->trees = trees;
  s->minimum = trees == 3U ? 3U : 2U;
  s->maxlen = s->minimum + 63U + 255U;
  s->ring = (unsigned char *)malloc (IM6_RING);
  s->head = (unsigned short *)malloc (IM6_HASH * sizeof (unsigned short));
  s->chain = (unsigned short *)malloc (IM6_RING * sizeof (unsigned short));
  s->stamp_lo
      = (unsigned long *)malloc ((IM6_RING / 2U) * sizeof (unsigned long));
  s->stamp_hi
      = (unsigned long *)malloc ((IM6_RING / 2U) * sizeof (unsigned long));

  if (s->ring == NULL || s->head == NULL || s->chain == NULL
      || s->stamp_lo == NULL || s->stamp_hi == NULL)
    {
      im6_destroy (s);
      return NULL;
    }

  s->tokens = tmpfile ();

  if (s->tokens == NULL)
    {
      im6_destroy (s);
      return NULL;
    }

  for (i = 0; i < IM6_HASH; ++i)
    {
      s->head[i] = IM6_NONE;
    }

  s->literal.size = 256U;
  s->length.size = 64U;
  s->distance.size = 64U;

  /* Every symbol must occur in the stored prefix-code tables. */
  for (i = 0; i < 256U; ++i)
    {
      s->literal.freq[i] = 1UL;
    }

  for (i = 0; i < 64U; ++i)
    {
      s->length.freq[i] = 1UL;
      s->distance.freq[i] = 1UL;
    }

  return s;
}

static unsigned
im6_at (const struct im6_state *s, unsigned long p)
{
  return s->ring[(unsigned)(p & (IM6_RING - 1U))];
}

static int
im6_fill (struct im6_state *s)
{
  unsigned available, wanted, n, j;
  unsigned char buffer[512];

  while (!s->eof && s->end - s->pos < (unsigned long)s->maxlen)
    {
      available = (unsigned)(s->end - s->pos);
      wanted = s->maxlen - available;

      if (wanted > sizeof (buffer))
        {
          wanted = sizeof (buffer);
        }

      n = s->read (s->opaque, buffer, wanted);

      if (n == (unsigned)EOF || n > wanted)
        {
          return 0;
        }

      if (n == 0U)
        {
          s->eof = 1;
          break;
        }

      for (j = 0; j < n; ++j)
        {
          s->ring[(unsigned)(s->end++ & (IM6_RING - 1U))] = buffer[j];
        }
    }

  return 1;
}

static unsigned
im6_hash (const struct im6_state *s, unsigned long p)
{
  return (im6_at (s, p) * 251U + im6_at (s, p + 1UL) * 31U) & (IM6_HASH - 1U);
}

static void
im6_insert (struct im6_state *s, unsigned long p)
{
  unsigned slot, h;

  if (s->end - p < 2UL)
    {
      return;
    }

  h = im6_hash (s, p);
  slot = (unsigned)(p & (IM6_RING - 1U));
  s->chain[slot] = s->head[h];
  s->head[h] = (unsigned short)slot;

  if (slot < IM6_RING / 2U)
    {
      s->stamp_lo[slot] = p;
    }
  else
    {
      s->stamp_hi[slot - IM6_RING / 2U] = p;
    }
}

static void
im6_match (struct im6_state *s, unsigned available, unsigned *bestlen,
           unsigned *bestdist)
{
  unsigned slot, tries, n, dist;
  unsigned long at;

  slot = s->head[im6_hash (s, s->pos)];

  for (tries = 0; slot != IM6_NONE && tries < 64U; ++tries)
    {
      at = slot < IM6_RING / 2U ? s->stamp_lo[slot]
                                : s->stamp_hi[slot - IM6_RING / 2U];
      if (at >= s->pos || s->pos - at > (unsigned long)s->window)
        {
          break;
        }

      dist = (unsigned)(s->pos - at);
      n = 0;

      /* Nonoverlap is conservative but not required by the format. */
      while (n < available && n < dist
             && im6_at (s, at + (unsigned long)n)
                    == im6_at (s, s->pos + (unsigned long)n))
        {
          ++n;
        }

      if (n > *bestlen)
        {
          *bestlen = n;
          *bestdist = dist;
        }

      slot = s->chain[slot];
    }
}

static void
im6_addfreq (unsigned long *v)
{
  if (*v != ULONG_MAX)
    {
      ++*v;
    }
}

static int
im6_tokens (struct im6_state *s)
{
  unsigned avail, n, best, bestdist, j, sym;

  while (1)
    {
      if (!im6_fill (s))
        {
          return 0;
        }

      avail = (unsigned)(s->end - s->pos);

      if (avail == 0U)
        {
          break;
        }

      best = 0;
      bestdist = 0;

      if (avail >= 2U)
        {
          im6_match (s, avail, &best, &bestdist);
        }

      /* A match of three or more beats literal coding even with two
       * raw-literal trees; shorter candidates seldom repay their cost. */
      if (best < 3U || best < s->minimum)
        {
          best = 0U;
        }

      if (best != 0U)
        {
          unsigned delta = best - s->minimum;
          unsigned slot = delta < 63U ? delta : 63U;
          sym = (bestdist - 1U) >> (s->window == 8192U ? 7U : 6U);

          if (fputc (1, s->tokens) == EOF
              || fputc ((int)(best & 255U), s->tokens) == EOF
              || fputc ((int)(best >> 8), s->tokens) == EOF
              || fputc ((int)(bestdist & 255U), s->tokens) == EOF
              || fputc ((int)(bestdist >> 8), s->tokens) == EOF)
            {
              return 0;
            }

          im6_addfreq (&s->length.freq[slot]);
          im6_addfreq (&s->distance.freq[sym]);
          n = best;
        }
      else
        {
          sym = im6_at (s, s->pos);
          if (fputc (0, s->tokens) == EOF
              || fputc ((int)sym, s->tokens) == EOF)
            {
              return 0;
            }

          im6_addfreq (&s->literal.freq[sym]);
          n = 1U;
        }

      for (j = 0; j < n; ++j)
        {
          im6_insert (s, s->pos + (unsigned long)j);
        }

      s->pos += (unsigned long)n;
    }

  if (fflush (s->tokens) != 0)
    {
      return 0;
    }

  return fseek (s->tokens, 0L, SEEK_SET) == 0;
}

/* Build a complete Huffman prefix code.  Uniform lengths are a safe
 * fallback if a pathological distribution exceeds 16 bits. */
static void
im6_make_tree (struct im6_tree *t)
{
  unsigned long weight[512];
  short parent[512];
  unsigned count[17], next[17], i, j, active, nodes, a, b, depth;
  unsigned long total;

  for (i = 0; i < t->size; ++i)
    {
      weight[i] = t->freq[i];
      parent[i] = -1;
    }

  nodes = t->size;
  active = t->size;

  while (active > 1U)
    {
      a = b = 65535U;

      for (i = 0; i < nodes; ++i)
        {
          if (parent[i] >= 0)
            {
              continue;
            }

          if (a == 65535U || weight[i] < weight[a])
            {
              b = a;
              a = i;
            }
          else if (b == 65535U || weight[i] < weight[b])
            {
              b = i;
            }
        }

      parent[a] = parent[b] = (short)nodes;
      total = weight[a] > ULONG_MAX - weight[b] ? ULONG_MAX
                                                : weight[a] + weight[b];
      weight[nodes] = total;
      parent[nodes] = -1;
      ++nodes;
      --active;
    }

  for (i = 0; i < t->size; ++i)
    {
      depth = 0;

      for (j = i; parent[j] >= 0; j = (unsigned)parent[j])
        {
          ++depth;
        }

      if (depth > 16U)
        {
          break;
        }

      t->len[i] = (unsigned char)depth;
    }

  if (i != t->size)
    {
      unsigned fixed = t->size == 256U ? 8U : 6U;

      for (j = 0; j < t->size; ++j)
        {
          t->len[j] = (unsigned char)fixed;
        }
    }

  for (i = 0; i <= 16U; ++i)
    {
      count[i] = 0;
      next[i] = 0;
    }

  for (i = 0; i < t->size; ++i)
    {
      ++count[t->len[i]];
    }

  for (i = 1; i <= 16U; ++i)
    {
      next[i] = (next[i - 1] + count[i - 1]) << 1;
    }

  for (i = 0; i < t->size; ++i)
    {
      unsigned len = t->len[i];
      unsigned code = next[len]++;
      unsigned rev = 0;

      for (j = 0; j < len; ++j)
        {
          rev = (rev << 1) | (code & 1U);
          code >>= 1;
        }

      t->code[i] = (unsigned short)((~rev) & ((1UL << len) - 1UL));
    }
}

static int
im6_flush (struct im6_state *s)
{
  if (s->outused == 0U)
    {
      return 1;
    }

  if (s->write (s->opaque, s->out, s->outused) != 0)
    {
      return 0;
    }

  s->outused = 0;

  return 1;
}

static int
im6_byte (struct im6_state *s, unsigned char b)
{
  s->out[s->outused++] = b;

  if (s->outused == IM6_OUT)
    {
      return im6_flush (s);
    }

  return 1;
}

static int
im6_bits (struct im6_state *s, unsigned value, unsigned width)
{
  s->bits |= (unsigned long)value << s->nbits;
  s->nbits += width;

  while (s->nbits >= 8U)
    {
      if (!im6_byte (s, (unsigned char)(s->bits & 255UL)))
        {
          return 0;
        }

      s->bits >>= 8;
      s->nbits -= 8;
    }

  return 1;
}

static int
im6_symbol (struct im6_state *s, const struct im6_tree *t, unsigned symbol)
{
  return im6_bits (s, t->code[symbol], t->len[symbol]);
}

/* RLE-compressed bit lengths (up to 16 lengths per run). */
static int
im6_header (struct im6_state *s, const struct im6_tree *t)
{
  unsigned i = 0, run, count = 0, v;
  unsigned char encoded[256];

  while (i < t->size)
    {
      run = 1;

      while (run < 16U && i + run < t->size && t->len[i] == t->len[i + run])
        {
          ++run;
        }
      encoded[count++] = (unsigned char)(((run - 1U) << 4) | (t->len[i] - 1U));
      i += run;
    }
  if (!im6_byte (s, (unsigned char)(count - 1U)))
    {
      return 0;
    }

  for (v = 0; v < count; ++v)
    {
      if (!im6_byte (s, encoded[v]))
        {
          return 0;
        }
    }

  return 1;
}

static int
im6_output (struct im6_state *s)
{
  int kind, a, b, c, d;
  unsigned len, dist, lowbits, delta, slot;

  im6_make_tree (&s->literal);
  im6_make_tree (&s->length);
  im6_make_tree (&s->distance);

  if (s->trees == 3U && !im6_header (s, &s->literal))
    {
      return 0;
    }

  if (!im6_header (s, &s->length) || !im6_header (s, &s->distance))
    {
      return 0;
    }

  /* Prefix-tree headers are whole bytes, not part of the bit stream. */
  lowbits = s->window == 8192U ? 7U : 6U;

  while ((kind = fgetc (s->tokens)) != EOF)
    {
      a = fgetc (s->tokens);

      if (a == EOF)
        {
          return 0;
        }

      if (kind == 0)
        {
          if (!im6_bits (s, 1U, 1U))
            {
              return 0;
            }

          if (s->trees == 3U)
            {
              if (!im6_symbol (s, &s->literal, (unsigned)a))
                {
                  return 0;
                }
            }
          else if (!im6_bits (s, (unsigned)a, 8U))
            {
              return 0;
            }
        }
      else if (kind == 1)
        {
          b = fgetc (s->tokens);
          c = fgetc (s->tokens);
          d = fgetc (s->tokens);

          if (b == EOF || c == EOF || d == EOF)
            {
              return 0;
            }

          len = (unsigned)a | ((unsigned)b << 8);
          dist = (unsigned)c | ((unsigned)d << 8);
          delta = len - s->minimum;
          slot = delta < 63U ? delta : 63U;

          if (!im6_bits (s, 0U, 1U)
              || !im6_bits (s, (dist - 1U) & ((1U << lowbits) - 1U), lowbits)
              || !im6_symbol (s, &s->distance, (dist - 1U) >> lowbits)
              || !im6_symbol (s, &s->length, slot))
            {
              return 0;
            }

          if (slot == 63U && !im6_bits (s, delta - 63U, 8U))
            {
              return 0;
            }
        }
      else
        {
          return 0;
        }
    }
  if (ferror (s->tokens))
    {
      return 0;
    }

  if (s->nbits && !im6_bits (s, 0U, 8U - s->nbits))
    {
      return 0;
    }

  return im6_flush (s);
}

/* Returns 0 on success, 1 for memory/tmpfile failure, 2 for I/O failure. */
static int
im6_encode (im6_read_fn rd, im6_write_fn wr, void *opaque, unsigned window,
            unsigned trees)
{
  struct im6_state *s;
  int ok;

  if ((window != 4096U && window != 8192U) || (trees != 2U && trees != 3U))
    {
      return 2;
    }

  s = im6_create (rd, wr, opaque, window, trees);

  if (s == NULL)
    {
      return 1;
    }

  ok = im6_tokens (s) && im6_output (s);
  im6_destroy (s);

  return ok ? 0 : 2;
}
