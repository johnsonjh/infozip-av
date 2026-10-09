/*
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

/*
 * The decoder adds each dictionary entry on reading the NEXT data code,
 * whereas the compressor adds it after emitting the previous code.  A
 * partial-clear marker is emitted AFTER that previous code so both tables
 * are in sync when pruning the leaves.  An entry added immediately after a
 * clear may refer to a just-pruned prefix; keep that entry allocated (the
 * decoder does), but don't index an unusable string for compression.
 */

#include <stdlib.h>
#include <string.h>

#define SHK_CODES 8192U
#define SHK_BUCKETS 4096U
#define SHK_FREE 65535U
#define SHK_INBUF 2048U
#define SHK_OUTBUF 512U

typedef unsigned (*shk_read_fn) (void *, unsigned char *, unsigned);
typedef int (*shk_write_fn) (void *, const unsigned char *, unsigned);

struct shk_ctx
{
  unsigned short *prefix;
  unsigned char *suffix;
  unsigned short *buckets;
  unsigned short *next;
  unsigned char *mark;
  unsigned short next_free;
  unsigned bits;
  unsigned long bitbuf;
  unsigned nbits;
  unsigned char inbuf[SHK_INBUF];
  unsigned char outbuf[SHK_OUTBUF];
  unsigned outused;
  shk_read_fn read;
  shk_write_fn write;
  void *opaque;
};

static void
shk_destroy (struct shk_ctx *s)
{
  if (s == NULL)
    {
      return;
    }

  free (s->prefix);
  free (s->suffix);
  free (s->buckets);
  free (s->next);
  free (s->mark);
  free (s);
}

static struct shk_ctx *
shk_create (shk_read_fn rd, shk_write_fn wr, void *opaque)
{
  struct shk_ctx *s;
  unsigned i;

  s = (struct shk_ctx *)malloc (sizeof (*s));

  if (s == NULL)
    {
      return NULL;
    }

  s->prefix = NULL;
  s->suffix = NULL;
  s->buckets = NULL;
  s->next = NULL;
  s->mark = NULL;
  s->prefix = (unsigned short *)malloc (SHK_CODES * sizeof (unsigned short));
  s->suffix = (unsigned char *)malloc (SHK_CODES);
  s->buckets
      = (unsigned short *)malloc (SHK_BUCKETS * sizeof (unsigned short));
  s->next = (unsigned short *)malloc (SHK_CODES * sizeof (unsigned short));
  s->mark = (unsigned char *)malloc (SHK_CODES / 8U);

  if (s->prefix == NULL || s->suffix == NULL || s->buckets == NULL
      || s->next == NULL || s->mark == NULL)
    {
      shk_destroy (s);
      return NULL;
    }

  for (i = 0; i < SHK_CODES; ++i)
    {
      s->prefix[i] = SHK_FREE;
    }

  for (i = 0; i < SHK_BUCKETS; ++i)
    {
      s->buckets[i] = SHK_FREE;
    }

  s->next_free = 257;
  s->bits = 9;
  s->bitbuf = 0;
  s->nbits = 0;
  s->outused = 0;
  s->read = rd;
  s->write = wr;
  s->opaque = opaque;

  return s;
}

static unsigned
shk_hash (unsigned prefix, unsigned suffix)
{
  /* Unsigned wrap is defined even when 'unsigned' is only 16 bits! */
  return (prefix * 33U + suffix * 257U) & (SHK_BUCKETS - 1U);
}

static void
shk_index (struct shk_ctx *s, unsigned code)
{
  unsigned h;

  h = shk_hash (s->prefix[code], s->suffix[code]);
  s->next[code] = s->buckets[h];
  s->buckets[h] = (unsigned short)code;
}

/* Beware orphan entries left by partial clearing, including self loops */
static int
shk_valid (const struct shk_ctx *s, unsigned code)
{
  unsigned hops;

  for (hops = 0; code >= 257U && hops < SHK_CODES; ++hops)
    {
      if (code >= SHK_CODES || s->prefix[code] == SHK_FREE)
        {
          return 0;
        }

      code = s->prefix[code];
    }

  return code < 256U;
}

static unsigned
shk_find (const struct shk_ctx *s, unsigned parent, unsigned char suffix)
{
  unsigned code;

  code = s->buckets[shk_hash (parent, suffix)];

  while (code != SHK_FREE)
    {
      if (s->prefix[code] == parent && s->suffix[code] == suffix)
        {
          return code;
        }

      code = s->next[code];
    }

  return SHK_FREE;
}

static unsigned
shk_slot (struct shk_ctx *s)
{
  unsigned i;

  for (i = s->next_free; i < SHK_CODES; ++i)
    {
      if (s->prefix[i] == SHK_FREE)
        {
          s->next_free = (unsigned short)(i + 1U);
          return i;
        }
    }

  s->next_free = SHK_CODES;

  return SHK_FREE;
}

static void
shk_insert (struct shk_ctx *s, unsigned code, unsigned parent,
            unsigned char byte)
{
  s->prefix[code] = (unsigned short)parent;
  s->suffix[code] = byte;

  if (code != parent && shk_valid (s, code))
    {
      shk_index (s, code);
    }
}

static void
shk_clear (struct shk_ctx *s)
{
  unsigned i, p;

  memset (s->mark, 0, SHK_CODES / 8U);

  for (i = 257; i < SHK_CODES; ++i)
    {
      p = s->prefix[i];

      if (p >= 257U && p < SHK_CODES)
        {
          s->mark[p >> 3] |= (unsigned char)(1U << (p & 7U));
        }
    }

  for (i = 257; i < SHK_CODES; ++i)
    {
      if ((s->mark[i >> 3] & (1U << (i & 7U))) == 0)
        {
          s->prefix[i] = SHK_FREE;
        }
    }

  for (i = 0; i < SHK_BUCKETS; ++i)
    {
      s->buckets[i] = SHK_FREE;
    }

  for (i = 257; i < SHK_CODES; ++i)
    {
      if (s->prefix[i] != SHK_FREE && shk_valid (s, i))
        {
          shk_index (s, i);
        }
    }

  s->next_free = 257;
}

static int
shk_flush (struct shk_ctx *s)
{
  if (s->outused != 0U)
    {
      if (s->write (s->opaque, s->outbuf, s->outused) != 0)
        {
          return 0;
        }

      s->outused = 0;
    }

  return 1;
}

static int
shk_byte (struct shk_ctx *s, unsigned byte)
{
  s->outbuf[s->outused++] = (unsigned char)byte;

  if (s->outused == SHK_OUTBUF)
    {
      return shk_flush (s);
    }

  return 1;
}

static int
shk_bits (struct shk_ctx *s, unsigned code)
{
  s->bitbuf |= (unsigned long)code << s->nbits;
  s->nbits += s->bits;

  while (s->nbits >= 8U)
    {
      if (!shk_byte (s, (unsigned)(s->bitbuf & 255UL)))
        {
          return 0;
        }

      s->bitbuf >>= 8;
      s->nbits -= 8;
    }

  return 1;
}

static int
shk_data (struct shk_ctx *s, unsigned code)
{
  while (code >= (1U << s->bits))
    {
      /* Both control codes are written at the OLD bit width */
      if (s->bits >= 13U || !shk_bits (s, 256U) || !shk_bits (s, 1U))
        {
          return 0;
        }

      ++s->bits;
    }
  return shk_bits (s, code);
}

/* Returns 0 on success, 1 on allocation failure, 2 on I/O failure. */
static int
shk_encode (shk_read_fn rd, shk_write_fn wr, void *opaque)
{
  struct shk_ctx *s;
  unsigned current, newcode, match;
  unsigned n, i;
  int have_current, no_recycle, status;
  unsigned char c;

  s = shk_create (rd, wr, opaque);

  if (s == NULL)
    {
      return 1;
    }

  have_current = 0;
  no_recycle = 0;
  status = 0;

  for (;;)
    {
      n = rd (opaque, s->inbuf, SHK_INBUF);

      if (n == (unsigned)-1 || n > SHK_INBUF)
        {
          status = 2;
          break;
        }

      if (n == 0)
        {
          break;
        }

      for (i = 0; i < n; ++i)
        {
          c = s->inbuf[i];

          if (!have_current)
            {
              current = c;
              have_current = 1;
              continue;
            }

          match = shk_find (s, current, c);

          if (match != SHK_FREE)
            {
              current = match;
              continue;
            }

          if (!shk_data (s, current))
            {
              status = 2;
              break;
            }

          newcode = shk_slot (s);
          if (newcode == SHK_FREE && !no_recycle)
            {
              /* The preceding data code lets the decoder catch up. */
              if (!shk_bits (s, 256U) || !shk_bits (s, 2U))
                {
                  status = 2;
                  break;
                }

              shk_clear (s);
              newcode = shk_slot (s);

              if (newcode == SHK_FREE)
                {
                  no_recycle = 1;
                }
            }

          if (newcode != SHK_FREE)
            {
              shk_insert (s, newcode, current, c);
            }

          current = c;
        }

      if (status != 0)
        {
          break;
        }
    }

  if (status == 0 && have_current && !shk_data (s, current))
    {
      status = 2;
    }

  if (status == 0 && s->nbits != 0U
      && !shk_byte (s, (unsigned)(s->bitbuf & 255UL)))
    {
      status = 2;
    }

  if (status == 0 && !shk_flush (s))
    {
      status = 2;
    }

  shk_destroy (s);

  return status;
}
