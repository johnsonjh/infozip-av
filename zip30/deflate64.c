/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "deflate64.h"

#define D64_HISTORY 65536UL
#define D64_MAX_MATCH 65538UL
#define D64_BLOCK_TARGET 65536UL
#define D64_HASH_BITS 16
#define D64_HASH_SIZE (1U << D64_HASH_BITS)
#define D64_IN_CAP (D64_HISTORY + D64_BLOCK_TARGET + D64_MAX_MATCH)
#define D64_OUT_SIZE 16384U
#define D64_MAX_TOKENS (D64_BLOCK_TARGET + 1UL)
#define D64_MAX_RLE 640U
#define D64_LIT_CODES 286U
#define D64_FIXED_LIT_CODES 288U
#define D64_DIST_CODES 32U
#define D64_BL_CODES 19U
#define D64_NIL (-1)

#define D64_OK 0
#define D64_MEM_ERROR 1
#define D64_WRITE_ERROR 2
#define D64_PARAM_ERROR 3

typedef struct d64_token
{
  unsigned long len;
  unsigned long dist;
  unsigned lit;
} d64_token;

typedef struct d64_rle
{
  unsigned sym;
  unsigned extra;
  unsigned extra_bits;
} d64_rle;

typedef struct d64_writer
{
  d64_write_func write_cb;
  void *opaque;
  unsigned char out[D64_OUT_SIZE];
  unsigned used;
  unsigned long bitbuf;
  unsigned bitcnt;
  unsigned long total;
  int error;
} d64_writer;

typedef struct d64_encoder
{
  d64_read_func read_cb;
  d64_write_func write_cb;
  void *opaque;
  int level;
  unsigned char *in;
  int *head;
  int *prev;
  d64_token *tokens;
  unsigned long in_len;
  unsigned long hist;
  int eof;
  d64_writer bw;
  d64_stats stats;
} d64_encoder;

typedef struct d64_level_cfg
{
  unsigned max_chain;
  unsigned long nice_match;
  int lazy;
} d64_level_cfg;

static const d64_level_cfg d64_levels[9]
    = { { 8U,   16UL,   0 }, { 16U,   32UL,   0 }, { 32U,   64UL,    0 },
        { 64U,  96UL,   1 }, { 128U,  160UL,  1 }, { 256U,  258UL,   1 },
        { 512U, 1024UL, 1 }, { 2048U, 8192UL, 1 }, { 8192U, 65538UL, 1 } };

static const unsigned short d64_len_base[29]
    = { 3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
        31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3 };

static const unsigned char d64_len_extra[29]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16 };

static const unsigned short d64_dist_base[32]
    = { 1,    2,    3,    4,    5,    7,     9,     13,    17,    25,   33,
        49,   65,   97,   129,  193,  257,   385,   513,   769,   1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153 };

static const unsigned char d64_dist_extra[32]
    = { 0, 0, 0, 0, 1, 1, 2,  2,  3,  3,  4,  4,  5,  5,  6,  6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14 };

static const unsigned char d64_bl_order[D64_BL_CODES]
    = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

static unsigned
d64_reverse_bits (unsigned code, unsigned bits)
{
  unsigned r;

  r = 0;

  while (bits-- != 0U)
    {
      r = (r << 1) | (code & 1U);
      code >>= 1;
    }

  return r;
}

static int
d64_writer_flush (d64_writer *w)
{
  if (w->error)
    {
      return D64_WRITE_ERROR;
    }

  if (w->used != 0U)
    {
      if ((*w->write_cb) (w->opaque, w->out, w->used) != 0)
        {
          w->error = 1;

          return D64_WRITE_ERROR;
        }

      w->total += (unsigned long)w->used;
      w->used = 0U;
    }

  return D64_OK;
}

static int
d64_writer_byte (d64_writer *w, unsigned byte)
{
  if (w->error)
    {
      return D64_WRITE_ERROR;
    }

  w->out[w->used++] = (unsigned char)byte;

  if (w->used == D64_OUT_SIZE)
    {
      return d64_writer_flush (w);
    }

  return D64_OK;
}

static int
d64_put_bits (d64_writer *w, unsigned value, unsigned bits)
{
  unsigned long mask;

  if (bits == 0U)
    {
      return D64_OK;
    }

  if (bits < (unsigned)(sizeof (unsigned long) * CHAR_BIT))
    {
      mask = (1UL << bits) - 1UL;
    }
  else
    {
      mask = ~0UL;
    }

  w->bitbuf |= ((unsigned long)value & mask) << w->bitcnt;
  w->bitcnt += bits;

  while (w->bitcnt >= 8U)
    {
      if (d64_writer_byte (w, (unsigned)(w->bitbuf & 0xffUL)) != D64_OK)
        {
          return D64_WRITE_ERROR;
        }

      w->bitbuf >>= 8;
      w->bitcnt -= 8U;
    }

  return D64_OK;
}

static int
d64_align_byte (d64_writer *w)
{
  if (w->bitcnt != 0U)
    {
      if (d64_writer_byte (w, (unsigned)(w->bitbuf & 0xffUL)) != D64_OK)
        {
          return D64_WRITE_ERROR;
        }

      w->bitbuf = 0UL;
      w->bitcnt = 0U;
    }

  return D64_OK;
}

static int
d64_writer_finish (d64_writer *w)
{
  if (d64_align_byte (w) != D64_OK)
    {
      return D64_WRITE_ERROR;
    }

  return d64_writer_flush (w);
}

static unsigned
d64_hash3 (const unsigned char *p)
{
  unsigned h;

  h = ((unsigned)p[0] << 8) ^ ((unsigned)p[1] << 4) ^ (unsigned)p[2];
  h ^= h >> 7;
  h *= 40503U;

  return h & (D64_HASH_SIZE - 1U);
}

static void
d64_insert (d64_encoder *e, unsigned long pos)
{
  unsigned h;

  if (pos + 2UL >= e->in_len)
    {
      return;
    }

  h = d64_hash3 (e->in + pos);
  e->prev[pos] = e->head[h];
  e->head[h] = (int)pos;
}

static unsigned long
d64_find_match (d64_encoder *e, unsigned long pos, unsigned long *dist_out)
{
  const d64_level_cfg *cfg;
  unsigned long avail;
  unsigned long max_len;
  unsigned long best_len;
  unsigned long best_dist;
  int cand;
  unsigned chain;
  unsigned h;

  *dist_out = 0UL;

  if (pos + 2UL >= e->in_len)
    {
      return 0UL;
    }

  avail = e->in_len - pos;
  max_len = avail < D64_MAX_MATCH ? avail : D64_MAX_MATCH;

  if (max_len < 3UL)
    {
      return 0UL;
    }

  cfg = &d64_levels[e->level == 11 ? 8 : e->level - 1];
  h = d64_hash3 (e->in + pos);
  cand = e->head[h];
  best_len = 2UL;
  best_dist = 0UL;
  chain = cfg->max_chain;

  while (cand != D64_NIL && chain-- != 0U)
    {
      unsigned long c;
      unsigned long dist;
      unsigned long n;

      c = (unsigned long)cand;

      if (c >= pos)
        {
          break;
        }

      dist = pos - c;

      if (dist > D64_HISTORY)
        {
          break;
        }

      if (best_len < max_len && e->in[c] == e->in[pos]
          && e->in[c + 1UL] == e->in[pos + 1UL]
          && e->in[c + 2UL] == e->in[pos + 2UL]
          && (best_len <= 3UL || e->in[c + best_len] == e->in[pos + best_len]))
        {
          n = 3UL;

          while (n < max_len && e->in[c + n] == e->in[pos + n])
            {
              ++n;
            }

          if (n > best_len)
            {
              best_len = n;
              best_dist = dist;

              if (n >= cfg->nice_match || n == max_len)
                {
                  break;
                }
            }
        }

      cand = e->prev[c];
    }

  if (best_len >= 3UL)
    {
      *dist_out = best_dist;

      return best_len;
    }

  return 0UL;
}

static unsigned
d64_length_code (unsigned long len, unsigned *extra, unsigned *extra_bits)
{
  unsigned i;

  if (len > 258UL)
    {
      *extra = (unsigned)(len - 3UL);
      *extra_bits = 16U;

      return 285U;
    }

  for (i = 0U; i < 28U; ++i)
    {
      unsigned long span;

      span = 1UL << d64_len_extra[i];

      if (len >= (unsigned long)d64_len_base[i]
          && len < (unsigned long)d64_len_base[i] + span)
        {
          *extra = (unsigned)(len - (unsigned long)d64_len_base[i]);
          *extra_bits = d64_len_extra[i];

          return 257U + i;
        }
    }

  *extra = 31U;
  *extra_bits = 5U;

  return 284U;
}

static unsigned
d64_distance_code (unsigned long dist, unsigned *extra, unsigned *extra_bits)
{
  unsigned i;

  for (i = 0U; i < D64_DIST_CODES; ++i)
    {
      unsigned long span;

      span = 1UL << d64_dist_extra[i];

      if (dist >= (unsigned long)d64_dist_base[i]
          && dist < (unsigned long)d64_dist_base[i] + span)
        {
          *extra = (unsigned)(dist - (unsigned long)d64_dist_base[i]);
          *extra_bits = d64_dist_extra[i];

          return i;
        }
    }

  *extra = 0U;
  *extra_bits = 0U;

  return 31U;
}

static unsigned long
d64_tokenize (d64_encoder *e, unsigned long start, unsigned long *end_out,
              unsigned long litfreq[D64_LIT_CODES],
              unsigned long distfreq[D64_DIST_CODES])
{
  const d64_level_cfg *cfg;
  unsigned long pos;
  unsigned long token_count;
  unsigned long block_bytes;
  unsigned i;

  memset (litfreq, 0, D64_LIT_CODES * sizeof (litfreq[0]));
  memset (distfreq, 0, D64_DIST_CODES * sizeof (distfreq[0]));

  for (i = 0U; i < D64_HASH_SIZE; ++i)
    {
      e->head[i] = D64_NIL;
    }

  for (pos = 0UL; pos < e->hist; ++pos)
    {
      e->prev[pos] = D64_NIL;
    }

  for (pos = 0UL; pos < e->hist; ++pos)
    {
      d64_insert (e, pos);
    }

  cfg = &d64_levels[e->level == 11 ? 8 : e->level - 1];
  pos = start;
  token_count = 0UL;
  block_bytes = 0UL;

  while (pos < e->in_len && block_bytes < D64_BLOCK_TARGET)
    {
      unsigned long len;
      unsigned long dist;
      unsigned long next_len;
      unsigned long next_dist;
      unsigned lc;
      unsigned dc;
      unsigned ex;
      unsigned eb;

      len = d64_find_match (e, pos, &dist);

      if (len >= 3UL && cfg->lazy && pos + 1UL < e->in_len
          && len < cfg->nice_match)
        {
          d64_insert (e, pos);
          next_len = d64_find_match (e, pos + 1UL, &next_dist);

          if (next_len > len + 1UL)
            {
              e->tokens[token_count].len = 0UL;
              e->tokens[token_count].dist = 0UL;
              e->tokens[token_count].lit = (unsigned)e->in[pos];
              ++litfreq[(unsigned)e->in[pos]];
              ++token_count;
              ++pos;
              ++block_bytes;

              continue;
            }
        }
      else if (len < 3UL)
        {
          d64_insert (e, pos);
        }

      if (len >= 3UL)
        {
          unsigned long k;

          if (!cfg->lazy || len >= cfg->nice_match)
            {
              d64_insert (e, pos);
            }

          e->tokens[token_count].len = len;
          e->tokens[token_count].dist = dist;
          e->tokens[token_count].lit = 0U;
          lc = d64_length_code (len, &ex, &eb);
          dc = d64_distance_code (dist, &ex, &eb);
          ++litfreq[lc];
          ++distfreq[dc];
          ++token_count;
          ++e->stats.matches;

          if (len > e->stats.max_match)
            {
              e->stats.max_match = len;
            }

          if (dist > e->stats.max_distance)
            {
              e->stats.max_distance = dist;
            }

          for (k = 1UL; k < len; ++k)
            {
              d64_insert (e, pos + k);
            }

          pos += len;
          block_bytes += len;
        }
      else
        {
          e->tokens[token_count].len = 0UL;
          e->tokens[token_count].dist = 0UL;
          e->tokens[token_count].lit = (unsigned)e->in[pos];
          ++litfreq[(unsigned)e->in[pos]];
          ++token_count;
          ++pos;
          ++block_bytes;
        }
    }

  ++litfreq[256U];
  *end_out = pos;

  return token_count;
}

typedef struct d64_hnode
{
  unsigned long freq;
  int parent;
  unsigned sym;
} d64_hnode;

typedef struct d64_symfreq
{
  unsigned sym;
  unsigned long freq;
} d64_symfreq;

static int
d64_symfreq_cmp (const void *a, const void *b)
{
  const d64_symfreq *aa;
  const d64_symfreq *bb;

  aa = (const d64_symfreq *)a;
  bb = (const d64_symfreq *)b;

  if (aa->freq < bb->freq)
    {
      return -1;
    }

  if (aa->freq > bb->freq)
    {
      return 1;
    }

  if (aa->sym < bb->sym)
    {
      return -1;
    }

  if (aa->sym > bb->sym)
    {
      return 1;
    }

  return 0;
}

static int
d64_heap_less (const d64_hnode *nodes, int a, int b)
{
  if (nodes[a].freq != nodes[b].freq)
    {
      return nodes[a].freq < nodes[b].freq;
    }

  return nodes[a].sym < nodes[b].sym;
}

static void
d64_heap_push (int *heap, unsigned *n, d64_hnode *nodes, int v)
{
  unsigned i;

  i = ++(*n);

  while (i > 1U && d64_heap_less (nodes, v, heap[i >> 1]))
    {
      heap[i] = heap[i >> 1];
      i >>= 1;
    }

  heap[i] = v;
}

static int
d64_heap_pop (int *heap, unsigned *n, d64_hnode *nodes)
{
  int top;
  int v;
  unsigned i;
  unsigned child;

  top = heap[1];
  v = heap[(*n)--];
  i = 1U;

  while ((child = i << 1) <= *n)
    {
      if (child < *n && d64_heap_less (nodes, heap[child + 1U], heap[child]))
        {
          ++child;
        }

      if (!d64_heap_less (nodes, heap[child], v))
        {
          break;
        }

      heap[i] = heap[child];
      i = child;
    }

  if (*n != 0U)
    {
      heap[i] = v;
    }

  return top;
}

/* Build a canonical, maximum-length-limited Huffman tree. */
static int
d64_build_lengths (const unsigned long *freq, unsigned nsyms, unsigned maxbits,
                   unsigned char *lengths)
{
  d64_hnode nodes[2U * D64_LIT_CODES + 2U];
  int heap[2U * D64_LIT_CODES + 2U];
  d64_symfreq order[D64_LIT_CODES];
  unsigned bl_count[64];
  unsigned heap_n;
  unsigned leaf_n;
  unsigned node_n;
  unsigned i;
  unsigned overflow;
  unsigned oi;

  memset (lengths, 0, nsyms * sizeof (lengths[0]));
  memset (bl_count, 0, sizeof (bl_count));
  heap_n = 0U;
  leaf_n = 0U;
  node_n = 0U;

  for (i = 0U; i < nsyms; ++i)
    {
      if (freq[i] != 0UL)
        {
          nodes[node_n].freq = freq[i];
          nodes[node_n].parent = D64_NIL;
          nodes[node_n].sym = i;
          order[leaf_n].sym = i;
          order[leaf_n].freq = freq[i];
          d64_heap_push (heap, &heap_n, nodes, (int)node_n);
          ++leaf_n;
          ++node_n;
        }
    }

  if (leaf_n == 0U)
    {
      return 0;
    }

  if (leaf_n == 1U)
    {
      lengths[order[0].sym] = 1U;

      return 1;
    }

  while (heap_n > 1U)
    {
      int a;
      int b;

      a = d64_heap_pop (heap, &heap_n, nodes);
      b = d64_heap_pop (heap, &heap_n, nodes);
      nodes[node_n].freq = nodes[a].freq + nodes[b].freq;
      nodes[node_n].parent = D64_NIL;
      nodes[node_n].sym = nsyms + node_n;
      nodes[a].parent = (int)node_n;
      nodes[b].parent = (int)node_n;
      d64_heap_push (heap, &heap_n, nodes, (int)node_n);
      ++node_n;
    }

  overflow = 0U;

  for (i = 0U; i < leaf_n; ++i)
    {
      unsigned bits;
      int p;

      bits = 0U;
      p = (int)i;

      while (nodes[p].parent != D64_NIL)
        {
          ++bits;
          p = nodes[p].parent;
        }

      if (bits > maxbits)
        {
          bits = maxbits;
          ++overflow;
        }

      ++bl_count[bits];
    }

  while (overflow != 0U)
    {
      unsigned bits;

      bits = maxbits - 1U;

      while (bits != 0U && bl_count[bits] == 0U)
        {
          --bits;
        }

      if (bits == 0U || bl_count[maxbits] == 0U)
        {
          return 0;
        }

      --bl_count[bits];
      bl_count[bits + 1U] += 2U;
      --bl_count[maxbits];

      if (overflow >= 2U)
        {
          overflow -= 2U;
        }
      else
        {
          overflow = 0U;
        }
    }

  qsort (order, leaf_n, sizeof (order[0]), d64_symfreq_cmp);
  oi = 0U;

  for (i = maxbits; i != 0U; --i)
    {
      unsigned k;

      for (k = 0U; k < bl_count[i]; ++k)
        {
          if (oi >= leaf_n)
            {
              return 0;
            }

          lengths[order[oi++].sym] = (unsigned char)i;
        }
    }

  return oi == leaf_n;
}

static int
d64_build_codes (const unsigned char *lengths, unsigned nsyms,
                 unsigned maxbits, unsigned short *codes)
{
  unsigned count[16];
  unsigned next[16];
  unsigned code;
  unsigned bits;
  unsigned i;

  if (maxbits > 15U)
    {
      return 0;
    }

  memset (count, 0, sizeof (count));
  memset (next, 0, sizeof (next));

  for (i = 0U; i < nsyms; ++i)
    {
      if (lengths[i] > maxbits)
        {
          return 0;
        }

      if (lengths[i] != 0U)
        {
          ++count[lengths[i]];
        }
    }

  code = 0U;
  count[0] = 0U;

  for (bits = 1U; bits <= maxbits; ++bits)
    {
      code = (code + count[bits - 1U]) << 1;
      next[bits] = code;
    }

  if (code + count[maxbits] > (1U << maxbits))
    {
      return 0;
    }

  for (i = 0U; i < nsyms; ++i)
    {
      bits = lengths[i];

      if (bits != 0U)
        {
          codes[i] = (unsigned short)d64_reverse_bits (next[bits]++, bits);
        }
      else
        {
          codes[i] = 0U;
        }
    }

  return 1;
}

static unsigned
d64_rle_lengths (const unsigned char *lens, unsigned count, d64_rle *out,
                 unsigned long freq[D64_BL_CODES])
{
  unsigned i;
  unsigned n;

  memset (freq, 0, D64_BL_CODES * sizeof (freq[0]));
  i = 0U;
  n = 0U;

  while (i < count)
    {
      unsigned value;
      unsigned run;

      value = lens[i];
      run = 1U;

      while (i + run < count && lens[i + run] == value)
        {
          ++run;
        }
      if (value == 0U)
        {
          unsigned left;
          left = run;

          while (left >= 11U)
            {
              unsigned take;

              take = left > 138U ? 138U : left;
              out[n].sym = 18U;
              out[n].extra = take - 11U;
              out[n].extra_bits = 7U;
              ++freq[18U];
              ++n;
              left -= take;
            }

          if (left >= 3U)
            {
              unsigned take;

              take = left > 10U ? 10U : left;
              out[n].sym = 17U;
              out[n].extra = take - 3U;
              out[n].extra_bits = 3U;
              ++freq[17U];
              ++n;
              left -= take;
            }

          while (left-- != 0U)
            {
              out[n].sym = 0U;
              out[n].extra = 0U;
              out[n].extra_bits = 0U;
              ++freq[0U];
              ++n;
            }
        }
      else
        {
          unsigned left;

          out[n].sym = value;
          out[n].extra = 0U;
          out[n].extra_bits = 0U;
          ++freq[value];
          ++n;
          left = run - 1U;

          while (left >= 3U)
            {
              unsigned take;

              take = left > 6U ? 6U : left;
              out[n].sym = 16U;
              out[n].extra = take - 3U;
              out[n].extra_bits = 2U;
              ++freq[16U];
              ++n;
              left -= take;
            }

          while (left-- != 0U)
            {
              out[n].sym = value;
              out[n].extra = 0U;
              out[n].extra_bits = 0U;
              ++freq[value];
              ++n;
            }
        }

      i += run;
    }

  return n;
}

static void
d64_fixed_lengths (unsigned char litlen[D64_FIXED_LIT_CODES],
                   unsigned char dist[D64_DIST_CODES])
{
  unsigned i;

  for (i = 0U; i <= 143U; ++i)
    {
      litlen[i] = 8U;
    }

  for (; i <= 255U; ++i)
    {
      litlen[i] = 9U;
    }

  for (; i <= 279U; ++i)
    {
      litlen[i] = 7U;
    }

  for (; i < D64_FIXED_LIT_CODES; ++i)
    {
      litlen[i] = 8U;
    }

  for (i = 0U; i < D64_DIST_CODES; ++i)
    {
      dist[i] = 5U;
    }
}

static unsigned long
d64_tokens_cost (const d64_token *tok, unsigned long ntok,
                 const unsigned char *ll, const unsigned char *dd)
{
  unsigned long cost;
  unsigned long i;

  cost = (unsigned long)ll[256U];

  for (i = 0UL; i < ntok; ++i)
    {
      if (tok[i].len == 0UL)
        {
          cost += (unsigned long)ll[tok[i].lit];
        }
      else
        {
          unsigned lc;
          unsigned dc;
          unsigned ex;
          unsigned eb;

          lc = d64_length_code (tok[i].len, &ex, &eb);
          cost += (unsigned long)ll[lc] + (unsigned long)eb;
          dc = d64_distance_code (tok[i].dist, &ex, &eb);
          cost += (unsigned long)dd[dc] + (unsigned long)eb;
        }
    }

  return cost;
}

static unsigned long
d64_stored_cost (unsigned bitcnt, unsigned long raw_len)
{
  unsigned long cost;
  unsigned long left;
  unsigned curbits;

  cost = 0UL;
  left = raw_len;
  curbits = bitcnt & 7U;

  do
    {
      unsigned long take;

      take = left > 65535UL ? 65535UL : left;
      cost += 3UL;
      curbits = (curbits + 3U) & 7U;

      if (curbits != 0U)
        {
          cost += (unsigned long)(8U - curbits);
          curbits = 0U;
        }

      cost += 32UL + take * 8UL;
      left -= take;
    }
  while (left != 0UL);

  return cost;
}

static int
d64_emit_symbol (d64_writer *w, unsigned sym, const unsigned char *lens,
                 const unsigned short *codes)
{
  if (lens[sym] == 0U)
    {
      return D64_PARAM_ERROR;
    }

  return d64_put_bits (w, (unsigned)codes[sym], (unsigned)lens[sym]);
}

static int
d64_emit_tokens (d64_writer *w, const d64_token *tok, unsigned long ntok,
                 const unsigned char *ll, const unsigned short *llcode,
                 const unsigned char *dd, const unsigned short *ddcode)
{
  unsigned long i;

  for (i = 0UL; i < ntok; ++i)
    {
      if (tok[i].len == 0UL)
        {
          if (d64_emit_symbol (w, tok[i].lit, ll, llcode) != D64_OK)
            {
              return D64_WRITE_ERROR;
            }
        }
      else
        {
          unsigned lc;
          unsigned dc;
          unsigned ex;
          unsigned eb;

          lc = d64_length_code (tok[i].len, &ex, &eb);

          if (d64_emit_symbol (w, lc, ll, llcode) != D64_OK
              || d64_put_bits (w, ex, eb) != D64_OK)
            {
              return D64_WRITE_ERROR;
            }

          dc = d64_distance_code (tok[i].dist, &ex, &eb);

          if (d64_emit_symbol (w, dc, dd, ddcode) != D64_OK
              || d64_put_bits (w, ex, eb) != D64_OK)
            {
              return D64_WRITE_ERROR;
            }
        }
    }

  return d64_emit_symbol (w, 256U, ll, llcode);
}

static int
d64_emit_stored (d64_writer *w, const unsigned char *raw,
                 unsigned long raw_len, int final)
{
  unsigned long off;
  unsigned long left;

  off = 0UL;
  left = raw_len;

  do
    {
      unsigned take;
      int last;
      unsigned nlen;

      take = (unsigned)(left > 65535UL ? 65535UL : left);
      last = final && left <= 65535UL;

      if (d64_put_bits (w, last ? 1U : 0U, 1U) != D64_OK
          || d64_put_bits (w, 0U, 2U) != D64_OK
          || d64_align_byte (w) != D64_OK)
        {
          return D64_WRITE_ERROR;
        }

      nlen = (~take) & 0xffffU;

      if (d64_writer_byte (w, take & 0xffU) != D64_OK
          || d64_writer_byte (w, (take >> 8) & 0xffU) != D64_OK
          || d64_writer_byte (w, nlen & 0xffU) != D64_OK
          || d64_writer_byte (w, (nlen >> 8) & 0xffU) != D64_OK)
        {
          return D64_WRITE_ERROR;
        }

      if (take != 0U)
        {
          unsigned i;

          for (i = 0U; i < take; ++i)
            {
              if (d64_writer_byte (w, raw[off + (unsigned long)i]) != D64_OK)
                {
                  return D64_WRITE_ERROR;
                }
            }
        }

      off += (unsigned long)take;
      left -= (unsigned long)take;
    }
  while (left != 0UL);

  return D64_OK;
}

static int
d64_emit_fixed (d64_writer *w, const d64_token *tok, unsigned long ntok,
                int final)
{
  unsigned char ll[D64_FIXED_LIT_CODES];
  unsigned char dd[D64_DIST_CODES];
  unsigned short llcode[D64_FIXED_LIT_CODES];
  unsigned short ddcode[D64_DIST_CODES];

  d64_fixed_lengths (ll, dd);

  if (!d64_build_codes (ll, D64_FIXED_LIT_CODES, 15U, llcode)
      || !d64_build_codes (dd, D64_DIST_CODES, 15U, ddcode))
    {
      return D64_PARAM_ERROR;
    }

  if (d64_put_bits (w, final ? 1U : 0U, 1U) != D64_OK
      || d64_put_bits (w, 1U, 2U) != D64_OK)
    {
      return D64_WRITE_ERROR;
    }

  return d64_emit_tokens (w, tok, ntok, ll, llcode, dd, ddcode);
}

static int
d64_prepare_dynamic (const unsigned long litfreq[D64_LIT_CODES],
                     const unsigned long distfreq[D64_DIST_CODES],
                     unsigned char ll[D64_LIT_CODES],
                     unsigned char dd[D64_DIST_CODES],
                     unsigned short llcode[D64_LIT_CODES],
                     unsigned short ddcode[D64_DIST_CODES],
                     d64_rle rle[D64_MAX_RLE], unsigned *nrle,
                     unsigned char bl[D64_BL_CODES],
                     unsigned short blcode[D64_BL_CODES], unsigned *hlit,
                     unsigned *hdist, unsigned *hclen,
                     unsigned long *header_cost)
{
  unsigned long lf[D64_LIT_CODES];
  unsigned long df[D64_DIST_CODES];
  unsigned long blfreq[D64_BL_CODES];
  unsigned char seq[D64_LIT_CODES + D64_DIST_CODES];
  unsigned i;
  unsigned nseq;
  unsigned long cost;

  memcpy (lf, litfreq, sizeof (lf));
  memcpy (df, distfreq, sizeof (df));

  if (lf[256U] == 0UL)
    {
      lf[256U] = 1UL;
    }

  /* Two distance symbols avoid incomplete one-symbol distance trees. */
  {
    unsigned active;
    active = 0U;

    for (i = 0U; i < D64_DIST_CODES; ++i)
      {
        if (df[i] != 0UL)
          {
            ++active;
          }
      }

    if (active == 0U)
      {
        df[0] = 1UL;
        df[1] = 1UL;
      }
    else if (active == 1U)
      {
        for (i = 0U; i < D64_DIST_CODES; ++i)
          {
            if (df[i] == 0UL)
              {
                df[i] = 1UL;

                break;
              }
          }
      }
  }

  if (!d64_build_lengths (lf, D64_LIT_CODES, 15U, ll)
      || !d64_build_lengths (df, D64_DIST_CODES, 15U, dd))
    {
      return 0;
    }

  if (!d64_build_codes (ll, D64_LIT_CODES, 15U, llcode)
      || !d64_build_codes (dd, D64_DIST_CODES, 15U, ddcode))
    {
      return 0;
    }

  *hlit = D64_LIT_CODES;

  while (*hlit > 257U && ll[*hlit - 1U] == 0U)
    {
      --(*hlit);
    }

  *hdist = D64_DIST_CODES;

  while (*hdist > 1U && dd[*hdist - 1U] == 0U)
    {
      --(*hdist);
    }

  nseq = 0U;

  for (i = 0U; i < *hlit; ++i)
    {
      seq[nseq++] = ll[i];
    }

  for (i = 0U; i < *hdist; ++i)
    {
      seq[nseq++] = dd[i];
    }

  *nrle = d64_rle_lengths (seq, nseq, rle, blfreq);

  if (*nrle > D64_MAX_RLE)
    {
      return 0;
    }

  /* As above, avoid a degenerate single-symbol code-length tree. */
  {
    unsigned active;
    active = 0U;

    for (i = 0U; i < D64_BL_CODES; ++i)
      {
        if (blfreq[i] != 0UL)
          {
            ++active;
          }
      }

    if (active == 1U)
      {
        for (i = 0U; i < D64_BL_CODES; ++i)
          {
            if (blfreq[i] == 0UL)
              {
                blfreq[i] = 1UL;

                break;
              }
          }
      }
  }

  if (!d64_build_lengths (blfreq, D64_BL_CODES, 7U, bl)
      || !d64_build_codes (bl, D64_BL_CODES, 7U, blcode))
    {
      return 0;
    }

  *hclen = D64_BL_CODES;

  while (*hclen > 4U && bl[d64_bl_order[*hclen - 1U]] == 0U)
    {
      --(*hclen);
    }

  cost = 5UL + 5UL + 4UL + (unsigned long)(*hclen) * 3UL;

  for (i = 0U; i < *nrle; ++i)
    {
      cost += (unsigned long)bl[rle[i].sym] + (unsigned long)rle[i].extra_bits;
    }

  *header_cost = cost;

  return 1;
}

static int
d64_emit_dynamic (d64_writer *w, const d64_token *tok, unsigned long ntok,
                  int final, const unsigned char *ll,
                  const unsigned short *llcode, const unsigned char *dd,
                  const unsigned short *ddcode, const d64_rle *rle,
                  unsigned nrle, const unsigned char *bl,
                  const unsigned short *blcode, unsigned hlit, unsigned hdist,
                  unsigned hclen)
{
  unsigned i;

  if (d64_put_bits (w, final ? 1U : 0U, 1U) != D64_OK
      || d64_put_bits (w, 2U, 2U) != D64_OK
      || d64_put_bits (w, hlit - 257U, 5U) != D64_OK
      || d64_put_bits (w, hdist - 1U, 5U) != D64_OK
      || d64_put_bits (w, hclen - 4U, 4U) != D64_OK)
    {
      return D64_WRITE_ERROR;
    }

  for (i = 0U; i < hclen; ++i)
    {
      if (d64_put_bits (w, bl[d64_bl_order[i]], 3U) != D64_OK)
        {
          return D64_WRITE_ERROR;
        }
    }

  for (i = 0U; i < nrle; ++i)
    {
      if (d64_emit_symbol (w, rle[i].sym, bl, blcode) != D64_OK
          || d64_put_bits (w, rle[i].extra, rle[i].extra_bits) != D64_OK)
        {
          return D64_WRITE_ERROR;
        }
    }

  return d64_emit_tokens (w, tok, ntok, ll, llcode, dd, ddcode);
}

#include "d64opt.inc"

static int
d64_encode_block (d64_encoder *e, const unsigned char *raw,
                  unsigned long raw_len, unsigned long ntok,
                  const unsigned long litfreq[D64_LIT_CODES],
                  const unsigned long distfreq[D64_DIST_CODES], int final)
{
  unsigned char fixed_ll[D64_FIXED_LIT_CODES];
  unsigned char fixed_dd[D64_DIST_CODES];
  unsigned char dyn_ll[D64_LIT_CODES];
  unsigned char dyn_dd[D64_DIST_CODES];
  unsigned char bl[D64_BL_CODES];
  unsigned short dyn_llcode[D64_LIT_CODES];
  unsigned short dyn_ddcode[D64_DIST_CODES];
  unsigned short blcode[D64_BL_CODES];
  d64_rle rle[D64_MAX_RLE];
  unsigned nrle;
  unsigned hlit;
  unsigned hdist;
  unsigned hclen;
  unsigned long dynamic_header;
  unsigned long fixed_cost;
  unsigned long dynamic_cost;
  unsigned long stored_cost;
  int dynamic_ok;

  d64_fixed_lengths (fixed_ll, fixed_dd);
  fixed_cost = 3UL + d64_tokens_cost (e->tokens, ntok, fixed_ll, fixed_dd);
  stored_cost = d64_stored_cost (e->bw.bitcnt, raw_len);

  dynamic_ok = d64_prepare_dynamic (
      litfreq, distfreq, dyn_ll, dyn_dd, dyn_llcode, dyn_ddcode, rle, &nrle,
      bl, blcode, &hlit, &hdist, &hclen, &dynamic_header);

  if (dynamic_ok)
    {
      dynamic_cost = 3UL + dynamic_header
                     + d64_tokens_cost (e->tokens, ntok, dyn_ll, dyn_dd);
    }
  else
    {
      dynamic_cost = ~0UL;
    }

  if (stored_cost <= fixed_cost && stored_cost <= dynamic_cost)
    {
      ++e->stats.blocks_stored;

      return d64_emit_stored (&e->bw, raw, raw_len, final);
    }

  if (dynamic_ok && dynamic_cost < fixed_cost)
    {
      ++e->stats.blocks_dynamic;

      return d64_emit_dynamic (&e->bw, e->tokens, ntok, final, dyn_ll,
                               dyn_llcode, dyn_dd, dyn_ddcode, rle, nrle, bl,
                               blcode, hlit, hdist, hclen);
    }

  ++e->stats.blocks_fixed;

  return d64_emit_fixed (&e->bw, e->tokens, ntok, final);
}

#include "d64split.inc"

static int
d64_fill (d64_encoder *e)
{
  while (!e->eof && e->in_len < D64_IN_CAP)
    {
      unsigned want;
      unsigned got;
      unsigned long room;
      room = D64_IN_CAP - e->in_len;
      want = room > 65535UL ? 65535U : (unsigned)room;
      got = (*e->read_cb) (e->opaque, e->in + e->in_len, want);

      if (got == 0U)
        {
          e->eof = 1;
          break;
        }

      if (got > want)
        {
          return D64_PARAM_ERROR;
        }

      e->in_len += (unsigned long)got;
      e->stats.input_size += (unsigned long)got;
    }

  return D64_OK;
}

static void
d64_slide (d64_encoder *e, unsigned long consumed)
{
  unsigned long keep_start;
  unsigned long keep_len;

  if (consumed > D64_HISTORY)
    {
      keep_start = consumed - D64_HISTORY;
    }
  else
    {
      keep_start = 0UL;
    }

  keep_len = e->in_len - keep_start;

  if (keep_start != 0UL)
    {
      memmove (e->in, e->in + keep_start, (size_t)keep_len);
    }

  e->hist = consumed - keep_start;
  e->in_len = keep_len;
}

int
d64_encode (d64_read_func read_cb, d64_write_func write_cb, void *opaque,
            int level, d64_stats *stats)
{
  d64_encoder e;
  int rc;
  int emitted;

  if (read_cb == NULL || write_cb == NULL || level < 1 || (level > 9 && level != 11))
    {
      return D64_PARAM_ERROR;
    }

  memset (&e, 0, sizeof (e));
  e.read_cb = read_cb;
  e.write_cb = write_cb;
  e.opaque = opaque;
  e.level = level;
  e.in = (unsigned char *)malloc ((size_t)D64_IN_CAP);
  e.head = (int *)malloc ((size_t)D64_HASH_SIZE * sizeof (e.head[0]));
  e.prev = (int *)malloc ((size_t)D64_IN_CAP * sizeof (e.prev[0]));
  e.tokens
      = (d64_token *)malloc ((size_t)D64_MAX_TOKENS * sizeof (e.tokens[0]));

  if (e.in == NULL || e.head == NULL || e.prev == NULL || e.tokens == NULL)
    {
      free (e.in);
      free (e.head);
      free (e.prev);
      free (e.tokens);

      return D64_MEM_ERROR;
    }

  e.bw.write_cb = write_cb;
  e.bw.opaque = opaque;
  emitted = 0;
  rc = d64_fill (&e);

  while (rc == D64_OK)
    {
      unsigned long start;
      unsigned long end;
      unsigned long ntok;
      unsigned long litfreq[D64_LIT_CODES];
      unsigned long distfreq[D64_DIST_CODES];
      int final;
      d64_stats before;

      start = e.hist;

      if (start == e.in_len)
        {
          if (!e.eof)
            {
              rc = d64_fill (&e);

              if (rc != D64_OK)
                {
                  break;
                }

              start = e.hist;
            }

          if (start == e.in_len && e.eof)
            {
              if (!emitted)
                {
                  memset (litfreq, 0, sizeof (litfreq));
                  memset (distfreq, 0, sizeof (distfreq));
                  litfreq[256U] = 1UL;
                  rc = d64_encode_block (&e, e.in + start, 0UL, 0UL, litfreq,
                                         distfreq, 1);
                }
              else
                {
                  rc = d64_emit_fixed (&e.bw, e.tokens, 0UL, 1);

                  if (rc == D64_OK)
                    {
                      ++e.stats.blocks_fixed;
                    }
                }

              break;
            }
        }

      before = e.stats;
        ntok = d64_tokenize (&e, start, &end, litfreq, distfreq);

        if (e.level == 11)
          {
            /* Higher effort is an additional search, not a replacement for
             * the -9 candidate.  Different Huffman models can otherwise
             * produce a worse result despite more extensive searching. */
            e.level = 9;
            ntok = d64_optimize (&e, start, end, ntok, litfreq, distfreq,
                                 &before);
            e.level = 11;
          }
        if (e.level >= 8)
          ntok = d64_optimize (&e, start, end, ntok, litfreq, distfreq,
                               &before);

      if (ntok > D64_MAX_TOKENS)
        {
          rc = D64_PARAM_ERROR;
          break;
        }

      final = e.eof && end == e.in_len;
      if (e.level == 11)
        rc = d64_split_encode (&e, e.in + start, end - start, ntok, litfreq,
                               distfreq, final, &before);
      else
        rc = d64_encode_block (&e, e.in + start, end - start, ntok, litfreq,
                               distfreq, final);

      if (rc != D64_OK)
        {
          break;
        }

      emitted = 1;

      if (final)
        {
          break;
        }

      d64_slide (&e, end);
      rc = d64_fill (&e);
    }

  if (rc == D64_OK)
    {
      rc = d64_writer_finish (&e.bw);
    }

  e.stats.output_size = e.bw.total;

  if (stats != NULL)
    {
      *stats = e.stats;
    }

  free (e.in);
  free (e.head);
  free (e.prev);
  free (e.tokens);

  return rc;
}
