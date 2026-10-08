/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#define D64_OPT_CLASSES 32U

#ifndef D64_OPT_MAX8
# define D64_OPT_MAX8 512UL
#endif /* ifndef D64_OPT_MAX8 */

#ifndef D64_OPT_MAX9
# define D64_OPT_MAX9 1024UL
#endif /* ifndef D64_OPT_MAX9 */

#ifndef D64_OPT_CHAIN8
# define D64_OPT_CHAIN8 64U
#endif /* ifndef D64_OPT_CHAIN8 */

#ifndef D64_OPT_CHAIN9
# define D64_OPT_CHAIN9 192U
#endif /* ifndef D64_OPT_CHAIN9 */

#define D64_OPT_INF (~0UL)

typedef struct d64_opt_match
{
  unsigned short len;
  unsigned short dist_minus_one; /* 0 through 65535 represents 1..65536 */
} d64_opt_match;

typedef struct d64_opt_node
{
  unsigned long bits;
  unsigned long pos;
} d64_opt_node;

typedef struct d64_opt_workspace
{
  d64_opt_match *matches;
  d64_opt_node *tree;
  unsigned long tree_base;
  unsigned short *choice_len;
  unsigned short *choice_dist;
  d64_token *best_tokens;
  unsigned long best_lf[D64_LIT_CODES];
  unsigned long best_df[D64_DIST_CODES];
  unsigned long best_bits;
  unsigned long best_ntok;
  unsigned long n;
} d64_opt_workspace;

static void
d64_opt_release (d64_opt_workspace *o)
{
  free (o->matches);
  free (o->tree);
  free (o->choice_len);
  free (o->choice_dist);
  free (o->best_tokens);
}

static int
d64_opt_allocate (d64_opt_workspace *o, unsigned long n)
{
  unsigned long base;

  memset (o, 0, sizeof (*o));

  if (n == 0UL || n > D64_BLOCK_TARGET)
    {
      return 0;
    }

  base = 1UL;

  while (base < n + 1UL)
    {
      base <<= 1;
    }

  o->n = n;
  o->tree_base = base;
  o->matches = (d64_opt_match *)calloc ((size_t)n * D64_OPT_CLASSES,
                                        sizeof (d64_opt_match));
  o->tree
      = (d64_opt_node *)malloc ((size_t)(base * 2UL) * sizeof (d64_opt_node));
  o->choice_len
      = (unsigned short *)malloc ((size_t)n * sizeof (unsigned short));
  o->choice_dist
      = (unsigned short *)malloc ((size_t)n * sizeof (unsigned short));
  o->best_tokens
      = (d64_token *)malloc ((size_t)D64_MAX_TOKENS * sizeof (d64_token));

  return o->matches != NULL && o->tree != NULL && o->choice_len != NULL
         && o->choice_dist != NULL && o->best_tokens != NULL;
}

static int
d64_opt_discover (d64_encoder *e, d64_opt_workspace *o, unsigned long start,
                  unsigned long limit)
{
  unsigned i;
  unsigned long pos;
  unsigned chain_limit;
  unsigned long max_match;
  unsigned long comparisons;
  unsigned long comparison_limit;

  comparisons = 0UL;
  comparison_limit = e->level == 8 ? 64000000UL : 128000000UL;
  chain_limit = e->level == 8 ? D64_OPT_CHAIN8 : D64_OPT_CHAIN9;
  max_match = e->level == 8 ? D64_OPT_MAX8 : D64_OPT_MAX9;

  for (i = 0U; i < D64_HASH_SIZE; ++i)
    {
      e->head[i] = D64_NIL;
    }

  for (pos = 0UL; pos < start; ++pos)
    {
      d64_insert (e, pos);
    }

  for (pos = start; pos < limit; ++pos)
    {
      unsigned long maxlen;
      unsigned h;
      int cand;
      unsigned remaining;
      d64_opt_match *slot;
      slot = o->matches + (size_t)(pos - start) * D64_OPT_CLASSES;
      maxlen = limit - pos;

      if (maxlen > max_match)
        {
          maxlen = max_match;
        }

      if (maxlen < 3UL)
        {
          d64_insert (e, pos);
          continue;
        }

      h = d64_hash3 (e->in + pos);
      cand = e->head[h];
      remaining = chain_limit;

      while (cand != D64_NIL && remaining-- != 0U)
        {
          unsigned long c;
          unsigned long d;
          unsigned long len;
          unsigned code;
          unsigned extra;
          unsigned bits;
          c = (unsigned long)cand;

          if (c >= pos)
            {
              break;
            }

          d = pos - c;

          if (d > D64_HISTORY)
            {
              break;
            }

          if (e->in[c] == e->in[pos] && e->in[c + 1UL] == e->in[pos + 1UL]
              && e->in[c + 2UL] == e->in[pos + 2UL])
            {
              len = 3UL;

              while (len < maxlen && e->in[c + len] == e->in[pos + len])
                {
                  ++len;
                }
              comparisons += len;

              if (comparisons > comparison_limit)
                {
                  return 0;
                }

              code = d64_distance_code (d, &extra, &bits);

              if (len > (unsigned long)slot[code].len)
                {
                  slot[code].len = (unsigned short)len;
                  slot[code].dist_minus_one = (unsigned short)(d - 1UL);
                }

              if (len == maxlen && d <= 4UL)
                {
                  break;
                }
            }

          cand = e->prev[c];
        }

      d64_insert (e, pos);
    }

  return 1;
}

static d64_opt_node
d64_opt_min (const d64_opt_workspace *o, unsigned long l, unsigned long r)
{
  d64_opt_node best;

  best.bits = D64_OPT_INF;
  best.pos = 0UL;
  l += o->tree_base;
  r += o->tree_base;

  while (l <= r)
    {
      d64_opt_node t;

      if ((l & 1UL) != 0UL)
        {
          t = o->tree[l++];

          if (t.bits < best.bits || (t.bits == best.bits && t.pos > best.pos))
            {
              best = t;
            }
        }

      if ((r & 1UL) == 0UL)
        {
          t = o->tree[r--];

          if (t.bits < best.bits || (t.bits == best.bits && t.pos > best.pos))
            {
              best = t;
            }
        }

      l >>= 1;
      r >>= 1;
    }

  return best;
}

static void
d64_opt_insert_cost (d64_opt_workspace *o, unsigned long i, unsigned long bits)
{
  unsigned long p;

  p = o->tree_base + i;
  o->tree[p].bits = bits;
  o->tree[p].pos = i;

  while (p > 1UL)
    {
      d64_opt_node a;
      d64_opt_node b;
      p >>= 1;
      a = o->tree[p * 2UL];
      b = o->tree[p * 2UL + 1UL];
      o->tree[p]
          = a.bits < b.bits || (a.bits == b.bits && a.pos >= b.pos) ? a : b;
    }
}

static unsigned long
d64_opt_parse (d64_encoder *e, d64_opt_workspace *o, unsigned long start,
               const unsigned char *ll, const unsigned char *dd,
               unsigned long *lf, unsigned long *df)
{
  unsigned long i;
  unsigned long ntok;
  unsigned long queries;
  unsigned long query_limit;

  queries = 0UL;
  query_limit = e->level == 8 ? 8000000UL : 16000000UL;

  for (i = 0UL; i < o->tree_base * 2UL; ++i)
    {
      o->tree[i].bits = D64_OPT_INF;
      o->tree[i].pos = 0UL;
    }

  d64_opt_insert_cost (o, o->n, 0UL);

  for (i = o->n; i-- != 0UL;)
    {
      unsigned long best;
      unsigned long best_len;
      unsigned long best_dist;
      unsigned literal_bits;
      unsigned cls;
      d64_opt_match *m;
      literal_bits = ll[e->in[start + i]] != 0U ? ll[e->in[start + i]] : 15U;
      best
          = (unsigned long)literal_bits + o->tree[o->tree_base + i + 1UL].bits;
      best_len = 0UL;
      best_dist = 0UL;
      m = o->matches + (size_t)i * D64_OPT_CLASSES;

      for (cls = 0U; cls < D64_OPT_CLASSES; ++cls)
        {
          unsigned sym;
          unsigned long maxlen;
          unsigned dist_bits;

          if (m[cls].len < 3U)
            {
              continue;
            }

          maxlen = (unsigned long)m[cls].len;
          dist_bits = (dd[cls] != 0U ? dd[cls] : 15U) + d64_dist_extra[cls];

          for (sym = 0U; sym < 29U; ++sym)
            {
              unsigned long low;
              unsigned long high;
              unsigned long base;
              unsigned long span;
              unsigned long cur;
              unsigned cost_bits;
              d64_opt_node suffix;
              base = (unsigned long)d64_len_base[sym];
              span = 1UL << d64_len_extra[sym];

              if (sym == 28U)
                {
                  low = 259UL;
                  high = maxlen;
                }
              else
                {
                  low = base;
                  high = base + span - 1UL;
                  if (high > maxlen)
                    {
                      high = maxlen;
                    }
                }

              if (high < low)
                {
                  continue;
                }

              if (++queries > query_limit)
                {
                  return 0UL;
                }

              suffix = d64_opt_min (o, i + low, i + high);
              cost_bits = (ll[257U + sym] != 0U ? ll[257U + sym] : 15U)
                          + d64_len_extra[sym] + dist_bits;
              cur = suffix.bits + (unsigned long)cost_bits;

              if (cur < best || (cur == best && suffix.pos - i > best_len))
                {
                  best = cur;
                  best_len = suffix.pos - i;
                  best_dist = (unsigned long)m[cls].dist_minus_one + 1UL;
                }
            }
        }

      o->choice_len[i] = (unsigned short)best_len;
      o->choice_dist[i]
          = (unsigned short)(best_dist == 0UL ? 0UL : best_dist - 1UL);
      d64_opt_insert_cost (o, i, best);
    }

  memset (lf, 0, D64_LIT_CODES * sizeof (lf[0]));
  memset (df, 0, D64_DIST_CODES * sizeof (df[0]));
  ntok = 0UL;
  i = 0UL;

  while (i < o->n)
    {
      unsigned long len;
      unsigned ex;
      unsigned bits;
      unsigned code;
      len = (unsigned long)o->choice_len[i];

      if (len == 0UL)
        {
          e->tokens[ntok].len = 0UL;
          e->tokens[ntok].dist = 0UL;
          e->tokens[ntok].lit = (unsigned)e->in[start + i];
          ++lf[e->tokens[ntok].lit];
          ++i;
        }
      else
        {
          unsigned long dist;
          dist = (unsigned long)o->choice_dist[i] + 1UL;
          e->tokens[ntok].len = len;
          e->tokens[ntok].dist = dist;
          e->tokens[ntok].lit = 0U;
          code = d64_length_code (len, &ex, &bits);
          ++lf[code];
          code = d64_distance_code (dist, &ex, &bits);
          ++df[code];
          i += len;
        }

      ++ntok;
    }

  ++lf[256U];

  return ntok;
}

static unsigned long
d64_opt_block_bits (d64_encoder *e, unsigned long raw_len, unsigned long ntok,
                    const unsigned long *lf, const unsigned long *df)
{
  unsigned char fixed_ll[D64_FIXED_LIT_CODES];
  unsigned char fixed_dd[D64_DIST_CODES];
  unsigned char dyn_ll[D64_LIT_CODES];
  unsigned char dyn_dd[D64_DIST_CODES];
  unsigned char bl[D64_BL_CODES];
  unsigned short llcode[D64_LIT_CODES];
  unsigned short ddcode[D64_DIST_CODES];
  unsigned short blcode[D64_BL_CODES];
  d64_rle rle[D64_MAX_RLE];
  unsigned nrle, hlit, hdist, hclen;
  unsigned long hdr;
  unsigned long best;
  unsigned long cur;

  d64_fixed_lengths (fixed_ll, fixed_dd);
  best = 3UL + d64_tokens_cost (e->tokens, ntok, fixed_ll, fixed_dd);
  cur = d64_stored_cost (e->bw.bitcnt, raw_len);

  if (cur < best)
    {
      best = cur;
    }

  if (d64_prepare_dynamic (lf, df, dyn_ll, dyn_dd, llcode, ddcode, rle, &nrle,
                           bl, blcode, &hlit, &hdist, &hclen, &hdr))
    {
      cur = 3UL + hdr + d64_tokens_cost (e->tokens, ntok, dyn_ll, dyn_dd);

      if (cur < best)
        {
          best = cur;
        }
    }

  return best;
}

static void
d64_opt_recount (d64_encoder *e, unsigned long ntok)
{
  unsigned long j;

  for (j = 0UL; j < ntok; ++j)
    {
      if (e->tokens[j].len != 0UL)
        {
          ++e->stats.matches;

          if (e->tokens[j].len > e->stats.max_match)
            {
              e->stats.max_match = e->tokens[j].len;
            }

          if (e->tokens[j].dist > e->stats.max_distance)
            {
              e->stats.max_distance = e->tokens[j].dist;
            }
        }
    }
}

static unsigned long
d64_optimize (d64_encoder *e, unsigned long start, unsigned long end,
              unsigned long ntok, unsigned long *litfreq,
              unsigned long *distfreq, const d64_stats *before)
{
  d64_opt_workspace o;
  unsigned char fixed_ll[D64_FIXED_LIT_CODES];
  unsigned char fixed_dd[D64_DIST_CODES];
  unsigned char dyn_ll[D64_LIT_CODES];
  unsigned char dyn_dd[D64_DIST_CODES];
  unsigned char bl[D64_BL_CODES];
  unsigned short llcode[D64_LIT_CODES];
  unsigned short ddcode[D64_DIST_CODES];
  unsigned short blcode[D64_BL_CODES];
  d64_rle rle[D64_MAX_RLE];
  unsigned nrle, hlit, hdist, hclen;
  unsigned long hdr;
  unsigned long lf[D64_LIT_CODES];
  unsigned long df[D64_DIST_CODES];
  unsigned long cur;
  unsigned long n;
  unsigned long count;
  unsigned pass;
  unsigned passes;
  int improved;
  int have_dynamic;

  n = end - start;

  if (!d64_opt_allocate (&o, n))
    {
      d64_opt_release (&o);
      return ntok;
    }

  improved = 0;
  o.best_ntok = ntok;
  memcpy (o.best_tokens, e->tokens, (size_t)ntok * sizeof (d64_token));
  memcpy (o.best_lf, litfreq, sizeof (o.best_lf));
  memcpy (o.best_df, distfreq, sizeof (o.best_df));
  o.best_bits = d64_opt_block_bits (e, n, ntok, litfreq, distfreq);

  if (o.best_bits <= n / 8UL)
    {
      d64_opt_release (&o);
      return ntok;
    }

  d64_fixed_lengths (fixed_ll, fixed_dd);

  if (!d64_opt_discover (e, &o, start, end))
    {
      d64_opt_release (&o);
      return ntok;
    }

  passes = e->level == 8 ? 2U : 3U;

  for (pass = 0U; pass < passes; ++pass)
    {
      const unsigned char *ll;
      const unsigned char *dd;

      if (pass == 0U)
        {
          ll = fixed_ll;
          dd = fixed_dd;
        }
      else
        {
          have_dynamic = d64_prepare_dynamic (
              pass == 1U ? litfreq : o.best_lf,
              pass == 1U ? distfreq : o.best_df, dyn_ll, dyn_dd, llcode,
              ddcode, rle, &nrle, bl, blcode, &hlit, &hdist, &hclen, &hdr);

          if (!have_dynamic)
            {
              continue;
            }

          ll = dyn_ll;
          dd = dyn_dd;
        }

      count = d64_opt_parse (e, &o, start, ll, dd, lf, df);

      if (count == 0UL)
        {
          continue;
        }

      cur = d64_opt_block_bits (e, n, count, lf, df);

      if (cur < o.best_bits && o.best_bits - cur >= 8UL)
        {
          improved = 1;
          o.best_bits = cur;
          o.best_ntok = count;
          memcpy (o.best_tokens, e->tokens,
                  (size_t)count * sizeof (d64_token));
          memcpy (o.best_lf, lf, sizeof (o.best_lf));
          memcpy (o.best_df, df, sizeof (o.best_df));
        }
    }

  if (improved)
    {
      e->stats.matches = before->matches;
      e->stats.max_match = before->max_match;
      e->stats.max_distance = before->max_distance;
      ntok = o.best_ntok;
      memcpy (e->tokens, o.best_tokens, (size_t)ntok * sizeof (d64_token));
      memcpy (litfreq, o.best_lf, sizeof (o.best_lf));
      memcpy (distfreq, o.best_df, sizeof (o.best_df));
      d64_opt_recount (e, ntok);
    }
  else
    {
      memcpy (e->tokens, o.best_tokens, (size_t)ntok * sizeof (d64_token));
    }

  d64_opt_release (&o);

  return ntok;
}
