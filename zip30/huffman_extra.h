/* SPDX-License-Identifier: MIT-0
 * Shared optional dynamic-header optimizer for Deflate and Deflate64.
 * Callers compares cost against its original header before adopting!
 */

#ifndef XTR_HUFFMAN_EXTRA_H

# define XTR_HUFFMAN_EXTRA_H

# include <limits.h>
# include <stdlib.h>
# include <string.h>

# define HE_MAX 318U
# define HE_INF 0x3fffffffUL

typedef struct he_result
{
  unsigned char lengths[19];
  unsigned char symbol[HE_MAX];
  unsigned char repeat[HE_MAX];
  unsigned count, hclen;
  unsigned long cost;
} he_result;

static const unsigned char he_order[19]
    = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

static unsigned
he_weight (unsigned l)
{
  return l ? (1U << (7U - l)) : 0U;
}

static unsigned
he_hclen (const unsigned char *lens)
{
  unsigned n = 19U;

  while (n > 4U && lens[he_order[n - 1U]] == 0U)
    {
      --n;
    }

  return n;
}

static int
he_valid (const unsigned char *lens)
{
  unsigned i, cap = 0U, active = 0U;

  for (i = 0; i < 19U; ++i)
    {
      if (lens[i] > 7U)
        {
          return 0;
        }

      if (lens[i])
        {
          cap += he_weight (lens[i]);
          ++active;
        }
    }

  return active >= 2U && cap == 128U;
}

/*
 * Exact fixed-tree RLE DP; token at i represents repeat[i] input lengths.
 * Symbol 16 can repeat a prior decoded code-length even at a token boundary.
 */

static unsigned long
he_exact (const unsigned char *seq, unsigned n, const unsigned char *lens,
          he_result *out, unsigned long *freq)
{
  unsigned long dp[HE_MAX + 1U];
  unsigned char choice[HE_MAX], runlen[HE_MAX];
  unsigned i, r, maxrun, val, sym, count;
  unsigned long cost, candidate;
  int at;

  if (n > HE_MAX || !he_valid (lens))
    {
      return HE_INF;
    }

  dp[n] = 0;

  for (at = (int)n - 1; at >= 0; --at)
    {
      val = seq[at];

      if (val > 15U)
        {
          return HE_INF;
        }

      cost = lens[val] && dp[at + 1] < HE_INF
                 ? (unsigned long)lens[val] + dp[at + 1]
                 : HE_INF;
      sym = val;
      count = 1U;
      maxrun = 1U;

      while ((unsigned)at + maxrun < n && maxrun < 138U
             && seq[at + maxrun] == val)
        {
          ++maxrun;
        }

      if (lens[16] && at > 0 && seq[at - 1] == val)
        {
          for (r = 3U; r <= 6U && r <= maxrun; ++r)
            {
              candidate
                  = dp[at + r] < HE_INF ? dp[at + r] + lens[16] + 2U : HE_INF;

              if (candidate < cost)
                {
                  cost = candidate;
                  sym = 16U;
                  count = r;
                }
            }
        }

      if (val == 0U && lens[17])
        {
          for (r = 3U; r <= 10U && r <= maxrun; ++r)
            {
              candidate
                  = dp[at + r] < HE_INF ? dp[at + r] + lens[17] + 3U : HE_INF;

              if (candidate < cost)
                {
                  cost = candidate;
                  sym = 17U;
                  count = r;
                }
            }
        }

      if (val == 0U && lens[18])
        {
          for (r = 11U; r <= 138U && r <= maxrun; ++r)
            {
              candidate
                  = dp[at + r] < HE_INF ? dp[at + r] + lens[18] + 7U : HE_INF;

              if (candidate < cost)
                {
                  cost = candidate;
                  sym = 18U;
                  count = r;
                }
            }
        }

      dp[at] = cost;
      choice[at] = (unsigned char)sym;
      runlen[at] = (unsigned char)count;
    }

  if (dp[0] >= HE_INF)
    {
      return HE_INF;
    }

  if (out != NULL)
    {
      out->count = 0U;
      memcpy (out->lengths, lens, 19U);
      out->hclen = he_hclen (lens);

      for (i = 0U; i < n; i += runlen[i])
        {
          out->symbol[out->count] = choice[i];
          out->repeat[out->count] = runlen[i];
          ++out->count;
        }

      out->cost = 14UL + 3UL * out->hclen + dp[0];
    }

  if (freq != NULL)
    {
      for (i = 0; i < 19U; ++i)
        {
          freq[i] = 0UL;
        }

      for (i = 0U; i < n; i += runlen[i])
        {
          ++freq[choice[i]];
        }
    }

  return 14UL + 3UL * he_hclen (lens) + dp[0];
}

/*
 * Length-limited Huffman builder for the 19-symbol CL alphabet.
 * The caller can also seed with the existing encoder's CL lengths
 */

static int
he_lengths (const unsigned long *freq, unsigned char *lens)
{
  struct he_node
  {
    unsigned long weight;
    int parent;
    unsigned order;
  } nodes[38];
  unsigned short sorted[19];
  unsigned cnt[8], active = 0U, i, j, left, right, newnode, bits,
                   overflow = 0U;
  int p;

  memset (lens, 0, 19U);
  memset (cnt, 0, sizeof (cnt));

  for (i = 0; i < 19U; ++i)
    {
      if (freq[i])
        {
          sorted[active] = (unsigned short)i;
          nodes[active].weight = freq[i];
          nodes[active].parent = -1;
          nodes[active].order = i;
          ++active;
        }
    }

  if (active == 0U)
    {
      return 0;
    }

  if (active == 1U)
    {
      lens[sorted[0]] = 1U;
      lens[sorted[0] ? 0U : 1U] = 1U;
      return 1;
    }

  /* Sort increasing frequency, then symbol, for deterministic codes. */
  for (i = 0; i < active; ++i)
    {
      for (j = i + 1U; j < active; ++j)
        {
          unsigned a = sorted[i], b = sorted[j];

          if (freq[b] < freq[a] || (freq[b] == freq[a] && b < a))
            {
              unsigned short tmp = sorted[i];
              sorted[i] = sorted[j];
              sorted[j] = tmp;
            }
        }
    }

  newnode = active;

  while (newnode < 2U * active - 1U)
    {
      left = right = 38U;

      for (i = 0; i < newnode; ++i)
        {
          if (nodes[i].parent == -1)
            {
              if (left == 38U || nodes[i].weight < nodes[left].weight
                  || (nodes[i].weight == nodes[left].weight
                      && nodes[i].order < nodes[left].order))
                {
                  right = left;
                  left = i;
                }
              else if (right == 38U || nodes[i].weight < nodes[right].weight
                       || (nodes[i].weight == nodes[right].weight
                           && nodes[i].order < nodes[right].order))
                {
                  right = i;
                }
            }
        }

      if (left == 38U || right == 38U)
        {
          return 0;
        }

      nodes[left].parent = nodes[right].parent = (int)newnode;
      nodes[newnode].weight = nodes[left].weight + nodes[right].weight;
      nodes[newnode].order = nodes[left].order < nodes[right].order
                                 ? nodes[left].order
                                 : nodes[right].order;
      nodes[newnode].parent = -1;
      ++newnode;
    }
  for (i = 0; i < active; ++i)
    {
      bits = 0U;
      p = (int)i;

      while (nodes[p].parent != -1)
        {
          ++bits;
          p = nodes[p].parent;
        }

      if (bits > 7U)
        {
          bits = 7U;
          ++overflow;
        }

      ++cnt[bits];
    }

  while (overflow)
    {
      bits = 6U;

      while (bits && cnt[bits] == 0U)
        {
          --bits;
        }

      if (!bits || !cnt[7])
        {
          return 0;
        }

      --cnt[bits];
      cnt[bits + 1U] += 2U;
      --cnt[7];
      overflow = overflow > 1U ? overflow - 2U : 0U;
    }

  j = 0U;

  for (bits = 7U; bits > 0U; --bits)
    {
      for (i = 0; i < cnt[bits]; ++i)
        {
          if (j >= active)
            {
              return 0;
            }

          lens[sorted[j++]] = (unsigned char)bits;
        }
    }

  return j == active && he_valid (lens);
}

static void
he_consider (const unsigned char *seq, unsigned n, const unsigned char *lens,
             he_result *best)
{
  he_result candidate;
  unsigned long cost = he_exact (seq, n, lens, &candidate, NULL);

  if (cost < best->cost)
    {
      memcpy (best, &candidate, sizeof (candidate));
    }
}

/* Cost of one identical nonzero run, first occurrence explicitly encoded. */
static unsigned long
he_positive (unsigned n, unsigned literal, unsigned rep)
{
  unsigned long dp[HE_MAX + 1U];
  unsigned i, r;

  dp[0] = 0UL;

  for (i = 1U; i <= n; ++i)
    {
      dp[i] = dp[i - 1U] + literal;

      if (rep && i >= 4U)
        {
          for (r = 3U; r <= 6U && r < i; ++r)
            {
              if (dp[i - r] + rep + 2UL < dp[i])
                {
                  dp[i] = dp[i - r] + rep + 2UL;
                }
            }
        }
    }

  return dp[n];
}

/* Exact cost of independent zero-length runs; avoid O(138*n) for R7. */
static unsigned long
he_zero_cost (const unsigned short *hist, unsigned longest, unsigned len0,
              unsigned len16, unsigned len17, unsigned len18)
{
  unsigned long dp[HE_MAX + 1U], total = 0UL, candidate;
  unsigned short queue[3][HE_MAX + 1U];
  unsigned head[3] = { 0U, 0U, 0U }, tail[3] = { 0U, 0U, 0U };
  static const unsigned minimum[3] = { 3U, 3U, 11U };
  static const unsigned maximum[3] = { 6U, 10U, 138U };
  static const unsigned extra[3] = { 2U, 3U, 7U };
  unsigned lengths[3], n, t, at;

  lengths[0] = len16;
  lengths[1] = len17;
  lengths[2] = len18;
  dp[0] = 0UL;

  for (n = 1U; n <= longest; ++n)
    {
      dp[n] = len0 && dp[n - 1U] < HE_INF ? dp[n - 1U] + len0 : HE_INF;

      for (t = 0; t < 3U; ++t)
        {
          if (!lengths[t] || n < minimum[t])
            {
              continue;
            }

          at = n - minimum[t];

          if (t == 0U && at == 0U)
            {
              continue;
            }

          while (tail[t] > head[t] && dp[queue[t][tail[t] - 1U]] >= dp[at])
            {
              --tail[t];
            }

          queue[t][tail[t]++] = (unsigned short)at;

          while (head[t] < tail[t]
                 && (unsigned)queue[t][head[t]] + maximum[t] < n)
            {
              ++head[t];
            }

          if (head[t] < tail[t] && dp[queue[t][head[t]]] < HE_INF)
            {
              candidate = dp[queue[t][head[t]]] + lengths[t] + extra[t];

              if (candidate < dp[n])
                {
                  dp[n] = candidate;
                }
            }
        }

      if (hist[n])
        {
          if (dp[n] >= HE_INF)
            {
              return HE_INF;
            }

          total += (unsigned long)hist[n] * dp[n];
        }
    }

  return total;
}

typedef struct he_r7work
{
  unsigned short hist[16][HE_MAX + 1U];
  unsigned longest[16], symbols[15];
  unsigned char back[16][129];
  unsigned long positive[16][8], prev[129], next[129];
} he_r7work;

static void
he_r7 (const unsigned char *seq, unsigned n, he_result *best)
{
  he_r7work *w;
  unsigned i, v, count, nsymbols = 0U, rep, len0, len17, len18, used, cap, c,
                        len, s, rest;
  unsigned long price, zero, fixed;
  unsigned char lens[19];

  w = (he_r7work *)malloc (sizeof (*w));
  if (!w)
    {
      return; /* malloc failure: never compromise encoding. */
    }

  memset (w, 0, sizeof (*w));
  i = 0U;

  while (i < n)
    {
      v = seq[i];
      count = 1U;

      while (i + count < n && seq[i + count] == v)
        {
          ++count;
        }

      ++w->hist[v][count];

      if (count > w->longest[v])
        {
          w->longest[v] = count;
        }

      i += count;
    }

  for (v = 1U; v <= 15U; ++v)
    {
      if (w->longest[v])
        {
          w->symbols[nsymbols++] = v;
        }
    }

  if (!nsymbols || (nsymbols == 1U && !w->longest[0]))
    {
      free (w);
      return;
    }

  /* HCLEN includes 16/17/18 in any actual R7 choice. */
  for (rep = 0U; rep <= 7U; ++rep)
    {
      /* The 16 symbol is useful for nonzero runs too. */
      int allowrep = 0;

      for (v = 0U; v < 16U; ++v)
        {
          if (w->longest[v] >= 4U)
            {
              allowrep = 1;
            }
        }

      if (rep == 0U && allowrep)
        {
          /* still consider */
        }

      if (rep != 0U && !allowrep)
        {
          continue;
        }

      for (v = 0U; v < nsymbols; ++v)
        {
          s = w->symbols[v];

          for (len = 1U; len <= 7U; ++len)
            {
              price = 0UL;

              for (i = 1U; i <= w->longest[s]; ++i)
                {
                  if (w->hist[s][i])
                    {
                      price += (unsigned long)w->hist[s][i]
                               * he_positive (i, len, rep);
                    }
                }

              w->positive[s][len] = price;
            }
        }

      for (cap = 0U; cap <= 128U; ++cap)
        {
          w->prev[cap] = HE_INF;
        }

      w->prev[0] = 0UL;

      for (v = 0U; v < nsymbols; ++v)
        {
          s = w->symbols[v];

          for (cap = 0U; cap <= 128U; ++cap)
            {
              w->next[cap] = HE_INF;
            }

          for (cap = 0U; cap <= 128U; ++cap)
            {
              if (w->prev[cap] >= HE_INF)
                {
                  continue;
                }

              for (len = 1U; len <= 7U; ++len)
                {
                  c = cap + he_weight (len);
                  if (c > 128U)
                    {
                      continue;
                    }

                  price = w->prev[cap] + w->positive[s][len];

                  if (price < w->next[c])
                    {
                      w->next[c] = price;
                      w->back[v + 1U][c] = (unsigned char)len;
                    }
                }
            }

          memcpy (w->prev, w->next, sizeof (w->prev));
        }

      for (len0 = 0U; len0 <= (w->longest[0] ? 7U : 0U); ++len0)
        {
          for (len17 = 0U; len17 <= (w->longest[0] >= 3U ? 7U : 0U); ++len17)
            {
              for (len18 = 0U; len18 <= (w->longest[0] >= 11U ? 7U : 0U);
                   ++len18)
                {
                  used = he_weight (rep) + he_weight (len0) + he_weight (len17)
                         + he_weight (len18);
                  if (used > 128U)
                    {
                      continue;
                    }

                  cap = 128U - used;

                  if (w->prev[cap] >= HE_INF)
                    {
                      continue;
                    }

                  if (w->prev[cap] + 14UL >= best->cost)
                    {
                      continue;
                    }

                  zero = he_zero_cost (w->hist[0], w->longest[0], len0, rep,
                                       len17, len18);
                  if (zero >= HE_INF
                      || w->prev[cap] + zero + 14UL >= best->cost)
                    {
                      continue;
                    }

                  memset (lens, 0, sizeof (lens));
                  lens[0] = (unsigned char)len0;
                  lens[16] = (unsigned char)rep;
                  lens[17] = (unsigned char)len17;
                  lens[18] = (unsigned char)len18;
                  rest = cap;

                  for (v = nsymbols; v > 0U; --v)
                    {
                      len = w->back[v][rest];

                      if (len == 0U || len > 7U || he_weight (len) > rest)
                        {
                          break;
                        }

                      lens[w->symbols[v - 1U]] = (unsigned char)len;
                      rest -= he_weight (len);
                    }

                  if (v || rest)
                    {
                      continue;
                    }

                  fixed = 14UL + 3UL * he_hclen (lens);

                  if (fixed + w->prev[cap] + zero >= best->cost)
                    {
                      continue;
                    }

                  he_consider (seq, n, lens, best);
                }
            }
        }
    }

  free (w);
}

/*
 * Run exact RLE, alternating tree/RLE refinement, and R7 on every call.
 * initial is the caller's existing CL tree; a strictly smaller complete
 * candidate replaces current.  No output is committed during evaluation
 */

static void
he_optimize (const unsigned char *seq, unsigned n,
             const unsigned char *initial, he_result *best)
{
  unsigned long freq[19];
  unsigned char candidate[19], current[19];
  unsigned pass;

  memset (best, 0, sizeof (*best));
  best->cost = HE_INF;

  if (n > HE_MAX || n == 0U)
    {
      return;
    }

  if (he_valid (initial))
    {
      he_consider (seq, n, initial, best);
    }

  if (best->cost == HE_INF)
    {
      return;
    }

  memcpy (current, initial, sizeof (current));

  for (pass = 0U; pass < 3U; ++pass)
    {
      if (he_exact (seq, n, current, NULL, freq) >= HE_INF)
        {
          break;
        }

      if (!he_lengths (freq, candidate))
        {
          break;
        }

      he_consider (seq, n, candidate, best);
      memcpy (current, candidate, sizeof (current));
    }

  he_r7 (seq, n, best);
}

#endif /* XTR_HUFFMAN_EXTRA_H */
