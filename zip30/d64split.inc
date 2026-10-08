/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#define D64_SPLIT_MAX_BLOCKS 3U
#define D64_SPLIT_CANDIDATES 16U
#define D64_SPLIT_MIN_RAW 1024UL

static int
d64_split_sink (void *opaque, const unsigned char *buf, unsigned size)
{
  (void)opaque;
  (void)buf;
  (void)size;
  return 0;
}

static void
d64_split_freq (const d64_token *tok, unsigned long ntok,
                unsigned long lf[D64_LIT_CODES],
                unsigned long df[D64_DIST_CODES])
{
  unsigned long i;
  unsigned ex, bits, code;

  memset (lf, 0, D64_LIT_CODES * sizeof (lf[0]));
  memset (df, 0, D64_DIST_CODES * sizeof (df[0]));

  for (i = 0UL; i < ntok; ++i)
    {
      if (tok[i].len == 0UL)
        {
          ++lf[tok[i].lit];
        }
      else
        {
          code = d64_length_code (tok[i].len, &ex, &bits);
          ++lf[code];
          code = d64_distance_code (tok[i].dist, &ex, &bits);
          ++df[code];
        }
    }

  ++lf[256U];
}

static unsigned long
d64_split_trial (const d64_encoder *actual, const unsigned char *raw,
                 unsigned nblocks, const unsigned long *cuts,
                 const unsigned long *rawcuts, int final)
{
  d64_encoder temp;
  unsigned long lf[D64_LIT_CODES], df[D64_DIST_CODES];
  unsigned j;
  unsigned long bits, start_bytes, end_bytes;
  int rc;

  temp = *actual;
  temp.bw.write_cb = d64_split_sink;
  temp.bw.opaque = NULL;

  for (j = 0U; j < nblocks; ++j)
    {
      unsigned long count;
      unsigned long length;

      count = cuts[j + 1U] - cuts[j];
      length = rawcuts[j + 1U] - rawcuts[j];

      if (count == 0UL || length == 0UL)
        {
          return ~0UL;
        }

      d64_split_freq (actual->tokens + cuts[j], count, lf, df);
      temp.tokens = actual->tokens + cuts[j];
      rc = d64_encode_block (&temp, raw + rawcuts[j], length, count, lf, df,
                             final && j + 1U == nblocks);
      if (rc != D64_OK)
        {
          return ~0UL;
        }
    }

  start_bytes = actual->bw.total + (unsigned long)actual->bw.used;
  end_bytes = temp.bw.total + (unsigned long)temp.bw.used;
  bits = (end_bytes - start_bytes) * 8UL;
  bits += (unsigned long)temp.bw.bitcnt;

  if (final && temp.bw.bitcnt != 0U)
    {
      bits += (unsigned long)(8U - temp.bw.bitcnt);
    }

  return bits;
}

static unsigned long
d64_split_try (const d64_encoder *e, const unsigned char *raw,
               unsigned nblocks, const unsigned long *cuts,
               const unsigned long *rawcuts, unsigned interval,
               unsigned long tok, unsigned long offset, int final)
{
  unsigned long trial_cuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long trial_raw[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned j;

  for (j = 0U; j <= interval; ++j)
    {
      trial_cuts[j] = cuts[j];
      trial_raw[j] = rawcuts[j];
    }

  trial_cuts[interval + 1U] = tok;
  trial_raw[interval + 1U] = offset;

  for (j = interval + 1U; j <= nblocks; ++j)
    {
      trial_cuts[j + 1U] = cuts[j];
      trial_raw[j + 1U] = rawcuts[j];
    }

  return d64_split_trial (e, raw, nblocks + 1U, trial_cuts, trial_raw, final);
}

#include "d64joint.inc"

static int
d64_split_encode (d64_encoder *e, const unsigned char *raw,
                  unsigned long rawlen, unsigned long ntok,
                  const unsigned long *lf, const unsigned long *df, int final,
                  const d64_stats *before)
{
  unsigned long cuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long rawcuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long winner_cuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long winner_raw[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long best_bits, candidate_bits;
  unsigned long split_tok, split_raw;
  unsigned nblocks, seg, s, winner_seg, j;
  unsigned long i, target, position, segsize;
  unsigned long lf1[D64_LIT_CODES], df1[D64_DIST_CODES];
  d64_token *original_tokens;
  int rc, joint_done;

  if (rawlen < 8192UL || ntok < 4UL)
    {
      return d64_encode_block (e, raw, rawlen, ntok, lf, df, final);
    }

  cuts[0] = rawcuts[0] = 0UL;
  cuts[1] = ntok;
  rawcuts[1] = rawlen;
  nblocks = 1U;
  best_bits = d64_split_trial (e, raw, nblocks, cuts, rawcuts, final);

  if (best_bits == ~0UL)
    {
      return d64_encode_block (e, raw, rawlen, ntok, lf, df, final);
    }

  while (nblocks < D64_SPLIT_MAX_BLOCKS)
    {
      winner_seg = D64_SPLIT_MAX_BLOCKS;
      split_tok = split_raw = 0UL;

      for (seg = 0U; seg < nblocks; ++seg)
        {
          segsize = rawcuts[seg + 1U] - rawcuts[seg];

          if (segsize < 2UL * D64_SPLIT_MIN_RAW)
            {
              continue;
            }

          position = rawcuts[seg];
          i = cuts[seg];

          for (s = 1U; s < D64_SPLIT_CANDIDATES; ++s)
            {
              target = rawcuts[seg]
                       + (segsize / D64_SPLIT_CANDIDATES) * (unsigned long)s;

              while (i < cuts[seg + 1U] && position < target)
                {
                  position += e->tokens[i].len != 0UL ? e->tokens[i].len : 1UL;
                  ++i;
                }

              if (i == cuts[seg] || i == cuts[seg + 1U]
                  || position - rawcuts[seg] < D64_SPLIT_MIN_RAW
                  || rawcuts[seg + 1U] - position < D64_SPLIT_MIN_RAW)
                {
                  continue;
                }

              candidate_bits = d64_split_try (e, raw, nblocks, cuts, rawcuts,
                                              seg, i, position, final);
              if (candidate_bits != ~0UL && candidate_bits < best_bits
                  && best_bits - candidate_bits >= 8UL)
                {
                  best_bits = candidate_bits;
                  winner_seg = seg;
                  split_tok = i;
                  split_raw = position;
                }
            }
        }

      if (winner_seg == D64_SPLIT_MAX_BLOCKS)
        {
          break;
        }

      for (j = 0U; j <= winner_seg; ++j)
        {
          winner_cuts[j] = cuts[j];
          winner_raw[j] = rawcuts[j];
        }

      winner_cuts[winner_seg + 1U] = split_tok;
      winner_raw[winner_seg + 1U] = split_raw;

      for (j = winner_seg + 1U; j <= nblocks; ++j)
        {
          winner_cuts[j + 1U] = cuts[j];
          winner_raw[j + 1U] = rawcuts[j];
        }

      ++nblocks;
      memcpy (cuts, winner_cuts, (size_t)(nblocks + 1U) * sizeof (cuts[0]));
      memcpy (rawcuts, winner_raw,
              (size_t)(nblocks + 1U) * sizeof (rawcuts[0]));
    }

  rc = d64_joint_encode (e, raw, rawlen, ntok, nblocks, cuts, rawcuts,
                         best_bits, before, final, &joint_done);
  if (rc != D64_OK || joint_done)
    {
      return rc;
    }

  if (nblocks == 1U)
    {
      return d64_encode_block (e, raw, rawlen, ntok, lf, df, final);
    }

  original_tokens = e->tokens;
  rc = D64_OK;

  for (j = 0U; j < nblocks; ++j)
    {
      unsigned long count, length;
      count = cuts[j + 1U] - cuts[j];
      length = rawcuts[j + 1U] - rawcuts[j];
      d64_split_freq (original_tokens + cuts[j], count, lf1, df1);
      e->tokens = original_tokens + cuts[j];
      rc = d64_encode_block (e, raw + rawcuts[j], length, count, lf1, df1,
                             final && j + 1U == nblocks);
      if (rc != D64_OK)
        {
          break;
        }
    }

  e->tokens = original_tokens;

  return rc;
}
