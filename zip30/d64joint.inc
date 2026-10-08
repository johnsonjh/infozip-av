/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#define D64_JOINT_MIN_RAW 2048UL
#define D64_JOINT_MIN_GAIN 8UL

#ifndef D64_JOINT_TRY_UNSPLIT
# define D64_JOINT_TRY_UNSPLIT 0
#endif /* ifndef D64_JOINT_TRY_UNSPLIT */

typedef struct d64_joint_candidate
{
  d64_token *tokens;
  unsigned long cuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long rawcuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long bits;
  unsigned nblocks;
} d64_joint_candidate;

static int
d64_joint_trial (d64_encoder *e, const unsigned char *raw, unsigned nblocks,
                 const unsigned long *source_cuts,
                 const unsigned long *rawcuts, unsigned long ntok,
                 d64_joint_candidate *out, int final)
{
  d64_encoder temp;
  unsigned long lf[D64_LIT_CODES], df[D64_DIST_CODES];
  unsigned long start_bytes, end_bytes, total;
  unsigned j;
  int rc;

  if (nblocks < 2U || nblocks > D64_SPLIT_MAX_BLOCKS)
    {
      return 0;
    }

  temp = *e;
  temp.bw.write_cb = d64_split_sink;
  temp.bw.opaque = NULL;
  total = 0UL;
  out->cuts[0] = 0UL;
  out->rawcuts[0] = 0UL;

  for (j = 0U; j < nblocks; ++j)
    {
      unsigned long len, count, parsed;
      d64_stats before;
      len = rawcuts[j + 1U] - rawcuts[j];
      count = source_cuts[j + 1U] - source_cuts[j];

      if (len < D64_JOINT_MIN_RAW || len > D64_BLOCK_TARGET || count == 0UL
          || total > D64_MAX_TOKENS - count)
        {
          return 0;
        }

      temp.tokens = out->tokens + total;
      memcpy (temp.tokens, e->tokens + source_cuts[j],
              (size_t)count * sizeof (d64_token));
      d64_split_freq (temp.tokens, count, lf, df);
      before = temp.stats;
      parsed
          = d64_optimize (&temp, e->hist + rawcuts[j],
                          e->hist + rawcuts[j + 1U], count, lf, df, &before);

      if (parsed == 0UL || parsed > D64_MAX_TOKENS - total)
        {
          return 0;
        }

      rc = d64_encode_block (&temp, raw + rawcuts[j], len, parsed, lf, df,
                             final && j + 1U == nblocks);
      if (rc != D64_OK)
        {
          return 0;
        }

      total += parsed;
      out->cuts[j + 1U] = total;
      out->rawcuts[j + 1U] = rawcuts[j + 1U];
    }

  if (out->rawcuts[nblocks] != rawcuts[nblocks]
      || source_cuts[nblocks] != ntok)
    {
      return 0;
    }

  start_bytes = e->bw.total + (unsigned long)e->bw.used;
  end_bytes = temp.bw.total + (unsigned long)temp.bw.used;
  out->bits = (end_bytes - start_bytes) * 8UL + (unsigned long)temp.bw.bitcnt;

  if (final && temp.bw.bitcnt != 0U)
    {
      out->bits += (unsigned long)(8U - temp.bw.bitcnt);
    }

  out->nblocks = nblocks;
  return 1;
}

static int
d64_joint_nearest (const d64_encoder *e, unsigned long ntok,
                   unsigned long rawlen, unsigned long target,
                   unsigned long *tok, unsigned long *offset)
{
  unsigned long i, p, bestdist;
  int found;

  p = 0UL;
  found = 0;
  bestdist = ~0UL;

  for (i = 0UL; i < ntok; ++i)
    {
      unsigned long dist;
      p += e->tokens[i].len != 0UL ? e->tokens[i].len : 1UL;

      if (p < D64_JOINT_MIN_RAW || rawlen - p < D64_JOINT_MIN_RAW)
        {
          continue;
        }

      dist = p >= target ? p - target : target - p;

      if (!found || dist < bestdist)
        {
          found = 1;
          bestdist = dist;
          *tok = i + 1UL;
          *offset = p;
        }

      if (p >= target)
        {
          break;
        }
    }

  return found;
}

static int
d64_joint_encode (d64_encoder *e, const unsigned char *raw,
                  unsigned long rawlen, unsigned long ntok, unsigned nblocks,
                  const unsigned long *cuts, const unsigned long *rawcuts,
                  unsigned long baseline_bits, const d64_stats *before,
                  int final, int *emitted)
{
  d64_joint_candidate trial, best;
  unsigned long attempt_cuts[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long attempt_raw[D64_SPLIT_MAX_BLOCKS + 1U];
  unsigned long tok, offset;
  unsigned tries, j;
  int rc;

  *emitted = 0;
  if ((nblocks == 1U && !D64_JOINT_TRY_UNSPLIT) || rawlen < 8192UL
      || rawlen > D64_BLOCK_TARGET || ntok < 4UL || baseline_bits == ~0UL)
    {
      return D64_OK;
    }

  trial.tokens
      = (d64_token *)malloc ((size_t)D64_MAX_TOKENS * sizeof (d64_token));
  best.tokens
      = (d64_token *)malloc ((size_t)D64_MAX_TOKENS * sizeof (d64_token));

  if (trial.tokens == NULL || best.tokens == NULL)
    {
      free (trial.tokens);
      free (best.tokens);
      return D64_OK;
    }

  best.bits = baseline_bits;
  best.nblocks = 0U;

  for (tries = 0U; tries < (nblocks > 1U ? 1U : 2U); ++tries)
    {
      unsigned trial_blocks;
      if (nblocks > 1U)
        {
          trial_blocks = nblocks;
          memcpy (attempt_cuts, cuts,
                  (size_t)(nblocks + 1U) * sizeof (cuts[0]));
          memcpy (attempt_raw, rawcuts,
                  (size_t)(nblocks + 1U) * sizeof (rawcuts[0]));
        }
      else
        {
          unsigned long target;
          target = tries == 0U ? rawlen / 2UL : rawlen / 3UL;

          if (!d64_joint_nearest (e, ntok, rawlen, target, &tok, &offset))
            {
              continue;
            }

          attempt_cuts[0] = attempt_raw[0] = 0UL;
          attempt_cuts[1] = tok;
          attempt_raw[1] = offset;
          attempt_cuts[2] = ntok;
          attempt_raw[2] = rawlen;
          trial_blocks = 2U;
        }

      if (d64_joint_trial (e, raw, trial_blocks, attempt_cuts, attempt_raw,
                           ntok, &trial, final)
          && trial.bits < best.bits
          && best.bits - trial.bits >= D64_JOINT_MIN_GAIN)
        {
          d64_token *swap;
          swap = best.tokens;
          best.tokens = trial.tokens;
          trial.tokens = swap;
          best.bits = trial.bits;
          best.nblocks = trial.nblocks;
          memcpy (best.cuts, trial.cuts, sizeof (best.cuts));
          memcpy (best.rawcuts, trial.rawcuts, sizeof (best.rawcuts));
        }
    }

  if (best.nblocks != 0U)
    {
      d64_token *original;
      unsigned long lf[D64_LIT_CODES], df[D64_DIST_CODES];
      original = e->tokens;
      e->stats.matches = before->matches;
      e->stats.max_match = before->max_match;
      e->stats.max_distance = before->max_distance;
      rc = D64_OK;
      for (j = 0U; j < best.nblocks; ++j)
        {
          unsigned long count, length;
          count = best.cuts[j + 1U] - best.cuts[j];
          length = best.rawcuts[j + 1U] - best.rawcuts[j];
          e->tokens = best.tokens + best.cuts[j];
          d64_opt_recount (e, count);
          d64_split_freq (e->tokens, count, lf, df);
          rc = d64_encode_block (e, raw + best.rawcuts[j], length, count, lf,
                                 df, final && j + 1U == best.nblocks);

          if (rc != D64_OK)
            {
              break;
            }
        }

      e->tokens = original;
      *emitted = 1;
    }
  else
    {
      rc = D64_OK;
    }

  free (trial.tokens);
  free (best.tokens);

  return rc;
}
