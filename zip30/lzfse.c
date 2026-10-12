/* Amalgamated and somewhat heavily modified for the Xtro-ZIP fork.
 *
 * Upstream: https://github.com/lzfse/lzfse
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Full original license follows:
 * Copyright (c) 2015-2016, Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3.  Neither the name of the copyright holder(s) nor the names of any
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "lzfse.h"

/* ===== original lzfse_fse.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Initialize encoder table T[NSYMBOLS]. */
/* NSTATES = sum FREQ[i] is the number of states (a power of 2) */
/* NSYMBOLS is the number of symbols. */
/* FREQ[NSYMBOLS] is a normalized histogram of symbol frequencies, with FREQ[i]
 */
/* >= 0. */
/* Some symbols may have a 0 frequency.  In that case, they should not be */
/* present in the data. */
void
fse_init_encoder_table (int nstates, int nsymbols, const izl_u16 *freq,
                        fse_encoder_entry *t)
{
  int offset = 0; /* current offset */
  int n_clz = __builtin_clz (nstates);
  {
    int i;
    for (i = 0; i < nsymbols; i++)
      {
        int f = (int)freq[i];
        if (f == 0)
          continue; /* skip this symbol, no occurrences */
        {
          int k = __builtin_clz (f)
                  - n_clz; /* shift needed to ensure N <= (F<<K) < 2*N */
          t[i].s0 = (izl_s16)((f << k) - nstates);
          t[i].k = (izl_s16)k;
          t[i].delta0 = (izl_s16)(offset - f + (nstates >> k));
          t[i].delta1
              = (izl_s16)(offset - f
                          + (k == 0 ? 2 * nstates : (nstates >> (k - 1))));
          offset += f;
        }
      }
  }
}

/* Initialize decoder table T[NSTATES]. */
/* NSTATES = sum FREQ[i] is the number of states (a power of 2) */
/* NSYMBOLS is the number of symbols. */
/* FREQ[NSYMBOLS] is a normalized histogram of symbol frequencies, with FREQ[i]
 */
/* >= 0. */
/* Some symbols may have a 0 frequency.  In that case, they should not be */
/* present in the data. */
int
fse_init_decoder_table (int nstates, int nsymbols, const izl_u16 *freq,
                        izl_s32 *t)
{
  assert (nsymbols <= 256);
  assert (fse_check_freq (freq, nsymbols, nstates) == 0);
  {
    int n_clz = __builtin_clz (nstates);
    int sum_of_freq = 0;
    {
      int i;
      for (i = 0; i < nsymbols; i++)
        {
          int f = (int)freq[i];
          if (f == 0)
            continue; /* skip this symbol, no occurrences */

          sum_of_freq += f;

          if (sum_of_freq > nstates)
            {
              return -1;
            }

          {
            int k = __builtin_clz (f)
                    - n_clz; /* shift needed to ensure N <= (F<<K) < 2*N */
            int j0 = ((2 * nstates) >> k) - f;

            /* Initialize all states S reached by this symbol: OFFSET <= S <
             * OFFSET + F */
            {
              int j;
              for (j = 0; j < f; j++)
                {
                  fse_decoder_entry e;

                  e.symbol = (izl_u8)i;
                  if (j < j0)
                    {
                      e.k = (izl_s8)k;
                      e.delta = (izl_s16)(((f + j) << k) - nstates);
                    }
                  else
                    {
                      e.k = (izl_s8)(k - 1);
                      e.delta = (izl_s16)(k == 0 ? 0 : ((j - j0) << (k - 1)));
                    }

                  memcpy (t, &e, sizeof (e));
                  t++;
                }
            }
          }
        }
    }

    return 0; /* OK */
  }
}

/* Initialize value decoder table T[NSTATES]. */
/* NSTATES = sum FREQ[i] is the number of states (a power of 2) */
/* NSYMBOLS is the number of symbols. */
/* FREQ[NSYMBOLS] is a normalized histogram of symbol frequencies, with FREQ[i]
 */
/* >= 0. */
/* SYMBOL_VBITS[NSYMBOLS] and SYMBOLS_VBASE[NSYMBOLS] are the number of value
 */
/* bits to read and the base value for each symbol. */
/* Some symbols may have a 0 frequency.  In that case, they should not be */
/* present in the data. */
void
fse_init_value_decoder_table (int nstates, int nsymbols, const izl_u16 *freq,
                              const izl_u8 *symbol_vbits,
                              const izl_s32 *symbol_vbase,
                              fse_value_decoder_entry *t)
{
  assert (nsymbols <= 256);
  assert (fse_check_freq (freq, nsymbols, nstates) == 0);

  {
    int n_clz = __builtin_clz (nstates);
    {
      int i;
      for (i = 0; i < nsymbols; i++)
        {
          int f = (int)freq[i];
          if (f == 0)
            continue; /* skip this symbol, no occurrences */

          {
            int k = __builtin_clz (f)
                    - n_clz; /* shift needed to ensure N <= (F<<K) < 2*N */
            int j0 = ((2 * nstates) >> k) - f;

            fse_value_decoder_entry ei = { 0 };
            ei.value_bits = symbol_vbits[i];
            ei.vbase = symbol_vbase[i];

            /* Initialize all states S reached by this symbol: OFFSET <= S <
             * OFFSET + F */
            {
              int j;
              for (j = 0; j < f; j++)
                {
                  fse_value_decoder_entry e = ei;

                  if (j < j0)
                    {
                      e.total_bits = (izl_u8)k + e.value_bits;
                      e.delta = (izl_s16)(((f + j) << k) - nstates);
                    }
                  else
                    {
                      e.total_bits = (izl_u8)(k - 1) + e.value_bits;
                      e.delta = (izl_s16)(k == 0 ? 0 : ((j - j0) << (k - 1)));
                    }

                  memcpy (t, &e, 8);
                  t++;
                }
            }
          }
        }
    }
  }
}

/* Remove states from symbols until the correct number of states is used. */
static void
fse_adjust_freqs (izl_u16 *freq, int overrun, int nsymbols)
{
  {
    int shift;
    for (shift = 3; overrun != 0; shift--)
      {
        {
          int sym;
          for (sym = 0; sym < nsymbols; sym++)
            {
              if (freq[sym] > 1)
                {
                  int n = (freq[sym] - 1) >> shift;
                  if (n > overrun)
                    n = overrun;
                  freq[sym] -= n;
                  overrun -= n;
                  if (overrun == 0)
                    break;
                }
            }
        }
      }
  }
}

/* Normalize a table T[NSYMBOLS] of occurrences to FREQ[NSYMBOLS]. */
void
fse_normalize_freq (int nstates, int nsymbols, const izl_u32 *t, izl_u16 *freq)
{
  izl_u32 s_count = 0;
  int remaining = nstates; /* must be signed; this may become < 0 */
  int max_freq = 0;
  int max_freq_sym = 0;
  int shift = __builtin_clz (nstates) - 1;
  izl_u32 highprec_step;

  /* Compute the total number of symbol occurrences */
  {
    int i;
    for (i = 0; i < nsymbols; i++)
      s_count += t[i];
  }

  if (s_count == 0)
    highprec_step = 0; /* no symbols used */
  else
    highprec_step = ((izl_u32)1 << 31) / s_count;

  {
    int i;
    for (i = 0; i < nsymbols; i++)
      {

        /* Rescale the occurrence count to get the normalized frequency. */
        /* Round up if the fractional part is >= 0.5; otherwise round down. */
        /* For efficiency, we do this calculation using integer arithmetic. */
        int f = (((t[i] * highprec_step) >> shift) + 1) >> 1;

        /* If a symbol was used, it must be given a nonzero normalized
         * frequency. */
        if (f == 0 && t[i] != 0)
          f = 1;

        freq[i] = f;
        remaining -= f;

        /* Remember the maximum frequency and which symbol had it. */
        if (f > max_freq)
          {
            max_freq = f;
            max_freq_sym = i;
          }
      }
  }

  /* If there remain states to be assigned, then just assign them to the most
   */
  /* frequent symbol.  Alternatively, if we assigned more states than were */
  /* actually available, then either remove states from the most frequent
   * symbol */
  /* (for minor overruns) or use the slower adjustment algorithm (for major */
  /* overruns). */
  if (-remaining < (max_freq >> 2))
    {
      freq[max_freq_sym] += remaining;
    }
  else
    {
      fse_adjust_freqs (freq, -remaining, nsymbols);
    }
}

/* ===== original lzvn_encode_base.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZVN low-level encoder */

#if defined(_MSC_VER) && !defined(__clang__)
# define 
#endif

/* =============================================================== */
/* Coarse/fine copy, non overlapping buffers */

/*! @abstract Copy at least \p nbytes bytes from \p src to \p dst, by blocks
 * of 8 bytes (may go beyond range). No overlap.
 * @return \p dst + \p nbytes. */
static unsigned char *
lzvn_copy64 (unsigned char *dst, const unsigned char *src, size_t nbytes)
{
  {
    size_t i;
    for (i = 0; i < nbytes; i += 8)
      store8 (dst + i, load8 (src + i));
  }
  return dst + nbytes;
}

/*! @abstract Copy exactly \p nbytes bytes from \p src to \p dst (respects
 * range). No overlap.
 * @return \p dst + \p nbytes. */
static unsigned char *
lzvn_copy8 (unsigned char *dst, const unsigned char *src, size_t nbytes)
{
  {
    size_t i;
    for (i = 0; i < nbytes; i++)
      dst[i] = src[i];
  }
  return dst + nbytes;
}

/*! @abstract Emit (L,0,0) instructions (final literal).
 * We read at most \p L bytes from \p p.
 * @param p input stream
 * @param q1 the first byte after the output buffer.
 * @return pointer to the next output, <= \p q1.
 * @return \p q1 if output is full. In that case, output will be partially
 * invalid.
 */
static unsigned char *
emit_literal (const unsigned char *p, unsigned char *q, unsigned char *q1,
              size_t L)
{
  size_t x;
  while (L > 15)
    {
      x = L < 271 ? L : 271;
      if (q + x + 10 >= q1)
        goto OUT_FULL;
      store2 (q, 0xE0 + ((x - 16) << 8));
      q += 2;
      L -= x;
      q = lzvn_copy8 (q, p, x);
      p += x;
    }
  if (L > 0)
    {
      if (q + L + 10 >= q1)
        goto OUT_FULL;
      *q++ = 0xE0 + L; /* 1110LLLL */
      q = lzvn_copy8 (q, p, L);
    }
  return q;

OUT_FULL:
  return q1;
}

/*! @abstract Emit (L,M,D) instructions. M>=3.
 * @param p input stream pointing to the beginning of the literal. We read at
 * most \p L+4 bytes from \p p.
 * @param q1 the first byte after the output buffer.
 * @return pointer to the next output, <= \p q1.
 * @return \p q1 if output is full. In that case, output will be partially
 * invalid.
 */
static unsigned char *
emit (const unsigned char *p, unsigned char *q, unsigned char *q1, size_t L,
      size_t M, size_t D, size_t D_prev)
{
  size_t x;
  while (L > 15)
    {
      x = L < 271 ? L : 271;
      if (q + x + 10 >= q1)
        goto OUT_FULL;
      store2 (q, 0xE0 + ((x - 16) << 8));
      q += 2;
      L -= x;
      q = lzvn_copy64 (q, p, x);
      p += x;
    }
  if (L > 3)
    {
      if (q + L + 10 >= q1)
        goto OUT_FULL;
      *q++ = 0xE0 + L; /* 1110LLLL */
      q = lzvn_copy64 (q, p, L);
      p += L;
      L = 0;
    }
  x = M <= 10 - 2 * L ? M : 10 - 2 * L; /* x = min(10-2*L,M) */
  M -= x;
  x -= 3; /* M = (x+3) + M'    max value for x is 7-2*L */

  /* Here L<4 literals remaining, we read them here */
  {
    izl_u32 literal = load4 (p);
    /* P is not accessed after this point */

    /* Relaxed capacity test covering all cases */
    if (q + 8 >= q1)
      goto OUT_FULL;

    if (D == D_prev)
      {
        if (L == 0)
          {
            *q++ = 0xF0 + (x + 3); /* XM! */
          }
        else
          {
            *q++ = (L << 6) + (x << 3) + 6; /*  LLxxx110 */
          }
        store4 (q, literal);
        q += L;
      }
    else if (D < 2048 - 2 * 256)
      {
        /* Short dist    D>>8 in 0..5 */
        *q++ = (D >> 8) + (L << 6) + (x << 3); /* LLxxxDDD */
        *q++ = D & 0xFF;
        store4 (q, literal);
        q += L;
      }
    else if (D >= (1 << 14) || M == 0 || (x + 3) + M > 34)
      {
        /* Long dist */
        *q++ = (L << 6) + (x << 3) + 7;
        store2 (q, D);
        q += 2;
        store4 (q, literal);
        q += L;
      }
    else
      {
        /* Medium distance */
        x += M;
        M = 0;
        *q++ = 0xA0 + (x >> 2) + (L << 3);
        store2 (q, D << 2 | (x & 3));
        q += 2;
        store4 (q, literal);
        q += L;
      }

    /* Issue remaining match */
    while (M > 15)
      {
        if (q + 2 >= q1)
          goto OUT_FULL;
        x = M < 271 ? M : 271;
        store2 (q, 0xf0 + ((x - 16) << 8));
        q += 2;
        M -= x;
      }
    if (M > 0)
      {
        if (q + 1 >= q1)
          goto OUT_FULL;
        *q++ = 0xF0 + M; /* M = 0..15 */
      }

    return q;

  OUT_FULL:
    return q1;
  }
}

/* =============================================================== */
/* Conversions */

/*! @abstract Return 32-bit value to store for offset x. */
static izl_s32
offset_to_s32 (lzvn_offset x)
{
  return (izl_s32)x;
}

/*! @abstract Get offset from 32-bit stored value x. */
static lzvn_offset
offset_from_s32 (izl_s32 x)
{
  return (lzvn_offset)x;
}

/* =============================================================== */
/* Hash and Matching */

/*! @abstract Get hash in range \c [0,LZVN_ENCODE_HASH_VALUES-1] from 3 bytes
 * in i. */
static izl_u32
hash3i (izl_u32 i)
{
  i &= 0xffffff; /* truncate to 24-bit input (slightly increases compression
                    ratio) */
  {
    izl_u32 h = (i * (1 + (1 << 6) + (1 << 12))) >> 12;
    return h & (LZVN_ENCODE_HASH_VALUES - 1);
  }
}

/*! @abstract Return the number [0, 4] of zero bytes in \p x, starting from the
 * least significant byte. */
static lzvn_offset
trailing_zero_bytes (izl_u32 x)
{
  return (x == 0) ? 4 : (__builtin_ctzl (x) >> 3);
}

/*! @abstract Return the number [0, 4] of matching chars between values at
 * \p src+i and \p src+j, starting from the least significant byte.
 * Assumes we can read 4 chars from each position. */
static lzvn_offset
nmatch4 (const unsigned char *src, lzvn_offset i, lzvn_offset j)
{
  izl_u32 vi = load4 (src + i);
  izl_u32 vj = load4 (src + j);
  return trailing_zero_bytes (vi ^ vj);
}

/*! @abstract Check if l_begin, m_begin, m0_begin (m0_begin < m_begin) can be
 * expanded to a match of length at least 3.
 * @param m_begin new string to match.
 * @param m0_begin candidate old string.
 * @param src source buffer, with valid indices src_begin <= i < src_end.
 * (src_begin may be <0)
 * @return If a match can be found, return 1 and set all \p match fields,
 * otherwise return 0.
 * @note \p *match should be 0 before the call. */
static int
lzvn_find_match (const unsigned char *src, lzvn_offset src_begin,
                 lzvn_offset src_end, lzvn_offset l_begin,
                 lzvn_offset m0_begin, lzvn_offset m_begin,
                 lzvn_match_info *match)
{
  lzvn_offset n = nmatch4 (src, m_begin, m0_begin);
  if (n < 3)
    return 0; /* no match */

  {
    lzvn_offset D = m_begin - m0_begin; /* actual distance */
    if (D <= 0 || D > LZVN_ENCODE_MAX_DISTANCE)
      return 0; /* distance out of range */

    /* Expand forward */
    {
      lzvn_offset m_end = m_begin + n;
      while (n == 4 && m_end + 4 < src_end)
        {
          n = nmatch4 (src, m_end, m_end - D);
          m_end += n;
        }

      /* Expand backwards over literal */
      while (m0_begin > src_begin && m_begin > l_begin
             && src[m_begin - 1] == src[m0_begin - 1])
        {
          m0_begin--;
          m_begin--;
        }

      /* OK, we keep it, update MATCH */
      {
        lzvn_offset M = m_end - m_begin; /* match length */
        match->m_begin = m_begin;
        match->m_end = m_end;
        match->K = M - ((D < 0x600) ? 2 : 3);
        match->M = M;
        match->D = D;

        return 1; /* OK */
      }
    }
  }
}

/*! @abstract Same as lzvn_find_match, but we already know that N bytes do
 *  match (N<=4). */
static int
lzvn_find_matchN (const unsigned char *src, lzvn_offset src_begin,
                  lzvn_offset src_end, lzvn_offset l_begin,
                  lzvn_offset m0_begin, lzvn_offset m_begin, lzvn_offset n,
                  lzvn_match_info *match)
{
  /* We can skip the first comparison on 4 bytes */
  if (n < 3)
    return 0; /* no match */

  {
    lzvn_offset D = m_begin - m0_begin; /* actual distance */
    if (D <= 0 || D > LZVN_ENCODE_MAX_DISTANCE)
      return 0; /* distance out of range */

    /* Expand forward */
    {
      lzvn_offset m_end = m_begin + n;
      while (n == 4 && m_end + 4 < src_end)
        {
          n = nmatch4 (src, m_end, m_end - D);
          m_end += n;
        }

      /* Expand backwards over literal */
      while (m0_begin > src_begin && m_begin > l_begin
             && src[m_begin - 1] == src[m0_begin - 1])
        {
          m0_begin--;
          m_begin--;
        }

      /* OK, we keep it, update MATCH */
      {
        lzvn_offset M = m_end - m_begin; /* match length */
        match->m_begin = m_begin;
        match->m_end = m_end;
        match->K = M - ((D < 0x600) ? 2 : 3);
        match->M = M;
        match->D = D;

        return 1; /* OK */
      }
    }
  }
}

/* =============================================================== */
/* Encoder Backend */

/*! @abstract Emit a match and update state.
 * @return number of bytes written to \p dst. May be 0 if there is no more
 * space in \p dst to emit the match. */
static lzvn_offset
lzvn_emit_match (lzvn_encoder_state *state, lzvn_match_info match)
{
  size_t L = (size_t)(match.m_begin - state->src_literal); /* literal count */
  size_t M = (size_t)match.M;                              /* match length */
  size_t D = (size_t)match.D;                              /* match distance */
  size_t D_prev
      = (size_t)state->d_prev; /* previously emitted match distance */
  unsigned char *dst = emit (state->src + state->src_literal, state->dst,
                             state->dst_end, L, M, D, D_prev);
  /* Check if DST is full */
  if (dst >= state->dst_end)
    {
      return 0; /* FULL */
    }

  /* Update state */
  {
    lzvn_offset dst_used = dst - state->dst;
    state->d_prev = match.D;
    state->dst = dst;
    state->src_literal = match.m_end;
    return dst_used;
  }
}

/*! @abstract Emit a n-bytes literal and update state.
 * @return number of bytes written to \p dst. May be 0 if there is no more
 * space in \p dst to emit the literal. */
static lzvn_offset
lzvn_emit_literal (lzvn_encoder_state *state, lzvn_offset n)
{
  size_t L = (size_t)n;
  unsigned char *dst = emit_literal (state->src + state->src_literal,
                                     state->dst, state->dst_end, L);
  /* Check if DST is full */
  if (dst >= state->dst_end)
    return 0; /* FULL */

  /* Update state */
  {
    lzvn_offset dst_used = dst - state->dst;
    state->dst = dst;
    state->src_literal += n;
    return dst_used;
  }
}

/*! @abstract Emit end-of-stream and update state.
 * @return number of bytes written to \p dst. May be 0 if there is no more
 * space in \p dst to emit the instruction. */
static lzvn_offset
lzvn_emit_end_of_stream (lzvn_encoder_state *state)
{
  /* Do we have 8 byte in dst? */
  if (state->dst_end < state->dst + 8)
    return 0; /* FULL */

  /* Insert end marker and update state */
  store8 (state->dst, 0x06); /* end-of-stream command */
  state->dst += 8;
  return 8; /* dst_used */
}

/* =============================================================== */
/* Encoder Functions */

/*! @abstract Initialize encoder table in \p state, uses current I/O
 * parameters. */
static void
lzvn_init_table (lzvn_encoder_state *state)
{
  lzvn_offset index = -LZVN_ENCODE_MAX_DISTANCE; /* max match distance */
  if (index < state->src_begin)
    index = state->src_begin;
  {
    izl_u32 value = load4 (state->src + index);

    lzvn_encode_entry_type e;
    {
      int i;
      for (i = 0; i < 4; i++)
        {
          e.indices[i] = offset_to_s32 (index);
          e.values[i] = value;
        }
    }
    {
      int u;
      for (u = 0; u < LZVN_ENCODE_HASH_VALUES; u++)
        state->table[u] = e;
    } /* fill entire table */
  }
}

void
lzvn_encode (lzvn_encoder_state *state)
{
  const lzvn_match_info NO_MATCH = { 0 };

  for (; state->src_current < state->src_current_end; state->src_current++)
    {
      /* Get 4 bytes at src_current */
      izl_u32 vi = load4 (state->src + state->src_current);

      /* Compute new hash H at position I, and push value into position table
       */
      int h = hash3i (vi); /* index of first entry */

      /* Read table entries for H */
      lzvn_encode_entry_type e = state->table[h];

      /* Update entry with index=current and value=vi */
      lzvn_encode_entry_type
          updated_e; /* rotate values, so we will replace the oldest */
      updated_e.indices[0] = offset_to_s32 (state->src_current);
      updated_e.indices[1] = e.indices[0];
      updated_e.indices[2] = e.indices[1];
      updated_e.indices[3] = e.indices[2];
      updated_e.values[0] = vi;
      updated_e.values[1] = e.values[0];
      updated_e.values[2] = e.values[1];
      updated_e.values[3] = e.values[2];

      /* Do not check matches if still in previously emitted match */
      if (state->src_current < state->src_literal)
        goto after_emit;

/* Update best with candidate if better */
#define UPDATE(best, candidate)                                               \
  do                                                                          \
    {                                                                         \
      if (candidate.K > best.K                                                \
          || ((candidate.K == best.K) && (candidate.m_end > best.m_end + 1))) \
        {                                                                     \
          best = candidate;                                                   \
        }                                                                     \
    }                                                                         \
  while (0)
/* Check candidate. Keep if better. */
#define CHECK_CANDIDATE(ik, nk)                                               \
  do                                                                          \
    {                                                                         \
      lzvn_match_info m1;                                                     \
      if (lzvn_find_matchN (state->src, state->src_begin, state->src_end,     \
                            state->src_literal, ik, state->src_current, nk,   \
                            &m1))                                             \
        {                                                                     \
          UPDATE (incoming, m1);                                              \
        }                                                                     \
    }                                                                         \
  while (0)
/* Emit match M. Return if we don't have enough space in the destination buffer
 */
#define EMIT_MATCH(m)                                                         \
  do                                                                          \
    {                                                                         \
      if (lzvn_emit_match (state, m) == 0)                                    \
        return;                                                               \
    }                                                                         \
  while (0)
/* Emit literal of length L. Return if we don't have enough space in the */
/* destination buffer */
#define EMIT_LITERAL(l)                                                       \
  do                                                                          \
    {                                                                         \
      if (lzvn_emit_literal (state, l) == 0)                                  \
        return;                                                               \
    }                                                                         \
  while (0)

      {
        lzvn_match_info incoming = NO_MATCH;

        /* Check candidates in order (closest first) */
        izl_u32 diffs[4];
        {
          int k;
          for (k = 0; k < 4; k++)
            diffs[k] = e.values[k] ^ vi;
        } /* XOR, 0 if equal */
        {
          lzvn_offset ik; /* index */
          lzvn_offset nk; /* match byte count */

          /* The values stored in e.xyzw are 32-bit signed indices, extended to
           * signed */
          /* type lzvn_offset */
          ik = offset_from_s32 (e.indices[0]);
          nk = trailing_zero_bytes (diffs[0]);
          CHECK_CANDIDATE (ik, nk);
          ik = offset_from_s32 (e.indices[1]);
          nk = trailing_zero_bytes (diffs[1]);
          CHECK_CANDIDATE (ik, nk);
          ik = offset_from_s32 (e.indices[2]);
          nk = trailing_zero_bytes (diffs[2]);
          CHECK_CANDIDATE (ik, nk);
          ik = offset_from_s32 (e.indices[3]);
          nk = trailing_zero_bytes (diffs[3]);
          CHECK_CANDIDATE (ik, nk);

          /* Check candidate at previous distance */
          if (state->d_prev != 0)
            {
              lzvn_match_info m1;
              if (lzvn_find_match (state->src, state->src_begin,
                                   state->src_end, state->src_literal,
                                   state->src_current - state->d_prev,
                                   state->src_current, &m1))
                {
                  m1.K = m1.M - 1; /* fix K for D_prev */
                  UPDATE (incoming, m1);
                }
            }

          /* Here we have the best candidate in incoming, may be NO_MATCH */

          /* If no incoming match, and literal backlog becomes too high, emit
           * pending */
          /* match, or literals if there is no pending match */
          if (incoming.M == 0)
            {
              if (state->src_current - state->src_literal
                  >= LZVN_ENCODE_MAX_LITERAL_BACKLOG) /* at this point, we
                                                         always have */
                                                      /* current >= literal */
                {
                  if (state->pending.M != 0)
                    {
                      EMIT_MATCH (state->pending);
                      state->pending = NO_MATCH;
                    }
                  else
                    {
                      EMIT_LITERAL (271); /* emit long literal (271 is the
                                             longest literal size we allow) */
                    }
                }
              goto after_emit;
            }

          if (state->pending.M == 0)
            {
              /* NOTE. Here, we can also emit incoming right away. It will make
               * the */
              /* encoder 1.5x faster, at a cost of ~10% lower compression
               * ratio: */
              /* EMIT_MATCH(incoming); */
              /* state->pending = NO_MATCH; */

              /* No pending match, emit nothing, keep incoming */
              state->pending = incoming;
            }
          else
            {
              /* Here we have both incoming and pending */
              if (state->pending.m_end <= incoming.m_begin)
                {
                  /* No overlap: emit pending, keep incoming */
                  EMIT_MATCH (state->pending);
                  state->pending = incoming;
                }
              else
                {
                  /* If pending is better, emit pending and discard incoming.
                   */
                  /* Otherwise, emit incoming and discard pending. */
                  if (incoming.K > state->pending.K)
                    state->pending = incoming;
                  EMIT_MATCH (state->pending);
                  state->pending = NO_MATCH;
                }
            }

        after_emit:

          /* We commit state changes only after we tried to emit instructions,
           * so we */
          /* can restart in the same state in case dst was full and we quit the
           * loop. */
          state->table[h] = updated_e;
        }
      }
    } /* i loop */

  /* Do not emit pending match here. We do it only at the end of stream. */
}

/* =============================================================== */
/* API entry points */

size_t
lzvn_encode_scratch_size (void)
{
  return LZVN_ENCODE_WORK_SIZE;
}

static size_t
lzvn_encode_partial (void *dst, size_t dst_size, const void *src,
                     size_t src_size, size_t *src_used, void *work)
{
  /* Min size checks to avoid accessing memory outside buffers. */
  if (dst_size < LZVN_ENCODE_MIN_DST_SIZE)
    {
      *src_used = 0;
      return 0;
    }
  /* Max input size check (limit to offsets on izl_u32). */
  if (src_size > LZVN_ENCODE_MAX_SRC_SIZE)
    {
      src_size = LZVN_ENCODE_MAX_SRC_SIZE;
    }

  /* Setup encoder state */
  {
    lzvn_encoder_state state;
    memset (&state, 0, sizeof (state));

    state.src = src;
    state.src_begin = 0;
    state.src_end = (lzvn_offset)src_size;
    state.src_literal = 0;
    state.src_current = 0;
    state.dst = dst;
    state.dst_begin = dst;
    state.dst_end = (unsigned char *)dst + dst_size
                    - 8; /* reserve 8 bytes for end-of-stream */
    state.table = work;

    /* Do not encode if the input buffer is too small. We'll emit a literal
     * instead. */
    if (src_size >= LZVN_ENCODE_MIN_SRC_SIZE)
      {

        state.src_current_end = (lzvn_offset)src_size - LZVN_ENCODE_MIN_MARGIN;
        lzvn_init_table (&state);
        lzvn_encode (&state);
      }

    /* No need to test the return value: src_literal will not be updated on
     * failure, */
    /* and we will fail later. */
    lzvn_emit_literal (&state, state.src_end - state.src_literal);

    /* Restore original size, so end-of-stream always succeeds, and emit it */
    state.dst_end = (unsigned char *)dst + dst_size;
    lzvn_emit_end_of_stream (&state);

    *src_used = state.src_literal;
    return (size_t)(state.dst - state.dst_begin);
  }
}

size_t
lzvn_encode_buffer (void *dst, size_t dst_size, const void *src,
                    size_t src_size, void *work)
{
  size_t src_used = 0;
  size_t dst_used
      = lzvn_encode_partial (dst, dst_size, src, src_size, &src_used, work);
  if (src_used != src_size)
    return 0;      /* could not encode entire input stream = fail */
  return dst_used; /* return encoded size */
}

/* ===== original lzvn_decode_base.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZVN low-level decoder */

#if !defined(HAVE_LABELS_AS_VALUES)
# if defined(__GNUC__) || defined(__clang__)
#  define HAVE_LABELS_AS_VALUES 1
# else
#  define HAVE_LABELS_AS_VALUES 0
# endif
#endif

/*  Both the source and destination buffers are represented by a pointer and */
/*  a length; they are *always* updated in concert using this macro; however */
/*  many bytes the pointer is advanced, the length is decremented by the same
 */
/*  amount. Thus, pointer + length always points to the byte one past the end
 */
/*  of the buffer. */
#define PTR_LEN_INC(_pointer, _length, _increment)                            \
  (_pointer += _increment, _length -= _increment)

/*  Update state with current positions and distance, corresponding to the */
/*  beginning of an instruction in both streams */
#define UPDATE_GOOD                                                           \
  (state->src = src_ptr, state->dst = dst_ptr, state->d_prev = D)

void
lzvn_decode (lzvn_decoder_state *state)
{
#if HAVE_LABELS_AS_VALUES
  /* Jump table for all instructions */
  static const void *opc_tbl[256] = {
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&eos,   &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&nop,   &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&nop,   &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
    &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
    &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
    &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
    &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
    &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
    &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
    &&lrg_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l,
    &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l,
    &&lrg_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m,
    &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m
  };
#endif
  size_t src_len = state->src_end - state->src;
  size_t dst_len = state->dst_end - state->dst;
  if (src_len == 0 || dst_len == 0)
    return; /* empty buffer */

  {
    const unsigned char *src_ptr = state->src;
    unsigned char *dst_ptr = state->dst;
    size_t D = state->d_prev;
    size_t M;
    size_t L;
    size_t opc_len;

    /* Do we have a partially expanded match saved in state? */
    if (state->L != 0 || state->M != 0)
      {
        L = state->L;
        M = state->M;
        D = state->D;
        opc_len = 0; /* we already skipped the op */
        state->L = state->M = state->D = 0;
        if (M == 0)
          goto copy_literal;
        if (L == 0)
          goto copy_match;
        goto copy_literal_and_match;
      }

    {
      unsigned char opc = src_ptr[0];

#if HAVE_LABELS_AS_VALUES
      goto *opc_tbl[opc];
#else
      for (;;)
        {
          switch (opc)
            {
#endif
/*  =============================================================== */
/*  These four opcodes (sml_d, med_d, lrg_d, and pre_d) encode both a */
/*  literal and a match. The bulk of their implementations are shared; */
/*  each label here only does the work of setting the opcode length (not */
/*  including any literal bytes), and extracting the literal length, match */
/*  length, and match distance (except in pre_d). They then jump into the */
/*  shared implementation to actually output the literal and match bytes. */
/* */
/*  No error checking happens in the first stage, except for ensuring that */
/*  the source has enough length to represent the full opcode before */
/*  reading past the first byte. */
#if HAVE_LABELS_AS_VALUES
    sml_d:
#endif
#if !HAVE_LABELS_AS_VALUES
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
    case 24:
    case 25:
    case 26:
    case 27:
    case 28:
    case 29:
    case 32:
    case 33:
    case 34:
    case 35:
    case 36:
    case 37:
    case 40:
    case 41:
    case 42:
    case 43:
    case 44:
    case 45:
    case 48:
    case 49:
    case 50:
    case 51:
    case 52:
    case 53:
    case 56:
    case 57:
    case 58:
    case 59:
    case 60:
    case 61:
    case 64:
    case 65:
    case 66:
    case 67:
    case 68:
    case 69:
    case 72:
    case 73:
    case 74:
    case 75:
    case 76:
    case 77:
    case 80:
    case 81:
    case 82:
    case 83:
    case 84:
    case 85:
    case 88:
    case 89:
    case 90:
    case 91:
    case 92:
    case 93:
    case 96:
    case 97:
    case 98:
    case 99:
    case 100:
    case 101:
    case 104:
    case 105:
    case 106:
    case 107:
    case 108:
    case 109:
    case 128:
    case 129:
    case 130:
    case 131:
    case 132:
    case 133:
    case 136:
    case 137:
    case 138:
    case 139:
    case 140:
    case 141:
    case 144:
    case 145:
    case 146:
    case 147:
    case 148:
    case 149:
    case 152:
    case 153:
    case 154:
    case 155:
    case 156:
    case 157:
    case 192:
    case 193:
    case 194:
    case 195:
    case 196:
    case 197:
    case 200:
    case 201:
    case 202:
    case 203:
    case 204:
    case 205:
#endif
      UPDATE_GOOD;
      /* "small distance": This opcode has the structure LLMMMDDD DDDDDDDD
       * LITERAL */
      /*  where the length of literal (0-3 bytes) is encoded by the high 2 bits
       * of */
      /*  the first byte. We first extract the literal length so we know how
       * long */
      /*  the opcode is, then check that the source can hold both this opcode
       * and */
      /*  at least one byte of the next (because any valid input stream must be
       */
      /*  terminated with an eos token). */
      opc_len = 2;
      L = (size_t)extract (opc, 6, 2);
      M = (size_t)extract (opc, 3, 3) + 3;
      /*  We need to ensure that the source buffer is long enough that we can
       */
      /*  safely read this entire opcode, the literal that follows, and the
       * first */
      /*  byte of the next opcode.  Once we satisfy this requirement, we can */
      /*  safely unpack the match distance. A check similar to this one is */
      /*  present in all the opcode implementations. */
      if (src_len <= opc_len + L)
        return; /* source truncated */
      D = (size_t)extract (opc, 0, 3) << 8 | src_ptr[1];
      goto copy_literal_and_match;

#if HAVE_LABELS_AS_VALUES
    med_d:
#endif
#if !HAVE_LABELS_AS_VALUES
    case 160:
    case 161:
    case 162:
    case 163:
    case 164:
    case 165:
    case 166:
    case 167:
    case 168:
    case 169:
    case 170:
    case 171:
    case 172:
    case 173:
    case 174:
    case 175:
    case 176:
    case 177:
    case 178:
    case 179:
    case 180:
    case 181:
    case 182:
    case 183:
    case 184:
    case 185:
    case 186:
    case 187:
    case 188:
    case 189:
    case 190:
    case 191:
#endif
      UPDATE_GOOD;
      /*  "medium distance": This is a minor variant of the "small distance" */
      /*  encoding, where we will now use two extra bytes instead of one to
       * encode */
      /*  the restof the match length and distance. This allows an extra two
       * bits */
      /*  for the match length, and an extra three bits for the match distance.
       * The */
      /*  full structure of the opcode is 101LLMMM DDDDDDMM DDDDDDDD LITERAL.
       */
      opc_len = 3;
      L = (size_t)extract (opc, 3, 2);
      if (src_len <= opc_len + L)
        return; /* source truncated */
      {
        izl_u16 opc23 = load2 (&src_ptr[1]);
        M = (size_t)((extract (opc, 0, 3) << 2 | extract (opc23, 0, 2)) + 3);
        D = (size_t)extract (opc23, 2, 14);
        goto copy_literal_and_match;

#if HAVE_LABELS_AS_VALUES
      lrg_d:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 7:
      case 15:
      case 23:
      case 31:
      case 39:
      case 47:
      case 55:
      case 63:
      case 71:
      case 79:
      case 87:
      case 95:
      case 103:
      case 111:
      case 135:
      case 143:
      case 151:
      case 159:
      case 199:
      case 207:
#endif
        UPDATE_GOOD;
        /*  "large distance": This is another variant of the "small distance"
         */
        /*  encoding, where we will now use two extra bytes to encode the match
         */
        /*  distance, which allows distances up to 65535 to be represented. The
         * full */
        /*  structure of the opcode is LLMMM111 DDDDDDDD DDDDDDDD LITERAL. */
        opc_len = 3;
        L = (size_t)extract (opc, 6, 2);
        M = (size_t)extract (opc, 3, 3) + 3;
        if (src_len <= opc_len + L)
          return; /* source truncated */
        D = load2 (&src_ptr[1]);
        goto copy_literal_and_match;

#if HAVE_LABELS_AS_VALUES
      pre_d:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 70:
      case 78:
      case 86:
      case 94:
      case 102:
      case 110:
      case 134:
      case 142:
      case 150:
      case 158:
      case 198:
      case 206:
#endif
        UPDATE_GOOD;
        /*  "previous distance": This opcode has the structure LLMMM110, where
         * the */
        /*  length of the literal (0-3 bytes) is encoded by the high 2 bits of
         * the */
        /*  first byte. We first extract the literal length so we know how long
         */
        /*  the opcode is, then check that the source can hold both this opcode
         * and */
        /*  at least one byte of the next (because any valid input stream must
         * be */
        /*  terminated with an eos token). */
        opc_len = 1;
        L = (size_t)extract (opc, 6, 2);
        M = (size_t)extract (opc, 3, 3) + 3;
        if (src_len <= opc_len + L)
          return; /* source truncated */
        goto copy_literal_and_match;

      copy_literal_and_match:
        /*  Common implementation of writing data for opcodes that have both a
         */
        /*  literal and a match. We begin by advancing the source pointer past
         */
        /*  the opcode, so that it points at the first literal byte (if L */
        /*  is non-zero; otherwise it points at the next opcode). */
        PTR_LEN_INC (src_ptr, src_len, opc_len);
        /*  Now we copy the literal from the source pointer to the destination.
         */
        if (__builtin_expect (dst_len >= 4 && src_len >= 4, 1))
          {
            /*  The literal is 0-3 bytes; if we are not near the end of the
             * buffer, */
            /*  we can safely just do a 4 byte copy (which is guaranteed to
             * cover */
            /*  the complete literal, and may include some other bytes as
             * well). */
            store4 (dst_ptr, load4 (src_ptr));
          }
        else if (L <= dst_len)
          {
            /*  We are too close to the end of either the input or output
             * stream */
            /*  to be able to safely use a four-byte copy, but we will not
             * exhaust */
            /*  either stream (we already know that the source will not be */
            /*  exhausted from checks in the individual opcode implementations,
             */
            /*  and we just tested that dst_len > L). Thus, we need to do a */
            /*  byte-by-byte copy of the literal. This is slow, but it can only
             * ever */
            /*  happen near the very end of a buffer, so it is not an important
             * case to */
            /*  optimize. */
            {
              size_t i;
              for (i = 0; i < L; ++i)
                dst_ptr[i] = src_ptr[i];
            }
          }
        else
          {
            /* Destination truncated: fill DST, and store partial match */

            /* Copy partial literal */
            {
              size_t i;
              for (i = 0; i < dst_len; ++i)
                dst_ptr[i] = src_ptr[i];
            }
            /* Save state */
            state->src = src_ptr + dst_len;
            state->dst = dst_ptr + dst_len;
            state->L = L - dst_len;
            state->M = M;
            state->D = D;
            return; /* destination truncated */
          }
        /*  Having completed the copy of the literal, we advance both the
         * source */
        /*  and destination pointers by the number of literal bytes. */
        PTR_LEN_INC (dst_ptr, dst_len, L);
        PTR_LEN_INC (src_ptr, src_len, L);
        /*  Check if the match distance is valid; matches must not reference */
        /*  bytes that preceed the start of the output buffer, nor can the
         * match */
        /*  distance be zero. */
        if (D > (size_t)(dst_ptr - state->dst_begin) || D == 0)
          goto invalid_match_distance;
      copy_match:
        /*  Now we copy the match from dst_ptr - D to dst_ptr. It is important
         * to keep */
        /*  in mind that we may have D < M, in which case the source and
         * destination */
        /*  windows overlap in the copy. The semantics of the match copy are
         * *not* */
        /*  those of memmove( ); if the buffers overlap it needs to behave as
         * though */
        /*  we were copying byte-by-byte in increasing address order. If, for
         * example, */
        /*  D is 1, the copy operation is equivalent to: */
        /* */
        /*      memset(dst_ptr, dst_ptr[-1], M); */
        /* */
        /*  i.e. it splats the previous byte. This means that we need to be
         * very */
        /*  careful about using wide loads or stores to perform the copy
         * operation. */
        if (__builtin_expect (dst_len >= M + 7 && D >= 8, 1))
          {
            /*  We are not near the end of the buffer, and the match distance
             */
            /*  is at least eight. Thus, we can safely loop using eight byte */
            /*  copies. The last of these may slop over the intended end of */
            /*  the match, but this is OK because we know we have a safety
             * bound */
            /*  away from the end of the destination buffer. */
            {
              size_t i;
              for (i = 0; i < M; i += 8)
                store8 (&dst_ptr[i], load8 (&dst_ptr[i - D]));
            }
          }
        else if (M <= dst_len)
          {
            /*  Either the match distance is too small, or we are too close to
             */
            /*  the end of the buffer to safely use eight byte copies. Fall
             * back */
            /*  on a simple byte-by-byte implementation. */
            {
              size_t i;
              for (i = 0; i < M; ++i)
                dst_ptr[i] = dst_ptr[i - D];
            }
          }
        else
          {
            /* Destination truncated: fill DST, and store partial match */

            /* Copy partial match */
            {
              size_t i;
              for (i = 0; i < dst_len; ++i)
                dst_ptr[i] = dst_ptr[i - D];
            }
            /* Save state */
            state->src = src_ptr;
            state->dst = dst_ptr + dst_len;
            state->L = 0;
            state->M = M - dst_len;
            state->D = D;
            return; /* destination truncated */
          }
        /*  Update the destination pointer and length to account for the bytes
         */
        /*  written by the match, then load the next opcode byte and branch to
         */
        /*  the appropriate implementation. */
        PTR_LEN_INC (dst_ptr, dst_len, M);
        opc = src_ptr[0];
#if HAVE_LABELS_AS_VALUES
        goto *opc_tbl[opc];
#else
                break;
#endif

/* =============================================================== */
/* Opcodes representing only a match (no literal). */
/*  These two opcodes (lrg_m and sml_m) encode only a match. The match */
/*  distance is carried over from the previous opcode, so all they need */
/*  to encode is the match length. We are able to reuse the match copy */
/*  sequence from the literal and match opcodes to perform the actual */
/*  copy implementation. */
#if HAVE_LABELS_AS_VALUES
      sml_m:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 241:
      case 242:
      case 243:
      case 244:
      case 245:
      case 246:
      case 247:
      case 248:
      case 249:
      case 250:
      case 251:
      case 252:
      case 253:
      case 254:
      case 255:
#endif
        UPDATE_GOOD;
        /*  "small match": This opcode has no literal, and uses the previous
         * match */
        /*  distance (i.e. it encodes only the match length), in a single byte
         * as */
        /*  1111MMMM. */
        opc_len = 1;
        if (src_len <= opc_len)
          return; /* source truncated */
        M = (size_t)extract (opc, 0, 4);
        PTR_LEN_INC (src_ptr, src_len, opc_len);
        goto copy_match;

#if HAVE_LABELS_AS_VALUES
      lrg_m:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 240:
#endif
        UPDATE_GOOD;
        /*  "large match": This opcode has no literal, and uses the previous
         * match */
        /*  distance (i.e. it encodes only the match length). It is encoded in
         * two */
        /*  bytes as 11110000 MMMMMMMM.  Because matches smaller than 16 bytes
         * can */
        /*  be represented by sml_m, there is an implicit bias of 16 on the
         * match */
        /*  length; the representable values are [16,271]. */
        opc_len = 2;
        if (src_len <= opc_len)
          return; /* source truncated */
        M = src_ptr[1] + 16;
        PTR_LEN_INC (src_ptr, src_len, opc_len);
        goto copy_match;

/* =============================================================== */
/* Opcodes representing only a literal (no match). */
/*  These two opcodes (lrg_l and sml_l) encode only a literal.  There is no */
/*  match length or match distance to worry about (but we need to *not* */
/*  touch D, as it must be preserved between opcodes). */
#if HAVE_LABELS_AS_VALUES
      sml_l:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 225:
      case 226:
      case 227:
      case 228:
      case 229:
      case 230:
      case 231:
      case 232:
      case 233:
      case 234:
      case 235:
      case 236:
      case 237:
      case 238:
      case 239:
#endif
        UPDATE_GOOD;
        /*  "small literal": This opcode has no match, and encodes only a
         * literal */
        /*  of length up to 15 bytes. The format is 1110LLLL LITERAL. */
        opc_len = 1;
        L = (size_t)extract (opc, 0, 4);
        goto copy_literal;

#if HAVE_LABELS_AS_VALUES
      lrg_l:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 224:
#endif
        UPDATE_GOOD;
        /*  "large literal": This opcode has no match, and uses the previous
         * match */
        /*  distance (i.e. it encodes only the match length). It is encoded in
         * two */
        /*  bytes as 11100000 LLLLLLLL LITERAL.  Because literals smaller than
         * 16 */
        /*  bytes can be represented by sml_l, there is an implicit bias of 16
         * on */
        /*  the literal length; the representable values are [16,271]. */
        opc_len = 2;
        if (src_len <= 2)
          return; /* source truncated */
        L = src_ptr[1] + 16;
        goto copy_literal;

      copy_literal:
        /*  Check that the source buffer is large enough to hold the complete
         */
        /*  literal and at least the first byte of the next opcode. If so,
         * advance */
        /*  the source pointer to point to the first byte of the literal and
         * adjust */
        /*  the source length accordingly. */
        if (src_len <= opc_len + L)
          return; /* source truncated */
        PTR_LEN_INC (src_ptr, src_len, opc_len);
        /*  Now we copy the literal from the source pointer to the destination.
         */
        if (dst_len >= L + 7 && src_len >= L + 7)
          {
            /*  We are not near the end of the source or destination buffers;
             * thus */
            /*  we can safely copy the literal using wide copies, without
             * worrying */
            /*  about reading or writing past the end of either buffer. */
            {
              size_t i;
              for (i = 0; i < L; i += 8)
                store8 (&dst_ptr[i], load8 (&src_ptr[i]));
            }
          }
        else if (L <= dst_len)
          {
            /*  We are too close to the end of either the input or output
             * stream */
            /*  to be able to safely use an eight-byte copy. Instead we copy
             * the */
            /*  literal byte-by-byte. */
            {
              size_t i;
              for (i = 0; i < L; ++i)
                dst_ptr[i] = src_ptr[i];
            }
          }
        else
          {
            /* Destination truncated: fill DST, and store partial match */

            /* Copy partial literal */
            {
              size_t i;
              for (i = 0; i < dst_len; ++i)
                dst_ptr[i] = src_ptr[i];
            }
            /* Save state */
            state->src = src_ptr + dst_len;
            state->dst = dst_ptr + dst_len;
            state->L = L - dst_len;
            state->M = 0;
            state->D = D;
            return; /* destination truncated */
          }
        /*  Having completed the copy of the literal, we advance both the
         * source */
        /*  and destination pointers by the number of literal bytes. */
        PTR_LEN_INC (dst_ptr, dst_len, L);
        PTR_LEN_INC (src_ptr, src_len, L);
        /*  Load the first byte of the next opcode, and jump to its
         * implementation. */
        opc = src_ptr[0];
#if HAVE_LABELS_AS_VALUES
        goto *opc_tbl[opc];
#else
                break;
#endif

/* =============================================================== */
/* Other opcodes */
#if HAVE_LABELS_AS_VALUES
      nop:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 14:
      case 22:
#endif
        UPDATE_GOOD;
        opc_len = 1;
        if (src_len <= opc_len)
          return; /* source truncated */
        PTR_LEN_INC (src_ptr, src_len, opc_len);
        opc = src_ptr[0];
#if HAVE_LABELS_AS_VALUES
        goto *opc_tbl[opc];
#else
                break;
#endif

#if HAVE_LABELS_AS_VALUES
      eos:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 6:
#endif
        opc_len = 8;
        if (src_len < opc_len)
          return; /* source truncated (here we don't need an extra byte for
                     next op */
                  /* code) */
        PTR_LEN_INC (src_ptr, src_len, opc_len);
        state->end_of_stream = 1;
        UPDATE_GOOD;
        return; /* end-of-stream */

/* =============================================================== */
/* Return on error */
#if HAVE_LABELS_AS_VALUES
      udef:
#endif
#if !HAVE_LABELS_AS_VALUES
      case 30:
      case 38:
      case 46:
      case 54:
      case 62:
      case 112:
      case 113:
      case 114:
      case 115:
      case 116:
      case 117:
      case 118:
      case 119:
      case 120:
      case 121:
      case 122:
      case 123:
      case 124:
      case 125:
      case 126:
      case 127:
      case 208:
      case 209:
      case 210:
      case 211:
      case 212:
      case 213:
      case 214:
      case 215:
      case 216:
      case 217:
      case 218:
      case 219:
      case 220:
      case 221:
      case 222:
      case 223:
#endif
      invalid_match_distance:

        return; /* we already updated state */
#if !HAVE_LABELS_AS_VALUES
      }
    }
  }
#endif
}
}
}

/* ===== original lzfse_encode_base.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZFSE encoder */

/*! @abstract Get hash in range [0, LZFSE_ENCODE_HASH_VALUES-1] from 4 bytes in
 * X. */
static izl_u32
hashX (izl_u32 x, unsigned int hash_bits)
{
  return (x * 2654435761U)
         >> (32 - hash_bits); /* Knuth multiplicative hash */
}

/*! @abstract Return value with all 0 except nbits<=32 unsigned bits from V
 * at bit offset OFFSET.
 * V is assumed to fit on nbits bits. */
static izl_u64
setField (izl_u32 v, int offset, int nbits)
{
  assert (offset + nbits < 64 && offset >= 0 && nbits <= 32);
  assert (nbits == 32 || (v < (1U << nbits)));
  return ((izl_u64)v << (izl_u64)offset);
}

/*! @abstract Encode all fields, except freq, from a
 * lzfse_compressed_block_header_v1 to a lzfse_compressed_block_header_v2.
 * All but the header_size and freq fields of the output are modified. */
static void
lzfse_encode_v1_state (lzfse_compressed_block_header_v2 *out,
                       const lzfse_compressed_block_header_v1 *in)
{
  out->magic = LZFSE_COMPRESSEDV2_BLOCK_MAGIC;
  out->n_raw_bytes = in->n_raw_bytes;

  /* Literal state */
  store8 (out->packed_fields + 0,
          setField (in->n_literals, 0, 20)
              | setField (in->n_literal_payload_bytes, 20, 20)
              | setField (in->n_matches, 40, 20)
              | setField (7 + in->literal_bits, 60, 3));
  store8 (out->packed_fields + 8,
          setField (in->literal_state[0], 0, 10)
              | setField (in->literal_state[1], 10, 10)
              | setField (in->literal_state[2], 20, 10)
              | setField (in->literal_state[3], 30, 10)
              | setField (in->n_lmd_payload_bytes, 40, 20)
              | setField (7 + in->lmd_bits, 60, 3));
  store8 (
      out->packed_fields + 16,
      load8 (out->packed_fields + 16) /* header_size already stored in v[2] */
          | setField (in->l_state, 32, 10) | setField (in->m_state, 42, 10)
          | setField (in->d_state, 52, 10));
}

/*! @abstract Encode an entry value in a freq table. Return bits, and sets
 * *nbits to the number of bits to serialize. */
static izl_u32
lzfse_encode_v1_freq_value (int value, int *nbits)
{
  /* Fixed Huffman code, bits are read from LSB. */
  /* Note that we rely on the position of the first '0' bit providing the
   * number */
  /* of bits. */
  switch (value)
    {
    case 0:
      *nbits = 2;
      return 0; /*    0.0 */
    case 1:
      *nbits = 2;
      return 2; /*    1.0 */
    case 2:
      *nbits = 3;
      return 1; /*   0.01 */
    case 3:
      *nbits = 3;
      return 5; /*   1.01 */
    case 4:
      *nbits = 5;
      return 3; /* 00.011 */
    case 5:
      *nbits = 5;
      return 11; /* 01.011 */
    case 6:
      *nbits = 5;
      return 19; /* 10.011 */
    case 7:
      *nbits = 5;
      return 27; /* 11.011 */
    default:
      break;
    }
  if (value < 24)
    {
      *nbits = 8;                    /* 4+4 */
      return 7 + ((value - 8) << 4); /* xxxx.0111 */
    }
  /* 24..1047 */
  *nbits = 14;                     /* 4+10 */
  return ((value - 24) << 4) + 15; /* xxxxxxxxxx.1111 */
}

/*! @abstract Encode all tables from a lzfse_compressed_block_header_v1
 * to a lzfse_compressed_block_header_v2.
 * Only the header_size and freq fields of the output are modified.
 * @return Size of the lzfse_compressed_block_header_v2 */
static size_t
lzfse_encode_v1_freq_table (lzfse_compressed_block_header_v2 *out,
                            const lzfse_compressed_block_header_v1 *in)
{
  izl_u32 accum = 0;
  int accum_nbits = 0;
  const izl_u16 *src
      = &(in->l_freq[0]); /* first value of first table (struct */
                          /* will not be modified, so this code */
                          /* will remain valid) */
  izl_u8 *dst = &(out->freq[0]);
  {
    int i;
    for (i = 0;
         i < LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS
                 + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS;
         i++)
      {
        /* Encode one value to accum */
        int nbits = 0;
        izl_u32 bits = lzfse_encode_v1_freq_value (src[i], &nbits);
        assert (bits < (1U << nbits));
        accum |= bits << accum_nbits;
        accum_nbits += nbits;

        /* Store bytes from accum to output buffer */
        while (accum_nbits >= 8)
          {
            *dst = (izl_u8)(accum & 0xff);
            accum >>= 8;
            accum_nbits -= 8;
            dst++;
          }
      }
  }
  /* Store final byte if needed */
  if (accum_nbits > 0)
    {
      *dst = (izl_u8)(accum & 0xff);
      dst++;
    }

  /* Return final size of out */
  {
    izl_u32 header_size = (izl_u32)(dst - (izl_u8 *)out);
    store8 (out->packed_fields + 0, 0);
    store8 (out->packed_fields + 8, 0);
    store8 (out->packed_fields + 16, setField (header_size, 0, 32));

    return header_size;
  }
}

/* We need to limit forward match length to make sure it won't split into a too
 */
/* large number of LMD. */
/* The limit itself is quite large, so it doesn't really impact compression */
/* ratio. */
/* The matches may still be expanded backwards by a few bytes, so the final */
/* length may be greater than this limit, which is OK. */
#define LZFSE_ENCODE_MAX_MATCH_LENGTH (100 * LZFSE_ENCODE_MAX_M_VALUE)

/* =============================================================== */
/* Encoder back end */

/*! @abstract Encode matches stored in STATE into a compressed/uncompressed
 * block.
 * @return LZFSE_STATUS_OK on success.
 * @return LZFSE_STATUS_DST_FULL and restore initial state if output buffer is
 * full. */
static int
lzfse_encode_matches (lzfse_encoder_state *s)
{
  if (s->n_literals == 0 && s->n_matches == 0)
    return LZFSE_STATUS_OK; /* nothing to store, OK */

  {
    izl_u32 l_occ[LZFSE_ENCODE_L_SYMBOLS];
    izl_u32 m_occ[LZFSE_ENCODE_M_SYMBOLS];
    izl_u32 d_occ[LZFSE_ENCODE_D_SYMBOLS];
    izl_u32 literal_occ[LZFSE_ENCODE_LITERAL_SYMBOLS];
    fse_encoder_entry l_encoder[LZFSE_ENCODE_L_SYMBOLS];
    fse_encoder_entry m_encoder[LZFSE_ENCODE_M_SYMBOLS];
    fse_encoder_entry d_encoder[LZFSE_ENCODE_D_SYMBOLS];
    fse_encoder_entry literal_encoder[LZFSE_ENCODE_LITERAL_SYMBOLS];
    int ok = 1;
    lzfse_compressed_block_header_v1 header1 = { 0 };
    lzfse_compressed_block_header_v2 header2_storage;
    lzfse_compressed_block_header_v2 *header2 = &header2_storage;
    size_t encoded_header_size = 0;

    /* Keep initial state to be able to restore it if DST full */
    izl_u8 *dst0 = s->dst;
    izl_u32 n_literals0 = s->n_literals;

    /* Add 0x00 literals until n_literals multiple of 4, since we encode 4 */
    /* interleaved literal streams. */
    while (s->n_literals & 3)
      {
        izl_u32 n = s->n_literals++;
        s->literals[n] = 0;
      }

    /* Encode previous distance */
    {
      izl_u32 d_prev = 0;
      {
        izl_u32 i;
        for (i = 0; i < s->n_matches; i++)
          {
            izl_u32 d = s->d_values[i];
            if (d == d_prev)
              s->d_values[i] = 0;
            else
              d_prev = d;
          }
      }

      /* Clear occurrence tables */
      memset (l_occ, 0, sizeof (l_occ));
      memset (m_occ, 0, sizeof (m_occ));
      memset (d_occ, 0, sizeof (d_occ));
      memset (literal_occ, 0, sizeof (literal_occ));

      /* Update occurrence tables in all 4 streams (L,M,D,literals) */
      {
        izl_u32 l_sum = 0;
        izl_u32 m_sum = 0;
        {
          izl_u32 i;
          for (i = 0; i < s->n_matches; i++)
            {
              izl_u32 l = s->l_values[i];
              l_sum += l;
              l_occ[l_base_from_value (l)]++;
            }
        }
        {
          izl_u32 i;
          for (i = 0; i < s->n_matches; i++)
            {
              izl_u32 m = s->m_values[i];
              m_sum += m;
              m_occ[m_base_from_value (m)]++;
            }
        }
        {
          izl_u32 i;
          for (i = 0; i < s->n_matches; i++)
            d_occ[d_base_from_value (s->d_values[i])]++;
        }
        {
          izl_u32 i;
          for (i = 0; i < s->n_literals; i++)
            literal_occ[s->literals[i]]++;
        }

        /* Make sure we have enough room for a _full_ V2 header */
        if (s->dst + sizeof (lzfse_compressed_block_header_v2) > s->dst_end)
          {
            ok = 0;
            goto IZ_LZFSE_FINISH;
          }
        memset (&header2_storage, 0, sizeof (header2_storage));

        /* Setup header V1 */
        header1.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
        header1.n_raw_bytes = m_sum + l_sum;
        header1.n_matches = s->n_matches;
        header1.n_literals = s->n_literals;

        /* Normalize occurrence tables to freq tables */
        fse_normalize_freq (LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS,
                            l_occ, header1.l_freq);
        fse_normalize_freq (LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS,
                            m_occ, header1.m_freq);
        fse_normalize_freq (LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS,
                            d_occ, header1.d_freq);
        fse_normalize_freq (LZFSE_ENCODE_LITERAL_STATES,
                            LZFSE_ENCODE_LITERAL_SYMBOLS, literal_occ,
                            header1.literal_freq);

        /* Compress freq tables to V2 header, and get actual size of V2 header
         */
        encoded_header_size = lzfse_encode_v1_freq_table (header2, &header1);
        s->dst += encoded_header_size;

        /* Initialize encoder tables from freq tables */
        fse_init_encoder_table (LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS,
                                header1.l_freq, l_encoder);
        fse_init_encoder_table (LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS,
                                header1.m_freq, m_encoder);
        fse_init_encoder_table (LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS,
                                header1.d_freq, d_encoder);
        fse_init_encoder_table (LZFSE_ENCODE_LITERAL_STATES,
                                LZFSE_ENCODE_LITERAL_SYMBOLS,
                                header1.literal_freq, literal_encoder);

        /* Encode literals */
        {
          fse_out_stream out;
          fse_out_init (&out);
          {
            fse_state state0, state1, state2, state3;
            state0 = state1 = state2 = state3 = 0;

            {
              izl_u8 *buf = s->dst;
              izl_u32 i = s->n_literals; /* I multiple of 4 */
              /* We encode starting from the last literal so we can decode
               * starting from */
              /* the first */
              while (i > 0)
                {
                  if (buf + 16 > s->dst_end)
                    {
                      ok = 0;
                      goto IZ_LZFSE_FINISH;
                    } /* out full */
                  i -= 4;
                  fse_encode (&state3, literal_encoder, &out,
                              s->literals[i + 3]); /* 10b */
                  fse_encode (&state2, literal_encoder, &out,
                              s->literals[i + 2]); /* 10b */
#if !FSE_IOSTREAM_64
                  fse_out_flush (&out, &buf);
#endif
                  fse_encode (&state1, literal_encoder, &out,
                              s->literals[i + 1]); /* 10b */
                  fse_encode (&state0, literal_encoder, &out,
                              s->literals[i + 0]); /* 10b */
                  fse_out_flush (&out, &buf);
                }
              fse_out_finish (&out, &buf);

              /* Update header with final encoder state */
              header1.literal_bits = out.accum_nbits; /* [-7, 0] */
              header1.n_literal_payload_bytes = (izl_u32)(buf - s->dst);
              header1.literal_state[0] = state0;
              header1.literal_state[1] = state1;
              header1.literal_state[2] = state2;
              header1.literal_state[3] = state3;

              /* Update state */
              s->dst = buf;
            }
          }
        } /* literals */

        /* Encode L,M,D */
        {
          fse_out_stream out;
          fse_out_init (&out);
          {
            fse_state l_state, m_state, d_state;
            l_state = m_state = d_state = 0;

            {
              izl_u8 *buf = s->dst;
              izl_u32 i = s->n_matches;

              /* Add 8 padding bytes to the L,M,D payload */
              if (buf + 8 > s->dst_end)
                {
                  ok = 0;
                  goto IZ_LZFSE_FINISH;
                } /* out full */
              store8 (buf, 0);
              buf += 8;

              /* We encode starting from the last match so we can decode
               * starting from the */
              /* first */
              while (i > 0)
                {
                  if (buf + 16 > s->dst_end)
                    {
                      ok = 0;
                      goto IZ_LZFSE_FINISH;
                    } /* out full */
                  i -= 1;

                  /* D requires 23b max */
                  {
                    izl_s32 d_value = s->d_values[i];
                    izl_u8 d_symbol = d_base_from_value (d_value);
                    izl_s32 d_nbits = d_extra_bits[d_symbol];
                    izl_s32 d_bits = d_value - d_base_value[d_symbol];
                    fse_out_push (&out, d_nbits, d_bits);
                    fse_encode (&d_state, d_encoder, &out, d_symbol);
#if !FSE_IOSTREAM_64
                    fse_out_flush (&out, &buf);
#endif

                    /* M requires 17b max */
                    {
                      izl_s32 m_value = s->m_values[i];
                      izl_u8 m_symbol = m_base_from_value (m_value);
                      izl_s32 m_nbits = m_extra_bits[m_symbol];
                      izl_s32 m_bits = m_value - m_base_value[m_symbol];
                      fse_out_push (&out, m_nbits, m_bits);
                      fse_encode (&m_state, m_encoder, &out, m_symbol);
#if !FSE_IOSTREAM_64
                      fse_out_flush (&out, &buf);
#endif

                      /* L requires 14b max */
                      {
                        izl_s32 l_value = s->l_values[i];
                        izl_u8 l_symbol = l_base_from_value (l_value);
                        izl_s32 l_nbits = l_extra_bits[l_symbol];
                        izl_s32 l_bits = l_value - l_base_value[l_symbol];
                        fse_out_push (&out, l_nbits, l_bits);
                        fse_encode (&l_state, l_encoder, &out, l_symbol);
                        fse_out_flush (&out, &buf);
                      }
                    }
                  }
                }
              fse_out_finish (&out, &buf);

              /* Update header with final encoder state */
              header1.n_lmd_payload_bytes = (izl_u32)(buf - s->dst);
              header1.lmd_bits = out.accum_nbits; /* [-7, 0] */
              header1.l_state = l_state;
              header1.m_state = m_state;
              header1.d_state = d_state;

              /* Update state */
              s->dst = buf;
            }
          }
        } /* L,M,D */

        /* Final state update, here we had enough space in DST, and are not
         * going to */
        /* revert state */
        s->n_literals = 0;
        s->n_matches = 0;

        /* Final payload size */
        header1.n_payload_bytes
            = header1.n_literal_payload_bytes + header1.n_lmd_payload_bytes;

        /* Encode state info in V2 header (we previously encoded the tables,
         * now we */
        /* set the other fields) */
        lzfse_encode_v1_state (header2, &header1);
        /* Header fields must not be accessed through an unaligned output
         * pointer. */
        memcpy (dst0, header2, encoded_header_size);

      IZ_LZFSE_FINISH:
        if (!ok)
          {
            /* Revert state, DST was full */

            /* Revert the d_prev encoding */
            izl_u32 d_prev = 0;
            {
              izl_u32 i;
              for (i = 0; i < s->n_matches; i++)
                {
                  izl_u32 d = s->d_values[i];
                  if (d == 0)
                    s->d_values[i] = d_prev;
                  else
                    d_prev = d;
                }
            }

            /* Revert literal count */
            s->n_literals = n_literals0;

            /* Revert DST */
            s->dst = dst0;

            return LZFSE_STATUS_DST_FULL; /* DST full */
          }

        return LZFSE_STATUS_OK;
      }
    }
  }
}

/*! @abstract Push a L,M,D match into the STATE.
 * @return LZFSE_STATUS_OK if OK.
 * @return LZFSE_STATUS_DST_FULL if the match can't be pushed, meaning one of
 * the buffers is full. In that case the state is not modified. */
static int
lzfse_push_lmd (lzfse_encoder_state *s, izl_u32 L, izl_u32 M, izl_u32 D)
{
  /* Check if we have enough space to push the match (we add some margin to
   * copy */
  /* literals faster here, and round final count later) */
  if (s->n_matches + 1 + 8 > LZFSE_MATCHES_PER_BLOCK)
    return LZFSE_STATUS_DST_FULL; /* state full */
  if (s->n_literals + L + 16 > LZFSE_LITERALS_PER_BLOCK)
    return LZFSE_STATUS_DST_FULL; /* state full */

  /* Store match */
  {
    izl_u32 n = s->n_matches++;
    s->l_values[n] = L;
    s->m_values[n] = M;
    s->d_values[n] = D;

    /* Store literals */
    {
      izl_u8 *dst = s->literals + s->n_literals;
      const izl_u8 *src = s->src + s->src_literal;
      izl_u8 *dst_end = dst + L;
      if (s->src_literal + L + 16 > s->src_end)
        {
          /* Careful at the end of SRC, we can't read 16 bytes */
          if (L > 0)
            memcpy (dst, src, L);
        }
      else
        {
          copy16 (dst, src);
          dst += 16;
          src += 16;
          while (dst < dst_end)
            {
              copy16 (dst, src);
              dst += 16;
              src += 16;
            }
        }
      s->n_literals += L;

      /* Update state */
      s->src_literal += L + M;

      return LZFSE_STATUS_OK;
    }
  }
}

/*! @abstract Split MATCH into one or more L,M,D parts, and push to STATE.
 * @return LZFSE_STATUS_OK if OK.
 * @return LZFSE_STATUS_DST_FULL if the match can't be pushed, meaning one of
 * the buffers is full. In that case the state is not modified. */
static int
lzfse_push_match (lzfse_encoder_state *s, const lzfse_match *match)
{
  /* Save the initial n_matches, n_literals, src_literal */
  izl_u32 n_matches0 = s->n_matches;
  izl_u32 n_literals0 = s->n_literals;
  lzfse_offset src_literals0 = s->src_literal;

  /* L,M,D */
  izl_u32 L = (izl_u32)(match->pos - s->src_literal); /* literal count */
  izl_u32 M = match->length;                          /* match length */
  izl_u32 D = (izl_u32)(match->pos - match->ref);     /* match distance */
  int ok = 1;

  /* Split L if too large */
  while (L > LZFSE_ENCODE_MAX_L_VALUE)
    {
      if (lzfse_push_lmd (s, LZFSE_ENCODE_MAX_L_VALUE, 0, 1) != 0)
        {
          ok = 0;
          goto IZ_LZFSE_FINISH;
        } /* take D=1 because most frequent, but not actually used */
      L -= LZFSE_ENCODE_MAX_L_VALUE;
    }

  /* Split if M too large */
  while (M > LZFSE_ENCODE_MAX_M_VALUE)
    {
      if (lzfse_push_lmd (s, L, LZFSE_ENCODE_MAX_M_VALUE, D) != 0)
        {
          ok = 0;
          goto IZ_LZFSE_FINISH;
        }
      L = 0;
      M -= LZFSE_ENCODE_MAX_M_VALUE;
    }

  /* L,M in range */
  if (L > 0 || M > 0)
    {
      if (lzfse_push_lmd (s, L, M, D) != 0)
        {
          ok = 0;
          goto IZ_LZFSE_FINISH;
        }
      L = M = 0;
      (void)L;
      (void)M; /* dead stores */
    }

IZ_LZFSE_FINISH:
  if (!ok)
    {
      /* Revert state */
      s->n_matches = n_matches0;
      s->n_literals = n_literals0;
      s->src_literal = src_literals0;

      return LZFSE_STATUS_DST_FULL; /* state tables full */
    }

  return LZFSE_STATUS_OK; /* OK */
}

/*! @abstract Backend: add MATCH to state S. Encode block if necessary, when
 * state is full.
 * @return LZFSE_STATUS_OK if OK.
 * @return LZFSE_STATUS_DST_FULL if the match can't be added, meaning one of
 * the buffers is full. In that case the state is not modified. */
static int
lzfse_backend_match (lzfse_encoder_state *s, const lzfse_match *match)
{
  /* Try to push the match in state */
  if (lzfse_push_match (s, match) == LZFSE_STATUS_OK)
    return LZFSE_STATUS_OK; /* OK, match added to state */

  /* Here state tables are full, try to emit block */
  if (lzfse_encode_matches (s) != LZFSE_STATUS_OK)
    return LZFSE_STATUS_DST_FULL; /* DST full, match not added */

  /* Here block has been emitted, re-try to push the match in state */
  return lzfse_push_match (s, match);
}

/*! @abstract Backend: add L literals to state S. Encode block if necessary,
 * when state is full.
 * @return LZFSE_STATUS_OK if OK.
 * @return LZFSE_STATUS_DST_FULL if the literals can't be added, meaning one of
 * the buffers is full. In that case the state is not modified. */
static int
lzfse_backend_literals (lzfse_encoder_state *s, lzfse_offset L)
{
  /* Create a fake match with M=0, D=1 */
  lzfse_match match;
  lzfse_offset pos = s->src_literal + L;
  match.pos = pos;
  match.ref = match.pos - 1;
  match.length = 0;
  return lzfse_backend_match (s, &match);
}

/*! @abstract Backend: flush final block, and emit end of stream
 * @return LZFSE_STATUS_OK if OK.
 * @return LZFSE_STATUS_DST_FULL if either the final block, or the
 * end-of-stream can't be added, meaning one of the buffers is full. If the
 * block was emitted, the state is updated to reflect this. Otherwise, it is
 * left unchanged. */
static int
lzfse_backend_end_of_stream (lzfse_encoder_state *s)
{
  /* Final match triggers write, otherwise emit blocks when we have enough */
  /* matches stored */
  if (lzfse_encode_matches (s) != LZFSE_STATUS_OK)
    return LZFSE_STATUS_DST_FULL; /* DST full */

  /* Emit end-of-stream block */
  if (s->dst + 4 > s->dst_end)
    return LZFSE_STATUS_DST_FULL; /* DST full */
  store4 (s->dst, LZFSE_ENDOFSTREAM_BLOCK_MAGIC);
  s->dst += 4;

  return LZFSE_STATUS_OK; /* OK */
}

/* =============================================================== */
/* Encoder state management */

/*! @abstract Initialize state:
 * @code
 * - hash table with all invalid pos, and value 0.
 * - pending match to NO_MATCH.
 * - src_literal to 0.
 * - d_prev to 0.
 @endcode
 * @return LZFSE_STATUS_OK */
int
lzfse_encode_init (lzfse_encoder_state *s)
{
  const lzfse_match NO_MATCH = { 0 };
  lzfse_history_set line;
  {
    int i;
    for (i = 0; i < LZFSE_ENCODE_HASH_WIDTH; i++)
      {
        line.pos[i] = -4 * LZFSE_ENCODE_MAX_D_VALUE; /* invalid pos */
        line.value[i] = 0;
      }
  }
  /* Fill the default 4-way table, or both halves of -11's 8-way table. */
  {
    int i;
    lzfse_history_set *active = s->ultra_history
                                ? s->ultra_history : s->history_table;
    unsigned int n = s->ultra_history
                     ? (1U << s->active_hash_bits) : LZFSE_ENCODE_HASH_VALUES;
    for (i = 0; i < (int)n; i++)
      {
        active[i] = line;
        if (s->ultra_history_extra)
          s->ultra_history_extra[i] = line;
      }
  }
  s->pending = NO_MATCH;
  s->src_literal = 0;

  return LZFSE_STATUS_OK; /* OK */
}

/*! @abstract Translate state \p src forward by \p delta > 0.
 * Offsets in \p src are updated backwards to point to the same positions.
 * @return  LZFSE_STATUS_OK */
int
lzfse_encode_translate (lzfse_encoder_state *s, lzfse_offset delta)
{
  assert (delta >= 0);
  if (delta == 0)
    return LZFSE_STATUS_OK; /* OK */

  /* SRC */
  s->src += delta;

  /* Offsets in SRC */
  s->src_end -= delta;
  s->src_encode_i -= delta;
  s->src_encode_end -= delta;
  s->src_literal -= delta;

  /* Pending match */
  s->pending.pos -= delta;
  s->pending.ref -= delta;

  /* history_table positions, translated, and clamped to invalid pos */
  {
    izl_s32 invalidPos = -4 * LZFSE_ENCODE_MAX_D_VALUE;
    {
      int i;
      unsigned int n = s->ultra_history
                       ? (1U << s->active_hash_bits) : LZFSE_ENCODE_HASH_VALUES;
      lzfse_history_set *active = s->ultra_history
                                  ? s->ultra_history : s->history_table;
      for (i = 0; i < (int)n; i++)
        {
          int group;
          for (group = 0; group < (s->ultra_history_extra ? 2 : 1); group++)
            {
              izl_s32 *p = group ? s->ultra_history_extra[i].pos
                                : active[i].pos;
              int j;
              for (j = 0; j < LZFSE_ENCODE_HASH_WIDTH; j++)
                {
                  lzfse_offset newPos = p[j] - delta;
                  p[j] = (izl_s32)((newPos < invalidPos) ? invalidPos
                                                         : newPos);
                }
            }
        }
    }

    return LZFSE_STATUS_OK; /* OK */
  }
}

/* =============================================================== */
/* Encoder front end */

int
lzfse_encode_base (lzfse_encoder_state *s)
{
  lzfse_history_set *history_table = s->ultra_history
                                      ? s->ultra_history : s->history_table;
  lzfse_history_set *extra_table = s->ultra_history_extra;
  lzfse_history_set *hashLine = 0;
  lzfse_history_set *hashLineExtra = 0;
  lzfse_history_set newH, newExtraH;
  const lzfse_match NO_MATCH = { 0 };
  int ok = 1;

  memset (&newH, 0x00, sizeof (newH));
  memset (&newExtraH, 0x00, sizeof (newExtraH));

  /* 8 byte padding at end of buffer */
  s->src_encode_end = s->src_end - 8;
  for (; s->src_encode_i < s->src_encode_end; s->src_encode_i++)
    {
      lzfse_offset pos = s->src_encode_i; /* pos >= 0 */

      /* Load 4 byte value and get hash line */
      izl_u32 x = load4 (s->src + pos);
      {
        izl_u32 hash = hashX (x, s->active_hash_bits);
        hashLine = history_table + hash;
        hashLineExtra = extra_table ? extra_table + hash : NULL;
      }
      {
        lzfse_history_set h = *hashLine;
        lzfse_history_set hExtra;
        if (hashLineExtra)
          hExtra = *hashLineExtra;

        /* Prepare next hash line (component 0 is the most recent) to prepare
         * new */
        /* entries (stored later) */
        {
          newH.pos[0] = (izl_s32)pos;
          {
            int k;
            for (k = 0; k < LZFSE_ENCODE_HASH_WIDTH - 1; k++)
              newH.pos[k + 1] = h.pos[k];
          }
          newH.value[0] = x;
          {
            int k;
            for (k = 0; k < LZFSE_ENCODE_HASH_WIDTH - 1; k++)
              newH.value[k + 1] = h.value[k];
          }
          if (hashLineExtra)
            {
              int k;
              newExtraH.pos[0] = h.pos[LZFSE_ENCODE_HASH_WIDTH - 1];
              newExtraH.value[0] = h.value[LZFSE_ENCODE_HASH_WIDTH - 1];
              for (k = 0; k < LZFSE_ENCODE_HASH_WIDTH - 1; k++)
                {
                  newExtraH.pos[k + 1] = hExtra.pos[k];
                  newExtraH.value[k + 1] = hExtra.value[k];
                }
            }
        }

        /* Do not look for a match if we are still covered by a previous match
         */
        if (pos < s->src_literal)
          goto END_POS;

        /* Search best incoming match */
        {
          lzfse_match incoming;
          incoming.pos = pos;
          incoming.ref = 0;
          incoming.length = 0;

          /* Check for matches.  We consider matches of length >= 4 only. */
          {
            int k, group;
            for (group = 0; group < (hashLineExtra ? 2 : 1); group++)
              for (k = 0; k < LZFSE_ENCODE_HASH_WIDTH; k++)
              {
                const lzfse_history_set *c = group ? &hExtra : &h;
                izl_u32 d = c->value[k] ^ x;
                if (d)
                  continue; /* no 4 byte match */
                {
                  izl_s32 ref = c->pos[k];
                  if (ref + LZFSE_ENCODE_MAX_D_VALUE < pos)
                    continue; /* too far */

                  {
                    const izl_u8 *src_ref = s->src + ref;
                    const izl_u8 *src_pos = s->src + pos;
                    izl_u32 length = 4;
                    izl_u32 maxLength = (izl_u32)(s->src_end - pos
                                                  - 8); /* ensure we don't hit
                                                           the end of SRC */
                    while (length < maxLength)
                      {
                        izl_u64 d = load8 (src_ref + length)
                                    ^ load8 (src_pos + length);
                        if (d == 0)
                          {
                            length += 8;
                            continue;
                          }

                        length += (__builtin_ctzll (d)
                                   >> 3); /* ctzll must be called only with D
                                             != 0 */
                        break;
                      }
                    if (length > incoming.length)
                      {
                        incoming.length = length;
                        incoming.ref = ref;
                      } /* keep if longer */
                  }
                }
              }
          }

          /* No incoming match? */
          if (incoming.length == 0)
            {
              /* We may still want to emit some literals here, to not lag too
               * far behind */
              /* the current search point, and avoid */
              /* ending up with a literal block not fitting in the state. */
              lzfse_offset n_literals = pos - s->src_literal;
              /* The threshold here should be larger than a couple of
               * MAX_L_VALUE, and */
              /* much smaller than LITERALS_PER_BLOCK */
              if (n_literals > 8 * LZFSE_ENCODE_MAX_L_VALUE)
                {
                  /* Here, we need to consume some literals. Emit pending match
                   * if there */
                  /* is one */
                  if (s->pending.length > 0)
                    {
                      if (lzfse_backend_match (s, &s->pending)
                          != LZFSE_STATUS_OK)
                        {
                          ok = 0;
                          goto IZ_LZFSE_FINISH;
                        }
                      s->pending = NO_MATCH;
                    }
                  else
                    {
                      /* No pending match, emit a full LZFSE_ENCODE_MAX_L_VALUE
                       * block of */
                      /* literals */
                      if (lzfse_backend_literals (s, LZFSE_ENCODE_MAX_L_VALUE)
                          != LZFSE_STATUS_OK)
                        {
                          ok = 0;
                          goto IZ_LZFSE_FINISH;
                        }
                    }
                }
              goto END_POS; /* no incoming match */
            }

          /* Limit match length (it may still be expanded backwards, but this
           * is */
          /* bounded by the limit on literals we tested before) */
          if (incoming.length > LZFSE_ENCODE_MAX_MATCH_LENGTH)
            {
              incoming.length = LZFSE_ENCODE_MAX_MATCH_LENGTH;
            }

          /* Expand backwards (since this is expensive, we do this for the best
           * match */
          /* only) */
          while (incoming.pos > s->src_literal && incoming.ref > 0
                 && s->src[incoming.ref - 1] == s->src[incoming.pos - 1])
            {
              incoming.pos--;
              incoming.ref--;
            }
          incoming.length
              += pos - incoming.pos; /* update length after expansion */

          /* Match filtering heuristic (from LZVN). INCOMING is always defined
           * here. */

          /* Incoming is 'good', emit incoming */
          if (incoming.length >= s->good_match_length)
            {
              if (lzfse_backend_match (s, &incoming) != LZFSE_STATUS_OK)
                {
                  ok = 0;
                  goto IZ_LZFSE_FINISH;
                }
              s->pending = NO_MATCH;
              goto END_POS;
            }

          /* No pending, keep incoming */
          if (s->pending.length == 0)
            {
              s->pending = incoming;
              goto END_POS;
            }

          /* No overlap, emit pending, keep incoming */
          if (s->pending.pos + s->pending.length <= incoming.pos)
            {
              if (lzfse_backend_match (s, &s->pending) != LZFSE_STATUS_OK)
                {
                  ok = 0;
                  goto IZ_LZFSE_FINISH;
                }
              s->pending = incoming;
              goto END_POS;
            }

          /* Overlap: emit longest */
          if (incoming.length > s->pending.length)
            {
              if (lzfse_backend_match (s, &incoming) != LZFSE_STATUS_OK)
                {
                  ok = 0;
                  goto IZ_LZFSE_FINISH;
                }
            }
          else
            {
              if (lzfse_backend_match (s, &s->pending) != LZFSE_STATUS_OK)
                {
                  ok = 0;
                  goto IZ_LZFSE_FINISH;
                }
            }
          s->pending = NO_MATCH;

        END_POS:
          /* We are done with this src_encode_i. */
          /* Update state now (s->pending has already been updated). */
          *hashLine = newH;
          if (hashLineExtra)
            *hashLineExtra = newExtraH;
        }
      }
    }

IZ_LZFSE_FINISH:
  return ok ? LZFSE_STATUS_OK : LZFSE_STATUS_DST_FULL;
}

int
lzfse_encode_finish (lzfse_encoder_state *s)
{
  const lzfse_match NO_MATCH = { 0 };

  /* Emit pending match */
  if (s->pending.length > 0)
    {
      if (lzfse_backend_match (s, &s->pending) != LZFSE_STATUS_OK)
        return LZFSE_STATUS_DST_FULL;
      s->pending = NO_MATCH;
    }

  /* Emit final literals if any */
  {
    lzfse_offset L = s->src_end - s->src_literal;
    if (L > 0)
      {
        if (lzfse_backend_literals (s, L) != LZFSE_STATUS_OK)
          return LZFSE_STATUS_DST_FULL;
      }

    /* Emit all matches, and end-of-stream block */
    if (lzfse_backend_end_of_stream (s) != LZFSE_STATUS_OK)
      return LZFSE_STATUS_DST_FULL;

    return LZFSE_STATUS_OK;
  }
}

/* ===== original lzfse_decode_base.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*! @abstract Decode an entry value from next bits of stream.
 *  Return \p value, and set \p *nbits to the number of bits to consume
 *  (starting with LSB). */
static int
lzfse_decode_v1_freq_value (izl_u32 bits, int *nbits)
{
  static const izl_s8 lzfse_freq_nbits_table[32]
      = { 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
          2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14 };
  static const izl_s8 lzfse_freq_value_table[32]
      = { 0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
          0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1 };

  izl_u32 b = bits & 31; /* lower 5 bits */
  int n = lzfse_freq_nbits_table[b];
  *nbits = n;

  /* Special cases for > 5 bits encoding */
  if (n == 8)
    return 8 + ((bits >> 4) & 0xf);
  if (n == 14)
    return 24 + ((bits >> 4) & 0x3ff);

  /* <= 5 bits encoding from table */
  return lzfse_freq_value_table[b];
}

/*! @abstract Extracts up to 32 bits from a 64-bit field beginning at
 *  \p offset, and zero-extends them to a \p izl_u32.
 *
 *  If we number the bits of \p v from 0 (least significant) to 63 (most
 *  significant), the result is bits \p offset to \p offset+nbits-1. */
static izl_u32
get_field (izl_u64 v, int offset, int nbits)
{
  assert (offset + nbits < 64 && offset >= 0 && nbits <= 32);
  if (nbits == 32)
    return (izl_u32)(v >> offset);
  return (izl_u32)((v >> offset) & ((1U << nbits) - 1U));
}

/*! @abstract Return \c header_size field from a \c
 * lzfse_compressed_block_header_v2. */
static izl_u32
lzfse_decode_v2_header_size (const lzfse_compressed_block_header_v2 *in)
{
  return get_field (load8 (in->packed_fields + 16), 0, 32);
}

/*! @abstract Decode all fields from a \c lzfse_compressed_block_header_v2 to a
 * \c lzfse_compressed_block_header_v1.
 * @return 0 on success.
 * @return -1 on failure. */
static int
lzfse_decode_v1 (lzfse_compressed_block_header_v1 *out,
                 const lzfse_compressed_block_header_v2 *in)
{
  /* Clear all fields */
  memset (out, 0x00, sizeof (lzfse_compressed_block_header_v1));

  {
    izl_u64 v0 = load8 (in->packed_fields + 0);
    izl_u64 v1 = load8 (in->packed_fields + 8);
    izl_u64 v2 = load8 (in->packed_fields + 16);

    out->magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
    out->n_raw_bytes = in->n_raw_bytes;

    /* Literal state */
    out->n_literals = get_field (v0, 0, 20);
    out->n_literal_payload_bytes = get_field (v0, 20, 20);
    out->literal_bits = (int)get_field (v0, 60, 3) - 7;
    out->literal_state[0] = get_field (v1, 0, 10);
    out->literal_state[1] = get_field (v1, 10, 10);
    out->literal_state[2] = get_field (v1, 20, 10);
    out->literal_state[3] = get_field (v1, 30, 10);

    /* L,M,D state */
    out->n_matches = get_field (v0, 40, 20);
    out->n_lmd_payload_bytes = get_field (v1, 40, 20);
    out->lmd_bits = (int)get_field (v1, 60, 3) - 7;
    out->l_state = get_field (v2, 32, 10);
    out->m_state = get_field (v2, 42, 10);
    out->d_state = get_field (v2, 52, 10);

    /* Total payload size */
    out->n_payload_bytes
        = out->n_literal_payload_bytes + out->n_lmd_payload_bytes;

    /* Freq tables */
    {
      izl_u16 *dst = &(out->l_freq[0]);
      const izl_u8 *src = &(in->freq[0]);
      const izl_u8 *src_end
          = (const izl_u8 *)in
            + get_field (v2, 0, 32); /* first byte after header */
      izl_u32 accum = 0;
      int accum_nbits = 0;

      /* No freq tables? */
      if (src_end == src)
        return 0; /* OK, freq tables were omitted */

      {
        int i;
        for (i = 0;
             i < LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS
                     + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS;
             i++)
          {
            /* Refill accum, one byte at a time, until we reach end of header,
             * or accum */
            /* is full */
            while (src < src_end && accum_nbits + 8 <= 32)
              {
                accum |= (izl_u32)(*src) << accum_nbits;
                accum_nbits += 8;
                src++;
              }

            /* Decode and store value */
            {
              int nbits = 0;
              dst[i] = lzfse_decode_v1_freq_value (accum, &nbits);

              if (nbits > accum_nbits)
                return -1; /* failed */

              /* Consume nbits bits */
              accum >>= nbits;
              accum_nbits -= nbits;
            }
          }
      }

      if (accum_nbits >= 8 || src != src_end)
        return -1; /* we need to end up exactly at the end of header, with less
                      than */
                   /* 8 bits in accumulator */

      return 0;
    }
  }
}

static void
copy (izl_u8 *dst, const izl_u8 *src, size_t length)
{
  const izl_u8 *dst_end = dst + length;
  do
    {
      copy8 (dst, src);
      dst += 8;
      src += 8;
    }
  while (dst < dst_end);
}

static int
lzfse_decode_lmd (lzfse_decoder_state *s)
{
  lzfse_compressed_block_decoder_state *bs
      = &(s->compressed_lzfse_block_state);
  fse_state l_state = bs->l_state;
  fse_state m_state = bs->m_state;
  fse_state d_state = bs->d_state;
  fse_in_stream in = bs->lmd_in_stream;
  const izl_u8 *src_start = s->src_begin;
  const izl_u8 *src = s->src + bs->lmd_in_buf;
  const izl_u8 *lit = bs->current_literal;
  izl_u8 *dst = s->dst;
  izl_u32 symbols = bs->n_matches;
  izl_s32 L = bs->l_value;
  izl_s32 M = bs->m_value;
  izl_s32 D = bs->d_value;

  assert (l_state < LZFSE_ENCODE_L_STATES);
  assert (m_state < LZFSE_ENCODE_M_STATES);
  assert (d_state < LZFSE_ENCODE_D_STATES);

  /*  Number of bytes remaining in the destination buffer, minus 32 to */
  /*  provide a margin of safety for using overlarge copies on the fast path.
   */
  /*  This is a signed quantity, and may go negative when we are close to the
   */
  /*  end of the buffer.  That's OK; we're careful about how we handle it */
  /*  in the slow-and-careful match execution path. */
  {
    ptrdiff_t remaining_bytes = s->dst_end - dst - 32;

    /*  If L or M is non-zero, that means that we have already started decoding
     */
    /*  this block, and that we needed to interrupt decoding to get more space
     */
    /*  from the caller.  There's a pending L, M, D triplet that we weren't */
    /*  able to completely process.  Jump ahead to finish executing that symbol
     */
    /*  before decoding new values. */
    if (L || M)
      goto ExecuteMatch;

    while (symbols > 0)
      {
        int res;
        /*  Decode the next L, M, D symbol from the input stream. */
        res = fse_in_flush (&in, &src, src_start);
        if (res)
          {
            return LZFSE_STATUS_ERROR;
          }
        L = fse_value_decode (&l_state, bs->l_decoder, &in);
        assert (l_state < LZFSE_ENCODE_L_STATES);
        if ((lit + L) >= (bs->literals + LZFSE_LITERALS_PER_BLOCK + 64))
          {
            return LZFSE_STATUS_ERROR;
          }
        res = fse_in_flush2 (&in, &src, src_start);
        if (res)
          {
            return LZFSE_STATUS_ERROR;
          }
        M = fse_value_decode (&m_state, bs->m_decoder, &in);
        assert (m_state < LZFSE_ENCODE_M_STATES);
        res = fse_in_flush2 (&in, &src, src_start);
        if (res)
          {
            return LZFSE_STATUS_ERROR;
          }
        {
          izl_s32 new_d = fse_value_decode (&d_state, bs->d_decoder, &in);
          assert (d_state < LZFSE_ENCODE_D_STATES);
          D = new_d ? new_d : D;
          symbols--;

        ExecuteMatch:
          /*  Error if D is out of range, so that we avoid passing through */
          /*  uninitialized data or accesssing memory out of the destination */
          /*  buffer. */
          if ((izl_u32)D > dst + L - s->dst_begin)
            return LZFSE_STATUS_ERROR;

          if (L + M <= remaining_bytes)
            {
              /*  If we have plenty of space remaining, we can copy the literal
               */
              /*  and match with 16- and 32-byte operations, without worrying
               */
              /*  about writing off the end of the buffer. */
              remaining_bytes -= L + M;
              copy (dst, lit, L);
              dst += L;
              lit += L;
              /*  For the match, we have two paths; a fast copy by 16-bytes if
               */
              /*  the match distance is large enough to allow it, and a more */
              /*  careful path that applies a permutation to account for the */
              /*  possible overlap between source and destination if the
               * distance */
              /*  is small. */
              if (D >= 8 || D >= M)
                copy (dst, dst - D, M);
              else
                {
                  izl_s32 i;
                  for (i = 0; i < M; i++)
                    dst[i] = dst[i - D];
                }
              dst += M;
            }

          else
            {
              /*  Otherwise, we are very close to the end of the destination */
              /*  buffer, so we cannot use wide copies that slop off the end */
              /*  of the region that we are copying to. First, we restore */
              /*  the true length remaining, rather than the sham value we've
               */
              /*  been using so far. */
              remaining_bytes += 32;
              /*  Now, we process the literal. Either there's space for it */
              /*  or there isn't; if there is, we copy the whole thing and */
              /*  update all the pointers and lengths to reflect the copy. */
              if (L <= remaining_bytes)
                {
                  {
                    izl_s32 i;
                    for (i = 0; i < L; i++)
                      dst[i] = lit[i];
                  }
                  dst += L;
                  lit += L;
                  remaining_bytes -= L;
                  L = 0;
                }
              /*  There isn't enough space to fit the whole literal. Copy as */
              /*  much of it as we can, update the pointers and the value of */
              /*  L, and report that the destination buffer is full. Note that
               */
              /*  we always write right up to the end of the destination
               * buffer. */
              else
                {
                  {
                    ptrdiff_t i;
                    for (i = 0; i < remaining_bytes; i++)
                      dst[i] = lit[i];
                  }
                  dst += remaining_bytes;
                  lit += remaining_bytes;
                  L -= remaining_bytes;
                  goto DestinationBufferIsFull;
                }
              /*  The match goes just like the literal does. We copy as much as
               */
              /*  we can byte-by-byte, and if we reach the end of the buffer */
              /*  before finishing, we return to the caller indicating that */
              /*  the buffer is full. */
              if (M <= remaining_bytes)
                {
                  {
                    izl_s32 i;
                    for (i = 0; i < M; i++)
                      dst[i] = dst[i - D];
                  }
                  dst += M;
                  remaining_bytes -= M;
                  M = 0;
                  (void)M; /* no dead store warning */
                  /*  We don't need to update M = 0, because there's no partial
                   */
                  /*  symbol to continue executing. Either we're at the end of
                   */
                  /*  the block, in which case we will never need to resume
                   * with */
                  /*  this state, or we're going to decode another L, M, D set,
                   */
                  /*  which will overwrite M anyway. */
                  /* */
                  /* But we still set M = 0, to maintain the post-condition. */
                }
              else
                {
                  {
                    ptrdiff_t i;
                    for (i = 0; i < remaining_bytes; i++)
                      dst[i] = dst[i - D];
                  }
                  dst += remaining_bytes;
                  M -= remaining_bytes;
                DestinationBufferIsFull:
                  /*  Because we want to be able to resume decoding where we've
                   * left */
                  /*  off (even in the middle of a literal or match), we need
                   * to */
                  /*  update all of the block state fields with the current
                   * values */
                  /*  so that we can resume execution from this point once the
                   */
                  /*  caller has given us more space to write into. */
                  bs->l_value = L;
                  bs->m_value = M;
                  bs->d_value = D;
                  bs->l_state = l_state;
                  bs->m_state = m_state;
                  bs->d_state = d_state;
                  bs->lmd_in_stream = in;
                  bs->n_matches = symbols;
                  bs->lmd_in_buf = (izl_u32)(src - s->src);
                  bs->current_literal = lit;
                  s->dst = dst;
                  return LZFSE_STATUS_DST_FULL;
                }
              /*  Restore the "sham" decremented value of remaining_bytes and
               */
              /*  continue to the next L, M, D triple. We'll just be back in */
              /*  the careful path again, but this only happens at the very end
               */
              /*  of the buffer, so a little minor inefficiency here is a good
               */
              /*  tradeoff for simpler code. */
              remaining_bytes -= 32;
            }
        }
      }
    /*  Because we've finished with the whole block, we don't need to update */
    /*  any of the blockstate fields; they will not be used again. We just */
    /*  update the destination pointer in the state object and return. */
    s->dst = dst;
    return LZFSE_STATUS_OK;
  }
}

int
lzfse_decode (lzfse_decoder_state *s)
{
  while (1)
    {
      /* Are we inside a block? */
      switch (s->block_magic)
        {
        case LZFSE_NO_BLOCK_MAGIC:
          {
            /* We need at least 4 bytes of magic number to identify next block
             */
            if (s->src + 4 > s->src_end)
              return LZFSE_STATUS_SRC_EMPTY; /* SRC truncated */
            {
              izl_u32 magic = load4 (s->src);

              if (magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC)
                {
                  s->src += 4;
                  s->end_of_stream = 1;
                  return LZFSE_STATUS_OK; /* done */
                }

              if (magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC)
                {
                  if (s->src + sizeof (uncompressed_block_header) > s->src_end)
                    return LZFSE_STATUS_SRC_EMPTY; /* SRC truncated */
                  /* Setup state for uncompressed block */
                  {
                    uncompressed_block_decoder_state *bs
                        = &(s->uncompressed_block_state);
                    bs->n_raw_bytes = load4 (
                        s->src
                        + offsetof (uncompressed_block_header, n_raw_bytes));
                    s->src += sizeof (uncompressed_block_header);
                    s->block_magic = magic;
                    break;
                  }
                }

              if (magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC)
                {
                  if (s->src + sizeof (lzvn_compressed_block_header)
                      > s->src_end)
                    return LZFSE_STATUS_SRC_EMPTY; /* SRC truncated */
                  /* Setup state for compressed LZVN block */
                  {
                    lzvn_compressed_block_decoder_state *bs
                        = &(s->compressed_lzvn_block_state);
                    bs->n_raw_bytes
                        = load4 (s->src
                                 + offsetof (lzvn_compressed_block_header,
                                             n_raw_bytes));
                    bs->n_payload_bytes
                        = load4 (s->src
                                 + offsetof (lzvn_compressed_block_header,
                                             n_payload_bytes));
                    bs->d_prev = 0;
                    s->src += sizeof (lzvn_compressed_block_header);
                    s->block_magic = magic;
                    break;
                  }
                }

              if (magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC
                  || magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC)
                {
                  lzfse_compressed_block_header_v1 header1;
                  size_t header_size = 0;

                  /* Decode compressed headers */
                  if (magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC)
                    {
                      /* Check we have the fixed part of the structure */
                      if (s->src
                              + offsetof (lzfse_compressed_block_header_v2,
                                          freq)
                          > s->src_end)
                        return LZFSE_STATUS_SRC_EMPTY; /* SRC truncated */

                      /* Read the fixed fields into aligned storage first.  A
                       * compressed block need not begin at a naturally aligned
                       * address. */
                      {
                        lzfse_compressed_block_header_v2 header2;
                        size_t remaining = (size_t)(s->src_end - s->src);
                        size_t minimum = offsetof (
                            lzfse_compressed_block_header_v2, freq);
                        memset (&header2, 0, sizeof (header2));
                        memcpy (&header2, s->src, minimum);
                        header_size = lzfse_decode_v2_header_size (&header2);
                        if (header_size < minimum
                            || header_size > sizeof (header2))
                          return LZFSE_STATUS_ERROR;
                        if (header_size > remaining)
                          return LZFSE_STATUS_SRC_EMPTY; /* SRC truncated */
                        memcpy (&header2, s->src, header_size);
                        if (lzfse_decode_v1 (&header1, &header2) != 0)
                          return LZFSE_STATUS_ERROR;
                      }
                    }
                  else
                    {
                      if (s->src + sizeof (lzfse_compressed_block_header_v1)
                          > s->src_end)
                        return LZFSE_STATUS_SRC_EMPTY; /* SRC truncated */
                      memcpy (&header1, s->src,
                              sizeof (lzfse_compressed_block_header_v1));
                      header_size = sizeof (lzfse_compressed_block_header_v1);
                    }

                  /* We require the header + entire encoded block to be present
                   * in SRC */
                  /* during the entire block decoding. */
                  /* This can be relaxed somehow, if it becomes a limiting
                   * factor, at the */
                  /* price of a more complex state maintenance. */
                  /* For DST, we can't easily require space for the entire
                   * decoded block, */
                  /* because it may expand to something very very large. */
                  {
                    size_t remaining = (size_t)(s->src_end - s->src);
                    if (header_size > remaining)
                      return LZFSE_STATUS_SRC_EMPTY;
                    remaining -= header_size;
                    if ((size_t)header1.n_literal_payload_bytes > remaining)
                      return LZFSE_STATUS_SRC_EMPTY;
                    remaining -= (size_t)header1.n_literal_payload_bytes;
                    if ((size_t)header1.n_lmd_payload_bytes > remaining)
                      return LZFSE_STATUS_SRC_EMPTY;
                  }

                  /* Sanity checks */
                  if (lzfse_check_block_header_v1 (&header1) != 0)
                    {
                      return LZFSE_STATUS_ERROR;
                    }

                  /* Skip header */
                  s->src += header_size;

                  /* Setup state for compressed V1 block from header */
                  {
                    lzfse_compressed_block_decoder_state *bs
                        = &(s->compressed_lzfse_block_state);
                    bs->n_lmd_payload_bytes = header1.n_lmd_payload_bytes;
                    bs->n_matches = header1.n_matches;
                    fse_init_decoder_table (LZFSE_ENCODE_LITERAL_STATES,
                                            LZFSE_ENCODE_LITERAL_SYMBOLS,
                                            header1.literal_freq,
                                            bs->literal_decoder);
                    fse_init_value_decoder_table (LZFSE_ENCODE_L_STATES,
                                                  LZFSE_ENCODE_L_SYMBOLS,
                                                  header1.l_freq, l_extra_bits,
                                                  l_base_value, bs->l_decoder);
                    fse_init_value_decoder_table (LZFSE_ENCODE_M_STATES,
                                                  LZFSE_ENCODE_M_SYMBOLS,
                                                  header1.m_freq, m_extra_bits,
                                                  m_base_value, bs->m_decoder);
                    fse_init_value_decoder_table (LZFSE_ENCODE_D_STATES,
                                                  LZFSE_ENCODE_D_SYMBOLS,
                                                  header1.d_freq, d_extra_bits,
                                                  d_base_value, bs->d_decoder);

                    /* Decode literals */
                    {
                      fse_in_stream in;
                      const izl_u8 *buf_start = s->src_begin;
                      s->src
                          += header1.n_literal_payload_bytes; /* skip literal
                                                                 payload */
                      {
                        const izl_u8 *buf
                            = s->src; /* read bits backwards from the end */
                        if (fse_in_init (&in, header1.literal_bits, &buf,
                                         buf_start)
                            != 0)
                          return LZFSE_STATUS_ERROR;

                        {
                          fse_state state0 = header1.literal_state[0];
                          fse_state state1 = header1.literal_state[1];
                          fse_state state2 = header1.literal_state[2];
                          fse_state state3 = header1.literal_state[3];

                          {
                            izl_u32 i;
                            for (i = 0; i < header1.n_literals;
                                 i += 4) /* n_literals is multiple of 4 */
                              {
#if FSE_IOSTREAM_64
                                if (fse_in_flush (&in, &buf, buf_start) != 0)
                                  return LZFSE_STATUS_ERROR; /* [57, 64] bits
                                                              */
                                bs->literals[i + 0]
                                    = fse_decode (&state0, bs->literal_decoder,
                                                  &in); /* 10b max */
                                bs->literals[i + 1]
                                    = fse_decode (&state1, bs->literal_decoder,
                                                  &in); /* 10b max */
                                bs->literals[i + 2]
                                    = fse_decode (&state2, bs->literal_decoder,
                                                  &in); /* 10b max */
                                bs->literals[i + 3]
                                    = fse_decode (&state3, bs->literal_decoder,
                                                  &in); /* 10b max */
#else
                                      if (fse_in_flush (&in, &buf, buf_start)
                                          != 0)
                                        return LZFSE_STATUS_ERROR; /* [25, 23]
                                                                      bits */
                                      bs->literals[i + 0] = fse_decode (
                                          &state0, bs->literal_decoder,
                                          &in); /* 10b max */
                                      bs->literals[i + 1] = fse_decode (
                                          &state1, bs->literal_decoder,
                                          &in); /* 10b max */
                                      if (fse_in_flush (&in, &buf, buf_start)
                                          != 0)
                                        return LZFSE_STATUS_ERROR; /* [25, 23]
                                                                      bits */
                                      bs->literals[i + 2] = fse_decode (
                                          &state2, bs->literal_decoder,
                                          &in); /* 10b max */
                                      bs->literals[i + 3] = fse_decode (
                                          &state3, bs->literal_decoder,
                                          &in); /* 10b max */
#endif
                              }
                          }

                          bs->current_literal = bs->literals;
                        }
                      }
                    } /* literals */

                    /* SRC is not incremented to skip the LMD payload, since we
                     * need it */
                    /* during block decode. */
                    /* We will increment SRC at the end of the block only after
                     * this point. */

                    /* Initialize the L,M,D decode stream, do not start
                     * decoding matches */
                    /* yet, and store decoder state */
                    {
                      fse_in_stream in;
                      /* read bits backwards from the end */
                      const izl_u8 *buf = s->src + header1.n_lmd_payload_bytes;
                      if (fse_in_init (&in, header1.lmd_bits, &buf, s->src)
                          != 0)
                        return LZFSE_STATUS_ERROR;

                      bs->l_state = header1.l_state;
                      bs->m_state = header1.m_state;
                      bs->d_state = header1.d_state;
                      bs->lmd_in_buf = (izl_u32)(buf - s->src);
                      bs->l_value = bs->m_value = 0;
                      /*  Initialize D to an illegal value so we can't
                       * erroneously use */
                      /*  an uninitialized "previous" value. */
                      bs->d_value = -1;
                      bs->lmd_in_stream = in;
                    }

                    s->block_magic = magic;
                    break;
                  }
                }

              /* Here we have an invalid magic number */
              return LZFSE_STATUS_ERROR;
            }
          } /* LZFSE_NO_BLOCK_MAGIC */

        case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
          {
            uncompressed_block_decoder_state *bs
                = &(s->uncompressed_block_state);

            /*  Compute the size (in bytes) of the data that we will actually
             * copy. */
            /*  This size is minimum(bs->n_raw_bytes, space in src, space in
             * dst). */

            izl_u32 copy_size = bs->n_raw_bytes; /* bytes left to copy */
            if (copy_size == 0)
              {
                s->block_magic = 0;
                break;
              } /* end of block */

            if (s->src_end <= s->src)
              return LZFSE_STATUS_SRC_EMPTY; /* need more SRC data */
            {
              const size_t src_space = s->src_end - s->src;
              if (copy_size > src_space)
                copy_size = (izl_u32)src_space; /* limit to SRC data (> 0) */

              if (s->dst_end <= s->dst)
                return LZFSE_STATUS_DST_FULL; /* need more DST capacity */
              {
                const size_t dst_space = s->dst_end - s->dst;
                if (copy_size > dst_space)
                  copy_size
                      = (izl_u32)dst_space; /* limit to DST capacity (> 0) */

                /* Now that we know that the copy size is bounded to the source
                 * and */
                /* dest buffers, go ahead and copy the data. */
                /* We always have copy_size > 0 here */
                memcpy (s->dst, s->src, copy_size);
                s->src += copy_size;
                s->dst += copy_size;
                bs->n_raw_bytes -= copy_size;

                break;
              }
            }
          } /* LZFSE_UNCOMPRESSED_BLOCK_MAGIC */

        case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
        case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
          {
            lzfse_compressed_block_decoder_state *bs
                = &(s->compressed_lzfse_block_state);
            /* Require the entire LMD payload to be in SRC */
            if (s->src_end <= s->src
                || bs->n_lmd_payload_bytes > (size_t)(s->src_end - s->src))
              return LZFSE_STATUS_SRC_EMPTY;

            {
              int status = lzfse_decode_lmd (s);
              if (status != LZFSE_STATUS_OK)
                return status;

              s->block_magic = LZFSE_NO_BLOCK_MAGIC;
              s->src += bs->n_lmd_payload_bytes; /* to next block */
              break;
            }
          } /* LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC
             */

        case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
          {
            lzvn_compressed_block_decoder_state *bs
                = &(s->compressed_lzvn_block_state);
            if (bs->n_payload_bytes > 0 && s->src_end <= s->src)
              return LZFSE_STATUS_SRC_EMPTY; /* need more SRC data */

            /* Init LZVN decoder state */
            {
              lzvn_decoder_state dstate;
              memset (&dstate, 0x00, sizeof (dstate));
              dstate.src = s->src;
              dstate.src_end = s->src_end;
              if (dstate.src_end - s->src > bs->n_payload_bytes)
                dstate.src_end
                    = s->src
                      + bs->n_payload_bytes; /* limit to payload bytes */
              dstate.dst_begin = s->dst_begin;
              dstate.dst = s->dst;
              dstate.dst_end = s->dst_end;
              if (dstate.dst_end - s->dst > bs->n_raw_bytes)
                dstate.dst_end
                    = s->dst + bs->n_raw_bytes; /* limit to raw bytes */
              dstate.d_prev = bs->d_prev;
              dstate.end_of_stream = 0;

              /* Run LZVN decoder */
              lzvn_decode (&dstate);

              /* Update our state */
              {
                size_t src_used = dstate.src - s->src;
                size_t dst_used = dstate.dst - s->dst;
                if (src_used > bs->n_payload_bytes
                    || dst_used > bs->n_raw_bytes)
                  return LZFSE_STATUS_ERROR; /* sanity check */
                s->src = dstate.src;
                s->dst = dstate.dst;
                bs->n_payload_bytes -= (izl_u32)src_used;
                bs->n_raw_bytes -= (izl_u32)dst_used;
                bs->d_prev = (izl_u32)dstate.d_prev;

                /* Test end of block */
                if (bs->n_payload_bytes == 0 && bs->n_raw_bytes == 0
                    && dstate.end_of_stream)
                  {
                    s->block_magic = 0;
                    break;
                  } /* block done */

                /* Check for invalid state */
                if (bs->n_payload_bytes == 0 || bs->n_raw_bytes == 0
                    || dstate.end_of_stream)
                  return LZFSE_STATUS_ERROR;

                /* Here, block is not done and state is valid, so we need more
                 * space in dst. */
                return LZFSE_STATUS_DST_FULL;
              }
            }
          }

        default:
          return LZFSE_STATUS_ERROR; /* invalid magic */

        } /* switch magic */

    } /* block loop */

  return LZFSE_STATUS_OK;
}

/* ===== original lzfse_encode.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZFSE encode API */

size_t
lzfse_encode_scratch_size (void)
{
  size_t s1 = sizeof (lzfse_encoder_state);
  size_t s2 = lzvn_encode_scratch_size ();
  return (s1 > s2) ? s1 : s2; /* max(lzfse,lzvn) */
}

size_t
lzfse_encode_buffer_with_options (izl_u8 *dst_buffer, size_t dst_size,
                                  const izl_u8 *src_buffer, size_t src_size,
                                  void *scratch_buffer,
                                  lzfse_history_set *ultra_history,
                                  lzfse_history_set *ultra_history_extra,
                                  unsigned int active_hash_bits,
                                  unsigned int good_match_length)
{
  const size_t original_size = src_size;

  /* If input is really really small, go directly to uncompressed buffer */
  /* (because LZVN will refuse to encode it, and we will report a failure) */
  if (src_size < LZVN_ENCODE_MIN_SRC_SIZE)
    goto try_uncompressed;

  /* If input is too small, try encoding with LZVN */
  if (src_size < LZFSE_ENCODE_LZVN_THRESHOLD)
    {
      /* need header + end-of-stream marker */
      size_t extra_size = 4 + sizeof (lzvn_compressed_block_header);
      if (dst_size <= extra_size)
        goto try_uncompressed; /* DST is really too small, give up */

      {
        size_t sz = lzvn_encode_buffer (
            dst_buffer + sizeof (lzvn_compressed_block_header),
            dst_size - extra_size, src_buffer, src_size, scratch_buffer);
        if (sz == 0 || sz >= src_size)
          goto try_uncompressed; /* failed, or no compression, fall back to */
                                 /* uncompressed block */

        /* If we could encode, setup header and end-of-stream marker (we left
         * room */
        /* for them, no need to test) */
        {
          lzvn_compressed_block_header header;
          header.magic = LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC;
          header.n_raw_bytes = (izl_u32)src_size;
          header.n_payload_bytes = (izl_u32)sz;
          memcpy (dst_buffer, &header, sizeof (header));
          store4 (dst_buffer + sizeof (lzvn_compressed_block_header) + sz,
                  LZFSE_ENDOFSTREAM_BLOCK_MAGIC);

          return sz + extra_size;
        }
      }
    }

  /* Try encoding with LZFSE */
  {
    lzfse_encoder_state *state = scratch_buffer;
    memset (state, 0x00, sizeof *state);
    state->ultra_history = ultra_history;
    state->ultra_history_extra = ultra_history_extra;
    state->active_hash_bits = active_hash_bits;
    state->good_match_length = good_match_length;
    if (lzfse_encode_init (state) != LZFSE_STATUS_OK)
      goto try_uncompressed;
    state->dst = dst_buffer;
    state->dst_begin = dst_buffer;
    state->dst_end = &dst_buffer[dst_size];
    state->src = src_buffer;
    state->src_encode_i = 0;

    if (src_size >= 0xffffffffU)
      {
        /*  lzfse only uses 32 bits for offsets internally, so if the input */
        /*  buffer is really huge, we need to process it in smaller chunks. */
        /*  Note that we switch over to this path for sizes much smaller */
        /*  2GB because it's actually faster to change algorithms well before
         */
        /*  it's necessary for correctness. */
        /*  The first chunk, we just process normally. */
        const lzfse_offset encoder_block_size = 262144;
        state->src_end = encoder_block_size;
        if (lzfse_encode_base (state) != LZFSE_STATUS_OK)
          goto try_uncompressed;
        src_size -= encoder_block_size;
        while (src_size >= (size_t)encoder_block_size)
          {
            /*  All subsequent chunks require a translation to keep the offsets
             */
            /*  from getting too big.  Note that we are always going from */
            /*  encoder_block_size up to 2*encoder_block_size so that the */
            /*  offsets remain positive (as opposed to resetting to zero and */
            /*  having negative offsets). */
            state->src_end = 2 * encoder_block_size;
            if (lzfse_encode_base (state) != LZFSE_STATUS_OK)
              goto try_uncompressed;
            lzfse_encode_translate (state, encoder_block_size);
            src_size -= encoder_block_size;
          }
        /*  Set the end for the final chunk. */
        state->src_end = encoder_block_size + (lzfse_offset)src_size;
      }
    /*  If the source buffer is small enough to use 32-bit offsets, we simply
     */
    /*  encode the whole thing in a single chunk. */
    else
      state->src_end = (lzfse_offset)src_size;
    /*  This is either the trailing chunk (if the source file is huge), or */
    /*  the whole source file. */
    if (lzfse_encode_base (state) != LZFSE_STATUS_OK)
      goto try_uncompressed;
    if (lzfse_encode_finish (state) != LZFSE_STATUS_OK)
      goto try_uncompressed;
    /*  No error occured, return compressed size. */
    return state->dst - dst_buffer;
  }

try_uncompressed:
  /*  Compression failed for some reason.  If we can fit the data into the */
  /*  output buffer uncompressed, go ahead and do that instead. */
  if (original_size + 12 <= dst_size && original_size < INT32_MAX)
    {
      uncompressed_block_header header;
      izl_u8 *dst_end = dst_buffer;
      header.magic = LZFSE_UNCOMPRESSED_BLOCK_MAGIC;
      header.n_raw_bytes = (izl_u32)original_size;
      memcpy (dst_end, &header, sizeof header);
      dst_end += sizeof header;
      memcpy (dst_end, src_buffer, original_size);
      dst_end += original_size;
      store4 (dst_end, LZFSE_ENDOFSTREAM_BLOCK_MAGIC);
      dst_end += 4;
      return dst_end - dst_buffer;
    }

  /*  Otherwise, there's nothing we can do, so return zero. */
  return 0;
}

size_t
lzfse_encode_buffer (izl_u8 *dst_buffer, size_t dst_size,
                     const izl_u8 *src_buffer, size_t src_size,
                     void *scratch_buffer)
{
  int has_malloc = 0;
  size_t ret = 0;

  /* Deal with the possible NULL pointer */
  if (scratch_buffer == NULL)
    {
      /* +1 in case scratch size could be zero */
      scratch_buffer = malloc (lzfse_encode_scratch_size () + 1);
      has_malloc = 1;
    }
  if (scratch_buffer == NULL)
    return 0;
  ret = lzfse_encode_buffer_with_options (dst_buffer, dst_size, src_buffer,
                                       src_size, scratch_buffer, NULL, NULL,
                                       LZFSE_ENCODE_HASH_BITS,
                                       LZFSE_ENCODE_GOOD_MATCH);
  if (has_malloc)
    free (scratch_buffer);
  return ret;
}

/* Private -11 candidate: eight retained match positions, 14-16 hash bits.
 * All parameters affect encoder search only; the stream format is unchanged.
 * Failure returns zero, allowing Zip to retain its default candidate.
 * No global state or decoder modifications. */
static size_t
iz_lzfse_encode_ultra_candidate (izl_u8 *dst, size_t dst_size,
                                  const izl_u8 *src, size_t src_size,
                                  void *scratch, unsigned int hash_bits,
                                  unsigned int good_match)
{
  lzfse_history_set *history, *extra;
  size_t count, result;
  if (hash_bits < 14U || hash_bits > 16U || good_match == 0U)
    return 0;
  count = (size_t)1U << hash_bits;
  history = (lzfse_history_set *)malloc (count * sizeof (*history));
  extra = (lzfse_history_set *)malloc (count * sizeof (*extra));
  if (history == NULL || extra == NULL)
    {
      free (history);
      free (extra);
      return 0;
    }
  result = lzfse_encode_buffer_with_options (dst, dst_size, src, src_size,
                                             scratch, history, extra,
                                             hash_bits, good_match);
  free (history);
  free (extra);
  return result;
}

/* ===== original lzfse_decode.c ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZFSE decode API */

size_t
lzfse_decode_scratch_size (void)
{
  return sizeof (lzfse_decoder_state);
}

size_t
lzfse_decode_buffer_with_scratch (izl_u8 *dst_buffer, size_t dst_size,
                                  const izl_u8 *src_buffer, size_t src_size,
                                  void *scratch_buffer)
{
  lzfse_decoder_state *s = (lzfse_decoder_state *)scratch_buffer;
  memset (s, 0x00, sizeof (*s));

  /* Initialize state */
  s->src = src_buffer;
  s->src_begin = src_buffer;
  s->src_end = s->src + src_size;
  s->dst = dst_buffer;
  s->dst_begin = dst_buffer;
  s->dst_end = dst_buffer + dst_size;

  /* Decode */
  {
    int status = lzfse_decode (s);
    if (status == LZFSE_STATUS_DST_FULL)
      return dst_size;
    if (status != LZFSE_STATUS_OK)
      return 0;                           /* failed */
    return (size_t)(s->dst - dst_buffer); /* bytes written */
  }
}

size_t
lzfse_decode_buffer (izl_u8 *dst_buffer, size_t dst_size,
                     const izl_u8 *src_buffer, size_t src_size,
                     void *scratch_buffer)
{
  int has_malloc = 0;
  size_t ret = 0;

  /* Deal with the possible NULL pointer */
  if (scratch_buffer == NULL)
    {
      /* +1 in case scratch size could be zero */
      scratch_buffer = malloc (lzfse_decode_scratch_size () + 1);
      has_malloc = 1;
    }
  if (scratch_buffer == NULL)
    return 0;
  ret = lzfse_decode_buffer_with_scratch (dst_buffer, dst_size, src_buffer,
                                          src_size, scratch_buffer);
  if (has_malloc)
    free (scratch_buffer);
  return ret;
}
