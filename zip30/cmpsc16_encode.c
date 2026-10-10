/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmpsc16_ascii_dict.h"

#define IZCM_NSYM 2048U
#define IZCM_PHRASE 260U

typedef unsigned (*izcm_read_fn) (void *, unsigned char *, unsigned);
typedef int (*izcm_write_fn) (void *, const unsigned char *, unsigned);
typedef struct
{
  unsigned char phrase[IZCM_NSYM][IZCM_PHRASE];
  unsigned short length[IZCM_NSYM];
  unsigned short next[IZCM_NSYM];
  unsigned short heads[256];
} izcm_enc;

static int
izcm_expand (izcm_enc *state, unsigned symbol)
{
  const unsigned char *e;
  unsigned char filled[IZCM_PHRASE];
  unsigned index, n = 0U, steps = 0U, psl, csl, offset, i;

  if (symbol < 256U)
    {
      state->phrase[symbol][0] = (unsigned char)symbol;
      state->length[symbol] = 1U;
      return 1;
    }

  memset (filled, 0, sizeof filled);
  index = symbol;
  for (;;)
    {
      if (++steps > IZCM_PHRASE || index >= IZCM_NSYM)
        {
          return 0;
        }

      e = iz_cmpsc16_ascii_dict + index * 8U;
      psl = (unsigned)(e[0] >> 5);
      if (psl)
        {
          if (psl > 5U)
            {
              return 0;
            }

          offset = (unsigned)e[7];
          if (offset > IZCM_PHRASE - psl)
            {
              return 0;
            }

          for (i = 0U; i < psl; ++i)
            {
              if (filled[offset + i])
                {
                  return 0;
                }

              state->phrase[symbol][offset + i] = e[2U + i];
              filled[offset + i] = 1U;
            }

          if (offset + psl > n)
            {
              n = offset + psl;
            }

          index = (((unsigned)e[0] & 31U) << 8) | (unsigned)e[1];
        }
      else
        {
          if (e[0] & 24U)
            {
              return 0;
            }

          csl = (unsigned)e[0] & 7U;
          if (!csl)
            {
              return 0;
            }

          for (i = 0U; i < csl; ++i)
            {
              if (filled[i])
                {
                  return 0;
                }

              state->phrase[symbol][i] = e[i + 1U];
              filled[i] = 1U;
            }

          if (csl > n)
            {
              n = csl;
            }

          for (i = 0U; i < n; ++i)
            {
              if (!filled[i])
                {
                  return 0;
                }
            }

          state->length[symbol] = (unsigned short)n;
          return n > 1U;
        }
    }
}

/* Returns 0 on success, -1 for I/O failure, -2 for allocation failure.
 * byte counting is handled by the ZIP adapter's write callback. */
static int
izcm_encode (izcm_read_fn reader, izcm_write_fn writer, void *ctx)
{
  izcm_enc *state;
  unsigned char look[IZCM_PHRASE], out[4096];
  unsigned char head[6] = { 1U, 0x8bU, 0U, 0x40U, 0U, 0U };
  unsigned len = 0U, remaining, j, n, best, bestlen, s, have = 0U;
  unsigned accum = 0U, used = 0U, k;
  int eof = 0, rc = -1;

  state = (izcm_enc *)calloc (1U, sizeof *state);
  if (!state)
    {
      return -2;
    }

  for (s = 0U; s < 256U; ++s)
    {
      state->heads[s] = 0xffffU;
    }

  for (s = 0U; s < IZCM_NSYM; ++s)
    {
      if (izcm_expand (state, s))
        {
          k = (unsigned)state->phrase[s][0];
          state->next[s] = state->heads[k];
          state->heads[k] = (unsigned short)s;
        }
    }

  if (writer (ctx, head, 6U) || writer (ctx, iz_cmpsc16_ascii_dict, 16384U))
    {
      goto done;
    }

  while (!eof || len)
    {
      while (len < IZCM_PHRASE && !eof)
        {
          n = reader (ctx, look + len, IZCM_PHRASE - len);
          if (n == 0U)
            {
              eof = 1;
            }
          else if (n == (unsigned)EOF)
            {
              goto done;
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
              && memcmp (state->phrase[s], look, (size_t)sl) == 0)
            {
              best = s;
              bestlen = sl;
            }
        }

      for (j = 0U; j < 11U; ++j)
        {
          accum = (accum << 1) | ((best >> (10U - j)) & 1U);
          if (++have == 8U)
            {
              out[used++] = (unsigned char)accum;
              accum = 0U;
              have = 0U;
              if (used == sizeof out)
                {
                  if (writer (ctx, out, used))
                    {
                      goto done;
                    }

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

  if (used && writer (ctx, out, used))
    {
      goto done;
    }

  rc = 0;
done:
  free (state);
  return rc;
}
