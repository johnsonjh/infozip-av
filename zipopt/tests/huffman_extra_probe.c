#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "huffman_extra.h"

int
main (void)
{
  unsigned t, n, i, j, pos, value, repeat, decoded;
  unsigned char seq[HE_MAX], initial[19];
  unsigned long freq[19];
  he_result result;
  unsigned long state = 0x123456UL;

  for (t = 0U; t < 1800U; ++t)
    {
      n = 1U + t % 318U;

      for (i = 0U; i < 19U; ++i)
        {
          freq[i] = (i % 7U) + 3U;
        }

      if (!he_lengths (freq, initial))
        {
          return 1;
        }

      for (i = 0U; i < n; ++i)
        {
          state = (state * 1664525UL + 1013904223UL) & 0xffffffffUL;
          seq[i] = (unsigned char)((state >> 16) & 15U);

          if (i >= 2U && (t % 5U == 0U))
            {
              seq[i] = seq[i - 1U];
            }

          if (i >= 3U && (t % 3U == 0U))
            {
              seq[i] = 0U;
            }
        }

      he_optimize (seq, n, initial, &result);

      if (result.cost >= HE_INF || !he_valid (result.lengths))
        {
          fprintf (stderr, "invalid result t=%u\n", t);

          return 2;
        }

      pos = 0U;

      for (j = 0U; j < result.count; ++j)
        {
          value = result.symbol[j];
          repeat = result.repeat[j];

          if (repeat == 0U || pos + repeat > n)
            {
              return 3;
            }

          if (value == 16U)
            {
              if (pos == 0U || repeat < 3U || repeat > 6U)
                {
                  return 4;
                }

              decoded = seq[pos - 1U];
            }
          else if (value == 17U || value == 18U)
            {
              if (repeat < (value == 17U ? 3U : 11U)
                  || repeat > (value == 17U ? 10U : 138U))
                {
                  return 5;
                }

              decoded = 0U;
            }
          else
            {
              if (value >= 16U || repeat != 1U)
                {
                  return 6;
                }

              decoded = value;
            }

          for (i = 0U; i < repeat; ++i)
            {
              if (seq[pos + i] != decoded)
                {
                  return 7;
                }
            }

          pos += repeat;
        }

      if (pos != n)
        {
          return 8;
        }

      if (he_exact (seq, n, result.lengths, NULL, NULL) != result.cost)
        {
          return 9;
        }
    }

  puts ("PASS: independent header invariants and RLE roundtrips");

  return 0;
}
