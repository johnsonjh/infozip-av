/* SPDX-License-Identifier: MIT-0 */
#include "xtrwin_ads.h"
#include <stdio.h>
#include <string.h>
static unsigned count, failed;
#define C(x)                                                                  \
  do                                                                          \
    {                                                                         \
      count++;                                                                \
      if (!(x))                                                               \
        {                                                                     \
          failed++;                                                           \
          fprintf (stderr, "failed line %d: %s\n", __LINE__, #x);             \
        }                                                                     \
    }                                                                         \
  while (0)
static int
from_ascii (const char *src, xtr_ads_name *out)
{
  unsigned short w[300];
  size_t i, n = strlen (src);

  if (n > 299U)
    {
      return XTR_ADS_CORRUPT;
    }

  for (i = 0; i < n; i++)
    {
      w[i] = (unsigned char)src[i];
    }

  return xtr_ads_parse_stream (w, n, out);
}
int
main (void)
{
  xtr_ads_name result;
  unsigned short w[] = { ':', 0xd83d, 0xde00, ':', '$', 'D', 'A', 'T', 'A' };
  unsigned short bad[] = { ':', 0xd800, ':', '$', 'D', 'A', 'T', 'A' };
  unsigned i, j;

  C (from_ascii ("::$DATA", &result) == XTR_ADS_DEFAULT);
  C (from_ascii (":notes:$DATA", &result) == XTR_ADS_OK);
  C (result.utf8_len == 5U && !memcmp (result.utf8, "notes", 5));
  C (result.utf16_len == 5U);
  C (from_ascii (":notes:$data", &result) == XTR_ADS_OK);
  C (from_ascii (":notes:$INDEX_ALLOCATION", &result) != XTR_ADS_OK);
  C (from_ascii (":evil/path:$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (from_ascii (":evil\\path:$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (from_ascii (":evil:name:$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (from_ascii (":. :$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (from_ascii (":notes.:$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (from_ascii (":notes :$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (from_ascii (":hello:$DATA:$DATA", &result) == XTR_ADS_UNSUPPORTED);
  C (xtr_ads_parse_stream (w, sizeof (w) / sizeof (w[0]), &result)
     == XTR_ADS_OK);
  C (result.utf8_len == 4U && result.utf8[0] == 0xf0U
     && result.utf8[1] == 0x9fU);
  C (xtr_ads_parse_stream (bad, sizeof (bad) / sizeof (bad[0]), &result)
     == XTR_ADS_CORRUPT);
  C (from_ascii (":x:$DATA", NULL) == XTR_ADS_CORRUPT);
  /* Exhaustively fuzz short suffix corruption; parser must not overread. */
  for (i = 0; i < 256U; i++)
    {
      for (j = 0; j < 64U; j++)
        {
          unsigned short f[10]
              = { ':', 'f', ':', '$', 'D', 'A', 'T', 'A', 0, 0 };
          size_t n = 8U;
          f[(i + j) % n] = (unsigned short)((i * 217U + j * 129U) & 65535U);
          {
            int r = xtr_ads_parse_stream (f, n, &result);
            C (r == XTR_ADS_OK || r == XTR_ADS_DEFAULT || r == XTR_ADS_CORRUPT
               || r == XTR_ADS_UNSUPPORTED);
            if (r == XTR_ADS_OK)
              {
                C (result.utf8_len > 0U
                   && result.utf8_len <= XTR_ADS_MAX_UTF8);
                C (result.utf8[result.utf8_len] == 0U);
                C (result.utf16_len > 0U
                   && result.utf16_len <= XTR_ADS_MAX_NAME);
              }
          }
        }
    }

  printf ("Windows ADS Unicode name parser: %u checks, %u failures\n", count,
          failed);
  return failed ? 1 : 0;
}
