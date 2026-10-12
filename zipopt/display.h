/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* ZIP size and ratio display helpers */

#ifndef ZO_DISPLAY_H
# define ZO_DISPLAY_H

# include "archive.h"
# include <stdio.h>
# include <string.h>

/* Caller supplies at least 32 bytes (64-bit unsigned decimal + NUL). */
static const char *
zo_decimal (zo_u64 value, char text[32])
{
  char backward[32];
  unsigned n = 0, i;

  do
    {
      backward[n++] = (char)('0' + (unsigned)(value % 10U));
      value /= 10U;
    }
  while (value != 0);

  for (i = 0; i < n; i++)
    {
      text[i] = backward[n - 1 - i];
    }

  text[n] = '\0';

  return text;
}

/*
 * Group bytes in sets of three without relying on locale-specific printf
 * flags, which are not in ISO C89 and vary across platforms. Caller supplies
 * at least 32 bytes (20 digits + 6 commas + NUL for a 64-bit value).
 */

static const char *
zo_byte_decimal (zo_u64 value, char text[32])
{
  char decimal[32];
  unsigned digits, i, at = 0;

  zo_decimal (value, decimal);
  digits = (unsigned)strlen (decimal);

  for (i = 0; i < digits; i++)
    {
      if (i != 0 && (digits - i) % 3U == 0U)
        {
          text[at++] = ',';
        }

      text[at++] = decimal[i];
    }

  text[at] = '\0';

  return text;
}

/*
 * Display only: floating arithmetic avoids a 100 * (usize-csize) overflow.
 * Negative percentages are intentional when compression expands the data.
 */

static double
zo_ratio (zo_u64 usize, zo_u64 csize)
{
  double ratio;

  if (usize == 0)
    {
      return 0.0;
    }

  ratio = 100.0 * (1.0 - (double)csize / (double)usize);

  /* Avoid displaying negative zero when expansion rounds to 0%. */
  return (ratio > -0.5 && ratio < 0.5) ? 0.0 : ratio;
}

/*
 * Verbose-column helpers use fixed-size buffers. For 64-bit sizes,
 * even the largest possible percentage fits comfortably in 64 bytes.
 * A zero original packed size and nonzero candidate size have no finite
 * relative percentage, so report n/a rather than divide by zero.
 */

static void
zo_ratio_text (zo_u64 usize, zo_u64 csize, char text[64])
{
  double ratio = 0.0;

  /*
   * Use integer differences before conversion to avoid cancellation on
   * large ZIP64 sizes. The integer-rounded summary uses zo_ratio(),
   * whose +/-0.5 clamp would incorrectly hide 0.1% verbose changes.
   */

  if (usize != 0)
    {
      if (usize >= csize)
        {
          ratio = 100.0 * (double)(usize - csize) / (double)usize;
        }
      else
        {
          ratio = -100.0 * (double)(csize - usize) / (double)usize;
        }
    }

  if (ratio > -0.05 && ratio < 0.05)
    {
      ratio = 0.0;
    }

  sprintf (text, "%.1f%%", ratio);
}

static void
zo_change_text (zo_u64 original, zo_u64 candidate, char *marker, char text[64])
{
  zo_u64 diff;

  if (original == 0 && candidate != 0)
    {
      *marker = '?';
      sprintf (text, "n/a");

      return;
    }

  if (candidate > original)
    {
      *marker = '+';
      diff = candidate - original;
    }
  else if (candidate < original)
    {
      *marker = '-';
      diff = original - candidate;
    }
  else
    {
      *marker = '=';
      diff = 0;
    }

  sprintf (text, "%.1f",
           original ? 100.0 * (double)diff / (double)original : 0.0);
}

#endif /* ifndef ZO_DISPLAY_H */
