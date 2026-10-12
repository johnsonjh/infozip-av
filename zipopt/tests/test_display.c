/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Portable size and percentage formatting regression */

#include "../display.h"

#include <stdio.h>
#include <string.h>

int
main (void)
{
  char buf[32];
  char grouped[32];
  zo_u64 large = ((zo_u64)1 << 32) + 123456U;

  if (strcmp (zo_decimal (0, buf), "0")
      || strcmp (zo_decimal (large, buf), "4295090752")
      || strcmp (zo_decimal ((zo_u64)-1, buf), "18446744073709551615")
      || strcmp (zo_byte_decimal (0, grouped), "0")
      || strcmp (zo_byte_decimal (1000, grouped), "1,000")
      || strcmp (zo_byte_decimal (5621, grouped), "5,621")
      || strcmp (zo_byte_decimal (large, grouped), "4,295,090,752")
      || strcmp (zo_byte_decimal ((zo_u64)-1, grouped),
                 "18,446,744,073,709,551,615")
      || zo_ratio (0, 0) != 0.0 || zo_ratio (100, 110) < -10.01
      || zo_ratio (100, 110) > -9.99 || zo_ratio (100, 50) != 50.0
      || zo_ratio (100, 100) != 0.0 || zo_ratio (large, large / 2U) < 49.0
      || zo_ratio (large, large / 2U) > 51.0 || zo_ratio (200, 100) != 50.0
      || zo_ratio (80, 100) != -25.0 || zo_ratio (100, 120) < -20.01
      || zo_ratio (100, 120) > -19.99 || zo_ratio (100, 99) < 0.99
      || zo_ratio (100, 99) > 1.01 || zo_ratio (0, 8) != 0.0)
    {
      fputs ("FAIL: size/ratio display\n", stderr);

      return 1;
    }

  sprintf (buf, "%.0f%% -> %.0f%% -> %.0f%%", zo_ratio (5621, 1914),
           zo_ratio (1914, 1672), zo_ratio (5621, 1672));

  if (strcmp (buf, "66% -> 13% -> 70%"))
    {
      fputs ("FAIL: starting, improvement, final ratio order\n", stderr);

      return 1;
    }

  {
    char ratio[64], delta[64], mark;
    zo_ratio_text (5485, 1346, ratio);
    zo_change_text (1346, 5485, &mark, delta);

    if (strcmp (ratio, "75.5%") || mark != '+' || strcmp (delta, "307.5"))
      {
        fputs ("FAIL: positive expansion display\n", stderr);

        return 1;
      }

    zo_ratio_text (10000, 9990, ratio);

    if (strcmp (ratio, "0.1%"))
      {
        fputs ("FAIL: small positive compression hidden by rounding\n",
               stderr);

        return 1;
      }

    zo_ratio_text (10000, 10010, ratio);

    if (strcmp (ratio, "-0.1%"))
      {
        fputs ("FAIL: small negative compression hidden by rounding\n",
               stderr);

        return 1;
      }

    zo_ratio_text (5485, 1198, ratio);
    zo_change_text (1346, 1198, &mark, delta);

    if (strcmp (ratio, "78.2%") || mark != '-' || strcmp (delta, "11.0"))
      {
        fputs ("FAIL: savings display\n", stderr);

        return 1;
      }

    zo_change_text (1346, 1346, &mark, delta);

    if (mark != '=' || strcmp (delta, "0.0"))
      {
        fputs ("FAIL: equal packed sizes\n", stderr);

        return 1;
      }

    zo_change_text (0, 0, &mark, delta);

    if (mark != '=' || strcmp (delta, "0.0"))
      {
        fputs ("FAIL: zero packed sizes\n", stderr);

        return 1;
      }

    zo_change_text (0, 10, &mark, delta);
    if (mark != '?' || strcmp (delta, "n/a"))
      {
        fputs ("FAIL: zero original packed denominator\n", stderr);

        return 1;
      }

    zo_change_text ((zo_u64)-1, 0, &mark, delta);

    if (mark != '-' || strcmp (delta, "100.0"))
      {
        fputs ("FAIL: large sizes\n", stderr);

        return 1;
      }
  }

  puts ("PASS: C89 ZIP64 byte grouping and compression percentage formatting");

  return 0;
}
