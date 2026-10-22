/* SPDX-License-Identifier: MIT-0 */

/* Strict decimal SOURCE_DATE_EPOCH parser, portable to ANSI C89 and 16-bit C.
 * Neither the input nor any part of it is ever passed to a shell. */
#ifndef XTR_SOURCE_EPOCH_H
# define XTR_SOURCE_EPOCH_H

# include <stdlib.h>

# define XTR_EPOCH_MIN 315532800UL  /* 1980-01-01 00:00:00 UTC */
# define XTR_EPOCH_MAX 2147483647UL /* 2038-01-19 03:14:07 UTC */

static int
xtr_source_epoch_parse (const char *s, unsigned long *result)
{
  unsigned long n = 0UL;
  unsigned digit;

  if (s == NULL || *s == '\0' || result == NULL)
    {
      return 0;
    }

  do
    {
      if (*s < '0' || *s > '9')
        {
          return 0;
        }

      digit = (unsigned)(*s++ - '0');
      if (n > (XTR_EPOCH_MAX - (unsigned long)digit) / 10UL)
        {
          return 0;
        }

      n = n * 10UL + (unsigned long)digit;
    }
  while (*s != '\0');

  if (n < XTR_EPOCH_MIN)
    {
      return 0;
    }

  *result = n;
  return 1;
}

#endif /* XTR_SOURCE_EPOCH_H */
