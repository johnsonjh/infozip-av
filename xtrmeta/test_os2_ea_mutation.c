/* SPDX-License-Identifier: MIT-0 */
/* Deterministic bounded mutation tests for the native OS/2 FEA2LIST parser.
 * No system random source, OS/2 runtime, or real filesystem is needed. */
#include "xtros2_ea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long state = 0x5e1f02UL;
static unsigned long
next_number (void)
{
  /* Defined unsigned arithmetic; this is a test mutator, NOT entropy. */
  state = (state * 1664525UL + 1013904223UL) & 0xffffffffUL;
  return state;
}
static void
fail (const char *why, unsigned long trial)
{
  fprintf (stderr, "OS/2 EA mutation FAILED at %lu: %s\n", trial, why);
  exit (1);
}
static void
put32 (unsigned char *p, unsigned long x)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      p[i] = (unsigned char)(x >> (i * 8));
    }
}
int
main (void)
{
  unsigned char original[80], work[80];
  static const unsigned char value[]
      = { 0xfd, 0xff, 5, 0, 't', 'a', 'r', 'g', 't' };
  unsigned long trial;
  size_t count;
  int rc;
  xtr_os2_ea_item output[2];

  memset (original, 0, sizeof (original));
  /* Two records; first 20 bytes aligned, then 25 byte final record. */
  put32 (original, 49UL);
  put32 (original + 4, 20UL);
  original[8] = 0;
  original[9] = 3;
  original[10] = 3;
  memcpy (original + 12, "AAA", 3);
  original[16] = 0x11;
  original[17] = 0x22;
  original[18] = 0x33;
  put32 (original + 24, 0);
  original[28] = 0x80;
  original[29] = 7;
  original[30] = (unsigned char)sizeof (value);
  memcpy (original + 32, "SYMLINK", 7);
  memcpy (original + 40, value, sizeof (value));
  rc = xtr_os2_ea_parse (original, 49, output, 2, &count);
  if (rc != XTR_OS2_EA_OK || count != 2 || output[1].flags != 0x80)
    {
      fail ("base list rejected", 0);
    }

  /* Parsing an undersized output array must never write the sentinel. */
  for (trial = 0; trial < 200000UL; trial++)
    {
      size_t length = (size_t)(next_number () % 81UL);
      size_t k;
      xtr_os2_ea_item limited[2];
      memcpy (work, original, sizeof (work));
      if (trial % 4UL == 0)
        {
          k = (size_t)(next_number () % 80UL);
          work[k] ^= (unsigned char)(1U << (next_number () % 8UL));
        }
      else if (trial % 4UL == 1)
        {
          size_t j;
          for (j = 0; j < 5; j++)
            {
              work[next_number () % 80UL] = (unsigned char)next_number ();
            }
        }
      else if (trial % 4UL == 2)
        {
          k = (size_t)(next_number () % 80UL);
          memset (work + k, (int)(next_number () & 255UL), 80U - k);
        }
      else
        {
          k = (size_t)(next_number () % 80UL);
          work[k] = (unsigned char)(next_number () & 255UL);
        }

      /* Full-size parse and count-only parse exercise independent paths. */
      memset (output, 0xa5, sizeof (output));
      count = 12345U;
      rc = xtr_os2_ea_parse (work, length, output, 2, &count);
      if (rc < XTR_OS2_EA_OK || rc > XTR_OS2_EA_CONFLICT)
        {
          fail ("undefined parser code", trial);
        }

      memset (limited, 0x5a, sizeof (limited));
      count = 12345U;
      rc = xtr_os2_ea_parse (work, length, limited, 1, &count);
      for (k = sizeof (limited[0]); k < sizeof (limited); k++)
        {
          if (((unsigned char *)limited)[k] != 0x5a)
            {
              fail ("capacity overrun", trial);
            }
        }

      count = 12345U;
      rc = xtr_os2_ea_parse (work, length, NULL, 0, &count);
      if (rc != XTR_OS2_EA_OK && rc != XTR_OS2_EA_BAD)
        {
          fail ("unexpected count-only status", trial);
        }
    }

  puts ("OS/2 EA deterministic mutation: 200000 cases passed");
  return 0;
}
