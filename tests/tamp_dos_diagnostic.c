#include "../common/xtr_tamp.h"

#include <stdio.h>

static unsigned char window[4096];

int
main (void)
{
  unsigned i;
  unsigned long sum;

  tamp_initialize_dictionary (window, sizeof (window), 8);
  sum = 0;

  for (i = 0; i < (unsigned)sizeof (window); ++i)
    {
      sum = (sum + window[i]) & 0xffffffffUL;
    }

  printf ("int=%u long=%u xtrt_u32=%u sum=%08lX\n", (unsigned)sizeof (int),
          (unsigned)sizeof (long), (unsigned)sizeof (xtrt_u32), sum);

  for (i = 0; i < 64U; ++i)
    {
      printf ("%02X", (unsigned)window[i]);
    }

  putchar ('\n');

  return 0;
}

#include "../common/xtr_tamp.c"
