#include <stdio.h>
#include <stdlib.h>

#include "tamp/decompressor.h"

int
main (void)
{
  TampDecompressor decoder;
  unsigned char *window;
  tamp_res result;

  window = (unsigned char *)malloc (32768U);

  if (!window)
    {
      return 2;
    }

  result = tamp_decompressor_init (&decoder, NULL, window, 15U);

  if (result != TAMP_OK)
    {
      free (window);

      return 3;
    }

  result = tamp_decompress_stream (&decoder, tamp_stream_stdio_read, stdin,
                                   tamp_stream_stdio_write, stdout, NULL, NULL,
                                   NULL, NULL);
  free (window);

  if (result != TAMP_OK || fflush (stdout) != 0)
    {
      fprintf (stderr, "stock Tamp C decoder failed: %d\n", (int)result);

      return 4;
    }

  return 0;
}
