#include "../common/xtr_tamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_SIZE 32768U
#define OUTPUT_CAPACITY 65536U

int
main (void)
{
  unsigned char *input;
  unsigned char *encoded;
  unsigned char *decoded;
  unsigned char *cwin;
  unsigned char *dwin;
  unsigned int level;
  int lazy;
  unsigned long seed;
  unsigned int i;
  int failed = 0;

  input = (unsigned char *)malloc (TEST_SIZE);
  encoded = (unsigned char *)malloc (OUTPUT_CAPACITY);
  decoded = (unsigned char *)malloc (TEST_SIZE);
  cwin = (unsigned char *)malloc (32768U);
  dwin = (unsigned char *)malloc (32768U);

  if (!input || !encoded || !decoded || !cwin || !dwin)
    {
      return 2;
    }

  seed = 1234567UL;

  for (i = 0; i < TEST_SIZE; ++i)
    {
      seed = (1103515245UL * seed + 12345UL) & 0xffffffffUL;
      input[i] = (i % 257U < 192U) ? (unsigned char)('a' + (i % 23U))
                                   : (unsigned char)(seed >> 16);
    }

  for (level = 1; level <= 11; ++level)
    {
      unsigned int window_bits;
      if (level == 10U)
        {
          continue;
        }

      window_bits = level <= 2U ? 8U : (level >= 9U ? 15U : level + 6U);

      for (lazy = 0; lazy <= 1; ++lazy)
        {
          TampConf conf;
          TampCompressor c;
          TampDecompressor d;
          size_t read_size, enc_size, comp_used, dec_size;
          tamp_res r;
          memset (&conf, 0, sizeof (conf));
          conf.window = window_bits;
          conf.literal = 8U;
          conf.extended = 1U;
          conf.lazy_matching = lazy;
          r = tamp_compressor_init (&c, &conf, cwin);

          if (r != TAMP_OK)
            {
              return 3;
            }

          r = tamp_compressor_compress_and_flush (&c, encoded, OUTPUT_CAPACITY,
                                                  &enc_size, input, TEST_SIZE,
                                                  &read_size, 0);

          if (r != TAMP_OK || read_size != TEST_SIZE)
            {
              fprintf (stderr,
                       "compress error level %u lazy %d: %d, read %lu\n",
                       level, lazy, (int)r, (unsigned long)read_size);
              return 4;
            }

          r = tamp_decompressor_init (&d, NULL, dwin, 15U);

          if (r != TAMP_OK)
            {
              return 5;
            }

          r = tamp_decompressor_decompress (&d, decoded, TEST_SIZE, &dec_size,
                                            encoded, enc_size, &comp_used);
          if ((r != TAMP_INPUT_EXHAUSTED && r != TAMP_OK
               && r != TAMP_OUTPUT_FULL)
              || dec_size != TEST_SIZE || memcmp (input, decoded, TEST_SIZE))
            {
              fprintf (stderr,
                       "decode error level %u lazy %d: %d, decoded %lu "
                       "encoded %lu consumed %lu\n",
                       level, lazy, (int)r, (unsigned long)dec_size,
                       (unsigned long)enc_size, (unsigned long)comp_used);
              failed = 1;
            }
          else
            {
              printf ("level=%u lazy=%d window=%u encoded=%lu OK\n", level,
                      lazy, window_bits, (unsigned long)enc_size);
            }
        }
    }

  free (input);
  free (encoded);
  free (decoded);
  free (cwin);
  free (dwin);

  return failed;
}
