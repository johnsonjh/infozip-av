/*
 * Compile with -DZOPFLI_TEST_OOM
 * SPDX-License-Identifier: MIT-0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZOPFLI_TEST_OOM

#include "../../zip30/zopfli.c"

static unsigned char sample[4096];
static int failures;

static void
require (int ok, const char *what, long failpoint)
{
  if (!ok)
    {
      fprintf (stderr, "zopfli OOM regression: %s at fault %ld\n", what,
               failpoint);
      failures++;
    }
}

static void
test_one (int length, int split, int blocktype)
{
  ZopfliOptions opts;
  long i, needed = -1;
  int ok;
  unsigned char bp;
  unsigned char *out;
  size_t outsize;

  ZopfliInitOptions (&opts);
  opts.numiterations = 1;
  opts.blocksplitting = split;
  opts.blocksplittingmax = 5;

  /* First run without faults to determine how many allocation calls occur. */
  zopfli_test_fail_after = -1;
  zopfli_test_alloc_count = 0;
  bp = 0;
  out = NULL;
  outsize = 0;
  ok = ZopfliDeflatePart (&opts, blocktype, 1, sample, 0, (size_t)length, &bp,
                          &out, &outsize);
  require (ok && out != NULL && outsize > 0, "reference encode", -1);
  needed = zopfli_test_alloc_count;
  free (out);
  require (zopfli_active_scope == NULL, "scope cleanup", -1);

  /* Every allocation, including a realloc, must be independently recoverable.
   * One additional run beyond the last allocation must still succeed. */
  for (i = 0; i < (needed <= 1000 ? needed + 1 : 45); ++i)
    {
      long failpoint;
      if (needed <= 1000)
        {
          failpoint = i;
        }
      else if (i < 16)
        {
          failpoint = i;
        }
      else if (i < 39)
        {
          failpoint = needed * (i - 15) / 24;
        }
      else
        {
          failpoint = needed - (45 - i - 1);
        }

      if (failpoint > needed)
        {
          failpoint = needed;
        }

#ifdef ZOPFLI_TEST_QUICK
      if (i >= 6)
        {
          break;
        }

#endif /* ifdef ZOPFLI_TEST_QUICK */
      bp = 0;
      outsize = 0;
      out = NULL;
      zopfli_test_fail_after = failpoint;
      zopfli_test_alloc_count = 0;
      ok = ZopfliDeflatePart (&opts, blocktype, 1, sample, 0, (size_t)length,
                              &bp, &out, &outsize);
      if (failpoint < needed)
        {
          require (!ok, "fault must return failure", failpoint);
          require (out == NULL && outsize == 0 && bp == 0,
                   "failure must reset output", failpoint);
        }
      else
        {
          require (ok && out != NULL && outsize > 0, "after final allocation",
                   failpoint);
        }

      require (zopfli_active_scope == NULL, "scope after call", failpoint);
      free (out);

      if (failures)
        {
          break;
        }
    }

  zopfli_test_fail_after = -1;
  printf ("zopfli block=%d split=%d input=%d: %ld allocations, %ld failures "
          "tested\n",
          blocktype, split, length, needed,
          (needed <= 1000 ? needed + 1 : 45));
}

static void
test_carry_failure (void)
{
  ZopfliOptions opts;
  unsigned char *out;
  unsigned char bp;
  size_t n;
  int ok;

  ZopfliInitOptions (&opts);
  opts.numiterations = 1;
  out = (unsigned char *)malloc (1);

  if (!out)
    {
      exit (2);
    }

  out[0] = 17;
  n = 1;
  bp = 3;
  zopfli_test_alloc_count = 0;
  zopfli_test_fail_after = 0;
  ok = ZopfliDeflatePart (&opts, 2, 1, sample, 0, 100, &bp, &out, &n);
  require (!ok && out == NULL && n == 0 && bp == 3,
           "caller-provided output cleanup", 0);
  require (zopfli_active_scope == NULL, "carry scope cleanup", 0);
  zopfli_test_fail_after = -1;
}

/*
 * Baseline compressed lengths and CRC-32 values are
 * from unmodified Zopfli 1.0.3, before adding
 * recoverable OOM support.  The exact bitstreams
 * must remain unchanged for successful allocations.
 */

typedef struct Golden
{
  int len;
  size_t output_size;
  unsigned long output_crc;
} Golden;

static const Golden golden[3][5] = { { { 0,    5,    0x4564cc52UL },
                                       { 7,    12,   0x4a3f31d1UL },
                                       { 128,  133,  0xb0667cedUL },
                                       { 1024, 1029, 0xf5cd6f24UL },
                                       { 8192, 8197, 0x1b98809eUL } },
                                     { { 0,    2,    0x6af4413cUL },
                                       { 7,    9,    0xd71ab623UL },
                                       { 128,  137,  0x206915a4UL },
                                       { 1024, 427,  0x4d9f995eUL },
                                       { 8192, 552,  0xd3616d56UL } },
                                     { { 0,    2,    0x6af4413cUL },
                                       { 7,    9,    0xd71ab623UL },
                                       { 128,  133,  0xb0667cedUL },
                                       { 1024, 399,  0xabdf599eUL },
                                       { 8192, 482,  0xa83b0bf3UL } } };

static unsigned long
crc32_bytes (const unsigned char *data, size_t n)
{
  unsigned long crc = 0xffffffffUL;
  size_t i;

  for (i = 0; i < n; ++i)
    {
      unsigned k;
      crc ^= (unsigned long)data[i];

      for (k = 0; k < 8; ++k)
        {
          crc = (crc >> 1) ^ ((crc & 1UL) ? 0xedb88320UL : 0UL);
        }
    }

  return (crc ^ 0xffffffffUL) & 0xffffffffUL;
}

static void
test_golden (void)
{
  unsigned char input[8192];
  ZopfliOptions opts;
  int i, typ, j;

  for (i = 0; i < 8192; ++i)
    {
      input[i] = (unsigned char)((i * 37 + (i / 19) * 13) % 256);
    }

  ZopfliInitOptions (&opts);
  opts.numiterations = 2;

  for (typ = 0; typ < 3; ++typ)
    {
      for (j = 0; j < 5; ++j)
        {
#ifdef ZOPFLI_TEST_QUICK
          if (j >= 3)
            {
              break;
            }

#endif /* ifdef ZOPFLI_TEST_QUICK */
          unsigned char *out = NULL;
          unsigned char bp = 0;
          size_t outsize = 0;
          int ok;
          const Golden *g = &golden[typ][j];
          zopfli_test_fail_after = -1;
          ok = ZopfliDeflatePart (&opts, typ, 1, input, 0, (size_t)g->len, &bp,
                                  &out, &outsize);
          require (ok && out && outsize == g->output_size,
                   "baseline output length", -1);

          if (ok && out && outsize == g->output_size)
            {
              require (crc32_bytes (out, outsize) == g->output_crc,
                       "baseline output checksum", -1);
            }

          free (out);
        }
    }

  puts ("zopfli bitstreams: 15 golden cases passed");
}

int
main (void)
{
  int i;

  for (i = 0; i < (int)sizeof (sample); ++i)
    {
      sample[i] = (unsigned char)((i * 37 + (i >> 3) * 11) & 255);
    }

  test_one (32, 0, 2);
  test_one (160, 1, 2);
  test_one (1024, 1, 2);
  test_one (512, 0, 1);
  test_one (512, 0, 0);
  test_carry_failure ();
  test_golden ();

  if (failures)
    {
      return 1;
    }

  puts ("zopfli OOM recovery: PASS");

  return 0;
}
