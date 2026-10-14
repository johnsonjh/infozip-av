/*
 * SPDX-License-Identifier: MIT-0.
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "../../unzip60/iz_accel_status.h"

extern unsigned long crc32 (unsigned long, const unsigned char *, size_t);
extern unsigned long iz_crc32_software (unsigned long, const unsigned char *,
                                        size_t);

static unsigned char sample[200040];

static int
check (const unsigned char *p, size_t n, unsigned long initial)
{
  unsigned long actual = crc32 (initial, p, n);
  unsigned long software = iz_crc32_software (initial, p, n);
  size_t at, take;
  unsigned long chain1 = initial, chain2 = initial;

  if (actual != software)
    {
      return 0;
    }

  for (at = 0; at < n; at += take)
    {
      take = n - at;
      if (take > 197U)
        {
          take = 197U;
        }

      chain1 = crc32 (chain1, p + at, take);
      chain2 = iz_crc32_software (chain2, p + at, take);
    }

  return chain1 == actual && chain2 == software;
}

int
main (void)
{
  static const size_t sizes[]
      = { 0,   1,   3,   15,   16,   63,   64,    127,   255,   256,
          257, 511, 512, 1023, 1024, 4096, 16384, 65536, 200000 };
  unsigned i, j, alignment;

  for (i = 0; i < sizeof (sample); ++i)
    {
      sample[i] = (unsigned char)((i * 173UL + (i >> 5)) & 255U);
    }

  if (crc32 (0, (const unsigned char *)"123456789", 9) != 0xcbf43926UL)
    {
      fputs ("CRC-32 known vector failed\n", stderr);
      return 1;
    }

  for (j = 0; j < sizeof (sizes) / sizeof (sizes[0]); ++j)
    {
      for (alignment = 0; alignment < 8; ++alignment)
        {
          if (!check (sample + alignment, sizes[j], 0UL)
              || !check (sample + alignment, sizes[j], 0x9db78cfaUL))
            {
              fprintf (stderr, "CRC mismatch length=%lu align=%u\n",
                       (unsigned long)sizes[j], alignment);
              return 1;
            }
        }
    }

  printf ("CRC self-test passed (PCLMUL CPU feature: %s; accelerated build: "
          "%s; reported: %s)\n",
          (iz_accel_status_mask () & IZ_ACCEL_STATUS_CRC) ? "yes" : "no",
#if defined(__x86_64__) || defined(__amd64__)
          "yes"
#else  /* if defined( __x86_64__ ) || defined( __amd64__ ) */
          "no"
#endif /* if defined( __x86_64__ ) || defined( __amd64__ ) */
          ,
          iz_accel_status_list () ? iz_accel_status_list () : "none");
  return 0;
}
