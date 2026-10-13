/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#include <zlib-ng.h>

int
main (void)
{
  zng_stream s = { 0 };
  const char *v = zlibng_version ();

  if (v == 0)
    {
      return 1;
    }

  return (int)(zng_crc32_z (0, (const uint8_t *)0, 0)
               | (uint32_t)(zng_deflateInit2 (&s, 1, Z_DEFLATED, -15, 8, 0)
                            != Z_OK));
}
