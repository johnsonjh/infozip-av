/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef IZ_CRC32_ARM_H
# define IZ_CRC32_ARM_H
# include "iz_arm_caps.h"
# if defined(IZ_ARM_CRYPTO_SUPPORTED) && !defined(USE_ZLIB) \
    && !defined(ASM_CRC) && !defined(CRC_TABLE_ONLY) \
    && !defined(IZ_CRC_BE_OPTIMIZ) && !defined(NO_ARM_CRC32)
#  define IZ_ARM_CRC32_ENABLED 1
#  include <arm_acle.h>
#  include <stddef.h>
static __attribute__ ((target ("+crc"), noinline, unused)) unsigned int
iz_arm_crc32 (unsigned int crc, const unsigned char *p, size_t n)
{
  unsigned int c = crc ^ 0xffffffffU;

  while (n >= 8)
    {
      unsigned long long v;
      __builtin_memcpy (&v, p, 8);
      c = __crc32d (c, v);
      p += 8;
      n -= 8;
    }
  while (n--)
    {
      c = __crc32b (c, *p++);
    }
  return c ^ 0xffffffffU;
}
# endif /* if defined( IZ_ARM_CRYPTO_SUPPORTED ) && !defined( USE_ZLIB ) && \
          !defined( ASM_CRC ) && !defined( CRC_TABLE_ONLY ) && !defined( \
          IZ_CRC_BE_OPTIMIZ ) && !defined( NO_ARM_CRC32 ) */
#endif /* ifndef IZ_CRC32_ARM_H */
