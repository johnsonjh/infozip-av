/*
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

#ifndef IZ_ACCEL_STATUS_H
# define IZ_ACCEL_STATUS_H

/* The x86 CRC path has a less restrictive compiler version requirement
 * than the AES/SHA paths.  Keep these guards separate. */
# if defined(__GNUC__) && (defined(__x86_64__) || defined(__amd64__))
#  define IZ_ACCEL_STATUS_X86 1
#  if !defined(USE_ZLIB) && !defined(ASM_CRC) && !defined(CRC_TABLE_ONLY) \
    && !defined(IZ_CRC_BE_OPTIMIZ) && !defined(NO_PCLMUL_CRC32) \
    && !defined(NO_PCLMUL_CRC)
#   define IZ_ACCEL_STATUS_X86_CRC 1
#  endif /* if !defined( USE_ZLIB ) && !defined( ASM_CRC ) && !defined( \
          CRC_TABLE_ONLY ) && !defined( IZ_CRC_BE_OPTIMIZ ) && !defined( \
          NO_PCLMUL_CRC32 ) && !defined( NO_PCLMUL_CRC ) */
#  if defined(__clang__) || (__GNUC__ >= 5)
#   define IZ_ACCEL_STATUS_X86_CRYPTO 1
#  endif /* if defined( __clang__ ) || ( __GNUC__ >= 5 ) */
#  include <cpuid.h>
# endif /* if defined( __GNUC__ ) && ( defined( __x86_64__ ) || defined( \
          __amd64__ )) */

/* Suppress CPUID entirely when no x86 accelerator survives the build flags. */
# if defined(IZ_ACCEL_STATUS_X86_CRYPTO)
#  if !defined(NO_AES) && (!defined(NO_AES_NI) || !defined(NO_GHASH_PCLMUL))
#   define IZ_ACCEL_STATUS_X86_AES 1
#  endif /* if !defined( NO_AES ) && ( !defined( NO_AES_NI ) || !defined( \
          NO_GHASH_PCLMUL )) */
#  if (!defined(NO_AES) && !defined(NO_SHA256_NI)) \
    || ((!defined(NO_AES) \
         || (defined(IZ_UNZIP_ACCEL_STATUS) && defined(USE_REFPTR))) \
        && !defined(NO_SHA1_NI) && !defined(IZ_NO_SHA1_NI))
#   define IZ_ACCEL_STATUS_X86_SHA 1
#  endif /* if ( !defined( NO_AES ) && !defined( NO_SHA256_NI )) || (( \
          !defined( NO_AES ) || ( defined( IZ_UNZIP_ACCEL_STATUS ) && \
          defined( USE_REFPTR ))) && !defined( NO_SHA1_NI ) && !defined( \
          IZ_NO_SHA1_NI )) */
# endif /* if defined( IZ_ACCEL_STATUS_X86_CRYPTO ) */

# include "iz_arm_caps.h"

/* Bit assignments are local to the version-info code. */
# define IZ_ACCEL_STATUS_CRC 1U
# define IZ_ACCEL_STATUS_AES 2U
# define IZ_ACCEL_STATUS_SHA 4U

static unsigned int
iz_accel_status_mask (void)
{
  unsigned int result = 0;

# if defined(IZ_ACCEL_STATUS_X86_CRC) || defined(IZ_ACCEL_STATUS_X86_AES) \
    || defined(IZ_ACCEL_STATUS_X86_SHA)
  unsigned int a, b, c, d;
  unsigned int ecx1 = 0;
#  if defined(IZ_ACCEL_STATUS_X86_SHA)
  unsigned int ebx7 = 0;
#  endif /* if defined( IZ_ACCEL_STATUS_X86_SHA ) */
  if (__get_cpuid (1, &a, &b, &c, &d))
    {
      ecx1 = c;
    }

#  if defined(IZ_ACCEL_STATUS_X86_SHA)
  /* SHA1 and SHA256 require both SHA extensions and SSSE3. */
  if (__get_cpuid_max (0, (unsigned int *)0) >= 7)
    {
      __cpuid_count (7, 0, a, b, c, d);
      ebx7 = b;
    }

#  endif /* if defined( IZ_ACCEL_STATUS_X86_SHA ) */
#  if defined(IZ_ACCEL_STATUS_X86_CRC)
  if (ecx1 & (1U << 1))
    {
      result |= IZ_ACCEL_STATUS_CRC;
    }

#  endif /* if defined( IZ_ACCEL_STATUS_X86_CRC ) */
#  if defined(IZ_ACCEL_STATUS_X86_AES) || defined(IZ_ACCEL_STATUS_X86_SHA)
    /* GHASH acceleration is part of AE-3, even when AES-NI is disabled. */
#   if !defined(NO_AES_NI) && !defined(NO_AES)
  if (ecx1 & (1U << 25))
    {
      result |= IZ_ACCEL_STATUS_AES;
    }

#   endif /* if !defined( NO_AES_NI ) && !defined( NO_AES ) */
#   if !defined(NO_GHASH_PCLMUL) && !defined(NO_AES)
  if (ecx1 & (1U << 1))
    {
      result |= IZ_ACCEL_STATUS_AES;
    }

#   endif /* if !defined( NO_GHASH_PCLMUL ) && !defined( NO_AES ) */
#   if !defined(NO_SHA256_NI) && !defined(NO_AES)
  if ((ecx1 & (1U << 9)) && (ebx7 & (1U << 29)))
    {
      result |= IZ_ACCEL_STATUS_SHA;
    }

#   endif /* if !defined( NO_SHA256_NI ) && !defined( NO_AES ) */
#  endif /* if defined( IZ_ACCEL_STATUS_X86_AES ) || defined( \
          IZ_ACCEL_STATUS_X86_SHA ) */
#  if defined(IZ_ACCEL_STATUS_X86_SHA) && !defined(NO_SHA1_NI) \
    && !defined(IZ_NO_SHA1_NI)
#   if !defined(NO_AES) || (defined(IZ_UNZIP_ACCEL_STATUS) && defined(USE_REFPTR))
  if ((ecx1 & (1U << 9)) && (ebx7 & (1U << 29)))
    {
      result |= IZ_ACCEL_STATUS_SHA;
    }

#   endif /* if !defined( NO_AES ) || ( defined( IZ_UNZIP_ACCEL_STATUS ) && \
          defined( USE_REFPTR )) */
#  endif /* if defined( IZ_ACCEL_STATUS_X86_SHA ) && !defined( NO_SHA1_NI ) && \
          !defined( IZ_NO_SHA1_NI ) */
# endif /* x86-64 */

# if defined(IZ_ARM_CRYPTO_SUPPORTED)
  /* Identical OS-backed feature query to the accelerated call sites. */
  unsigned long caps = iz_arm_capabilities ();
#  if !defined(USE_ZLIB) && !defined(ASM_CRC) && !defined(CRC_TABLE_ONLY) \
    && !defined(IZ_CRC_BE_OPTIMIZ) && !defined(NO_ARM_CRC32)
  if (caps & IZ_ARM_CRC_BIT)
    {
      result |= IZ_ACCEL_STATUS_CRC;
    }

#  endif /* if !defined( USE_ZLIB ) && !defined( ASM_CRC ) && !defined( \
          CRC_TABLE_ONLY ) && !defined( IZ_CRC_BE_OPTIMIZ ) && !defined( \
          NO_ARM_CRC32 ) */
#  if !defined(NO_AES)
#   if !defined(NO_ARM_AES)
  if (caps & IZ_ARM_AES_BIT)
    {
      result |= IZ_ACCEL_STATUS_AES;
    }

#   endif /* if !defined( NO_ARM_AES ) */
#   if !defined(NO_ARM_PMULL)
  if (caps & IZ_ARM_PMULL_BIT)
    {
      result |= IZ_ACCEL_STATUS_AES;
    }

#   endif /* if !defined( NO_ARM_PMULL ) */
#   if !defined(NO_ARM_SHA256)
  if (caps & IZ_ARM_SHA2_BIT)
    {
      result |= IZ_ACCEL_STATUS_SHA;
    }

#   endif /* if !defined( NO_ARM_SHA256 ) */
#  endif /* if !defined( NO_AES ) */
#  if !defined(NO_ARM_SHA1)
#   if !defined(NO_AES) || (defined(IZ_UNZIP_ACCEL_STATUS) && defined(USE_REFPTR))
  if (caps & IZ_ARM_SHA1_BIT)
    {
      result |= IZ_ACCEL_STATUS_SHA;
    }

#   endif /* if !defined( NO_AES ) || ( defined( IZ_UNZIP_ACCEL_STATUS ) && \
          defined( USE_REFPTR )) */
#  endif /* if !defined( NO_ARM_SHA1 ) */
# endif /* AArch64 */

  return result;
}

/* Fixed strings keep the output deterministic and avoid allocation, mutable
 * globals, and platform-specific formatting.  NULL suppresses the line. */
static const char *
iz_accel_status_list (void)
{
  switch (iz_accel_status_mask ())
    {
    case IZ_ACCEL_STATUS_CRC:
      return "CRC";

    case IZ_ACCEL_STATUS_AES:
      return "AES";

    case IZ_ACCEL_STATUS_SHA:
      return "SHA";

    case IZ_ACCEL_STATUS_CRC | IZ_ACCEL_STATUS_AES:
      return "CRC and AES";

    case IZ_ACCEL_STATUS_CRC | IZ_ACCEL_STATUS_SHA:
      return "CRC and SHA";

    case IZ_ACCEL_STATUS_AES | IZ_ACCEL_STATUS_SHA:
      return "AES and SHA";

    case IZ_ACCEL_STATUS_CRC | IZ_ACCEL_STATUS_AES | IZ_ACCEL_STATUS_SHA:
      return "CRC, AES, and SHA";

    default:
      return (const char *)0;
    }
}
#endif /* IZ_ACCEL_STATUS_H */
