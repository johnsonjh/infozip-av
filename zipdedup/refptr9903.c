/*
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

/*
 * The fruits of reverse engineering:
 *
 * The 20-byte central-directory extra-field payload is:
 *     LE32(refptr9903_crc(...)) + uuid[16]
 *
 * CRC32 input, 28 bytes in exactly this order:
 *     LE32(method), LE16(DOS time), LE16(DOS date),
 *     LE32(ordinary ZIP file CRC32), uuid[16].
 *
 * 'method' is the actual member method (92 for a reference),
 * represented in four bytes in the CRC input (despite ZIP
 * usual two-byte CD method fields).
 */

/*
 * No WinZip code or objects were used produce this implementation!
 */

#include <limits.h>
#include <stddef.h>

/* Requires a bytes to represent ZIP octets */
#if CHAR_BIT != 8
# error "ZIP checksum implementation requires 8-bit bytes"
#endif /* if CHAR_BIT != 8 */

static void
refptr9903_put16 (unsigned char *out, unsigned int value)
{
  out[0] = (unsigned char)(value & 255U);
  out[1] = (unsigned char)((value >> 8) & 255U);
}

static void
refptr9903_put32 (unsigned char *out, unsigned long value)
{
  out[0] = (unsigned char)(value & 255UL);
  out[1] = (unsigned char)((value >> 8) & 255UL);
  out[2] = (unsigned char)((value >> 16) & 255UL);
  out[3] = (unsigned char)((value >> 24) & 255UL);
}

unsigned long
refptr9903_crc (unsigned long method, unsigned int dos_time,
                unsigned int dos_date, unsigned long uncompressed_crc32,
                const unsigned char uuid[16])
{
  unsigned char input[28];
  unsigned long crc;
  size_t i;
  unsigned int j;

  refptr9903_put32 (input, method);
  refptr9903_put16 (input + 4, dos_time);
  refptr9903_put16 (input + 6, dos_date);
  refptr9903_put32 (input + 8, uncompressed_crc32);

  for (i = 0; i < 16; ++i)
    {
      input[12 + i] = uuid[i];
    }

  crc = 0xffffffffUL;

  for (i = 0; i < sizeof (input); ++i)
    {
      crc ^= (unsigned long)input[i];

      for (j = 0; j < 8; ++j)
        {
          if ((crc & 1UL) != 0UL)
            {
              crc = (crc >> 1) ^ 0xedb88320UL;
            }
          else
            {
              crc >>= 1;
            }
        }
    }

  return (crc ^ 0xffffffffUL) & 0xffffffffUL;
}
