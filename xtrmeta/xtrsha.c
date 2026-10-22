/* MIT-0. Self-contained SHA-256 (FIPS 180-4), C89, 32/64-bit long. */
#include "xtrsha.h"
#include <string.h>
/* SHA-NI/ARM SHA-2 compressors shared with AE-3.  Leave the software
 * compressor and all SFX builds untouched when acceleration is absent. */
#ifndef SFX
#define IZ_SHA256_ONLY 1
#ifndef NO_SHA256_NI
#include "../zip30/iz_aes_x86.h"
#endif
#ifndef NO_ARM_SHA256
#include "../zip30/iz_arm_crypto.h"
#endif
#undef IZ_SHA256_ONLY
#endif
#define M 0xffffffffUL
#define R(x, n) (((x) >> (n)) | (((x) << (32 - (n))) & M))
static const unsigned long k[64]
    = { 0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
        0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
        0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
        0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
        0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
        0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
        0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
        0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
        0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
        0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL };
static unsigned long
load32 (const unsigned char *p)
{
  return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16)
         | ((unsigned long)p[2] << 8) | p[3];
}
static void
put32 (unsigned char *p, unsigned long v)
{
  p[0] = (unsigned char)(v >> 24);
  p[1] = (unsigned char)(v >> 16);
  p[2] = (unsigned char)(v >> 8);
  p[3] = (unsigned char)v;
}
/* Keep the original one-argument software compressor in small SFX builds. */
#ifdef SFX
#define XTR_SHA_BLOCK(s, p) transform (s)
#else
#define XTR_SHA_BLOCK(s, p) transform (s, p)
#endif
static void
#ifdef SFX
transform (xtr_sha256 *s)
#else
transform (xtr_sha256 *s, const unsigned char *block)
#endif
{
  unsigned long w[64], a, b, c, d, e, f, g, h, t1, t2;
  unsigned i;
#ifdef SFX
  const unsigned char *block = s->block;
#endif
#ifdef IZ_SHA256_NI_ENABLED
  if (iz_sha256_ni_available ())
    {
      iz_sha256_ni_block (s->h, block, k);
      return;
    }
#endif
#ifdef IZ_ARM_SHA256_ENABLED
  if (iz_arm_has (IZ_ARM_SHA2_BIT))
    {
      iz_arm_sha256_block (s->h, block, k);
      return;
    }
#endif

  for (i = 0; i < 16; i++)
    {
      w[i] = load32 (block + 4 * i);
    }

  for (i = 16; i < 64; i++)
    {
      unsigned long x = w[i - 15], y = w[i - 2];
      w[i] = (w[i - 16] + (R (x, 7) ^ R (x, 18) ^ (x >> 3)) + w[i - 7]
              + (R (y, 17) ^ R (y, 19) ^ (y >> 10)))
             & M;
    }

  a = s->h[0];
  b = s->h[1];
  c = s->h[2];
  d = s->h[3];
  e = s->h[4];
  f = s->h[5];
  g = s->h[6];
  h = s->h[7];
  for (i = 0; i < 64; i++)
    {
      t1 = (h + (R (e, 6) ^ R (e, 11) ^ R (e, 25)) + ((e & f) ^ (~e & g))
            + k[i] + w[i])
           & M;
      t2 = ((R (a, 2) ^ R (a, 13) ^ R (a, 22)) + ((a & b) ^ (a & c) ^ (b & c)))
           & M;
      h = g;
      g = f;
      f = e;
      e = (d + t1) & M;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & M;
    }

  s->h[0] = (s->h[0] + a) & M;
  s->h[1] = (s->h[1] + b) & M;
  s->h[2] = (s->h[2] + c) & M;
  s->h[3] = (s->h[3] + d) & M;
  s->h[4] = (s->h[4] + e) & M;
  s->h[5] = (s->h[5] + f) & M;
  s->h[6] = (s->h[6] + g) & M;
  s->h[7] = (s->h[7] + h) & M;
}
void
xtr_sha256_init (xtr_sha256 *s)
{
  static const unsigned long iv[8]
      = { 0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
          0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };

  memcpy (s->h, iv, sizeof (iv));
  s->bytes_lo = 0;
  s->bytes_hi = 0;
  s->used = 0;
}
void
xtr_sha256_update (xtr_sha256 *s, const unsigned char *p, size_t n)
{
  size_t orig = n, take;
  unsigned long lo;

  if (n == 0)
    {
      return;
    }

#ifndef SFX
  /* Process whole input blocks directly when the staging buffer is empty.
   * Keep the original copy path for partial blocks and tail bytes. */
  if (s->used == 0)
    {
      while (n >= 64U)
        {
          XTR_SHA_BLOCK (s, p);
          p += 64U;
          n -= 64U;
        }
    }
#endif
  /* Each fallback iteration uses <=64 bytes, works with 16/32/64-bit size_t. */
  while (n)
    {
      take = 64U - s->used;
      if (take > n)
        {
          take = n;
        }

      memcpy (s->block + s->used, p, take);
      s->used += (unsigned)take;
      p += take;
      n -= take;
      if (s->used == 64)
        {
          XTR_SHA_BLOCK (s, s->block);
          s->used = 0;
        }
    }
  /* Count bytes modulo 2^64 without converting size_t through long. */
  while (orig)
    {
      take = orig;
      if (take > 65535U)
        {
          take = 65535U;
        }

      lo = s->bytes_lo;
      s->bytes_lo = (lo + (unsigned long)take) & M;
      if (s->bytes_lo < lo)
        {
          s->bytes_hi = (s->bytes_hi + 1UL) & M;
        }

      orig -= take;
    }
}
void
xtr_sha256_final (xtr_sha256 *s, unsigned char digest[32])
{
  unsigned i;
  unsigned long bits_hi = ((s->bytes_hi << 3) | (s->bytes_lo >> 29)) & M;
  unsigned long bits_lo = (s->bytes_lo << 3) & M;

  s->block[s->used++] = 0x80;
  if (s->used > 56)
    {
      memset (s->block + s->used, 0, 64 - s->used);
      XTR_SHA_BLOCK (s, s->block);
      s->used = 0;
    }

  memset (s->block + s->used, 0, 56 - s->used);
  put32 (s->block + 56, bits_hi);
  put32 (s->block + 60, bits_lo);
  XTR_SHA_BLOCK (s, s->block);
  for (i = 0; i < 8; i++)
    {
      put32 (digest + 4 * i, s->h[i]);
    }

  memset (s, 0, sizeof (*s));
}
