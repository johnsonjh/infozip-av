/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef XM_FWKCS_MD5_H
# define XM_FWKCS_MD5_H

# include <limits.h>
# include <string.h>

# if CHAR_BIT != 8 || ULONG_MAX < 0xffffffffUL
#  error FWKCS MD5 needs 8-bit bytes and at least 32-bit unsigned long
# endif /* if CHAR_BIT != 8 || ULONG_MAX < 0xffffffffUL */

typedef struct xm_md5_ctx
{
  unsigned long state[4];
  unsigned long count[2];
  unsigned char buffer[64];
} xm_md5_ctx;

# define XM_MD5_MASK ((unsigned long)0xffffffffUL)

# define XM_MD5_ROT(x, n) \
  ((unsigned long)(((((x) & XM_MD5_MASK) << (n)) \
                    | (((x) & XM_MD5_MASK) >> (32 - (n)))) \
                   & XM_MD5_MASK))

static void
xm_md5_transform (unsigned long *state, const unsigned char *block)
{
  static const unsigned long k[64]
      = { 0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL, 0xf57c0fafUL,
          0x4787c62aUL, 0xa8304613UL, 0xfd469501UL, 0x698098d8UL, 0x8b44f7afUL,
          0xffff5bb1UL, 0x895cd7beUL, 0x6b901122UL, 0xfd987193UL, 0xa679438eUL,
          0x49b40821UL, 0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL,
          0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL, 0x21e1cde6UL,
          0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL, 0xa9e3e905UL, 0xfcefa3f8UL,
          0x676f02d9UL, 0x8d2a4c8aUL, 0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL,
          0xfde5380cUL, 0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
          0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL, 0xd9d4d039UL,
          0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL, 0xf4292244UL, 0x432aff97UL,
          0xab9423a7UL, 0xfc93a039UL, 0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL,
          0x85845dd1UL, 0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
          0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL };

  static const unsigned char r[64]
      = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
          5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

  unsigned long a = state[0], b = state[1], c = state[2], d = state[3], x[16];
  unsigned long f, t;
  unsigned i, g;

  for (i = 0; i < 16; ++i)
    {
      const unsigned char *p = block + (i << 2);

      x[i] = (unsigned long)p[0] | ((unsigned long)p[1] << 8)
             | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
    }

  for (i = 0; i < 64; ++i)
    {
      if (i < 16)
        {
          f = ((b & c) | ((~b) & d)) & XM_MD5_MASK;
          g = i;
        }
      else if (i < 32)
        {
          f = ((d & b) | ((~d) & c)) & XM_MD5_MASK;
          g = (5 * i + 1) & 15;
        }
      else if (i < 48)
        {
          f = (b ^ c ^ d) & XM_MD5_MASK;
          g = (3 * i + 5) & 15;
        }
      else
        {
          f = (c ^ (b | (~d))) & XM_MD5_MASK;
          g = (7 * i) & 15;
        }

      t = d;
      d = c;
      c = b;
      b = (b + XM_MD5_ROT ((a + f + k[i] + x[g]) & XM_MD5_MASK, r[i]))
          & XM_MD5_MASK;
      a = t;
    }

  state[0] = (state[0] + a) & XM_MD5_MASK;
  state[1] = (state[1] + b) & XM_MD5_MASK;
  state[2] = (state[2] + c) & XM_MD5_MASK;
  state[3] = (state[3] + d) & XM_MD5_MASK;
}

static void
xm_md5_init (xm_md5_ctx *ctx)
{
  ctx->count[0] = ctx->count[1] = 0;
  ctx->state[0] = (unsigned long)0x67452301UL;
  ctx->state[1] = (unsigned long)0xefcdab89UL;
  ctx->state[2] = (unsigned long)0x98badcfeUL;
  ctx->state[3] = (unsigned long)0x10325476UL;
}

static void
xm_md5_update (xm_md5_ctx *ctx, const unsigned char *data, unsigned len)
{
  unsigned i, used = (unsigned)((ctx->count[0] >> 3) & 63);
  unsigned long bits = (unsigned long)len << 3;

  {
    unsigned long old = ctx->count[0];

    ctx->count[0] = (ctx->count[0] + bits) & XM_MD5_MASK;
    if (ctx->count[0] < old)
      {
        ctx->count[1] = (ctx->count[1] + 1) & XM_MD5_MASK;
      }

    ctx->count[1] = (ctx->count[1] + ((unsigned long)len >> 29)) & XM_MD5_MASK;
  }

  if (used)
    {
      unsigned freeb = 64 - used;

      if (len < freeb)
        {
          memcpy (ctx->buffer + used, data, len);

          return;
        }

      memcpy (ctx->buffer + used, data, freeb);
      xm_md5_transform (ctx->state, ctx->buffer);
      data += freeb;
      len -= freeb;
    }

  for (i = 0; i + 63 < len; i += 64)
    {
      xm_md5_transform (ctx->state, data + i);
    }

  if (i < len)
    {
      memcpy (ctx->buffer, data + i, len - i);
    }
}

static void
xm_md5_final (unsigned char *digest, xm_md5_ctx *ctx)
{
  static const unsigned char pad[64] = { 0x80 };
  unsigned char bits[8];
  unsigned i, used, padlen;

  for (i = 0; i < 4; ++i)
    {
      bits[i] = (unsigned char)(ctx->count[0] >> (i << 3));
      bits[i + 4] = (unsigned char)(ctx->count[1] >> (i << 3));
    }

  used = (unsigned)((ctx->count[0] >> 3) & 63);
  padlen = (used < 56) ? 56 - used : 120 - used;
  xm_md5_update (ctx, pad, padlen);
  xm_md5_update (ctx, bits, 8);

  for (i = 0; i < 16; ++i)
    {
      digest[i] = (unsigned char)(ctx->state[i >> 2] >> ((i & 3) << 3));
    }
}

#endif /* XM_FWKCS_MD5_H */
