/* Amalgamated and modified for the Info-ZIP fork.
 * Upstream: https://github.com/lzfse/lzfse (Apple Inc., BSD-3-Clause).
 * Full original license follows.
 * Copyright (c) 2015-2016, Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3.  Neither the name of the copyright holder(s) nor the names of any
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef IZ_LZFSE_H
# define IZ_LZFSE_H
# define HAVE_LABELS_AS_VALUES 0

/* ===== original lzfse.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

# ifndef LZFSE_H
#  define LZFSE_H

#  include <limits.h>
#  include <stddef.h>
/* The wire format requires 64-bit arithmetic, not a 64-bit C long.
 * Windows (including Win64) uses 32-bit long.  ISO C89 has no portable
 * 64-bit integer type; GCC/Clang provide one in their C89 language mode.
 * Keep that unavoidable extension in these two declarations.  Compiling
 * with -std=c89 -pedantic-errors remains possible on both data models.
 * IZ_LZFSE_TEST_LLONG exercises the LLP64 integer path on LP64 CI hosts.
 */
#  if CHAR_BIT != 8 || UINT_MAX != 0xffffffffU || USHRT_MAX != 0xffffU
#   error "LZFSE requires 8-bit bytes, 16-bit short and 32-bit int"
#  endif
typedef unsigned char izl_u8;
typedef signed char izl_s8;
typedef unsigned short izl_u16;
typedef signed short izl_s16;
typedef unsigned int izl_u32;
typedef signed int izl_s32;
#  if ULONG_MAX > 0xffffffffUL && !defined(IZ_LZFSE_TEST_LLONG)
typedef unsigned long izl_u64;
typedef signed long izl_s64;
#  elif defined(__GNUC__) || defined(__clang__)
__extension__ typedef unsigned long long izl_u64;
__extension__ typedef signed long long izl_s64;
#  else
#   error "LZFSE needs a 64-bit C integer (GCC/Clang on 32-bit-long targets)"
#  endif

static int
izl_count_clz (unsigned int x)
{
  int n = 0;
  if (x == 0U)
    return 32;
  while ((x & 0x80000000U) == 0U)
    {
      ++n;
      x <<= 1;
    }
  return n;
}
static int
izl_count_ctzl (unsigned long x)
{
  int n = 0;
  if (x == 0UL)
    return (int)(8 * sizeof (unsigned long));
  while ((x & 1UL) == 0UL)
    {
      ++n;
      x >>= 1;
    }
  return n;
}
static int
izl_count_ctzll (izl_u64 x)
{
  /* Never truncate to unsigned long: that is 32-bit even on Win64. */
  izl_u32 lo = (izl_u32)x;
  if (lo != 0U)
    return izl_count_ctzl ((unsigned long)lo);
  if ((izl_u32)(x >> 32) != 0U)
    return 32 + izl_count_ctzl ((unsigned long)(izl_u32)(x >> 32));
  return 64;
}
#  define __builtin_clz(x) izl_count_clz ((unsigned int)(x))
#  define __builtin_ctzl(x) izl_count_ctzl ((unsigned long)(x))
#  define __builtin_ctzll(x) izl_count_ctzll ((izl_u64)(x))
#  define __builtin_expect(x, y) (x)

#  ifndef INT32_MAX
#   define INT32_MAX 2147483647
#  endif

#  ifdef __cplusplus
extern "C"
{
#  endif

#  if 0 /* MSVC extensions excluded from portable C89 amalgamation */
#   define __attribute__(X)
#   pragma warning(disable : 4068)
#  endif

#  if defined(LZFSE_DLL)
#   if defined(_WIN32) || defined(__CYGWIN__)
#    if defined(LZFSE_DLL_EXPORTS)
#     define LZFSE_API __declspec (dllexport)
#    else
#     define LZFSE_API __declspec (dllimport)
#    endif
#   endif
#  endif

#  if !defined(LZFSE_API)
#   if __GNUC__ >= 4
#    define LZFSE_API __attribute__ ((visibility ("default")))
#   else
#    define LZFSE_API
#   endif
#  endif

  /*! @abstract Get the required scratch buffer size to compress using LZFSE.
   */
  LZFSE_API size_t lzfse_encode_scratch_size (void);

  /*! @abstract Compress a buffer using LZFSE.
   *
   *  @param dst_buffer
   *  Pointer to the first byte of the destination buffer.
   *
   *  @param dst_size
   *  Size of the destination buffer in bytes.
   *
   *  @param src_buffer
   *  Pointer to the first byte of the source buffer.
   *
   *  @param src_size
   *  Size of the source buffer in bytes.
   *
   *  @param scratch_buffer
   *  If non-NULL, a pointer to scratch space for the routine to use as
   * workspace; the routine may use up to lzfse_encode_scratch_size( ) bytes of
   * workspace during its operation, and will not perform any internal
   * allocations. If NULL, the routine may allocate its own memory to use
   * during operation via a single call to malloc( ), and will release it by
   * calling free( ) prior to returning. For most use, passing NULL is
   * perfectly satisfactory, but if you require strict control over allocation,
   * you will want to pass an explicit scratch buffer.
   *
   *  @return
   *  The number of bytes written to the destination buffer if the input is
   *  successfully compressed. If the input cannot be compressed to fit into
   *  the provided buffer, or an error occurs, zero is returned, and the
   *  contents of dst_buffer are unspecified. */
  LZFSE_API size_t lzfse_encode_buffer (izl_u8 *dst_buffer, size_t dst_size,
                                        const izl_u8 *src_buffer,
                                        size_t src_size, void *scratch_buffer);

  /*! @abstract Get the required scratch buffer size to decompress using LZFSE.
   */
  LZFSE_API size_t lzfse_decode_scratch_size (void);

  /*! @abstract Decompress a buffer using LZFSE.
   *
   *  @param dst_buffer
   *  Pointer to the first byte of the destination buffer.
   *
   *  @param dst_size
   *  Size of the destination buffer in bytes.
   *
   *  @param src_buffer
   *  Pointer to the first byte of the source buffer.
   *
   *  @param src_size
   *  Size of the source buffer in bytes.
   *
   *  @param scratch_buffer
   *  If non-NULL, a pointer to scratch space for the routine to use as
   * workspace; the routine may use up to lzfse_decode_scratch_size( ) bytes of
   * workspace during its operation, and will not perform any internal
   * allocations. If NULL, the routine may allocate its own memory to use
   * during operation via a single call to malloc( ), and will release it by
   * calling free( ) prior to returning. For most use, passing NULL is
   * perfectly satisfactory, but if you require strict control over allocation,
   * you will want to pass an explicit scratch buffer.
   *
   *  @return
   *  The number of bytes written to the destination buffer if the input is
   *  successfully decompressed. If there is not enough space in the
   * destination buffer to hold the entire expanded output, only the first
   * dst_size bytes will be written to the buffer and dst_size is returned.
   * Note that this behavior differs from that of lzfse_encode_buffer. */
  LZFSE_API size_t lzfse_decode_buffer (izl_u8 *dst_buffer, size_t dst_size,
                                        const izl_u8 *src_buffer,
                                        size_t src_size, void *scratch_buffer);

#  ifdef __cplusplus
} /* extern "C" */
#  endif

# endif /* LZFSE_H */

/* ===== original lzfse_tunables.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

# ifndef LZFSE_TUNABLES_H
#  define LZFSE_TUNABLES_H

/*  Parameters controlling details of the LZ-style match search. These values
 */
/*  may be modified to fine tune compression ratio vs. encoding speed, while */
/*  keeping the compressed format compatible with LZFSE. Note that */
/*  modifying them will also change the amount of work space required by */
/*  the encoder. The values here are those used in the compression library */
/*  on iOS and OS X. */

/*  Number of bits for hash function to produce. Should be in the range */
/*  [10, 16]. Larger values reduce the number of false-positive found during */
/*  the match search, and expand the history table, which may allow additional
 */
/*  matches to be found, generally improving the achieved compression ratio. */
/*  Larger values also increase the workspace size, and make it less likely */
/*  that the history table will be present in cache, which reduces performance.
 */
#  define LZFSE_ENCODE_HASH_BITS 14

/*  Number of positions to store for each line in the history table. May */
/*  be either 4 or 8. Using 8 doubles the size of the history table, which */
/*  increases the chance of finding matches (thus improving compression ratio),
 */
/*  but also increases the workspace size. */
#  define LZFSE_ENCODE_HASH_WIDTH 4

/*  Match length in bytes to cause immediate emission. Generally speaking, */
/*  LZFSE maintains multiple candidate matches and waits to decide which match
 */
/*  to emit until more information is available. When a match exceeds this */
/*  threshold, it is emitted immediately. Thus, smaller values may give */
/*  somewhat better performance, and larger values may give somewhat better */
/*  compression ratios. */
#  define LZFSE_ENCODE_GOOD_MATCH 40

/*  When the source buffer is very small, LZFSE doesn't compress as well as */
/*  some simpler algorithms. To maintain reasonable compression for these */
/*  cases, we transition to use LZVN instead if the size of the source buffer
 */
/*  is below this threshold. */
#  define LZFSE_ENCODE_LZVN_THRESHOLD 4096

# endif /* LZFSE_TUNABLES_H */

/* ===== original lzfse_fse.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Finite state entropy coding (FSE) */
/* This is an implementation of the tANS algorithm described by Jarek Duda, */
/* we use the more descriptive name "Finite State Entropy". */

# include <assert.h>
# include <stddef.h>

# include <stdlib.h>
# include <string.h>

/*  Select between 32/64-bit I/O streams for FSE. Note that the FSE stream */
/*  size need not match the word size of the machine, but in practice you */
/*  want to use 64b streams on 64b systems for better performance. */
# if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__)
#  define FSE_IOSTREAM_64 1
# else
#  define FSE_IOSTREAM_64 0
# endif

# if 0 /* MSVC extensions excluded from portable C89 amalgamation */
#  define FSE_INLINE __forceinline
#  define inline __inline
#  pragma warning(disable : 4068) /* warning C4068: unknown pragma */
# else
#  define FSE_INLINE static
# endif

/* MARK: - Bit utils */

/*! @abstract Signed type used to represent bit count. */
typedef izl_s32 fse_bit_count;

/*! @abstract Unsigned type used to represent FSE state. */
typedef izl_u16 fse_state;

/* Mask the NBITS lsb of X. 0 <= NBITS < 64 */
static izl_u64
fse_mask_lsb64 (izl_u64 x, fse_bit_count nbits)
{
  /* Avoid 64-bit UL constants, which are not C89 integer constants on
   * ILP32/LLP64, and do not shift a 64-bit value by 64. */
  assert (nbits >= 0 && nbits <= 64);
  if (nbits == 64)
    return x;
  return x & (((izl_u64)1 << nbits) - 1);
}

/* Mask the NBITS lsb of X. 0 <= NBITS < 32 */
static izl_u32
fse_mask_lsb32 (izl_u32 x, fse_bit_count nbits)
{
  static const izl_u32 mtable[33] = {
    0x0000000000000000U, 0x0000000000000001U, 0x0000000000000003U,
    0x0000000000000007U, 0x000000000000000fU, 0x000000000000001fU,
    0x000000000000003fU, 0x000000000000007fU, 0x00000000000000ffU,
    0x00000000000001ffU, 0x00000000000003ffU, 0x00000000000007ffU,
    0x0000000000000fffU, 0x0000000000001fffU, 0x0000000000003fffU,
    0x0000000000007fffU, 0x000000000000ffffU, 0x000000000001ffffU,
    0x000000000003ffffU, 0x000000000007ffffU, 0x00000000000fffffU,
    0x00000000001fffffU, 0x00000000003fffffU, 0x00000000007fffffU,
    0x0000000000ffffffU, 0x0000000001ffffffU, 0x0000000003ffffffU,
    0x0000000007ffffffU, 0x000000000fffffffU, 0x000000001fffffffU,
    0x000000003fffffffU, 0x000000007fffffffU, 0x00000000ffffffffU,
  };
  return x & mtable[nbits];
}

/*! @abstract Select \c nbits at index \c start from \c x.
 *  0 <= start <= start+nbits <= 64 */
FSE_INLINE izl_u64
fse_extract_bits64 (izl_u64 x, fse_bit_count start, fse_bit_count nbits)
{
# if defined(__GNUC__)
  /* If START and NBITS are constants, map to bit-field extraction instructions
   */
  if (0)
    return fse_mask_lsb64 (x >> start, nbits);
# endif

  /* Otherwise, shift and mask */
  return fse_mask_lsb64 (x >> start, nbits);
}

/*! @abstract Select \c nbits at index \c start from \c x.
 *  0 <= start <= start+nbits <= 32 */
FSE_INLINE izl_u32
fse_extract_bits32 (izl_u32 x, fse_bit_count start, fse_bit_count nbits)
{
# if defined(__GNUC__)
  /* If START and NBITS are constants, map to bit-field extraction instructions
   */
  if (0)
    return (x >> start) & ((1U << nbits) - 1U);
# endif

  /* Otherwise, shift and mask */
  return fse_mask_lsb32 (x >> start, nbits);
}

/* MARK: - Bit stream */

/* I/O streams */
/* The streams can be shared between several FSE encoders/decoders, which is
 * why */
/* they are not in the state struct */

/*! @abstract Output stream, 64-bit accum. */
typedef struct
{
  izl_u64 accum; /* Output bits */
  fse_bit_count
      accum_nbits; /* Number of valid bits in ACCUM, other bits are 0 */
} fse_out_stream64;

/*! @abstract Output stream, 32-bit accum. */
typedef struct
{
  izl_u32 accum; /* Output bits */
  fse_bit_count
      accum_nbits; /* Number of valid bits in ACCUM, other bits are 0 */
} fse_out_stream32;

/*! @abstract Object representing an input stream. */
typedef struct
{
  izl_u64 accum; /* Input bits */
  fse_bit_count
      accum_nbits; /* Number of valid bits in ACCUM, other bits are 0 */
} fse_in_stream64;

/*! @abstract Object representing an input stream. */
typedef struct
{
  izl_u32 accum; /* Input bits */
  fse_bit_count
      accum_nbits; /* Number of valid bits in ACCUM, other bits are 0 */
} fse_in_stream32;

/*! @abstract Initialize an output stream object. */
FSE_INLINE void
fse_out_init64 (fse_out_stream64 *s)
{
  s->accum = 0;
  s->accum_nbits = 0;
}

/*! @abstract Initialize an output stream object. */
FSE_INLINE void
fse_out_init32 (fse_out_stream32 *s)
{
  s->accum = 0;
  s->accum_nbits = 0;
}

/*! @abstract Write full bytes from the accumulator to output buffer, ensuring
 * accum_nbits is in [0, 7].
 * We assume we can write 8 bytes to the output buffer \c (*pbuf[0..7]) in all
 * cases.
 * @note *pbuf is incremented by the number of written bytes. */
FSE_INLINE void
fse_out_flush64 (fse_out_stream64 *s, izl_u8 **pbuf)
{
  fse_bit_count nbits
      = s->accum_nbits & -8; /* number of bits written, multiple of 8 */

  /* Write 8 bytes of current accumulator */
  memcpy (*pbuf, &(s->accum), 8);
  *pbuf += (nbits >> 3); /* bytes */

  /* Update state */
  s->accum >>= nbits; /* remove nbits */
  s->accum_nbits -= nbits;

  assert (s->accum_nbits >= 0 && s->accum_nbits <= 7);
  assert (s->accum_nbits == 64 || (s->accum >> s->accum_nbits) == 0);
}

/*! @abstract Write full bytes from the accumulator to output buffer, ensuring
 * accum_nbits is in [0, 7].
 * We assume we can write 4 bytes to the output buffer \c (*pbuf[0..3]) in all
 * cases.
 * @note *pbuf is incremented by the number of written bytes. */
FSE_INLINE void
fse_out_flush32 (fse_out_stream32 *s, izl_u8 **pbuf)
{
  fse_bit_count nbits
      = s->accum_nbits & -8; /* number of bits written, multiple of 8 */

  /* Write 4 bytes of current accumulator */
  memcpy (*pbuf, &(s->accum), 4);
  *pbuf += (nbits >> 3); /* bytes */

  /* Update state */
  s->accum >>= nbits; /* remove nbits */
  s->accum_nbits -= nbits;

  assert (s->accum_nbits >= 0 && s->accum_nbits <= 7);
  assert (s->accum_nbits == 32 || (s->accum >> s->accum_nbits) == 0);
}

/*! @abstract Write the last bytes from the accumulator to output buffer,
 * ensuring accum_nbits is in [-7, 0]. Bits are padded with 0 if needed.
 * We assume we can write 8 bytes to the output buffer \c (*pbuf[0..7]) in all
 * cases.
 * @note *pbuf is incremented by the number of written bytes. */
FSE_INLINE void
fse_out_finish64 (fse_out_stream64 *s, izl_u8 **pbuf)
{
  fse_bit_count nbits
      = (s->accum_nbits + 7) & -8; /* number of bits written, multiple of 8 */

  /* Write 8 bytes of current accumulator */
  memcpy (*pbuf, &(s->accum), 8);
  *pbuf += (nbits >> 3); /* bytes */

  /* Update state */
  s->accum = 0; /* remove nbits */
  s->accum_nbits -= nbits;

  assert (s->accum_nbits >= -7 && s->accum_nbits <= 0);
}

/*! @abstract Write the last bytes from the accumulator to output buffer,
 * ensuring accum_nbits is in [-7, 0]. Bits are padded with 0 if needed.
 * We assume we can write 4 bytes to the output buffer \c (*pbuf[0..3]) in all
 * cases.
 * @note *pbuf is incremented by the number of written bytes. */
FSE_INLINE void
fse_out_finish32 (fse_out_stream32 *s, izl_u8 **pbuf)
{
  fse_bit_count nbits
      = (s->accum_nbits + 7) & -8; /* number of bits written, multiple of 8 */

  /* Write 8 bytes of current accumulator */
  memcpy (*pbuf, &(s->accum), 4);
  *pbuf += (nbits >> 3); /* bytes */

  /* Update state */
  s->accum = 0; /* remove nbits */
  s->accum_nbits -= nbits;

  assert (s->accum_nbits >= -7 && s->accum_nbits <= 0);
}

/*! @abstract Accumulate \c n bits \c b to output stream \c s. We \b must have:
 * 0 <= b < 2^n, and N + s->accum_nbits <= 64.
 * @note The caller must ensure out_flush is called \b before the accumulator
 * overflows to more than 64 bits. */
FSE_INLINE void
fse_out_push64 (fse_out_stream64 *s, fse_bit_count n, izl_u64 b)
{
  s->accum |= b << s->accum_nbits;
  s->accum_nbits += n;

  assert (s->accum_nbits >= 0 && s->accum_nbits <= 64);
  assert (s->accum_nbits == 64 || (s->accum >> s->accum_nbits) == 0);
}

/*! @abstract Accumulate \c n bits \c b to output stream \c s. We \b must have:
 * 0 <= n < 2^n, and n + s->accum_nbits <= 32.
 * @note The caller must ensure out_flush is called \b before the accumulator
 * overflows to more than 32 bits. */
FSE_INLINE void
fse_out_push32 (fse_out_stream32 *s, fse_bit_count n, izl_u32 b)
{
  s->accum |= b << s->accum_nbits;
  s->accum_nbits += n;

  assert (s->accum_nbits >= 0 && s->accum_nbits <= 32);
  assert (s->accum_nbits == 32 || (s->accum >> s->accum_nbits) == 0);
}

# if FSE_IOSTREAM_64
#  define DEBUG_CHECK_INPUT_STREAM_PARAMETERS                                   \
  assert (s->accum_nbits >= 56 && s->accum_nbits < 64);                       \
  assert ((s->accum >> s->accum_nbits) == 0);
# else
#  define DEBUG_CHECK_INPUT_STREAM_PARAMETERS                                   \
  assert (s->accum_nbits >= 24 && s->accum_nbits < 32);                       \
  assert ((s->accum >> s->accum_nbits) == 0);
# endif

/*! @abstract   Initialize the fse input stream so that accum holds between 56
 *  and 63 bits. We never want to have 64 bits in the stream, because that
 * allows us to avoid a special case in the fse_in_pull function (eliminating
 * an unpredictable branch), while not requiring any additional fse_flush
 *  operations. This is why we have the special case for n == 0 (in which case
 *  we want to load only 7 bytes instead of 8). */
FSE_INLINE int
fse_in_checked_init64 (fse_in_stream64 *s, fse_bit_count n,
                       const izl_u8 **pbuf, const izl_u8 *buf_start)
{
  if (n)
    {
      if (*pbuf < buf_start + 8)
        return -1; /* out of range */
      *pbuf -= 8;
      memcpy (&(s->accum), *pbuf, 8);
      s->accum_nbits = n + 64;
    }
  else
    {
      if (*pbuf < buf_start + 7)
        return -1; /* out of range */
      *pbuf -= 7;
      memcpy (&(s->accum), *pbuf, 7);
      s->accum &= (((izl_u64)1 << 56) - 1);
      s->accum_nbits = n + 56;
    }

  if ((s->accum_nbits < 56 || s->accum_nbits >= 64)
      || ((s->accum >> s->accum_nbits) != 0))
    {
      return -1; /* the incoming input is wrong (encoder should have zeroed the
                  */
                 /* upper bits) */
    }

  return 0; /* OK */
}

/*! @abstract Identical to previous function, but for 32-bit operation
 * (resulting bit count is between 24 and 31 bits). */
FSE_INLINE int
fse_in_checked_init32 (fse_in_stream32 *s, fse_bit_count n,
                       const izl_u8 **pbuf, const izl_u8 *buf_start)
{
  if (n)
    {
      if (*pbuf < buf_start + 4)
        return -1; /* out of range */
      *pbuf -= 4;
      memcpy (&(s->accum), *pbuf, 4);
      s->accum_nbits = n + 32;
    }
  else
    {
      if (*pbuf < buf_start + 3)
        return -1; /* out of range */
      *pbuf -= 3;
      memcpy (&(s->accum), *pbuf, 3);
      s->accum &= 0xffffff;
      s->accum_nbits = n + 24;
    }

  if ((s->accum_nbits < 24 || s->accum_nbits >= 32)
      || ((s->accum >> s->accum_nbits) != 0))
    {
      return -1; /* the incoming input is wrong (encoder should have zeroed the
                  */
                 /* upper bits) */
    }

  return 0; /* OK */
}

/*! @abstract  Read in new bytes from buffer to ensure that we have a full
 * complement of bits in the stream object (again, between 56 and 63 bits).
 * checking the new value of \c *pbuf remains >= \c buf_start.
 * @return 0 if OK.
 * @return -1 on failure. */
FSE_INLINE int
fse_in_checked_flush64 (fse_in_stream64 *s, const izl_u8 **pbuf,
                        const izl_u8 *buf_start)
{
  /*  Get number of bits to add to bring us into the desired range. */
  fse_bit_count nbits = (63 - s->accum_nbits) & -8;
  /*  Convert bits to bytes and decrement buffer address, then load new data.
   */
  const izl_u8 *buf = (*pbuf) - (nbits >> 3);
  if (buf < buf_start)
    {
      return -1; /* out of range */
    }
  *pbuf = buf;
  {
    izl_u64 incoming;
    memcpy (&incoming, buf, 8);
    /* Update the state object and verify its validity (in DEBUG). */
    s->accum = (s->accum << nbits) | fse_mask_lsb64 (incoming, nbits);
    s->accum_nbits += nbits;
    DEBUG_CHECK_INPUT_STREAM_PARAMETERS
    return 0; /* OK */
  }
}

/*! @abstract Identical to previous function (but again, we're only filling
 * a 32-bit field with between 24 and 31 bits). */
FSE_INLINE int
fse_in_checked_flush32 (fse_in_stream32 *s, const izl_u8 **pbuf,
                        const izl_u8 *buf_start)
{
  /*  Get number of bits to add to bring us into the desired range. */
  fse_bit_count nbits = (31 - s->accum_nbits) & -8;

  if (nbits > 0)
    {
      /*  Convert bits to bytes and decrement buffer address, then load new
       * data. */
      const izl_u8 *buf = (*pbuf) - (nbits >> 3);
      if (buf < buf_start)
        {
          return -1; /* out of range */
        }

      *pbuf = buf;

      {
        izl_u32 incoming = *((izl_u32 *)buf);

        /* Update the state object and verify its validity (in DEBUG). */
        s->accum = (s->accum << nbits) | fse_mask_lsb32 (incoming, nbits);
        s->accum_nbits += nbits;
      }
    }
  DEBUG_CHECK_INPUT_STREAM_PARAMETERS
  return 0; /* OK */
}

/*! @abstract Pull n bits out of the fse stream object. */
FSE_INLINE izl_u64
fse_in_pull64 (fse_in_stream64 *s, fse_bit_count n)
{
  assert (n >= 0 && n <= s->accum_nbits);
  s->accum_nbits -= n;
  {
    izl_u64 result = s->accum >> s->accum_nbits;
    s->accum = fse_mask_lsb64 (s->accum, s->accum_nbits);
    return result;
  }
}

/*! @abstract Pull n bits out of the fse stream object. */
FSE_INLINE izl_u32
fse_in_pull32 (fse_in_stream32 *s, fse_bit_count n)
{
  assert (n >= 0 && n <= s->accum_nbits);
  s->accum_nbits -= n;
  {
    izl_u32 result = s->accum >> s->accum_nbits;
    s->accum = fse_mask_lsb32 (s->accum, s->accum_nbits);
    return result;
  }
}

/* MARK: - Encode/Decode */

/* Map to 32/64-bit implementations and types for I/O */
# if FSE_IOSTREAM_64

typedef izl_u64 fse_bits;
typedef fse_out_stream64 fse_out_stream;
typedef fse_in_stream64 fse_in_stream;
#  define fse_mask_lsb fse_mask_lsb64
#  define fse_extract_bits fse_extract_bits64
#  define fse_out_init fse_out_init64
#  define fse_out_flush fse_out_flush64
#  define fse_out_finish fse_out_finish64
#  define fse_out_push fse_out_push64
#  define fse_in_init fse_in_checked_init64
#  define fse_in_checked_init fse_in_checked_init64
#  define fse_in_flush fse_in_checked_flush64
#  define fse_in_checked_flush fse_in_checked_flush64
#  define fse_in_flush2(_unused, _parameters, _unused2) 0 /* nothing */
#  define fse_in_checked_flush2(_unused, _parameters)     /* nothing */
#  define fse_in_pull fse_in_pull64

# else

typedef izl_u32 fse_bits;
typedef fse_out_stream32 fse_out_stream;
typedef fse_in_stream32 fse_in_stream;
#  define fse_mask_lsb fse_mask_lsb32
#  define fse_extract_bits fse_extract_bits32
#  define fse_out_init fse_out_init32
#  define fse_out_flush fse_out_flush32
#  define fse_out_finish fse_out_finish32
#  define fse_out_push fse_out_push32
#  define fse_in_init fse_in_checked_init32
#  define fse_in_checked_init fse_in_checked_init32
#  define fse_in_flush fse_in_checked_flush32
#  define fse_in_checked_flush fse_in_checked_flush32
#  define fse_in_flush2 fse_in_checked_flush32
#  define fse_in_checked_flush2 fse_in_checked_flush32
#  define fse_in_pull fse_in_pull32

# endif

/*! @abstract Entry for one symbol in the encoder table (64b). */
typedef struct
{
  izl_s16 s0; /* First state requiring a K-bit shift */
  izl_s16 k;  /* States S >= S0 are shifted K bits. States S < S0 are */
              /* shifted K-1 bits */
  izl_s16
      delta0; /* Relative increment used to compute next state if S >= S0 */
  izl_s16 delta1; /* Relative increment used to compute next state if S < S0 */
} fse_encoder_entry;

/*! @abstract  Entry for one state in the decoder table (32b). */
typedef struct
{                /* DO NOT REORDER THE FIELDS */
  izl_s8 k;      /* Number of bits to read */
  izl_u8 symbol; /* Emitted symbol */
  izl_s16 delta; /* Signed increment used to compute next state (+bias) */
} fse_decoder_entry;

/*! @abstract  Entry for one state in the value decoder table (64b). */
typedef struct
{ /* DO NOT REORDER THE FIELDS */
  izl_u8
      total_bits; /* state bits + extra value bits = shift for next decode */
  izl_u8 value_bits; /* extra value bits */
  izl_s16 delta;     /* state base (delta) */
  izl_s32 vbase;     /* value base */
} fse_value_decoder_entry;

/*! @abstract Encode SYMBOL using the encoder table, and update \c *pstate,
 *  \c out.
 *  @note The caller must ensure we have enough bits available in the output
 *  stream accumulator. */
FSE_INLINE void
fse_encode (fse_state *pstate, const fse_encoder_entry *encoder_table,
            fse_out_stream *out, izl_u8 symbol)
{
  int s = *pstate;
  fse_encoder_entry e = encoder_table[symbol];
  int s0 = e.s0;
  int k = e.k;
  int delta0 = e.delta0;
  int delta1 = e.delta1;

  /* Number of bits to write */
  int hi = s >= s0;
  fse_bit_count nbits = hi ? k : (k - 1);
  fse_state delta = hi ? delta0 : delta1;

  /* Write lower NBITS of state */
  fse_bits b = fse_mask_lsb (s, nbits);
  fse_out_push (out, nbits, b);

  /* Update state with remaining bits and delta */
  *pstate = delta + (s >> nbits);
}

/*! @abstract Decode and return symbol using the decoder table, and update
 *  \c *pstate, \c in.
 *  @note The caller must ensure we have enough bits available in the input
 *  stream accumulator. */
FSE_INLINE izl_u8
fse_decode (fse_state *pstate, const izl_s32 *decoder_table, fse_in_stream *in)
{
  izl_s32 e = decoder_table[*pstate];

  /* Update state from K bits of input + DELTA */
  *pstate = (fse_state)(e >> 16) + (fse_state)fse_in_pull (in, e & 0xff);

  /* Return the symbol for this state */
  return fse_extract_bits (e, 8, 8); /* symbol */
}

/*! @abstract Decode and return value using the decoder table, and update \c
 *  *pstate, \c in.
 * \c value_decoder_table[nstates]
 * @note The caller must ensure we have enough bits available in the input
 * stream accumulator. */
FSE_INLINE izl_s32
fse_value_decode (fse_state *pstate,
                  const fse_value_decoder_entry *value_decoder_table,
                  fse_in_stream *in)
{
  fse_value_decoder_entry entry = value_decoder_table[*pstate];
  izl_u32 state_and_value_bits = (izl_u32)fse_in_pull (in, entry.total_bits);
  *pstate
      = (fse_state)(entry.delta + (state_and_value_bits >> entry.value_bits));
  return (izl_s32)(entry.vbase
                   + fse_mask_lsb (state_and_value_bits, entry.value_bits));
}

/* MARK: - Tables */

/* IMPORTANT: To properly decode an FSE encoded stream, both encoder/decoder */
/* tables shall be initialized with the same parameters, including the */
/* FREQ[NSYMBOL] array. */
/* */

/*! @abstract Sanity check on frequency table, verify sum of \c freq
 *  is <= \c number_of_states. */
FSE_INLINE int
fse_check_freq (const izl_u16 *freq_table, const size_t table_size,
                const size_t number_of_states)
{
  size_t sum_of_freq = 0;
  {
    int i;
    for (i = 0; (size_t)i < table_size; i++)
      {
        sum_of_freq += freq_table[i];
      }
  }
  return (sum_of_freq > number_of_states) ? -1 : 0;
}

/*! @abstract Initialize encoder table \c t[nsymbols].
 *
 * @param nstates
 * sum \c freq[i]; the number of states (a power of 2).
 *
 * @param nsymbols
 * the number of symbols.
 *
 * @param freq[nsymbols]
 * is a normalized histogram of symbol frequencies, with \c freq[i] >= 0.
 * Some symbols may have a 0 frequency. In that case they should not be
 * present in the data.
 */
void fse_init_encoder_table (int nstates, int nsymbols, const izl_u16 *freq,
                             fse_encoder_entry *t);

/*! @abstract Initialize decoder table \c t[nstates].
 *
 * @param nstates
 * sum \c freq[i]; the number of states (a power of 2).
 *
 * @param nsymbols
 * the number of symbols.
 *
 * @param feq[nsymbols]
 * a normalized histogram of symbol frequencies, with \c freq[i] >= 0.
 * Some symbols may have a 0 frequency. In that case they should not be
 * present in the data.
 *
 * @return 0 if OK.
 * @return -1 on failure.
 */
int fse_init_decoder_table (int nstates, int nsymbols, const izl_u16 *freq,
                            izl_s32 *t);

/*! @abstract Initialize value decoder table \c t[nstates].
 *
 * @param nstates
 * sum \cfreq[i]; the number of states (a power of 2).
 *
 * @param nsymbols
 * the number of symbols.
 *
 * @param freq[nsymbols]
 * a normalized histogram of symbol frequencies, with \c freq[i] >= 0.
 * \c symbol_vbits[nsymbols] and \c symbol_vbase[nsymbols] are the number of
 * value bits to read and the base value for each symbol.
 * Some symbols may have a 0 frequency.  In that case they should not be
 * present in the data.
 */
void fse_init_value_decoder_table (int nstates, int nsymbols,
                                   const izl_u16 *freq,
                                   const izl_u8 *symbol_vbits,
                                   const izl_s32 *symbol_vbase,
                                   fse_value_decoder_entry *t);

/*! @abstract Normalize a table \c t[nsymbols] of occurrences to
 *  \c freq[nsymbols]. */
void fse_normalize_freq (int nstates, int nsymbols, const izl_u32 *t,
                         izl_u16 *freq);

/* ===== original lzfse_internal.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

# ifndef LZFSE_INTERNAL_H
#  define LZFSE_INTERNAL_H

/*  Unlike the tunable parameters defined in lzfse_tunables.h, you probably */
/*  should not modify the values defined in this header. Doing so will either
 */
/*  break the compressor, or result in a compressed data format that is */
/*  incompatible. */

#  include <limits.h>
#  include <stddef.h>

#  if 0 /* MSVC extensions excluded from portable C89 amalgamation */
#   define LZFSE_INLINE __forceinline
#   define __builtin_expect(X, Y) (X)
#   define __attribute__(X)
#   pragma warning(disable : 4068) /* warning C4068: unknown pragma */
#  else
#   define LZFSE_INLINE static
#  endif

/* Implement GCC bit scan builtins for MSVC */

#  if 0 /* MSVC extensions excluded from portable C89 amalgamation */
#   include <intrin.h>

LZFSE_INLINE int __builtin_clz(unsigned int val) {
    unsigned long r = 0;
    if (_BitScanReverse(&r, val)) {
        return 31 - r;
    }
    return 32;
}

LZFSE_INLINE int __builtin_ctzl(unsigned long val) {
  unsigned long r = 0;
  if (_BitScanForward(&r, val)) {
    return r;
  }
  return 32;
}

LZFSE_INLINE int __builtin_ctzll(izl_u64 val) {
  unsigned long r = 0;
#   if defined(_M_AMD64) || defined(_M_ARM)
  if (_BitScanForward64(&r, val)) {
    return r;
  }
#   else
  if (_BitScanForward(&r, (izl_u32)val)) {
    return r;
  }
  if (_BitScanForward(&r, (izl_u32)(val >> 32))) {
    return 32 + r;
  }
#   endif
  return 64;
}
#  endif

/*  Throughout LZFSE we refer to "L", "M" and "D"; these will always appear as
 */
/*  a triplet, and represent a "usual" LZ-style literal and match pair.  "L" */
/*  is the number of literal bytes, "M" is the number of match bytes, and "D"
 */
/*  is the match "distance"; the distance in bytes between the current pointer
 */
/*  and the start of the match. */
#  define LZFSE_ENCODE_HASH_VALUES (1 << LZFSE_ENCODE_HASH_BITS)
#  define LZFSE_ENCODE_L_SYMBOLS 20
#  define LZFSE_ENCODE_M_SYMBOLS 20
#  define LZFSE_ENCODE_D_SYMBOLS 64
#  define LZFSE_ENCODE_LITERAL_SYMBOLS 256
#  define LZFSE_ENCODE_L_STATES 64
#  define LZFSE_ENCODE_M_STATES 64
#  define LZFSE_ENCODE_D_STATES 256
#  define LZFSE_ENCODE_LITERAL_STATES 1024
#  define LZFSE_MATCHES_PER_BLOCK 10000
#  define LZFSE_LITERALS_PER_BLOCK (4 * LZFSE_MATCHES_PER_BLOCK)
#  define LZFSE_DECODE_LITERALS_PER_BLOCK (4 * LZFSE_DECODE_MATCHES_PER_BLOCK)

/*  LZFSE internal status. These values are used by internal LZFSE routines */
/*  as return codes.  There should not be any good reason to change their */
/*  values; it is plausible that additional codes might be added in the */
/*  future. */
#  define LZFSE_STATUS_OK 0
#  define LZFSE_STATUS_SRC_EMPTY -1
#  define LZFSE_STATUS_DST_FULL -2
#  define LZFSE_STATUS_ERROR -3

/*  Type representing an offset between elements in a buffer. On 64-bit */
/*  systems, this is stored in a 64-bit container to avoid extra sign- */
/*  extension operations in addressing arithmetic, but the value is always */
/*  representable as a 32-bit signed value in LZFSE's usage. */
#  if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__)
typedef izl_s64 lzfse_offset;
#  else
typedef izl_s32 lzfse_offset;
#  endif

/*! @abstract History table set. Each line of the history table represents a
 * set of candidate match locations, each of which begins with four bytes with
 * the same hash. The table contains not only the positions, but also the first
 *  four bytes at each position. This doubles the memory footprint of the
 *  table, but allows us to quickly eliminate false-positive matches without
 *  doing any pointer chasing and without pulling in any additional cachelines.
 *  This provides a large performance win in practice. */
typedef struct
{
  izl_s32 pos[LZFSE_ENCODE_HASH_WIDTH];
  izl_u32 value[LZFSE_ENCODE_HASH_WIDTH];
} lzfse_history_set;

/*! @abstract An lzfse match is a sequence of bytes in the source buffer that
 *  exactly matches an earlier (but possibly overlapping) sequence of bytes in
 *  the same buffer.
 *  @code
 *  exeMPLARYexaMPLE
 *  |  |     | ||-|--- lzfse_match2.length=3
 *  |  |     | ||----- lzfse_match2.pos
 *  |  |     |-|------ lzfse_match1.length=3
 *  |  |     |-------- lzfse_match1.pos
 *  |  |-------------- lzfse_match2.ref
 *  |----------------- lzfse_match1.ref
 *  @endcode
 */
typedef struct
{
  /*  Offset of the first byte in the match. */
  lzfse_offset pos;
  /*  First byte of the source -- the earlier location in the buffer with the
   */
  /*  same contents. */
  lzfse_offset ref;
  /*  Length of the match. */
  izl_u32 length;
} lzfse_match;

/* MARK: - Encoder and Decoder state objects */

/*! @abstract Encoder state object. */
typedef struct
{
  /*  Pointer to first byte of the source buffer. */
  const izl_u8 *src;
  /*  Length of the source buffer in bytes. Note that this is not a size_t, */
  /*  but rather lzfse_offset, which is a signed type. The largest */
  /*  representable buffer is 2GB, but arbitrarily large buffers may be */
  /*  handled by repeatedly calling the encoder function and "translating" */
  /*  the state between calls. When doing this, it is beneficial to use */
  /*  blocks smaller than 2GB in order to maintain residency in the last-level
   */
  /*  cache. Consult the implementation of lzfse_encode_buffer for details. */
  lzfse_offset src_end;
  /*  Offset of the first byte of the next literal to encode in the source */
  /*  buffer. */
  lzfse_offset src_literal;
  /*  Offset of the byte currently being checked for a match. */
  lzfse_offset src_encode_i;
  /*  The last byte offset to consider for a match.  In some uses it makes */
  /*  sense to use a smaller offset than src_end. */
  lzfse_offset src_encode_end;
  /*  Pointer to the next byte to be written in the destination buffer. */
  izl_u8 *dst;
  /*  Pointer to the first byte of the destination buffer. */
  izl_u8 *dst_begin;
  /*  Pointer to one byte past the end of the destination buffer. */
  izl_u8 *dst_end;
  /*  Pending match; will be emitted unless a better match is found. */
  lzfse_match pending;
  /*  The number of matches written so far. Note that there is no problem in */
  /*  using a 32-bit field for this quantity, because the state already limits
   */
  /*  us to at most 2GB of data; there cannot possibly be more matches than */
  /*  there are bytes in the input. */
  izl_u32 n_matches;
  /*  The number of literals written so far. */
  izl_u32 n_literals;
  /*  Lengths of found literals. */
  izl_u32 l_values[LZFSE_MATCHES_PER_BLOCK];
  /*  Lengths of found matches. */
  izl_u32 m_values[LZFSE_MATCHES_PER_BLOCK];
  /*  Distances of found matches. */
  izl_u32 d_values[LZFSE_MATCHES_PER_BLOCK];
  /*  Concatenated literal bytes. */
  izl_u8 literals[LZFSE_LITERALS_PER_BLOCK];
  /*  History table used to search for matches. Each entry of the table */
  /*  corresponds to a group of four byte sequences in the input stream */
  /*  that hash to the same value. */
  lzfse_history_set history_table[LZFSE_ENCODE_HASH_VALUES];
} lzfse_encoder_state;

/*! @abstract Decoder state object for lzfse compressed blocks. */
typedef struct
{
  /*  Number of matches remaining in the block. */
  izl_u32 n_matches;
  /*  Number of bytes used to encode L, M, D triplets for the block. */
  izl_u32 n_lmd_payload_bytes;
  /*  Pointer to the next literal to emit. */
  const izl_u8 *current_literal;
  /*  L, M, D triplet for the match currently being emitted. This is used only
   */
  /*  if we need to restart after reaching the end of the destination buffer in
   */
  /*  the middle of a literal or match. */
  izl_s32 l_value, m_value, d_value;
  /*  FSE stream object. */
  fse_in_stream lmd_in_stream;
  /*  Offset of L,M,D encoding in the input buffer. Because we read through an
   */
  /*  FSE stream *backwards* while decoding, this is decremented as we move */
  /*  through a block. */
  izl_u32 lmd_in_buf;
  /*  The current state of the L, M, and D FSE decoders. */
  izl_u16 l_state, m_state, d_state;
  /*  Internal FSE decoder tables for the current block. These have */
  /*  alignment forced to 8 bytes to guarantee that a single state's */
  /*  entry cannot span two cachelines. */
  fse_value_decoder_entry l_decoder[LZFSE_ENCODE_L_STATES];
  fse_value_decoder_entry m_decoder[LZFSE_ENCODE_M_STATES];
  fse_value_decoder_entry d_decoder[LZFSE_ENCODE_D_STATES];
  izl_s32 literal_decoder[LZFSE_ENCODE_LITERAL_STATES];
  /*  The literal stream for the block, plus padding to allow for faster copy
   */
  /*  operations. */
  izl_u8 literals[LZFSE_LITERALS_PER_BLOCK + 64];
} lzfse_compressed_block_decoder_state;

/*  Decoder state object for uncompressed blocks. */
typedef struct
{
  izl_u32 n_raw_bytes;
} uncompressed_block_decoder_state;

/*! @abstract Decoder state object for lzvn-compressed blocks. */
typedef struct
{
  izl_u32 n_raw_bytes;
  izl_u32 n_payload_bytes;
  izl_u32 d_prev;
} lzvn_compressed_block_decoder_state;

/*! @abstract Decoder state object. */
typedef struct
{
  /*  Pointer to next byte to read from source buffer (this is advanced as we
   */
  /*  decode; src_begin describe the buffer and do not change). */
  const izl_u8 *src;
  /*  Pointer to first byte of source buffer. */
  const izl_u8 *src_begin;
  /*  Pointer to one byte past the end of the source buffer. */
  const izl_u8 *src_end;
  /*  Pointer to the next byte to write to destination buffer (this is advanced
   */
  /*  as we decode; dst_begin and dst_end describe the buffer and do not
   * change). */
  izl_u8 *dst;
  /*  Pointer to first byte of destination buffer. */
  izl_u8 *dst_begin;
  /*  Pointer to one byte past the end of the destination buffer. */
  izl_u8 *dst_end;
  /*  1 if we have reached the end of the stream, 0 otherwise. */
  int end_of_stream;
  /*  magic number of the current block if we are within a block, */
  /*  LZFSE_NO_BLOCK_MAGIC otherwise. */
  izl_u32 block_magic;
  lzfse_compressed_block_decoder_state compressed_lzfse_block_state;
  lzvn_compressed_block_decoder_state compressed_lzvn_block_state;
  uncompressed_block_decoder_state uncompressed_block_state;
} lzfse_decoder_state;

/* MARK: - Block header objects */

#  define LZFSE_NO_BLOCK_MAGIC 0x00000000           /* 0    (invalid) */
#  define LZFSE_ENDOFSTREAM_BLOCK_MAGIC 0x24787662  /* bvx$ (end of stream) */
#  define LZFSE_UNCOMPRESSED_BLOCK_MAGIC 0x2d787662 /* bvx- (raw data) */
#  define LZFSE_COMPRESSEDV1_BLOCK_MAGIC                                        \
  0x31787662 /* bvx1 (lzfse compressed, uncompressed tables) */
#  define LZFSE_COMPRESSEDV2_BLOCK_MAGIC                                        \
  0x32787662 /* bvx2 (lzfse compressed, compressed tables) */
#  define LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC                                      \
  0x6e787662 /* bvxn (lzvn compressed) */

/*! @abstract Uncompressed block header in encoder stream. */
typedef struct
{
  /*  Magic number, always LZFSE_UNCOMPRESSED_BLOCK_MAGIC. */
  izl_u32 magic;
  /*  Number of raw bytes in block. */
  izl_u32 n_raw_bytes;
} uncompressed_block_header;

/*! @abstract Compressed block header with uncompressed tables. */
typedef struct
{
  /*  Magic number, always LZFSE_COMPRESSEDV1_BLOCK_MAGIC. */
  izl_u32 magic;
  /*  Number of decoded (output) bytes in block. */
  izl_u32 n_raw_bytes;
  /*  Number of encoded (source) bytes in block. */
  izl_u32 n_payload_bytes;
  /*  Number of literal bytes output by block (*not* the number of literals).
   */
  izl_u32 n_literals;
  /*  Number of matches in block (which is also the number of literals). */
  izl_u32 n_matches;
  /*  Number of bytes used to encode literals. */
  izl_u32 n_literal_payload_bytes;
  /*  Number of bytes used to encode matches. */
  izl_u32 n_lmd_payload_bytes;

  /*  Final encoder states for the block, which will be the initial states for
   */
  /*  the decoder: */
  /*  Final accum_nbits for literals stream. */
  izl_s32 literal_bits;
  /*  There are four interleaved streams of literals, so there are four final
   */
  /*  states. */
  izl_u16 literal_state[4];
  /*  accum_nbits for the l, m, d stream. */
  izl_s32 lmd_bits;
  /*  Final L (literal length) state. */
  izl_u16 l_state;
  /*  Final M (match length) state. */
  izl_u16 m_state;
  /*  Final D (match distance) state. */
  izl_u16 d_state;

  /*  Normalized frequency tables for each stream. Sum of values in each */
  /*  array is the number of states. */
  izl_u16 l_freq[LZFSE_ENCODE_L_SYMBOLS];
  izl_u16 m_freq[LZFSE_ENCODE_M_SYMBOLS];
  izl_u16 d_freq[LZFSE_ENCODE_D_SYMBOLS];
  izl_u16 literal_freq[LZFSE_ENCODE_LITERAL_SYMBOLS];
} lzfse_compressed_block_header_v1;

/*! @abstract Compressed block header with compressed tables. Note that because
 *  freq[] is compressed, the structure-as-stored-in-the-stream is *truncated*;
 *  we only store the used bytes of freq[]. This means that some extra care
 * must be taken when reading one of these headers from the stream. */
typedef struct
{
  /*  Magic number, always LZFSE_COMPRESSEDV2_BLOCK_MAGIC. */
  izl_u32 magic;
  /*  Number of decoded (output) bytes in block. */
  izl_u32 n_raw_bytes;
  /*  The fields n_payload_bytes ... d_state from the */
  /*  lzfse_compressed_block_header_v1 object are packed into three 64-bit */
  /*  fields in the compressed header, as follows: */
  /* */
  /*    offset  bits  value */
  /*    0       20    n_literals */
  /*    20      20    n_literal_payload_bytes */
  /*    40      20    n_matches */
  /*    60      3     literal_bits */
  /*    63      1     --- unused --- */
  /* */
  /*    0       10    literal_state[0] */
  /*    10      10    literal_state[1] */
  /*    20      10    literal_state[2] */
  /*    30      10    literal_state[3] */
  /*    40      20    n_lmd_payload_bytes */
  /*    60      3     lmd_bits */
  /*    63      1     --- unused --- */
  /* */
  /*    0       32    header_size (total header size in bytes; this does not */
  /*                  correspond to a field in the uncompressed header version,
   */
  /*                  but is required; we wouldn't know the size of the */
  /*                  compresssed header otherwise. */
  /*    32      10    l_state */
  /*    42      10    m_state */
  /*    52      10    d_state */
  /*    62      2     --- unused --- */
  unsigned char packed_fields[24];
  /*  Variable size freq tables, using a Huffman-style fixed encoding. */
  /*  Size allocated here is an upper bound (all values stored on 16 bits). */
  izl_u8 freq[2
              * (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS
                 + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS)];
} lzfse_compressed_block_header_v2;

/*! @abstract LZVN compressed block header. */
typedef struct
{
  /*  Magic number, always LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC. */
  izl_u32 magic;
  /*  Number of decoded (output) bytes. */
  izl_u32 n_raw_bytes;
  /*  Number of encoded (source) bytes. */
  izl_u32 n_payload_bytes;
} lzvn_compressed_block_header;

/* MARK: - LZFSE encode/decode interfaces */

int lzfse_encode_init (lzfse_encoder_state *s);
int lzfse_encode_translate (lzfse_encoder_state *s, lzfse_offset delta);
int lzfse_encode_base (lzfse_encoder_state *s);
int lzfse_encode_finish (lzfse_encoder_state *s);
int lzfse_decode (lzfse_decoder_state *s);

/* MARK: - LZVN encode/decode interfaces */

/*  Minimum source buffer size for compression. Smaller buffers will not be */
/*  compressed; the lzvn encoder will simply return. */
#  define LZVN_ENCODE_MIN_SRC_SIZE ((size_t)8)

/*  Maximum source buffer size for compression. Larger buffers will be */
/*  compressed partially. */
#  define LZVN_ENCODE_MAX_SRC_SIZE ((size_t)0xffffffffU)

/*  Minimum destination buffer size for compression. No compression will take
 */
/*  place if smaller. */
#  define LZVN_ENCODE_MIN_DST_SIZE ((size_t)8)

size_t lzvn_decode_scratch_size (void);
size_t lzvn_encode_scratch_size (void);
size_t lzvn_encode_buffer (void *dst, size_t dst_size, const void *src,
                           size_t src_size, void *work);
size_t lzvn_decode_buffer (void *dst, size_t dst_size, const void *src,
                           size_t src_size);

/*! @abstract Signed offset in buffers, stored on either 32 or 64 bits. */
#  if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__)
typedef izl_s64 lzvn_offset;
#  else
typedef izl_s32 lzvn_offset;
#  endif

/* MARK: - LZFSE utility functions */

/*! @abstract Load bytes from memory location SRC. */
LZFSE_INLINE izl_u16
load2 (const void *ptr)
{
  izl_u16 data;
  memcpy (&data, ptr, sizeof data);
  return data;
}

LZFSE_INLINE izl_u32
load4 (const void *ptr)
{
  izl_u32 data;
  memcpy (&data, ptr, sizeof data);
  return data;
}

LZFSE_INLINE izl_u64
load8 (const void *ptr)
{
  izl_u64 data;
  memcpy (&data, ptr, sizeof data);
  return data;
}

/*! @abstract Store bytes to memory location DST. */
LZFSE_INLINE void
store2 (void *ptr, izl_u16 data)
{
  memcpy (ptr, &data, sizeof data);
}

LZFSE_INLINE void
store4 (void *ptr, izl_u32 data)
{
  memcpy (ptr, &data, sizeof data);
}

LZFSE_INLINE void
store8 (void *ptr, izl_u64 data)
{
  memcpy (ptr, &data, sizeof data);
}

/*! @abstract Load+store bytes from locations SRC to DST. Not intended for use
 * with overlapping buffers. Note that for LZ-style compression, you need
 * copies to behave like naive memcpy( ) implementations do, splatting the
 * leading sequence if the buffers overlap. This copy does not do that, so
 * should not be used with overlapping buffers. */
LZFSE_INLINE void
copy8 (void *dst, const void *src)
{
  store8 (dst, load8 (src));
}
LZFSE_INLINE void
copy16 (void *dst, const void *src)
{
  izl_u64 m0 = load8 (src);
  izl_u64 m1 = load8 ((const unsigned char *)src + 8);
  store8 (dst, m0);
  store8 ((unsigned char *)dst + 8, m1);
}

/* =============================================================== */
/* Bitfield Operations */

/*! @abstract Extracts \p width bits from \p container, starting with \p lsb;
 * if we view \p container as a bit array, we extract \c
 * container[lsb:lsb+width]. */
LZFSE_INLINE izl_u64
extract (izl_u64 container, unsigned lsb, unsigned width)
{
  static const size_t container_width = sizeof container * 8;
  assert (lsb < container_width);
  assert (width > 0 && width <= container_width);
  assert (lsb + width <= container_width);
  if (width == container_width)
    return container;
  return (container >> lsb) & (((izl_u64)1 << width) - 1);
}

/*! @abstract Inserts \p width bits from \p data into \p container, starting
 * with \p lsb. Viewed as bit arrays, the operations is:
 * @code
 * container[:lsb] is unchanged
 * container[lsb:lsb+width] <-- data[0:width]
 * container[lsb+width:] is unchanged
 * @endcode
 */
LZFSE_INLINE izl_u64
insert (izl_u64 container, izl_u64 data, unsigned lsb, unsigned width)
{
  static const size_t container_width = sizeof container * 8;
  assert (lsb < container_width);
  assert (width > 0 && width <= container_width);
  assert (lsb + width <= container_width);
  if (width == container_width)
    return container;
  {
    izl_u64 mask = ((izl_u64)1 << width) - 1;
    return (container & ~(mask << lsb)) | (data & mask) << lsb;
  }
}

/*! @abstract Perform sanity checks on the values of
 * lzfse_compressed_block_header_v1. Test that the field values are in the
 * allowed limits, verify that the frequency tables sum to value less than
 * total number of states.
 * @return 0 if all tests passed.
 * @return negative error code with 1 bit set for each failed test. */
LZFSE_INLINE int
lzfse_check_block_header_v1 (const lzfse_compressed_block_header_v1 *header)
{
  int tests_results = 0;
  tests_results
      = tests_results
        | ((header->magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC) ? 0 : (1 << 0));
  tests_results
      = tests_results
        | ((header->n_literals <= LZFSE_LITERALS_PER_BLOCK) ? 0 : (1 << 1));
  tests_results
      = tests_results
        | ((header->n_matches <= LZFSE_MATCHES_PER_BLOCK) ? 0 : (1 << 2));

  {
    izl_u16 literal_state[4];
    memcpy (literal_state, header->literal_state, sizeof (izl_u16) * 4);

    tests_results
        = tests_results
          | ((literal_state[0] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 3));
    tests_results
        = tests_results
          | ((literal_state[1] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 4));
    tests_results
        = tests_results
          | ((literal_state[2] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 5));
    tests_results
        = tests_results
          | ((literal_state[3] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 6));

    tests_results
        = tests_results
          | ((header->l_state < LZFSE_ENCODE_L_STATES) ? 0 : (1 << 7));
    tests_results
        = tests_results
          | ((header->m_state < LZFSE_ENCODE_M_STATES) ? 0 : (1 << 8));
    tests_results
        = tests_results
          | ((header->d_state < LZFSE_ENCODE_D_STATES) ? 0 : (1 << 9));

    {
      int res;
      res = fse_check_freq (header->l_freq, LZFSE_ENCODE_L_SYMBOLS,
                            LZFSE_ENCODE_L_STATES);
      tests_results = tests_results | ((res == 0) ? 0 : (1 << 10));
      res = fse_check_freq (header->m_freq, LZFSE_ENCODE_M_SYMBOLS,
                            LZFSE_ENCODE_M_STATES);
      tests_results = tests_results | ((res == 0) ? 0 : (1 << 11));
      res = fse_check_freq (header->d_freq, LZFSE_ENCODE_D_SYMBOLS,
                            LZFSE_ENCODE_D_STATES);
      tests_results = tests_results | ((res == 0) ? 0 : (1 << 12));
      res = fse_check_freq (header->literal_freq, LZFSE_ENCODE_LITERAL_SYMBOLS,
                            LZFSE_ENCODE_LITERAL_STATES);
      tests_results = tests_results | ((res == 0) ? 0 : (1 << 13));

      if (tests_results)
        {
          return tests_results
                 | 0x80000000; /* each 1 bit is a test that failed */
                               /* (except for the sign bit) */
        }

      return 0; /* OK */
    }
  }
}

/* MARK: - L, M, D encoding constants for LZFSE */

/*  Largest encodable L (literal length), M (match length) and D (match */
/*  distance) values. */
#  define LZFSE_ENCODE_MAX_L_VALUE 315
#  define LZFSE_ENCODE_MAX_M_VALUE 2359
#  define LZFSE_ENCODE_MAX_D_VALUE 262139

/*! @abstract The L, M, D data streams are all encoded as a "base" value, which
 * is FSE-encoded, and an "extra bits" value, which is the difference between
 * value and base, and is simply represented as a raw bit value (because it
 * is the low-order bits of a larger number, not much entropy can be
 * extracted from these bits by more complex encoding schemes). The following
 * tables represent the number of low-order bits to encode separately and the
 * base values for each of L, M, and D.
 *
 * @note The inverse tables for mapping the other way are significantly larger.
 * Those tables have been split out to lzfse_encode_tables.h in order to keep
 * this file relatively small. */
static const izl_u8 l_extra_bits[LZFSE_ENCODE_L_SYMBOLS]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8 };
static const izl_s32 l_base_value[LZFSE_ENCODE_L_SYMBOLS]
    = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60 };
static const izl_u8 m_extra_bits[LZFSE_ENCODE_M_SYMBOLS]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11 };
static const izl_s32 m_base_value[LZFSE_ENCODE_M_SYMBOLS] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312
};
static const izl_u8 d_extra_bits[LZFSE_ENCODE_D_SYMBOLS]
    = { 0,  0,  0,  0,  1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,  3,
        4,  4,  4,  4,  5,  5,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
        8,  8,  8,  8,  9,  9,  9,  9,  10, 10, 10, 10, 11, 11, 11, 11,
        12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15 };
static const izl_s32 d_base_value[LZFSE_ENCODE_D_SYMBOLS]
    = { 0,     1,     2,     3,      4,      6,      8,      10,
        12,    16,    20,    24,     28,     36,     44,     52,
        60,    76,    92,    108,    124,    156,    188,    220,
        252,   316,   380,   444,    508,    636,    764,    892,
        1020,  1276,  1532,  1788,   2044,   2556,   3068,   3580,
        4092,  5116,  6140,  7164,   8188,   10236,  12284,  14332,
        16380, 20476, 24572, 28668,  32764,  40956,  49148,  57340,
        65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372 };

# endif /* LZFSE_INTERNAL_H */

/* ===== original lzvn_encode_base.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZVN low-level encoder */

# ifndef LZVN_ENCODE_BASE_H
#  define LZVN_ENCODE_BASE_H

/* =============================================================== */
/* Types and Constants */

#  define LZVN_ENCODE_HASH_BITS                                                 \
  14 /* number of bits returned by the hash function [10, 16] */
#  define LZVN_ENCODE_OFFSETS_PER_HASH                                          \
  4 /* stored offsets stack for each hash value, MUST be 4 */
#  define LZVN_ENCODE_HASH_VALUES                                               \
  (1 << LZVN_ENCODE_HASH_BITS) /* number of entries in hash table */
#  define LZVN_ENCODE_MAX_DISTANCE                                              \
  0xffff /* max match distance we can represent with LZVN encoding, MUST be   \
          */
         /* 0xFFFF */
#  define LZVN_ENCODE_MIN_MARGIN                                                \
  8 /* min number of bytes required between current and end during encoding,  \
     */
    /* MUST be >= 8 */
#  define LZVN_ENCODE_MAX_LITERAL_BACKLOG                                       \
  400 /* if the number of pending literals exceeds this size, emit a long */
      /* literal, MUST be >= 271 */

/*! @abstract Type of table entry. */
typedef struct
{
  izl_s32 indices[4]; /* signed indices in source buffer */
  izl_u32 values[4];  /* corresponding 32-bit values */
} lzvn_encode_entry_type;

/* Work size */
#  define LZVN_ENCODE_WORK_SIZE                                                 \
  (LZVN_ENCODE_HASH_VALUES * sizeof (lzvn_encode_entry_type))

/*! @abstract Match */
typedef struct
{
  lzvn_offset m_begin; /* beginning of match, current position */
  lzvn_offset
      m_end;     /* end of match, this is where the next literal would begin */
                 /* if we emit the entire match */
  lzvn_offset M; /* match length M: m_end - m_begin */
  lzvn_offset D; /* match distance D */
  lzvn_offset K; /* match gain: M - distance storage (L not included) */
} lzvn_match_info;

/* =============================================================== */
/* Internal encoder state */

/*! @abstract Base encoder state and I/O. */
typedef struct
{

  /* Encoder I/O */

  /* Source buffer */
  const unsigned char *src;
  /* Valid range in source buffer: we can access src[i] for src_begin <= i < */
  /* src_end. src_begin may be negative. */
  lzvn_offset src_begin;
  lzvn_offset src_end;
  /* Next byte to process in source buffer */
  lzvn_offset src_current;
  /* Next byte after the last byte to process in source buffer. We MUST have:
   */
  /* src_current_end + 8 <= src_end. */
  lzvn_offset src_current_end;
  /* Next byte to encode in source buffer, may be before or after src_current.
   */
  lzvn_offset src_literal;

  /* Next byte to write in destination buffer */
  unsigned char *dst;
  /* Valid range in destination buffer: [dst_begin, dst_end - 1] */
  unsigned char *dst_begin;
  unsigned char *dst_end;

  /* Encoder state */

  /* Pending match */
  lzvn_match_info pending;

  /* Distance for last emitted match, or 0 */
  lzvn_offset d_prev;

  /* Hash table used to find matches. Stores LZVN_ENCODE_OFFSETS_PER_HASH
   * 32-bit */
  /* signed indices in the source buffer, and the corresponding 4-byte values.
   */
  /* The number of entries in the table is LZVN_ENCODE_HASH_VALUES. */
  lzvn_encode_entry_type *table;

} lzvn_encoder_state;

/*! @abstract Encode source to destination.
 *  Update \p state.
 *  The call ensures \c src_literal is never left too far behind \c
 * src_current. */
void lzvn_encode (lzvn_encoder_state *state);

# endif /* LZVN_ENCODE_BASE_H */

/* ===== original lzvn_decode_base.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* LZVN low-level decoder (v2) */
/* Functions in the low-level API should switch to these at some point. */
/* Apr 2014 */

# ifndef LZVN_DECODE_BASE_H
#  define LZVN_DECODE_BASE_H

/*! @abstract Base decoder state. */
typedef struct
{

  /* Decoder I/O */

  /* Next byte to read in source buffer */
  const unsigned char *src;
  /* Next byte after source buffer */
  const unsigned char *src_end;

  /* Next byte to write in destination buffer (by decoder) */
  unsigned char *dst;
  /* Valid range for destination buffer is [dst_begin, dst_end - 1] */
  unsigned char *dst_begin;
  unsigned char *dst_end;
  /* Next byte to read in destination buffer (modified by caller) */
  unsigned char *dst_current;

  /* Decoder state */

  /* Partially expanded match, or 0,0,0. */
  /* In that case, src points to the next literal to copy, or the next op-code
   */
  /* if L==0. */
  size_t L, M, D;

  /* Distance for last emitted match, or 0 */
  lzvn_offset d_prev;

  /* Did we decode end-of-stream? */
  int end_of_stream;

} lzvn_decoder_state;

/*! @abstract Decode source to destination.
 *  Updates \p state (src,dst,d_prev). */
void lzvn_decode (lzvn_decoder_state *state);

# endif /* LZVN_DECODE_BASE_H */

/* ===== original lzfse_encode_tables.h ===== */
/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

# ifndef LZFSE_ENCODE_TABLES_H
#  define LZFSE_ENCODE_TABLES_H

#  if 0 /* MSVC extensions excluded from portable C89 amalgamation */
#   define inline __inline
#  endif

static izl_u8
l_base_from_value (izl_s32 value)
{
  static const izl_u8 sym[LZFSE_ENCODE_MAX_L_VALUE + 1] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 16, 16,
    16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19
  };
  return sym[value];
}
static izl_u8
m_base_from_value (izl_s32 value)
{
  static const izl_u8 sym[LZFSE_ENCODE_MAX_M_VALUE + 1] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 16, 16,
    16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19
  };
  return sym[value];
}

static izl_u8
d_base_from_value (izl_s32 value)
{
  static const izl_u8 sym[64 * 4] = {
    0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  7,  7,  8,  8,  8,  8,  9,  9,  9,
    9,  10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13,
    13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15,
    15, 15, 15, 16, 16, 16, 16, 16, 17, 18, 19, 20, 20, 21, 21, 22, 22, 23, 23,
    24, 24, 24, 24, 25, 25, 25, 25, 26, 26, 26, 26, 27, 27, 27, 27, 28, 28, 28,
    28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 30, 30, 30, 30, 30, 30,
    30, 30, 31, 31, 31, 31, 31, 31, 31, 31, 32, 32, 32, 32, 32, 33, 34, 35, 36,
    36, 37, 37, 38, 38, 39, 39, 40, 40, 40, 40, 41, 41, 41, 41, 42, 42, 42, 42,
    43, 43, 43, 43, 44, 44, 44, 44, 44, 44, 44, 44, 45, 45, 45, 45, 45, 45, 45,
    45, 46, 46, 46, 46, 46, 46, 46, 46, 47, 47, 47, 47, 47, 47, 47, 47, 48, 48,
    48, 48, 48, 49, 50, 51, 52, 52, 53, 53, 54, 54, 55, 55, 56, 56, 56, 56, 57,
    57, 57, 57, 58, 58, 58, 58, 59, 59, 59, 59, 60, 60, 60, 60, 60, 60, 60, 60,
    61, 61, 61, 61, 61, 61, 61, 61, 62, 62, 62, 62, 62, 62, 62, 62, 63, 63, 63,
    63, 63, 63, 63, 63, 0,  0,  0,  0
  };
  int index = 0;
  int in_range_k;
  in_range_k = (value >= 0 && value < 60);
  index |= (((value - 0) >> 0) + 0) & -in_range_k;
  in_range_k = (value >= 60 && value < 1020);
  index |= (((value - 60) >> 4) + 64) & -in_range_k;
  in_range_k = (value >= 1020 && value < 16380);
  index |= (((value - 1020) >> 8) + 128) & -in_range_k;
  in_range_k = (value >= 16380 && value < 262140);
  index |= (((value - 16380) >> 12) + 192) & -in_range_k;
  return sym[index & 255];
}

# endif /* LZFSE_ENCODE_TABLES_H */

#endif /* IZ_LZFSE_H */
