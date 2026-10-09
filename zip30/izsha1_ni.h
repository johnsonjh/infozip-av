/*
 * Intel/AMD SHA extension SHA-1 block compression.
 * SPDX-License-Identifier: MIT-0
 */
#ifndef IZ_SHA1_NI_H
#define IZ_SHA1_NI_H
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__amd64__)) \
    && !defined(NO_SHA1_NI) && !defined(IZ_NO_SHA1_NI) \
    && (defined(__clang__) || (__GNUC__ >= 5))
#define IZ_SHA1_NI_ENABLED 1
#include <cpuid.h>
#include <immintrin.h>

/* GCC/Clang both accept function-local instruction-set selection.
 * The caller and CPUID gate remain baseline x86-64 code. */
#define IZ_SHA1_NI_TARGET __attribute__((target("sha,ssse3")))

static int
iz_sha1_ni_available(void)
{
  /* Atomic even in concurrent library callers; redundant CPUID checks
   * during initialization are harmless. No pthread linkage required. */
  static int cached = 0; /* 0 unknown, 1 no, 2 yes */
  int choice = __atomic_load_n(&cached, __ATOMIC_RELAXED);
  unsigned int a, b, c, d;
  if (choice != 0)
    return choice == 2;
  choice = 1;
  if (__get_cpuid_max(0, (unsigned int *)0) >= 7 &&
      __get_cpuid(1, &a, &b, &c, &d) && (c & (1U << 9)) &&
      __get_cpuid_count(7, 0, &a, &b, &c, &d) &&
      (b & (1U << 29)))
    choice = 2;
  __atomic_store_n(&cached, choice, __ATOMIC_RELAXED);
  return choice == 2;
}

/* Input is an arbitrary unaligned 64-byte block; state words are
 * stored in big-endian SHA-1 order as the original C core expects.
 * SHA1MSG1/SHA1MSG2 expand four schedule words at a time.
 * SHA1RNDS4 calculates four SHA-1 rounds at a time. */
static IZ_SHA1_NI_TARGET void
iz_sha1_ni_transform(iz_sha1 *s, const unsigned char *p)
{
  __m128i w[4], abcd, save, e, esave, old, next, msg, mask;
  unsigned int state[4];
  unsigned int i;
  /* Reverse all 16 input bytes: endian convert AND reorder words.
   * The most-significant SIMD lane holds the earliest SHA word. */
  mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,
                      8, 9, 10, 11, 12, 13, 14, 15);
  for (i = 0; i < 4; ++i)
    w[i] = _mm_shuffle_epi8(
      _mm_loadu_si128((const __m128i *)(const void *)(p + 16 * i)),
      mask);

  abcd = _mm_set_epi32((int)s->h[0], (int)s->h[1],
                       (int)s->h[2], (int)s->h[3]);
  e = _mm_set_epi32((int)s->h[4], 0, 0, 0);
  save = abcd;
  esave = e;
  old = abcd;
  msg = _mm_add_epi32(w[0], e);
  abcd = _mm_sha1rnds4_epu32(abcd, msg, 0);
#define IZ_SHA1_NI_ROUNDS(I, K) do { \
    if ((I) >= 4) \
      w[(I) & 3] = _mm_sha1msg2_epu32( \
        _mm_xor_si128(_mm_sha1msg1_epu32(w[(I) & 3], \
                                         w[((I) + 1) & 3]), \
                      w[((I) + 2) & 3]), w[((I) + 3) & 3]); \
    next = abcd; \
    msg = _mm_sha1nexte_epu32(old, w[(I) & 3]); \
    abcd = _mm_sha1rnds4_epu32(abcd, msg, K); \
    old = next; \
  } while (0)
  IZ_SHA1_NI_ROUNDS(1, 0);
  IZ_SHA1_NI_ROUNDS(2, 0);
  IZ_SHA1_NI_ROUNDS(3, 0);
  IZ_SHA1_NI_ROUNDS(4, 0);
  IZ_SHA1_NI_ROUNDS(5, 1);
  IZ_SHA1_NI_ROUNDS(6, 1);
  IZ_SHA1_NI_ROUNDS(7, 1);
  IZ_SHA1_NI_ROUNDS(8, 1);
  IZ_SHA1_NI_ROUNDS(9, 1);
  IZ_SHA1_NI_ROUNDS(10, 2);
  IZ_SHA1_NI_ROUNDS(11, 2);
  IZ_SHA1_NI_ROUNDS(12, 2);
  IZ_SHA1_NI_ROUNDS(13, 2);
  IZ_SHA1_NI_ROUNDS(14, 2);
  IZ_SHA1_NI_ROUNDS(15, 3);
  IZ_SHA1_NI_ROUNDS(16, 3);
  IZ_SHA1_NI_ROUNDS(17, 3);
  IZ_SHA1_NI_ROUNDS(18, 3);
  IZ_SHA1_NI_ROUNDS(19, 3);
#undef IZ_SHA1_NI_ROUNDS
  e = _mm_sha1nexte_epu32(old, esave);
  abcd = _mm_add_epi32(abcd, save);
  _mm_storeu_si128((__m128i *)(void *)state, abcd);
  s->h[0] = (unsigned long)state[3];
  s->h[1] = (unsigned long)state[2];
  s->h[2] = (unsigned long)state[1];
  s->h[3] = (unsigned long)state[0];
  s->h[4] = (unsigned long)(unsigned int)_mm_cvtsi128_si32(
                       _mm_srli_si128(e, 12));
  /* The portable SHA-1 implementation erases its message schedule.
   * Preserve that property for SHA-NI and erase the temporary state. */
  {
    volatile unsigned char *v = (volatile unsigned char *)(void *)w;
    for (i = 0; i < sizeof(w); ++i)
      v[i] = 0;
    v = (volatile unsigned char *)(void *)state;
    for (i = 0; i < sizeof(state); ++i)
      v[i] = 0;
  }
}
#undef IZ_SHA1_NI_TARGET
#endif /* IZ_SHA1_NI_ENABLED */
#endif /* IZ_SHA1_NI_H */
