/*
 * CRC-32/IEEE carry-less-multiplication accelerator for x86-64.
 * SPDX-License-Identifier: MIT-0
 */
#ifndef IZ_CRC32_PCLMUL_H
#define IZ_CRC32_PCLMUL_H

#if defined(__GNUC__) && \
    (defined(__x86_64__) || defined(__amd64__)) && \
    !defined(USE_ZLIB) && !defined(ASM_CRC) && \
    !defined(CRC_TABLE_ONLY) && !defined(IZ_CRC_BE_OPTIMIZ) && \
    !defined(NO_PCLMUL_CRC32) && !defined(NO_PCLMUL_CRC)
#define IZ_CRC32_PCLMUL 1

/* All words below are little-endian 32-bit halves of 64-bit GF(2) keys.
 * The x86-64 ABI guarantees unsigned int is 32 bits.  movdqu accepts
 * unaligned constant data and unaligned input data. */
static ZCONST unsigned int iz_pclmul_keys[4][4] = {
    { 0x54442bd4U, 1U, 0xc6e41596U, 1U }, /* 512-bit fold */
    { 0x751997d0U, 1U, 0xccaa009eU, 0U }, /* 128-bit fold */
    { 0x63cd6124U, 1U, 0U,          0U }, /* 128 -> 64 -> 32 */
    { 0xdb710641U, 1U, 0xf7011641U, 1U }  /* Barrett reduction */
};

/* No unsynchronized mutable cache: no data race in reentrant or DLL builds.
 * GCC/Clang atomics are used for a one-time feature check where available. */
static int iz_pclmul_available(void)
{
    static int cached = 0; /* 0 = unknown, 1 = absent, 2 = present */
    int v;
    unsigned int a, b, c, d;

#if defined(__clang__) || (__GNUC__ > 4) || \
    (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)
    v = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (v != 0)
        return v == 2;
#else
    /* Old GNU compilers have no __atomic builtins: re-query each time.
     * In this configuration cached is never written or read at runtime. */
    (void)cached;
#endif
    a = 1U;
    c = 0U;
    __asm__ __volatile__("cpuid"
                         : "+a"(a), "=b"(b), "+c"(c), "=d"(d)
                         : : "memory");
    (void)a;
    (void)b;
    (void)d;
    v = (c & 2U) ? 2 : 1; /* CPUID.01H:ECX.PCLMULQDQ[1] */
#if defined(__clang__) || (__GNUC__ > 4) || \
    (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)
    __atomic_store_n(&cached, v, __ATOMIC_RELAXED);
#endif
    return v == 2;
}

/* Process a positive multiple of 16 bytes (minimum 64).  Callers handle
 * shorter inputs and the 0..15 trailing bytes with the original CRC code.
 * The four independent folding streams reduce carry-less multiply latency. */
static z_uint4 iz_crc32_pclmul(z_uint4 crc, ZCONST uch *buf, extent len)
{
    ZCONST uch *p = buf;
    extent n = len;
    unsigned int result;
    unsigned int seed = (unsigned int)crc ^ 0xffffffffU;

    __asm__ __volatile__(
        "movdqu   0(%[p]), %%xmm0\n\t"
        "movdqu  16(%[p]), %%xmm1\n\t"
        "movdqu  32(%[p]), %%xmm2\n\t"
        "movdqu  48(%[p]), %%xmm3\n\t"
        "movd %[seed], %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "addq $64, %[p]\n\t"
        "subq $64, %[n]\n\t"
        "movdqu 0(%[keys]), %%xmm4\n\t"
        "cmpq $64, %[n]\n\t"
        "jb 2f\n\t"
        "1:\n\t"
        /* Each lane represents every fourth 16-byte block. */
        "movdqa %%xmm0, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm0\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "movdqu 0(%[p]), %%xmm6\n\t"
        "pxor %%xmm6, %%xmm0\n\t"
        "movdqa %%xmm1, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm1\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm1\n\t"
        "movdqu 16(%[p]), %%xmm6\n\t"
        "pxor %%xmm6, %%xmm1\n\t"
        "movdqa %%xmm2, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm2\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm2\n\t"
        "movdqu 32(%[p]), %%xmm6\n\t"
        "pxor %%xmm6, %%xmm2\n\t"
        "movdqa %%xmm3, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm3\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm3\n\t"
        "movdqu 48(%[p]), %%xmm6\n\t"
        "pxor %%xmm6, %%xmm3\n\t"
        "addq $64, %[p]\n\t"
        "subq $64, %[n]\n\t"
        "cmpq $64, %[n]\n\t"
        "jae 1b\n\t"
        "2:\n\t"
        /* Merge 4 independent accumulators in stream order. */
        "movdqu 16(%[keys]), %%xmm4\n\t"
        "movdqa %%xmm0, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm0\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm0\n\t"
        "movdqa %%xmm0, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm0\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "pxor %%xmm2, %%xmm0\n\t"
        "movdqa %%xmm0, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm0\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "pxor %%xmm3, %%xmm0\n\t"
        /* Remaining full 16-byte blocks, still using 128-bit fold. */
        "cmpq $16, %[n]\n\t"
        "jb 4f\n\t"
        "3:\n\t"
        "movdqa %%xmm0, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm0\n\t"
        "pclmulqdq $0x11, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "movdqu (%[p]), %%xmm6\n\t"
        "pxor %%xmm6, %%xmm0\n\t"
        "addq $16, %[p]\n\t"
        "subq $16, %[n]\n\t"
        "cmpq $16, %[n]\n\t"
        "jae 3b\n\t"
        "4:\n\t"
        /* Fold 128 bits down to 64, then reduce using Barrett. */
        "movdqa %%xmm0, %%xmm5\n\t"
        "pclmulqdq $0x10, %%xmm4, %%xmm0\n\t"
        "psrldq $8, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "pcmpeqd %%xmm7, %%xmm7\n\t"
        "psrldq $12, %%xmm7\n\t"
        "movdqa %%xmm0, %%xmm5\n\t"
        "pand %%xmm7, %%xmm5\n\t"
        "movdqu 32(%[keys]), %%xmm4\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm5\n\t"
        "psrldq $4, %%xmm0\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "movdqa %%xmm0, %%xmm5\n\t"
        "pand %%xmm7, %%xmm5\n\t"
        "movdqu 48(%[keys]), %%xmm4\n\t"
        "pclmulqdq $0x10, %%xmm4, %%xmm5\n\t"
        "pand %%xmm7, %%xmm5\n\t"
        "pclmulqdq $0x00, %%xmm4, %%xmm5\n\t"
        "pxor %%xmm5, %%xmm0\n\t"
        "psrlq $32, %%xmm0\n\t"
        "movd %%xmm0, %[out]\n\t"
        "notl %[out]\n\t"
        : [out] "=r"(result), [p] "+r"(p), [n] "+r"(n)
        : [seed] "r"(seed), [keys] "r"(iz_pclmul_keys)
        : "cc", "memory", "xmm0", "xmm1", "xmm2", "xmm3",
          "xmm4", "xmm5", "xmm6", "xmm7");
    return (z_uint4)result;
}

#endif /* eligible GNU x86-64 built-in CRC */
#endif /* IZ_CRC32_PCLMUL_H */
