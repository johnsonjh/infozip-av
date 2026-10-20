/* SPDX-License-Identifier: MIT-0
 * Host API mock for testing OW2's weak OS/2 compatibility entropy branch.
 * Does not establish cryptographic quality or actual native OS/2 behavior.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "entropy/os2.h"
#include "../../zip30/wzaes.h"

static int fail_clock;
static int fail_memory;
static int fail_after = -1;
static int observed;
APIRET DosGetDateTime(DATETIME *dt)
{
    if (fail_clock || fail_after == 0) return 5UL;
    if (fail_after > 0) --fail_after;
    memset(dt, 0, sizeof(*dt));
    dt->year = 2026; dt->month = 10; dt->day = 20;
    dt->hours = 15; dt->minutes = 40; dt->seconds = 2;
    dt->hundredths = (unsigned char)(observed++ % 100);
    return 0;
}
APIRET DosQuerySysInfo(ULONG low, ULONG high, void *ptr, ULONG length)
{
    ULONG i, *p = (ULONG *)ptr;
    if (fail_memory) return 5UL;
    if (low != QSV_MS_COUNT || high != QSV_TOTAVAILMEM ||
        length != sizeof(ULONG) * 6UL) return 87UL;
    for (i = 0; i < 6; i++) p[i] = 12345UL + i + (ULONG)observed;
    return 0;
}
APIRET DosGetInfoBlocks(PTIB *t, PPIB *p)
{
    static TIB tib;
    static PIB pib = {987UL};
    *t = &tib; *p = &pib;
    return 0;
}
int main(int argc, char **argv)
{
    unsigned char a[16], b[16], sentinel[16], bigger[48];
    if (argc > 1 && strcmp(argv[1], "seed_failure") == 0) {
        size_t i;
        memset(a, 0xcc, sizeof(a));
        fail_clock = 1;
        if (iz_aes_entropy(a, sizeof(a)) != 0) return 11;
        for (i=0; i<sizeof(a); ++i) if (a[i]) return 12;
        fail_clock = 0;
        fail_memory = 1;
        memset(a, 0xcc, sizeof(a));
        if (iz_aes_entropy(a, sizeof(a)) != 0) return 13;
        for (i=0; i<sizeof(a); ++i) if (a[i]) return 14;
        puts("OS/2 initial entropy failure tests: PASS");
        return 0;
    }
    memset(a, 0xcc, sizeof(a));
    if (iz_aes_entropy(a, sizeof(a)) != 1) return 1;
    if (iz_aes_entropy(b, sizeof(b)) != 1) return 2;
    if (memcmp(a,b,sizeof(a)) == 0) return 3;
    if (iz_aes_entropy(NULL, 16U) != 0) return 4;
    if (iz_aes_entropy(sentinel, 0U) != 0) return 5;
    memset(sentinel, 0xcc, sizeof(sentinel));
    fail_clock = 1;
    if (iz_aes_entropy(sentinel, sizeof(sentinel)) != 0) return 6;
    { size_t i; for (i=0; i<sizeof(sentinel); ++i) if (sentinel[i]) return 7; }
    fail_clock = 0;
    fail_memory = 1;
    memset(sentinel, 0xcc, sizeof(sentinel));
    if (iz_aes_entropy(sentinel, sizeof(sentinel)) != 0) return 8;
    { size_t i; for (i=0; i<sizeof(sentinel); ++i) if (sentinel[i]) return 9; }
    fail_memory = 0;
    if (iz_aes_entropy(sentinel, sizeof(sentinel)) != 1) return 10;
    memset(bigger,0xcc,sizeof(bigger));
    fail_after = 1; /* First SHA-1 output block succeeds; second fails. */
    if (iz_aes_entropy(bigger, sizeof(bigger)) != 0) return 15;
    { size_t i; for (i=0; i<sizeof(bigger); ++i) if (bigger[i]) return 16; }
    fail_after = -1;
    if (iz_aes_entropy(bigger, sizeof(bigger)) != 1) return 17;
    puts("OS/2 weak-entropy API-mock tests: PASS");
    return 0;
}
