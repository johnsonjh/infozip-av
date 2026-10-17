/* Native host test of the portable DOS16 one-shot salt-pool implementation.
 * This does not establish that an actual DOS emulator implements rename().
 * Compile as strict ANSI C89.  The header's only external helper is the
 * intentional nonoptimizable wipe routine, defined here for isolation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void iz_aes_wipe(void *ptr, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (n--) *p++ = 0;
}
#include "../../zip30/msdos/aes_entropy.h"

int main(int argc, char **argv)
{
    unsigned char expected[48], output[16];
    FILE *f;
    if (argc != 2) return 2;
    if (strcmp(argv[1], "missing") == 0) {
        if (iz_dos_salt_from_pool(output, 16)) return 3;
        return 0;
    }
    if (strcmp(argv[1], "leftover") == 0) {
        if (iz_dos_salt_from_pool(output, 16)) return 4;
        return 0;
    }
    if (strcmp(argv[1], "present") != 0) return 2;
    f = fopen("XTRRND.BIN", "rb");
    if (f == NULL) return 5;
    if (fread(expected, 1, sizeof(expected), f) != sizeof(expected)) {
        fclose(f);
        return 6;
    }
    fclose(f);
    if (!iz_dos_salt_from_pool(output, 8) ||
        memcmp(output, expected, 8) != 0) return 7;
    if (!iz_dos_salt_from_pool(output, 12) ||
        memcmp(output, expected + 16, 12) != 0) return 8;
    if (!iz_dos_salt_from_pool(output, 16) ||
        memcmp(output, expected + 32, 16) != 0) return 9;
    if (iz_dos_salt_from_pool(output, 8)) return 10;
    f = fopen("XTRRND.BIN", "rb");
    if (f != NULL) {fclose(f); return 11;}
    /* .USE is removed by the atexit handler, not returned as a new pool. */
    f = fopen("XTRRND.USE", "rb");
    if (f == NULL) return 12;
    fclose(f);
    iz_aes_wipe(expected, sizeof(expected));
    return 0;
}
