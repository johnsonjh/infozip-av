/* SPDX-License-Identifier: MIT-0 */
/* Build with -std=c89 -pedantic -Wall -Wextra -Werror; ASan/UBSan optional. */
#include "../unzip60/xtro_assoc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char companion[] =
    "__XTRO_ZIP__/x/0123456789abcdef0123456789abcdef.xtm";
static unsigned char extra[76];

static void init_extra(void)
{
    unsigned i;
    static const unsigned char id[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    memset(extra, 0, sizeof(extra));
    extra[0] = 0x54;
    extra[1] = 0x58;
    extra[2] = 72;
    memcpy(extra + 4, "XTRO\001\000\002\000", 8);
    for (i = 0; i < 16; ++i) extra[12 + i] = id[i];
}

int main(void)
{
    unsigned i, j;
    unsigned long seed = 1UL;
    char label[96], copy[52];
    unsigned char noise[96];
    const uz_xtro_assoc *a;

    init_extra();
    assert(uz_xtro_assoc_extra_kind(extra, sizeof(extra)) ==
           UZ_XTRO_ASSOC_OWNER);
    assert(uz_xtro_assoc_note(companion, NULL, 0) ==
           UZ_XTRO_ASSOC_COMPANION);
    assert(!uz_xtro_assoc_owner(uz_xtro_assoc_first()));
    assert(uz_xtro_assoc_note("SOURCE/ONE.TXT", extra, sizeof(extra)) ==
           UZ_XTRO_ASSOC_OWNER);
    assert(!strcmp(uz_xtro_assoc_label(companion, label, sizeof(label)),
                   "[Xtro: SOURCE/ONE.TXT]"));
    a = uz_xtro_assoc_first();
    assert(a && uz_xtro_assoc_has_companion(a));
    uz_xtro_assoc_member_name(a, copy);
    assert(!strcmp(copy, companion));
    assert(!uz_xtro_assoc_next(a));

    assert(uz_xtro_assoc_note("SOURCE/TWO.TXT", extra, sizeof(extra)) ==
           UZ_XTRO_ASSOC_OWNER);
    assert(!strcmp(uz_xtro_assoc_label(companion, label, sizeof(label)),
                   "[Xtro: ambiguous owner]"));
    uz_xtro_assoc_reset();

    assert(uz_xtro_assoc_note(companion, NULL, 0) ==
           UZ_XTRO_ASSOC_COMPANION);
    assert(!strcmp(uz_xtro_assoc_label(companion, label, sizeof(label)),
                   "[Xtro: owner not yet identified]"));
    assert(uz_xtro_assoc_note("SOURCE/ONE.TXT", extra, sizeof(extra)) ==
           UZ_XTRO_ASSOC_OWNER);
    assert(uz_xtro_assoc_needs_followup(uz_xtro_assoc_first()));
    assert(!strcmp(uz_xtro_assoc_label(companion, label, sizeof(label)),
                   "[Xtro: SOURCE/ONE.TXT]"));
    uz_xtro_assoc_reset();

    extra[8] = 2; /* unsupported metadata version */
    assert(!uz_xtro_assoc_extra_kind(extra, sizeof(extra)));
    extra[8] = 1;
    for (i = 0; i < 20000; ++i) {
        for (j = 0; j < sizeof(noise); ++j) {
            seed = seed * 1664525UL + 1013904223UL;
            noise[j] = (unsigned char)(seed >> 24);
        }
        (void)uz_xtro_assoc_note("FUZZ.TXT", noise,
                                 (size_t)(i % sizeof(noise)));
        if (i % 4096U == 0U) uz_xtro_assoc_reset();
    }
    uz_xtro_assoc_reset();
    puts("PASS: Xtro association C89 corpus");
    return 0;
}
