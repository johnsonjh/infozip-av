/* SPDX-License-Identifier: MIT-0
 * MPEG Huffman codebook checks for CC0 minimp3-derived inverse tables.
 */
#include "wzmp3_codebooks.h"
#include <stdio.h>
#include <stdlib.h>
static int valid(const wzmp3_codebook books[34])
{
    unsigned int t, a, b, count, expected;
    for (t = 0; t < 34U; ++t) {
        const wzmp3_codebook *p = &books[t];
        count = 0U;
        if (t == 0U || t == 4U || t == 14U) continue;
        if (p->linbits > 13U || p->maxvalue > 15U || p->quad > 1U)
            return 0;
        expected = p->quad ? 16U : (p->maxvalue + 1U) * (p->maxvalue + 1U);
        for (a = 0; a < 256U; ++a) {
            const wzmp3_codeword *x = &p->symbols[a];
            if (!x->length) continue;
            ++count;
            if (x->length > 32U ||
                (x->length < 32U && (x->code >> x->length) != 0UL))
                return 0;
            for (b = 0; b < 256U; ++b) {
                const wzmp3_codeword *y = &p->symbols[b];
                if (a == b || !y->length) continue;
                if (x->length <= y->length &&
                    (y->code >> (y->length - x->length)) == x->code)
                    return 0;
            }
        }
        if (count != expected) return 0;
    }
    if (books[0].maxvalue || books[0].symbols[0].length ||
        books[4].symbols[0].length || books[14].symbols[0].length)
        return 0;
    return 1;
}
int main(void)
{
    wzmp3_codebook *books;
    int ok;
    books = (wzmp3_codebook *)malloc(34U * sizeof(*books));
    if (!books) return 2;
    wzmp3_codebooks_init(books);
    ok = valid(books);
    free(books);
    printf("CC0 MPEG Huffman codebooks: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
