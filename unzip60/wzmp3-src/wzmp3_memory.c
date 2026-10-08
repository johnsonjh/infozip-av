/* SPDX-License-Identifier: MIT-0 */
#include "wzmp3_memory.h"
#include <stdlib.h>
#include <string.h>
/* A union ensures returned pointers preserve malloc's alignment. */
typedef union wzmp3_memory_header_u {
    size_t total;
    double aligned_double;
    void *aligned_pointer;
    long aligned_long;
} wzmp3_memory_header;
void wzmp3_memory_init(wzmp3_memory *m, size_t limit)
{
    if (m) { m->current = m->peak = 0U; m->limit = limit; m->exhausted = 0; }
}
void *wzmp3_memory_alloc(wzmp3_memory *m, size_t count)
{
    wzmp3_memory_header *h;
    size_t total;
    if (!count) count = 1U;
    if (count > ((size_t)-1) - sizeof(*h)) goto failed;
    total = count + sizeof(*h);
    if (m && total > m->limit - m->current) goto failed;
    h = (wzmp3_memory_header *)malloc(total);
    if (!h) goto failed;
    h->total = total;
    if (m) {
        m->current += total;
        if (m->current > m->peak) m->peak = m->current;
    }
    return (void *)(h + 1);
failed:
    if (m) m->exhausted = 1;
    return NULL;
}
void *wzmp3_memory_calloc(wzmp3_memory *m, size_t count, size_t size)
{
    size_t total;
    void *p;
    if (size && count > ((size_t)-1)/size) {
        if (m) m->exhausted = 1;
        return NULL;
    }
    total = count * size;
    p = wzmp3_memory_alloc(m, total);
    if (p) memset(p, 0, total);
    return p;
}
void *wzmp3_memory_realloc(wzmp3_memory *m, void *ptr, size_t count)
{
    wzmp3_memory_header *h, *n;
    size_t total, old;
    if (!ptr) return wzmp3_memory_alloc(m, count);
    if (!count) count = 1U;
    if (count > ((size_t)-1) - sizeof(*h)) goto failed;
    total = count + sizeof(*h);
    h = ((wzmp3_memory_header *)ptr) - 1;
    old = h->total;
    if (m && (old > m->current || (total > old &&
              total-old > m->limit-m->current))) goto failed;
    n = (wzmp3_memory_header *)realloc(h, total);
    if (!n) goto failed;
    n->total = total;
    if (m) {
        m->current = m->current - old + total;
        if (m->current > m->peak) m->peak = m->current;
    }
    return (void *)(n + 1);
failed:
    if (m) m->exhausted = 1;
    return NULL;
}
void wzmp3_memory_free(wzmp3_memory *m, void *ptr)
{
    wzmp3_memory_header *h;
    if (!ptr) return;
    h = ((wzmp3_memory_header *)ptr) - 1;
    if (m) {
        if (h->total <= m->current) m->current -= h->total;
        else m->exhausted = 1; /* internal bookkeeping error */
    }
    free(h);
}
