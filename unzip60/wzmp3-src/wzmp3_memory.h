/* SPDX-License-Identifier: MIT-0
 * Per-decoder, C89 allocation accounting. Each block includes its header in
 * the budget. Does not claim to account for the platform malloc overhead.
 */
#ifndef WZMP3_MEMORY_H
#define WZMP3_MEMORY_H
#include <stddef.h>
typedef struct wzmp3_memory_s {
    size_t current, peak, limit;
    int exhausted;
} wzmp3_memory;
void wzmp3_memory_init(wzmp3_memory *m, size_t limit);
void *wzmp3_memory_alloc(wzmp3_memory *m, size_t count);
void *wzmp3_memory_calloc(wzmp3_memory *m, size_t count, size_t size);
void *wzmp3_memory_realloc(wzmp3_memory *m, void *ptr, size_t count);
void wzmp3_memory_free(wzmp3_memory *m, void *ptr);
#endif
