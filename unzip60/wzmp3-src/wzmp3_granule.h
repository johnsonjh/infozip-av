/* SPDX-License-Identifier: MIT-0
 * Incremental Method 94 per-granule state (development API).
 * DOES NOT implement MPEG spectral coefficients, bit reservoir, or output.
 */
#ifndef WZMP3_GRANULE_H
#define WZMP3_GRANULE_H
#include "wzmp3_regions.h"

typedef struct {
    wzmp3_memory *memory;
    wzmp3_ppm_model *scale_models;
    wzmp3_ppm_model small_bound;
    wzmp3_ppm_model damaged_bound;
    unsigned char long_history[2][21];
    unsigned char short_history[2][12];
    unsigned char sharing[2][4];
    unsigned int last_bound[2];
    unsigned int channel_count;
    unsigned long step;
    unsigned long total_steps;
    int ready;
    int pending_bound;
} wzmp3_granule_state;

int wzmp3_granule_init(wzmp3_granule_state *st, const wzmp3_header *h, wzmp3_memory *memory);
/* Call exactly once for each granule in frame/granule/channel order.
 * Spectral decoding MUST be performed between successive calls by the
 * eventual complete decoder; this API does not do it on its own.
 */
int wzmp3_granule_scalefactors(wzmp3_granule_state *st,
                              wzmp3_range *range,
                              const wzmp3_granule *g,
                              unsigned int channel,
                              unsigned int granule_within_frame,
                              unsigned char result[36]);
/* Decode the next per-granule spectral-region bound; updates region limits
 * only for the damaged-frame extension defined by the stream format.
 */
int wzmp3_granule_small_bound(wzmp3_granule_state *st,
                             wzmp3_range *range,
                             wzmp3_granule *g,
                             unsigned int channel,
                             unsigned int *small_bound);
void wzmp3_granule_destroy(wzmp3_granule_state *st);
#endif
