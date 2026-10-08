/* SPDX-License-Identifier: MIT-0
 * Independent MPEG-1 Layer III granule region reconstruction for WZ-MP3.
 * Not a complete MP3 decoder; fields stored in channel-major order.
 */
#ifndef WZMP3_REGIONS_H
#define WZMP3_REGIONS_H
#include "wzmp3_ppm.h"

typedef struct wzmp3_granule_s {
    unsigned int sw, type, gain, slength;
    unsigned int big_values;
    unsigned int part_length, mixed;
    unsigned int r0, r1;
    unsigned int table[3], small_table;
    unsigned int bound[3];
    unsigned int share, preflag, coarse, subgain[3];
} wzmp3_granule;

/* Requires the switch, block-type, global gain, and scalefactor-compress
 * fields to have been decoded. Exactly 2 * frame_count granules per channel.
 * Returns zero for corruption, unsupported arguments, or allocation failure.
 */
int wzmp3_regions_decode(wzmp3_range *ar, const wzmp3_header *h,
                         wzmp3_granule *granules);
/* Each granule has 36 output slots: 21 long scalefactors or 3 x 12
 * short scalefactors. The buffer holds channel-major granules.
 */
int wzmp3_scalefactors_decode(wzmp3_range *ar, const wzmp3_header *h,
                             const wzmp3_granule *g,
                             unsigned char *out);
int wzmp3_ms_stereo_decode(wzmp3_range *ar, const wzmp3_header *h,
                           unsigned char *flags);
int wzmp3_scalefactor_controls_decode(wzmp3_range *ar,
                                     const wzmp3_header *h,
                                     wzmp3_granule *granules);
#endif
