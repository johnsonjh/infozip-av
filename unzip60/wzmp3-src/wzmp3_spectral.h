/* SPDX-License-Identifier: MIT-0
 * Adaptive coefficient and inter-granule stuffing reader for WZ-MP3 1.0.
 * This module emits decoded symbols, not MPEG Huffman-coded output.
 */
#ifndef WZMP3_SPECTRAL_H
#define WZMP3_SPECTRAL_H
#include "wzmp3_granule.h"
#include "wzmp3_binary.h"

typedef struct wzmp3_bin2_s {
    unsigned short frequency[16][16][2];
    unsigned int previous, current;
} wzmp3_bin2;

typedef struct wzmp3_spectral_s {
    wzmp3_memory *memory;
    wzmp3_ppm_model *magnitudes[2][8][32];
    wzmp3_bin2 *small[2][8][2];
    wzmp3_bin2 *signs[2][8];
    wzmp3_ppm_model *lengths[2][14];
    wzmp3_bin2 remainder;
    wzmp3_ppm_model stuffing_count;
    wzmp3_binary stuffing_bits;
    unsigned char history_abs[2][2][580];
    unsigned char history_sign[2][2][580];
    unsigned char history_len[2][2][580];
    unsigned char retained_width[2][576];
    unsigned int last_stuff_count,last_stuff_bit;
    unsigned int channels,joint;
    int initialized;
} wzmp3_spectral;

typedef struct wzmp3_spectrum_s {
    unsigned char magnitude[576],negative[576],extra_width[576];
    unsigned short extra_bits[576];
    unsigned int small_boundary;
    unsigned int stuffing_count;
    unsigned char stuffing_bits[4096]; /* unpacked 0/1; byte output not yet implemented */
} wzmp3_spectrum;

int wzmp3_spectral_init(wzmp3_spectral *st,const wzmp3_header *header,
                        wzmp3_memory *memory);
/* Call in frame/granule/channel order; pass the current frame's ch0 block type.
 * For channel 0, ch0_type must equal granule->type, and other_type is
 * the next channel's block type (or the same type for mono).
 */
int wzmp3_spectral_read(wzmp3_spectral *st,wzmp3_range *ar,
                        const wzmp3_granule *granule,unsigned int small_boundary,
                        unsigned int channel,unsigned int ch0_type,
                        unsigned int other_type,unsigned int ms_stereo,wzmp3_spectrum *out);
void wzmp3_spectral_free(wzmp3_spectral *st);
#endif
