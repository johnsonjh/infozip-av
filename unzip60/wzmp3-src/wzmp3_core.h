/* SPDX-License-Identifier: MIT-0
 * WinZip Method 94 / packMP3 1.0 independently written decoder primitives.
 * Complete reconstruction uses wzmp3_decode plus MPEG Huffman codebooks.
 */
#ifndef WZMP3_CORE_H
#define WZMP3_CORE_H
#include "wzmp3_memory.h"

/* Callback returns 1 and fills *byte, or 0 on failure. */
typedef int (*wzmp3_read_cb)(void *opaque, unsigned char *byte);

typedef struct wzmp3_input_s {
    wzmp3_read_cb read;
    void *opaque;
    unsigned long remaining_hi;
    unsigned long remaining_lo;
    unsigned long consumed_hi;
    unsigned long consumed_lo;
    unsigned int bit_left;
    unsigned int bit_byte;
    unsigned int virtual_bits;
    int failed;
    wzmp3_memory *memory; /* set only for duration of a decode */
} wzmp3_input;

typedef struct wzmp3_header_s {
    unsigned int samplerate;
    unsigned int channels;
    unsigned int channel_mode;
    unsigned int bitrate_kbps;   /* 0 indicates per-frame bitrate */
    unsigned int has_padding;
    unsigned int has_ms_stereo;
    unsigned int has_intensity_stereo;
    unsigned int has_special_blocks;
    unsigned int has_subblock_gain;
    unsigned int has_scf_sharing;
    unsigned int has_preemphasis;
    unsigned int has_coarse_scf;
    unsigned int protection_bit;
    unsigned int original_bit;
    unsigned int copyright_bit;
    unsigned int private_bit;
    unsigned int emphasis;
    unsigned int has_leading_bytes;
    unsigned int has_trailing_bytes;
    unsigned int has_bit_reservoir;
    unsigned int has_special_differences;
    unsigned int has_damaged_first_frames;
    unsigned long frame_count;
} wzmp3_header;

typedef struct wzmp3_range_s {
    wzmp3_input *source;
    unsigned long lower;
    unsigned long upper;
    unsigned long tag;
    unsigned long quantum;
    unsigned int pending;
    int failed;
} wzmp3_range;

void wzmp3_input_init(wzmp3_input *s, wzmp3_read_cb cb, void *opaque,
                      unsigned long length_hi, unsigned long length_lo);
int wzmp3_input_octet(wzmp3_input *s, unsigned char *out);
int wzmp3_parse_header(wzmp3_input *s, wzmp3_header *out);
/* Optional verbatim repair records precede the arithmetic stream.
 * The caller owns the allocated byte buffer and must free() it.
 */
int wzmp3_read_repairs(wzmp3_input *s, const wzmp3_header *h,
                       unsigned char **data, unsigned int *length);

/* Arithmetic part operates on unsigned integers up to exactly 31 bits.
 * This is the primitive; adaptive statistical contexts are not yet present.
 */
int wzmp3_range_init(wzmp3_range *d, wzmp3_input *s);
int wzmp3_range_count(wzmp3_range *d, unsigned long scale,
                      unsigned long *count);
int wzmp3_range_remove(wzmp3_range *d, unsigned long scale,
                       unsigned long bottom, unsigned long top);

#endif
