/* SPDX-License-Identifier: MIT-0
 * MPEG-1 Layer III bit-accurate frame serialization and Huffman output.
 * Format fields follow ISO/IEC 11172-3; no MPEG audio decoder is linked.
 */
#ifndef WZMP3_MPEG_H
#define WZMP3_MPEG_H
#include <stddef.h>
#include "wzmp3_spectral.h"
#define WZMP3_FRAME_LIMIT 2048U
#define WZMP3_HUFF_SYMBOLS 256U

typedef struct wzmp3_bitwriter_s {
    unsigned char *bytes;
    size_t capacity;
    size_t bits;
    int failed;
} wzmp3_bitwriter;

typedef struct wzmp3_codeword_s {
    unsigned long code;
    unsigned char length;
} wzmp3_codeword;

typedef struct wzmp3_codebook_s {
    wzmp3_codeword symbols[WZMP3_HUFF_SYMBOLS];
    unsigned int linbits;
    unsigned int quad;
    unsigned int maxvalue;
} wzmp3_codebook;

typedef struct wzmp3_mpeg_frame_s {
    unsigned char header[4];
    unsigned char crc[2];
    unsigned int crc_present;
    unsigned int bitrate_index, rate_index, padding;
    unsigned int channels, frame_bytes, side_bytes;
    unsigned int main_data_begin, side_private;
    unsigned int scfsi[2];
    wzmp3_granule granules[2][2];  /* [granule][channel] */
} wzmp3_mpeg_frame;

void wzmp3_bits_start(wzmp3_bitwriter *w,unsigned char *dst,size_t cap);
int wzmp3_bits_put(wzmp3_bitwriter *w,unsigned int value,unsigned int nbits);
int wzmp3_bits_put_long(wzmp3_bitwriter *w,unsigned long value,unsigned int nbits);
int wzmp3_bits_align(wzmp3_bitwriter *w);
int wzmp3_bits_size(const wzmp3_bitwriter *w,size_t *size);

int wzmp3_mpeg_parse(const unsigned char *data,size_t available,
                     wzmp3_mpeg_frame *frame);
/* Find a frame's first encoded main-data bit in the concatenation of
 * earlier and current frame main-data areas. Never resolves a filesystem
 * location or trusts an unchecked backward offset. */
int wzmp3_mpeg_main_position(const wzmp3_mpeg_frame *f,
                             size_t main_bytes_before_frame,
                             size_t *bit_position);
int wzmp3_mpeg_write_header(const wzmp3_mpeg_frame *frame,
                            unsigned char *out,size_t capacity,
                            size_t *length);
/* MPEG-1 Layer III pair: Huffman codeword, x linbits, x sign, y linbits,
 * y sign. Only the ISO table numbers' actual codewords are supplied by
 * the caller; these generic primitives do not embed LGPL codebooks.
 */
int wzmp3_huffman_pair(wzmp3_bitwriter *writer,const wzmp3_codebook *book,
                       unsigned int x,unsigned int y,
                       unsigned int xnegative,unsigned int ynegative);
int wzmp3_huffman_quad(wzmp3_bitwriter *writer,const wzmp3_codebook *book,
                       const unsigned char magnitudes[4],
                       const unsigned char negatives[4]);
/* Reconstruct one MPEG granule's Huffman-coded spectral section using the
 * standard ISO codebooks supplied by the caller. The caller separately
 * writes scalefactors and sets the resulting part2_3_length.
 */
/* Emit scalefactors from the granule reader in MPEG standard order.
 * share_flags are the first granule's SCFSI bits for this channel.
 * Mixed short/long blocks require a separately verified path.
 */
int wzmp3_mpeg_scalefactors(wzmp3_bitwriter *writer,
                            const wzmp3_granule *granule,
                            const unsigned char values[36],
                            unsigned int granule_index,
                            unsigned int share_flags);
int wzmp3_huffman_spectrum(wzmp3_bitwriter *writer,
                           const wzmp3_codebook books[34],
                           const wzmp3_granule *granule,
                           const wzmp3_spectrum *spectrum);
#endif
