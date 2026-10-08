/* SPDX-License-Identifier: MIT-0
 * WinZip Method 94: reconstruction of MPEG-1 Layer III frame byte layout.
 * Independent implementation; no MPEG Huffman/entropy codebooks included.
 */
#ifndef WZMP3_JOIN_H
#define WZMP3_JOIN_H
#include <stddef.h>

typedef struct wzmp3_join_frame_s {
    unsigned char header[40];
    size_t header_bytes;
    size_t body_bytes;
} wzmp3_join_frame;

typedef struct wzmp3_join_s {
    wzmp3_join_frame *frames;
    unsigned char *main_data;
    size_t main_capacity;
    size_t main_bits;
    size_t physical_bytes;
    size_t frame_count;
    size_t frames_used;
    int error;
} wzmp3_join;

typedef int (*wzmp3_write_cb)(void *,const unsigned char *,size_t);

/* main_capacity bounds the entire contiguous MPEG frame-body stream. The
 * caller may choose a stricter limit based on the ZIP uncompressed size. */
int wzmp3_join_init(wzmp3_join *j,size_t main_capacity,size_t frame_count);
void wzmp3_join_free(wzmp3_join *j);
/* `audio` is the MPEG part2_3 bitstream of all granules of this frame,
 * concatenated in granule/channel order. `tail` fills the remaining bits
 * through the next reservoir start; both are packed MSB-first. */
int wzmp3_join_frame_add(wzmp3_join *j,const unsigned char *header,
                         size_t header_bytes,size_t frame_bytes,
                         unsigned int main_data_begin,
                         const unsigned char *audio,size_t audio_bits,
                         const unsigned char *tail,size_t tail_bits);
/* Emits prefix, complete frames, suffix; only callable after all physical
 * body bytes have been reconstructed exactly. A failing output callback may
 * leave partially written output; the caller must handle that failure. */
int wzmp3_join_emit(const wzmp3_join *j,
                    const unsigned char *prefix,size_t prefix_bytes,
                    const unsigned char *suffix,size_t suffix_bytes,
                    wzmp3_write_cb write,void *opaque);
#endif
