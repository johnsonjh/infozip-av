/* SPDX-License-Identifier: MIT-0
 * packMP3 1.0 frame-tail, bitrate and reservoir bitstream reader.
 * Must be combined with independent MPEG Huffman codebooks for decoding.
 */
#ifndef WZMP3_TAIL_H
#define WZMP3_TAIL_H
#include "wzmp3_mpeg.h"

typedef struct wzmp3_tail_s {
    wzmp3_ppm_model aux_model,bitrate_model;
    wzmp3_binary control_model;
    unsigned short raw_freq[256][2];
    unsigned int bitrate_kbps,has_reservoir,rate,channels,crc_present;
    unsigned int last_aux_context,pad_history;
    unsigned int predictor_phase,predictor_length,predictor_constant;
    unsigned char predictor_text[20];
    int reservoir;
    int initialized;
} wzmp3_tail;

typedef struct wzmp3_tail_result_s {
    unsigned int bitrate_index,frame_bytes;
    unsigned int main_size,main_data_begin,aux_bytes,following_reservoir;
    unsigned int payload_bits;
    unsigned char payload[2048];
} wzmp3_tail_result;
int wzmp3_tail_init(wzmp3_tail *tail,const wzmp3_header *header);
int wzmp3_tail_read(wzmp3_tail *tail,wzmp3_range *ar,
                    unsigned int main_bits,unsigned int padding,
                    int last_frame,wzmp3_tail_result *out);
void wzmp3_tail_free(wzmp3_tail *tail);
#endif
