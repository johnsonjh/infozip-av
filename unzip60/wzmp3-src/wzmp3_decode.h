/* SPDX-License-Identifier: MIT-0
 * Standalone Method 94 decoder API. No ZIP integration.
 * Huffman tables supplied separately by independently licensed provider.
 */
#ifndef WZMP3_DECODE_H
#define WZMP3_DECODE_H
#include "wzmp3_make.h"
#include "wzmp3_join.h"
typedef struct wzmp3_decode_options_s {
    size_t maximum_output; /* hard output bound; should be ZIP uncompressed size */
    unsigned long maximum_frames;
} wzmp3_decode_options;
/* Returns 1 on success, 0 for invalid data/output error, and -1 for
 * exhausted decoder heap budget or system allocation failure. */
int wzmp3_decode(wzmp3_input *input,const wzmp3_codebook books[34],
                 const wzmp3_decode_options *options,
                 wzmp3_write_cb output,void *output_context);
#endif
