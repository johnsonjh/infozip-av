/* SPDX-License-Identifier: MIT-0
 * Order-one adaptive binary arithmetic contexts for Method 94.
 */
#ifndef WZMP3_BINARY_H
#define WZMP3_BINARY_H
#include "wzmp3_core.h"
typedef struct wzmp3_binary_s {
    unsigned short freq[16][2];
    unsigned int current;
} wzmp3_binary;
void wzmp3_binary_init(wzmp3_binary *model);
int wzmp3_binary_shift(wzmp3_binary *model,unsigned int context);
int wzmp3_binary_decode(wzmp3_binary *model,wzmp3_range *r,
                        unsigned int *symbol);
void wzmp3_binary_flush(wzmp3_binary *model,unsigned int shift);
#endif
