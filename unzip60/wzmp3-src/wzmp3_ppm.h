/* SPDX-License-Identifier: MIT-0 */
#ifndef WZMP3_PPM_H
#define WZMP3_PPM_H
#include "wzmp3_core.h"

typedef struct wzmp3_ppm_node_s wzmp3_ppm_node;

typedef struct wzmp3_ppm_model_s {
    wzmp3_memory *memory;
    unsigned int alphabet;
    unsigned int context_alphabet;
    unsigned int order;
    unsigned int threshold;
    unsigned long allocated;
    unsigned long node_limit;
    wzmp3_ppm_node *all_nodes;
    wzmp3_ppm_node *active[5];
    wzmp3_ppm_node *root;
} wzmp3_ppm_model;

int wzmp3_ppm_init(wzmp3_ppm_model *m, unsigned int alphabet,
                   unsigned int context_alphabet, unsigned int order,
                   unsigned int threshold, unsigned long node_limit,
                   wzmp3_memory *memory);
void wzmp3_ppm_cleanup(wzmp3_ppm_model *m);
int wzmp3_ppm_shift(wzmp3_ppm_model *m,unsigned int context);
int wzmp3_ppm_flush(wzmp3_ppm_model *m,unsigned int shift);
int wzmp3_ppm_decode(wzmp3_ppm_model *m,wzmp3_range *r,
                     unsigned int *symbol);
#endif
