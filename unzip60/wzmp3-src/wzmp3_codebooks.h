/* SPDX-License-Identifier: CC0-1.0 or MIT-0
 * Derived from the independently published minimp3.h by lieff and contributors.
 * https://github.com/lieff/minimp3
 * This is an inverse representation of its MPEG Layer III decoder tables.
 * CC0 dedication: https://creativecommons.org/publicdomain/zero/1.0/
 * No LGPL packMP3 data or code used to produce these tables.
 */
#ifndef WZMP3_CODEBOOKS_H
#define WZMP3_CODEBOOKS_H
#include "wzmp3_mpeg.h"
void wzmp3_codebooks_init(wzmp3_codebook books[34]);
#endif
