/* SPDX-License-Identifier: MIT-0 */

#ifndef ZO_WAVPACK_ENCODER_H

# define ZO_WAVPACK_ENCODER_H

# include "archive.h"
# include <stdio.h>

/* 1: complete compatible candidate, 0: actual encoder failure,
 * 2: input is not a supported PCM/float RIFF/WAVE stream (normal skip),
 * -1: input or output I/O failure. */
# define ZO_WAVPACK_NOT_APPLICABLE 2
int zo_wavpack_encode (FILE *in, FILE *out, zo_u64 *size, unsigned level,
                       unsigned extra);

#endif /* ifndef ZO_WAVPACK_ENCODER_H */
