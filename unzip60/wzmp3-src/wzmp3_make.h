/* SPDX-License-Identifier: MIT-0
 * Independent Method 94 reconstruction of MPEG-1 Layer III frame headers.
 */
#ifndef WZMP3_MAKE_H
#define WZMP3_MAKE_H
#include "wzmp3_mpeg.h"
#include "wzmp3_core.h"
/* May apply repair record to the frame's original private/original/copyright,
 * reservoir, granule bit lengths, scale lengths, and big-value counts.
 * Fixed-frame headers are independently reconstructible without file access.
 * Caller must supply decoded frame/bitstream fields, never original MP3 bytes.
 */
int wzmp3_make_frame(const wzmp3_header *h,
                     const wzmp3_granule *gs,
                     unsigned int bitrate_index, unsigned int padding,
                     unsigned int middle_stereo, unsigned int reservoir,
                     unsigned long frame_index,
                     const unsigned char *repairs,unsigned int repair_len,
                     wzmp3_mpeg_frame *out);
#endif
