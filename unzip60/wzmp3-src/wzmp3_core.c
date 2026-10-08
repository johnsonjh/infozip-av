/* SPDX-License-Identifier: MIT-0
 * Independent bounded packMP3 v1.0 header reader and 31-bit arithmetic
 * decoding primitive, conforming to ISO C90 (ANSI C89).
 * A functioning WZ-MP3 decoder ALSO needs adaptive statistical models,
 * frame reconstruction, Huffman encoding and ancillary-data handling.
 */
#include "wzmp3_core.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define WZMP3_MASK32 0xffffffffUL
#define WZMP3_TOP 0x7fffffffUL
#define WZMP3_HALF 0x40000000UL
#define WZMP3_QUARTER 0x20000000UL
#define WZMP3_THREE_QUARTERS 0x60000000UL

void wzmp3_input_init(wzmp3_input *s, wzmp3_read_cb cb, void *opaque,
                      unsigned long length_hi, unsigned long length_lo)
{
    memset(s, 0, sizeof(*s));
    s->read = cb;
    s->opaque = opaque;
    s->remaining_hi = length_hi & WZMP3_MASK32;
    s->remaining_lo = length_lo & WZMP3_MASK32;
    if (CHAR_BIT != 8 || ULONG_MAX < WZMP3_MASK32 ||
        cb == 0 || length_hi > WZMP3_MASK32 ||
        length_lo > WZMP3_MASK32)
        s->failed = 1;
}

int wzmp3_input_octet(wzmp3_input *s, unsigned char *out)
{
    unsigned char byte;
    if (s->failed || !out || s->bit_left != 0)
        return 0;
    if (!s->remaining_hi && !s->remaining_lo)
        return 0;
    if (!s->read(s->opaque, &byte)) {
        s->failed = 1;
        return 0;
    }
    if (s->remaining_lo == 0) {
        --s->remaining_hi;
        s->remaining_lo = WZMP3_MASK32;
    } else
        --s->remaining_lo;
    if (++s->consumed_lo > WZMP3_MASK32) {
        s->consumed_lo = 0;
        ++s->consumed_hi;
    }
    *out = byte;
    return 1;
}

int wzmp3_parse_header(wzmp3_input *s, wzmp3_header *out)
{
    static const unsigned int rates[3] = { 44100U, 48000U, 32000U };
    static const unsigned int br[15] = {
        0U,32U,40U,48U,56U,64U,80U,96U,112U,128U,160U,
        192U,224U,256U,320U
    };
    unsigned char b[11];
    unsigned int i, sr, mode, bitrate;
    if (!out || !s || s->failed || s->bit_left)
        return 0;
    for (i = 0; i != 11; ++i)
        if (!wzmp3_input_octet(s, &b[i]))
            return 0;
    if (b[0] != 0x4d || b[1] != 0x53 || b[2] != 0x0a)
        return 0;
    sr = (unsigned int)(b[3] >> 6);
    mode = (unsigned int)((b[3] >> 4) & 3U);
    bitrate = (unsigned int)(b[3] & 15U);
    if (sr >= 3 || bitrate >= 15 || (b[6] & 31U) != 0)
        return 0;
    memset(out, 0, sizeof(*out));
    out->frame_count = ((unsigned long)b[7] << 24) |
        ((unsigned long)b[8] << 16) |
        ((unsigned long)b[9] << 8) | (unsigned long)b[10];
    if (out->frame_count == 0)
        return 0;
    out->samplerate = rates[sr];
    out->channel_mode = mode;
    out->channels = mode == 3 ? 1U : 2U;
    out->bitrate_kbps = br[bitrate];
    out->has_padding = (b[4] >> 7) & 1U;
    out->has_ms_stereo = (b[4] >> 6) & 1U;
    out->has_intensity_stereo = (b[4] >> 5) & 1U;
    out->has_special_blocks = (b[4] >> 4) & 1U;
    out->has_subblock_gain = (b[4] >> 3) & 1U;
    out->has_scf_sharing = (b[4] >> 2) & 1U;
    out->has_preemphasis = (b[4] >> 1) & 1U;
    out->has_coarse_scf = b[4] & 1U;
    out->protection_bit = (b[5] >> 7) & 1U;
    out->original_bit = (b[5] >> 6) & 1U;
    out->copyright_bit = (b[5] >> 5) & 1U;
    out->private_bit = (b[5] >> 4) & 1U;
    out->emphasis = (b[5] >> 2) & 3U;
    out->has_leading_bytes = (b[5] >> 1) & 1U;
    out->has_trailing_bytes = b[5] & 1U;
    out->has_bit_reservoir = (b[6] >> 7) & 1U;
    out->has_special_differences = (b[6] >> 6) & 1U;
    out->has_damaged_first_frames = (b[6] >> 5) & 1U;
    return 1;
}

int wzmp3_read_repairs(wzmp3_input *s, const wzmp3_header *h,
                       unsigned char **data, unsigned int *length)
{
    unsigned char n;
    unsigned char *memory;
    unsigned int needed, i;
    if (!s || !h || !data || !length) return 0;
    *data = 0;
    *length = 0;
    if (!h->has_damaged_first_frames) return 1;
    if (!wzmp3_input_octet(s, &n) || (unsigned long)n > h->frame_count)
        return 0;
    needed = 1U + (unsigned int)n * (2U + h->channels * 8U);
    memory = (unsigned char *)malloc((size_t)needed);
    if (!memory) return 0;
    memory[0] = n;
    for (i = 1; i < needed; ++i) {
        if (!wzmp3_input_octet(s, &memory[i])) {
            free(memory);
            return 0;
        }
    }
    *data = memory;
    *length = needed;
    return 1;
}

/* Once the physical stream ends, arithmetic decoding may need a limited
 * run of implicit trailing zero bits. More than 31 is treated as corruption.
 * A higher layer must check ZIP sizes and CRC on successful extraction.
 */
static int wzmp3_bit(wzmp3_input *s, unsigned int *value)
{
    unsigned char b;
    if (s->bit_left == 0) {
        if (wzmp3_input_octet(s, &b)) {
            s->bit_byte = b;
            s->bit_left = 8;
        } else if (!s->failed && !s->remaining_lo &&
                   !s->remaining_hi && s->virtual_bits < 31U) {
            ++s->virtual_bits;
            *value = 0;
            return 1;
        } else {
            s->failed = 1;
            return 0;
        }
    }
    --s->bit_left;
    *value = (s->bit_byte >> s->bit_left) & 1U;
    return 1;
}

int wzmp3_range_init(wzmp3_range *d, wzmp3_input *s)
{
    unsigned int i, b;
    if (!d || !s || s->failed)
        return 0;
    memset(d, 0, sizeof(*d));
    d->source = s;
    d->upper = WZMP3_TOP;
    for (i = 0; i < 31; ++i) {
        if (!wzmp3_bit(s, &b)) {
            d->failed = 1;
            return 0;
        }
        d->tag = (d->tag << 1) | (unsigned long)b;
    }
    return 1;
}

int wzmp3_range_count(wzmp3_range *d, unsigned long scale,
                      unsigned long *count)
{
    unsigned long width;
    if (!d || d->failed || !count || scale == 0 ||
        scale >= WZMP3_QUARTER || d->upper < d->lower ||
        d->tag < d->lower || d->tag > d->upper)
        return 0;
    width = d->upper - d->lower + 1UL;
    d->quantum = width / scale;
    if (!d->quantum)
        return 0;
    *count = (d->tag - d->lower) / d->quantum;
    if (*count >= scale)
        return 0;
    return 1;
}

int wzmp3_range_remove(wzmp3_range *d, unsigned long scale,
                       unsigned long bottom, unsigned long top)
{
    unsigned int b;
    unsigned long q;
    if (!d || d->failed || scale == 0 ||
        scale >= WZMP3_QUARTER || bottom >= top || top > scale ||
        d->upper < d->lower)
        return 0;
    q = (d->upper - d->lower + 1UL) / scale;
    if (!q) return 0;
    d->upper = d->lower + q * top - 1UL;
    d->lower += q * bottom;
    if (d->tag < d->lower || d->tag > d->upper)
        return 0;
    for (;;) {
        if (d->upper < WZMP3_HALF) {
            /* Low half, nothing to subtract. */
        } else if (d->lower >= WZMP3_HALF) {
            d->lower -= WZMP3_HALF;
            d->upper -= WZMP3_HALF;
            d->tag -= WZMP3_HALF;
        } else if (d->lower >= WZMP3_QUARTER &&
                   d->upper < WZMP3_THREE_QUARTERS) {
            d->lower -= WZMP3_QUARTER;
            d->upper -= WZMP3_QUARTER;
            d->tag -= WZMP3_QUARTER;
        } else
            break;
        d->lower = d->lower << 1;
        d->upper = (d->upper << 1) | 1UL;
        if (!wzmp3_bit(d->source, &b)) {
            d->failed = 1;
            return 0;
        }
        d->tag = (d->tag << 1) | (unsigned long)b;
    }
    return 1;
}
