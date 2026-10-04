/*
 * ozunreduce.h - ZIP Reduce (methods 2 through 5) decompressor
 *
 * ANSI C89 adaptation for Info-ZIP AV, based on Ozunreduce / Old ZIP
 * Unreduce by Jason Summers (OldUnzip).
 *
 * Copyright (C) 2019 Jason Summers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Upstream: https://github.com/jsummers/oldunzip
 * Upstream version: OZUR_VERSION 20191011.
 *
 * This adaptation removes C99-only syntax and makes the default offset type
 * a C89 type. Applications may override the type macros below.
 */

#ifndef OZUNREDUCE_H_INCLUDED
#define OZUNREDUCE_H_INCLUDED

#include <stddef.h>

#define OZUR_VERSION 20191011

#ifndef OZUR_UINT8
#  define OZUR_UINT8 unsigned char
#endif
#ifndef OZUR_OFF_T
#  define OZUR_OFF_T long
#endif
#ifndef OZUR_API
#  define OZUR_API(ty) static ty
#endif

#define OZUR_ERRCODE_OK                  0
#define OZUR_ERRCODE_GENERIC_ERROR       1
#define OZUR_ERRCODE_BAD_CDATA           2
#define OZUR_ERRCODE_READ_FAILED         6
#define OZUR_ERRCODE_WRITE_FAILED        7
#define OZUR_ERRCODE_INSUFFICIENT_CDATA  8
#define OZUR_CIRCBUF_SIZE 4096
#define OZUR_INBUF_SIZE 1024

struct ozur_follower_item {
    OZUR_UINT8 count;
    OZUR_UINT8 nbits;
    OZUR_UINT8 values[32];
};

struct ozur_ctx_type;
typedef struct ozur_ctx_type ozur_ctx;
typedef size_t (*ozur_cb_read_type)(ozur_ctx *, OZUR_UINT8 *, size_t);
typedef size_t (*ozur_cb_write_type)(ozur_ctx *, const OZUR_UINT8 *, size_t);
typedef void (*ozur_cb_post_follower_sets_type)(ozur_ctx *);

struct ozur_ctx_type {
    void *userdata;
    unsigned int cmpr_factor;
    OZUR_OFF_T cmpr_size;
    OZUR_OFF_T uncmpr_size;
    ozur_cb_read_type cb_read;
    ozur_cb_write_type cb_write;
    ozur_cb_post_follower_sets_type cb_post_follower_sets;

    int error_code;
    OZUR_OFF_T uncmpr_nbytes_written;
    OZUR_OFF_T cmpr_nbytes_consumed;

    OZUR_OFF_T cmpr_nbytes_read;
    OZUR_OFF_T uncmpr_nbytes_emitted;
    unsigned long bitreader_buf;
    unsigned int bitreader_nbits_in_buf;
    int state;
    unsigned int var_Len;
    OZUR_UINT8 last_char;
    OZUR_UINT8 var_V;
    struct ozur_follower_item followers[256];
    size_t circbuf_pos;
    OZUR_UINT8 circbuf[OZUR_CIRCBUF_SIZE];
    size_t inbuf_nbytes_consumed;
    size_t inbuf_nbytes_total;
    OZUR_UINT8 inbuf[OZUR_INBUF_SIZE];
};

OZUR_API(void) ozur_set_error(ozur_ctx *ozur, int error_code)
{
    if (ozur->error_code == OZUR_ERRCODE_OK)
        ozur->error_code = error_code;
}

OZUR_API(void) ozur_refill_inbuf(ozur_ctx *ozur)
{
    size_t ret;
    size_t nbytes_to_read;
    OZUR_OFF_T left;

    ozur->inbuf_nbytes_total = 0;
    ozur->inbuf_nbytes_consumed = 0;

    left = ozur->cmpr_size - ozur->cmpr_nbytes_read;
    if (left > (OZUR_OFF_T)OZUR_INBUF_SIZE)
        nbytes_to_read = OZUR_INBUF_SIZE;
    else if (left > 0)
        nbytes_to_read = (size_t)left;
    else
        return;

    ret = ozur->cb_read(ozur, ozur->inbuf, nbytes_to_read);
    if (ret != nbytes_to_read) {
        ozur_set_error(ozur, OZUR_ERRCODE_READ_FAILED);
        return;
    }
    ozur->cmpr_nbytes_read += (OZUR_OFF_T)nbytes_to_read;
    ozur->inbuf_nbytes_total = nbytes_to_read;
}

OZUR_API(OZUR_UINT8) ozur_nextbyte(ozur_ctx *ozur)
{
    OZUR_UINT8 x;

    if (ozur->error_code != OZUR_ERRCODE_OK)
        return 0;
    if (ozur->cmpr_nbytes_consumed >= ozur->cmpr_size) {
        ozur_set_error(ozur, OZUR_ERRCODE_INSUFFICIENT_CDATA);
        return 0;
    }
    if (ozur->inbuf_nbytes_consumed >= ozur->inbuf_nbytes_total) {
        ozur_refill_inbuf(ozur);
        if (ozur->error_code != OZUR_ERRCODE_OK ||
            ozur->inbuf_nbytes_total == 0)
            return 0;
    }
    x = ozur->inbuf[ozur->inbuf_nbytes_consumed++];
    ++ozur->cmpr_nbytes_consumed;
    return x;
}

OZUR_API(OZUR_UINT8) ozur_bitreader_getbits(ozur_ctx *ozur,
                                            unsigned int nbits)
{
    OZUR_UINT8 n;
    unsigned long mask;

    if (nbits < 1 || nbits > 8) {
        ozur_set_error(ozur, OZUR_ERRCODE_GENERIC_ERROR);
        return 0;
    }

    while (ozur->bitreader_nbits_in_buf < nbits) {
        OZUR_UINT8 b;
        b = ozur_nextbyte(ozur);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            return 0;
        ozur->bitreader_buf |= ((unsigned long)b) <<
                               ozur->bitreader_nbits_in_buf;
        ozur->bitreader_nbits_in_buf += 8;
    }

    mask = (1UL << nbits) - 1UL;
    n = (OZUR_UINT8)(ozur->bitreader_buf & mask);
    ozur->bitreader_buf >>= nbits;
    ozur->bitreader_nbits_in_buf -= nbits;
    return n;
}

OZUR_API(OZUR_UINT8) ozur_func_B(OZUR_UINT8 x)
{
    if (x <= 2) return 1;
    if (x <= 4) return 2;
    if (x <= 8) return 3;
    if (x <= 16) return 4;
    return 5;
}

OZUR_API(void) ozur_part1_readfollowersets(ozur_ctx *ozur)
{
    int k;

    for (k = 255; k >= 0; --k) {
        unsigned int z;
        struct ozur_follower_item *fi;

        fi = &ozur->followers[k];
        fi->count = ozur_bitreader_getbits(ozur, 6);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            return;
        if (fi->count > 32) {
            ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);
            return;
        }

        if (fi->count > 0)
            fi->nbits = ozur_func_B(fi->count);

        for (z = 0; z < (unsigned int)fi->count; ++z) {
            fi->values[z] = ozur_bitreader_getbits(ozur, 8);
            if (ozur->error_code != OZUR_ERRCODE_OK)
                return;
        }
    }
}

OZUR_API(OZUR_UINT8) ozur_part1_getnextbyte(ozur_ctx *ozur)
{
    OZUR_UINT8 outbyte;
    struct ozur_follower_item *fi;

    outbyte = 0;
    fi = &ozur->followers[(unsigned int)ozur->last_char];

    if (fi->count == 0) {
        outbyte = ozur_bitreader_getbits(ozur, 8);
    }
    else {
        OZUR_UINT8 bitval;
        bitval = ozur_bitreader_getbits(ozur, 1);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            return 0;
        if (bitval) {
            outbyte = ozur_bitreader_getbits(ozur, 8);
        }
        else {
            unsigned int idx;
            idx = (unsigned int)ozur_bitreader_getbits(
                ozur, (unsigned int)fi->nbits);
            if (ozur->error_code != OZUR_ERRCODE_OK)
                return 0;
            if (idx >= (unsigned int)fi->count) {
                ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);
                return 0;
            }
            outbyte = fi->values[idx];
        }
    }

    if (ozur->error_code == OZUR_ERRCODE_OK)
        ozur->last_char = outbyte;
    return outbyte;
}

OZUR_API(void) ozur_flush(ozur_ctx *ozur)
{
    size_t ret;
    size_t n;

    if (ozur->error_code != OZUR_ERRCODE_OK)
        return;
    n = ozur->circbuf_pos;
    if (n == 0 || n > OZUR_CIRCBUF_SIZE)
        return;

    ret = ozur->cb_write(ozur, ozur->circbuf, n);
    if (ret != n) {
        ozur_set_error(ozur, OZUR_ERRCODE_WRITE_FAILED);
        return;
    }
    ozur->uncmpr_nbytes_written += (OZUR_OFF_T)ret;
}

OZUR_API(void) ozur_emit_byte(ozur_ctx *ozur, OZUR_UINT8 x)
{
    if (ozur->error_code != OZUR_ERRCODE_OK)
        return;

    ozur->circbuf[ozur->circbuf_pos++] = x;
    if (ozur->circbuf_pos >= OZUR_CIRCBUF_SIZE) {
        ozur_flush(ozur);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            return;
        ozur->circbuf_pos = 0;
    }
    ++ozur->uncmpr_nbytes_emitted;
}

OZUR_API(void) ozur_emit_copy_of_prev_bytes(ozur_ctx *ozur,
                                             size_t lookback, size_t nbytes)
{
    size_t i;
    size_t src_pos;

    if (lookback == 0 || lookback > 4096) {
        ozur_set_error(ozur, OZUR_ERRCODE_GENERIC_ERROR);
        return;
    }
    if (nbytes > lookback) {
        ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);
        return;
    }
    if (ozur->uncmpr_nbytes_emitted + (OZUR_OFF_T)nbytes >
        ozur->uncmpr_size) {
        ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);
        return;
    }

    src_pos = (ozur->circbuf_pos + OZUR_CIRCBUF_SIZE - lookback) %
              OZUR_CIRCBUF_SIZE;
    for (i = 0; i < nbytes; ++i) {
        ozur_emit_byte(ozur, ozur->circbuf[src_pos++]);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            return;
        if (src_pos >= OZUR_CIRCBUF_SIZE)
            src_pos = 0;
    }
}

OZUR_API(void) ozur_part2(ozur_ctx *ozur, OZUR_UINT8 c)
{
    size_t lookback;
    size_t copylen;

    switch (ozur->state) {
    case 0:
        if (c == 144)
            ozur->state = 1;
        else
            ozur_emit_byte(ozur, c);
        break;

    case 1:
        if (c != 0) {
            ozur->var_V = c;
            ozur->var_Len = (unsigned int)(c &
                (OZUR_UINT8)(0xffU >> ozur->cmpr_factor));
            if (ozur->var_Len ==
                (unsigned int)(0xffU >> ozur->cmpr_factor))
                ozur->state = 2;
            else
                ozur->state = 3;
        }
        else {
            ozur_emit_byte(ozur, 144);
            ozur->state = 0;
        }
        break;

    case 2:
        ozur->var_Len += (unsigned int)c;
        ozur->state = 3;
        break;

    case 3:
        lookback = (size_t)(ozur->var_V >> (8 - ozur->cmpr_factor)) *
                   256U + (size_t)c + 1U;
        copylen = (size_t)ozur->var_Len + 3U;
        ozur_emit_copy_of_prev_bytes(ozur, lookback, copylen);
        ozur->state = 0;
        break;

    default:
        ozur_set_error(ozur, OZUR_ERRCODE_GENERIC_ERROR);
        break;
    }
}

OZUR_API(void) ozur_run(ozur_ctx *ozur)
{
    if (ozur == NULL || ozur->cmpr_factor < 1 || ozur->cmpr_factor > 4 ||
        ozur->cb_read == NULL || ozur->cb_write == NULL ||
        ozur->cmpr_size < 0 || ozur->uncmpr_size < 0) {
        if (ozur != NULL)
            ozur_set_error(ozur, OZUR_ERRCODE_GENERIC_ERROR);
        return;
    }

    ozur_part1_readfollowersets(ozur);
    if (ozur->error_code != OZUR_ERRCODE_OK)
        goto done;

    if (ozur->cb_post_follower_sets != NULL)
        ozur->cb_post_follower_sets(ozur);

    while (ozur->uncmpr_nbytes_emitted < ozur->uncmpr_size) {
        OZUR_UINT8 outbyte;
        outbyte = ozur_part1_getnextbyte(ozur);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            goto done;
        ozur_part2(ozur, outbyte);
        if (ozur->error_code != OZUR_ERRCODE_OK)
            goto done;
    }

    if (ozur->state != 0)
        ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);

done:
    ozur_flush(ozur);
}

#endif /* OZUNREDUCE_H_INCLUDED */
