/*
 * ozunshrink.h - ZIP Shrink (method 1) decompressor
 *
 * ANSI C89 adaptation for Info-ZIP AV, based on Ozunshrink / Old ZIP
 * Unshrink by Jason Summers (OldUnzip).
 *
 * Copyright (C) 2019-2020 Jason Summers
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
 * Upstream version: OZUS_VERSION 20200213.
 *
 * This adaptation removes C99-only syntax and makes the default integer and
 * offset types C89 types. Applications may override the type macros below.
 */

#ifndef OZUNSHRINK_H_INCLUDED
#define OZUNSHRINK_H_INCLUDED

#include <stddef.h>
#include <string.h>

#define OZUS_VERSION 20200213

#ifndef OZUS_UINT8
#  define OZUS_UINT8 unsigned char
#endif
#ifndef OZUS_UINT16
#  define OZUS_UINT16 unsigned short
#endif
#ifndef OZUS_OFF_T
#  define OZUS_OFF_T long
#endif
#ifndef OZUS_MEMCPY
#  define OZUS_MEMCPY memcpy
#endif
#ifndef OZUS_API
#  define OZUS_API(ty) static ty
#endif

#define OZUS_ERRCODE_OK                  0
#define OZUS_ERRCODE_GENERIC_ERROR       1
#define OZUS_ERRCODE_BAD_CDATA           2
#define OZUS_ERRCODE_READ_FAILED         6
#define OZUS_ERRCODE_WRITE_FAILED        7
#define OZUS_ERRCODE_INSUFFICIENT_CDATA  8

typedef OZUS_UINT16 OZUS_CODE;

#define OZUS_INITIAL_CODE_SIZE 9
#define OZUS_MAX_CODE_SIZE 13
#define OZUS_NUM_CODES 8192
#define OZUS_INVALID_CODE 256
#define OZUS_VALBUFSIZE 7936
#define OZUS_INBUF_SIZE 1024
#define OZUS_OUTBUF_SIZE 1024

struct ozus_tableentry {
    OZUS_CODE parent;
    OZUS_UINT8 value;
    OZUS_UINT8 flags;
};

struct ozus_ctx_type;
typedef struct ozus_ctx_type ozus_ctx;
typedef size_t (*ozus_cb_read_type)(ozus_ctx *, OZUS_UINT8 *, size_t);
typedef size_t (*ozus_cb_write_type)(ozus_ctx *, const OZUS_UINT8 *, size_t);
typedef void (*ozus_cb_inc_code_size_type)(ozus_ctx *);
typedef void (*ozus_cb_pre_partial_clear_type)(ozus_ctx *);

struct ozus_ctx_type {
    void *userdata;
    OZUS_OFF_T cmpr_size;
    OZUS_OFF_T uncmpr_size;
    ozus_cb_read_type cb_read;
    ozus_cb_write_type cb_write;
    ozus_cb_inc_code_size_type cb_inc_code_size;
    ozus_cb_pre_partial_clear_type cb_pre_partial_clear;

    int error_code;
    OZUS_OFF_T cmpr_nbytes_consumed;
    OZUS_OFF_T uncmpr_nbytes_written;

    unsigned int curr_code_size;
    int have_oldcode;
    OZUS_CODE oldcode;
    OZUS_CODE last_code_added;
    OZUS_CODE highest_code_ever_used;
    OZUS_CODE free_code_search_start;
    OZUS_UINT8 last_value;

    unsigned long bitreader_buf;
    unsigned int bitreader_nbits_in_buf;

    size_t inbuf_nbytes_consumed;
    size_t inbuf_nbytes_total;
    size_t outbuf_nbytes_used;

    struct ozus_tableentry ct[OZUS_NUM_CODES];
    OZUS_UINT8 valbuf[OZUS_VALBUFSIZE];
    OZUS_UINT8 inbuf[OZUS_INBUF_SIZE];
    OZUS_UINT8 outbuf[OZUS_OUTBUF_SIZE];
};

OZUS_API(void) ozus_set_error(ozus_ctx *ozus, int error_code)
{
    if (ozus->error_code == OZUS_ERRCODE_OK)
        ozus->error_code = error_code;
}

OZUS_API(void) ozus_init(ozus_ctx *ozus)
{
    OZUS_CODE i;

    for (i = 0; i < 256; i++) {
        ozus->ct[i].parent = OZUS_INVALID_CODE;
        ozus->ct[i].value = (OZUS_UINT8)i;
        ozus->ct[i].flags = 0;
    }
    for (i = 256; i < OZUS_NUM_CODES; i++) {
        ozus->ct[i].parent = OZUS_INVALID_CODE;
        ozus->ct[i].value = 0;
        ozus->ct[i].flags = 0;
    }
    ozus->free_code_search_start = 257;
}

OZUS_API(void) ozus_refill_inbuf(ozus_ctx *ozus)
{
    size_t ret;
    size_t nbytes_to_read;
    OZUS_OFF_T left;

    ozus->inbuf_nbytes_total = 0;
    ozus->inbuf_nbytes_consumed = 0;

    left = ozus->cmpr_size - ozus->cmpr_nbytes_consumed;
    if (left > (OZUS_OFF_T)OZUS_INBUF_SIZE)
        nbytes_to_read = OZUS_INBUF_SIZE;
    else if (left > 0)
        nbytes_to_read = (size_t)left;
    else
        return;

    ret = ozus->cb_read(ozus, ozus->inbuf, nbytes_to_read);
    if (ret != nbytes_to_read) {
        ozus_set_error(ozus, OZUS_ERRCODE_READ_FAILED);
        return;
    }
    ozus->inbuf_nbytes_total = nbytes_to_read;
}

OZUS_API(OZUS_UINT8) ozus_getnextbyte(ozus_ctx *ozus)
{
    OZUS_UINT8 x;

    if (ozus->error_code != OZUS_ERRCODE_OK)
        return 0;
    if (ozus->cmpr_nbytes_consumed >= ozus->cmpr_size) {
        ozus_set_error(ozus, OZUS_ERRCODE_INSUFFICIENT_CDATA);
        return 0;
    }
    if (ozus->inbuf_nbytes_consumed >= ozus->inbuf_nbytes_total) {
        ozus_refill_inbuf(ozus);
        if (ozus->error_code != OZUS_ERRCODE_OK ||
            ozus->inbuf_nbytes_total == 0) {
            if (ozus->error_code == OZUS_ERRCODE_OK)
                ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
            return 0;
        }
    }

    x = ozus->inbuf[ozus->inbuf_nbytes_consumed++];
    ozus->cmpr_nbytes_consumed++;
    return x;
}

OZUS_API(OZUS_CODE) ozus_getnextcode(ozus_ctx *ozus)
{
    unsigned int nbits;
    unsigned long mask;
    OZUS_CODE n;

    nbits = ozus->curr_code_size;
    while (ozus->bitreader_nbits_in_buf < nbits) {
        OZUS_UINT8 b;
        b = ozus_getnextbyte(ozus);
        if (ozus->error_code != OZUS_ERRCODE_OK)
            return 0;
        ozus->bitreader_buf |= ((unsigned long)b) <<
                               ozus->bitreader_nbits_in_buf;
        ozus->bitreader_nbits_in_buf += 8;
    }

    mask = (1UL << nbits) - 1UL;
    n = (OZUS_CODE)(ozus->bitreader_buf & mask);
    ozus->bitreader_buf >>= nbits;
    ozus->bitreader_nbits_in_buf -= nbits;
    return n;
}

OZUS_API(void) ozus_write_unbuffered(ozus_ctx *ozus,
                                     const OZUS_UINT8 *buf, size_t n)
{
    size_t ret;

    if (ozus->error_code != OZUS_ERRCODE_OK || n == 0)
        return;
    ret = ozus->cb_write(ozus, buf, n);
    if (ret != n) {
        ozus_set_error(ozus, OZUS_ERRCODE_WRITE_FAILED);
        return;
    }
    ozus->uncmpr_nbytes_written += (OZUS_OFF_T)n;
}

OZUS_API(void) ozus_flush(ozus_ctx *ozus)
{
    size_t n;

    if (ozus->error_code != OZUS_ERRCODE_OK)
        return;
    n = ozus->outbuf_nbytes_used;
    if (n != 0)
        ozus_write_unbuffered(ozus, ozus->outbuf, n);
    if (ozus->error_code == OZUS_ERRCODE_OK)
        ozus->outbuf_nbytes_used = 0;
}

OZUS_API(void) ozus_write(ozus_ctx *ozus,
                          const OZUS_UINT8 *buf, size_t n)
{
    if (ozus->error_code != OZUS_ERRCODE_OK || n == 0)
        return;

    if (ozus->outbuf_nbytes_used + n <= OZUS_OUTBUF_SIZE) {
        OZUS_MEMCPY(ozus->outbuf + ozus->outbuf_nbytes_used, buf, n);
        ozus->outbuf_nbytes_used += n;
        return;
    }

    ozus_flush(ozus);
    if (ozus->error_code != OZUS_ERRCODE_OK)
        return;

    if (n > OZUS_OUTBUF_SIZE) {
        ozus_write_unbuffered(ozus, buf, n);
        return;
    }

    OZUS_MEMCPY(ozus->outbuf, buf, n);
    ozus->outbuf_nbytes_used = n;
}

OZUS_API(void) ozus_emit_code(ozus_ctx *ozus, OZUS_CODE code1)
{
    OZUS_CODE code;
    size_t valbuf_pos;

    code = code1;
    valbuf_pos = OZUS_VALBUFSIZE;

    for (;;) {
        if (code >= OZUS_NUM_CODES || valbuf_pos == 0) {
            ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
            return;
        }
        --valbuf_pos;

        if (code >= 257 && ozus->ct[code].parent == OZUS_INVALID_CODE) {
            ozus->valbuf[valbuf_pos] = ozus->last_value;
            code = ozus->oldcode;
            continue;
        }

        ozus->valbuf[valbuf_pos] = ozus->ct[code].value;
        if (code < 257) {
            ozus->last_value = ozus->ct[code].value;
            break;
        }
        code = ozus->ct[code].parent;
    }

    ozus_write(ozus, ozus->valbuf + valbuf_pos,
               OZUS_VALBUFSIZE - valbuf_pos);
}

OZUS_API(void) ozus_find_first_free_entry(ozus_ctx *ozus,
                                           OZUS_CODE *pentry)
{
    OZUS_CODE k;

    for (k = ozus->free_code_search_start; k < OZUS_NUM_CODES; k++) {
        if (ozus->ct[k].parent == OZUS_INVALID_CODE) {
            *pentry = k;
            return;
        }
    }

    *pentry = OZUS_NUM_CODES - 1;
    ozus_set_error(ozus, OZUS_ERRCODE_BAD_CDATA);
}

OZUS_API(void) ozus_add_to_dict(ozus_ctx *ozus, OZUS_CODE parent,
                                OZUS_UINT8 value)
{
    OZUS_CODE newpos;

    ozus_find_first_free_entry(ozus, &newpos);
    if (ozus->error_code != OZUS_ERRCODE_OK)
        return;

    ozus->ct[newpos].parent = parent;
    ozus->ct[newpos].value = value;
    ozus->ct[newpos].flags = 0;
    ozus->last_code_added = newpos;
    ozus->free_code_search_start = newpos + 1;
    if (newpos > ozus->highest_code_ever_used)
        ozus->highest_code_ever_used = newpos;
}

OZUS_API(void) ozus_process_data_code(ozus_ctx *ozus, OZUS_CODE code)
{
    if (code >= OZUS_NUM_CODES) {
        ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
        return;
    }

    if (!ozus->have_oldcode) {
        if (code >= 256) {
            ozus_set_error(ozus, OZUS_ERRCODE_BAD_CDATA);
            return;
        }
        ozus_emit_code(ozus, code);
        if (ozus->error_code != OZUS_ERRCODE_OK)
            return;
        ozus->oldcode = code;
        ozus->have_oldcode = 1;
        ozus->last_value = (OZUS_UINT8)code;
        return;
    }

    if (code < 256 || ozus->ct[code].parent != OZUS_INVALID_CODE) {
        ozus_emit_code(ozus, code);
        if (ozus->error_code != OZUS_ERRCODE_OK)
            return;
        ozus_add_to_dict(ozus, ozus->oldcode, ozus->last_value);
    }
    else {
        ozus_add_to_dict(ozus, ozus->oldcode, ozus->last_value);
        if (ozus->error_code != OZUS_ERRCODE_OK)
            return;
        if (code != ozus->last_code_added) {
            ozus_set_error(ozus, OZUS_ERRCODE_BAD_CDATA);
            return;
        }
        ozus_emit_code(ozus, ozus->last_code_added);
    }

    if (ozus->error_code == OZUS_ERRCODE_OK)
        ozus->oldcode = code;
}

OZUS_API(void) ozus_partial_clear(ozus_ctx *ozus)
{
    OZUS_CODE i;

    if (ozus->cb_pre_partial_clear != NULL)
        ozus->cb_pre_partial_clear(ozus);

    for (i = 257; i <= ozus->highest_code_ever_used; i++) {
        if (ozus->ct[i].parent != OZUS_INVALID_CODE &&
            ozus->ct[i].parent < OZUS_NUM_CODES)
            ozus->ct[ozus->ct[i].parent].flags = 1;
    }

    for (i = 257; i <= ozus->highest_code_ever_used; i++) {
        if (ozus->ct[i].flags == 0) {
            ozus->ct[i].parent = OZUS_INVALID_CODE;
            ozus->ct[i].value = 0;
        }
        else {
            ozus->ct[i].flags = 0;
        }
    }

    ozus->free_code_search_start = 257;
}

OZUS_API(void) ozus_run(ozus_ctx *ozus)
{
    OZUS_CODE code;

    if (ozus == NULL || ozus->cb_read == NULL || ozus->cb_write == NULL ||
        ozus->cmpr_size < 0 || ozus->uncmpr_size < 0) {
        if (ozus != NULL)
            ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
        return;
    }

    ozus_init(ozus);
    if (ozus->error_code != OZUS_ERRCODE_OK)
        goto done;

    ozus->curr_code_size = OZUS_INITIAL_CODE_SIZE;
    for (;;) {
        if (ozus->uncmpr_nbytes_written +
            (OZUS_OFF_T)ozus->outbuf_nbytes_used >= ozus->uncmpr_size)
            goto done;

        code = ozus_getnextcode(ozus);
        if (ozus->error_code != OZUS_ERRCODE_OK)
            goto done;

        if (code == 256) {
            OZUS_CODE n;
            n = ozus_getnextcode(ozus);
            if (ozus->error_code != OZUS_ERRCODE_OK)
                goto done;

            if (n == 1 && ozus->curr_code_size < OZUS_MAX_CODE_SIZE) {
                ++ozus->curr_code_size;
                if (ozus->cb_inc_code_size != NULL)
                    ozus->cb_inc_code_size(ozus);
            }
            else if (n == 2) {
                ozus_partial_clear(ozus);
                if (ozus->error_code != OZUS_ERRCODE_OK)
                    goto done;
            }
            else {
                ozus_set_error(ozus, OZUS_ERRCODE_BAD_CDATA);
                goto done;
            }
        }
        else {
            ozus_process_data_code(ozus, code);
            if (ozus->error_code != OZUS_ERRCODE_OK)
                goto done;
        }
    }

done:
    ozus_flush(ozus);
}

#endif /* OZUNSHRINK_H_INCLUDED */
