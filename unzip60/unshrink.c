/*
 * unshrink.c - Info-ZIP adapter for OldUnzip ozunshrink.h
 *
 * The decompression engine is Jason Summers' MIT/public-domain OldUnzip
 * implementation, adapted to strict ANSI C89 in ozunshrink.h.  This file
 * contains only the Info-ZIP input/output and error mapping glue.
 */

#define __UNSHRINK_C
#define UNZIP_INTERNAL
#include "unzip.h"

#define OZUS_UINT8  uch
#define OZUS_UINT16 ush
#define OZUS_OFF_T  zoff_t
#define OZUS_MEMCPY memcpy
#include "ozunshrink.h"

struct ozus_iz_state {
#ifdef REENTRANT
    Uz_Globs *pG;
#endif
    zoff_t remaining;
    zusz_t total;
    zusz_t expected;
    int output_error;
};

static size_t ozus_iz_read(ozus_ctx *ozus, OZUS_UINT8 *buf, size_t size)
{
    struct ozus_iz_state *s;
    size_t want;
    size_t got;
    int c;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct ozus_iz_state *)ozus->userdata;
#ifdef REENTRANT
    pG = s->pG;
#endif

    if (s->remaining <= 0)
        return 0;

    want = size;
    if ((zoff_t)want > s->remaining)
        want = (size_t)s->remaining;

    got = 0;
    while (got < want) {
        c = NEXTBYTE;
        if (c == EOF)
            break;
        buf[got++] = (OZUS_UINT8)c;
    }
    s->remaining -= (zoff_t)got;
    return got;
}

static size_t ozus_iz_write(ozus_ctx *ozus, const OZUS_UINT8 *buf,
                            size_t size)
{
    struct ozus_iz_state *s;
    int r;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct ozus_iz_state *)ozus->userdata;
#ifdef REENTRANT
    pG = s->pG;
#endif

    if (size == 0)
        return 0;
    if (s->output_error != 0)
        return 0;
    if (s->total > s->expected ||
        (zusz_t)size > s->expected - s->total) {
        s->output_error = PK_ERR;
        return 0;
    }

    r = flush(__G__ (uch *)buf, (ulg)size, 0);
    if (r != PK_COOL) {
        s->output_error = r;
        return 0;
    }

    s->total += (zusz_t)size;
    return size;
}

static void ozus_iz_drain(__GPRO__ struct ozus_iz_state *s)
{
    int c;

    while (s->remaining > 0) {
        c = NEXTBYTE;
        if (c == EOF)
            break;
        --s->remaining;
    }
}

int unshrink(__G)
    __GDEF
{
    ozus_ctx *ozus;
    struct ozus_iz_state s;
    zoff_t compressed;
    zoff_t consumed;
    int engine_error;

    compressed = G.csize + (zoff_t)G.incnt;
    if (compressed < 0)
        return PK_ERR;

    ozus = (ozus_ctx *)malloc(sizeof(ozus_ctx));
    if (ozus == NULL)
        return PK_MEM3;
    memzero(ozus, sizeof(ozus_ctx));
    memzero(&s, sizeof(s));

#ifdef REENTRANT
    s.pG = pG;
#endif
    s.remaining = compressed;
    s.expected = G.lrec.ucsize;

    ozus->userdata = (void *)&s;
    ozus->cmpr_size = compressed;
    ozus->uncmpr_size = (zoff_t)G.lrec.ucsize;
    ozus->cb_read = ozus_iz_read;
    ozus->cb_write = ozus_iz_write;

    ozus_run(ozus);
    consumed = ozus->cmpr_nbytes_consumed;
    engine_error = ozus->error_code;

    /*
     * The OldUnzip engine buffers compressed input. Drain any unread member
     * bytes so an error in this member cannot misalign the next local header.
     */
    ozus_iz_drain(__G__ &s);

    if (s.output_error != 0) {
        int r;
        r = s.output_error;
        free(ozus);
        return r;
    }

    if (engine_error != OZUS_ERRCODE_OK || s.total != s.expected ||
        consumed != compressed || s.remaining != 0) {
        free(ozus);
        return PK_ERR;
    }

    free(ozus);
    return PK_COOL;
}
