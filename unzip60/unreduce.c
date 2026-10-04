/*
 * unreduce.c - Info-ZIP adapter for OldUnzip ozunreduce.h
 *
 * The decompression engine is Jason Summers' MIT/public-domain OldUnzip
 * implementation, adapted to strict ANSI C89 in ozunreduce.h.  This file
 * contains only the Info-ZIP input/output and error mapping glue.
 */

#define __UNREDUCE_C
#define UNZIP_INTERNAL
#include "unzip.h"

#define OZUR_UINT8 uch
#define OZUR_OFF_T zoff_t
#include "ozunreduce.h"

struct ozur_iz_state {
#ifdef REENTRANT
    Uz_Globs *pG;
#endif
    zoff_t remaining;
    zusz_t total;
    zusz_t expected;
    int output_error;
};

static size_t ozur_iz_read(ozur_ctx *ozur, OZUR_UINT8 *buf, size_t size)
{
    struct ozur_iz_state *s;
    size_t want;
    size_t got;
    int c;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct ozur_iz_state *)ozur->userdata;
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
        buf[got++] = (OZUR_UINT8)c;
    }
    s->remaining -= (zoff_t)got;
    return got;
}

static size_t ozur_iz_write(ozur_ctx *ozur, const OZUR_UINT8 *buf,
                            size_t size)
{
    struct ozur_iz_state *s;
    int r;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct ozur_iz_state *)ozur->userdata;
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

static void ozur_iz_drain(__GPRO__ struct ozur_iz_state *s)
{
    int c;

    while (s->remaining > 0) {
        c = NEXTBYTE;
        if (c == EOF)
            break;
        --s->remaining;
    }
}

int unreduce(__G)
    __GDEF
{
    ozur_ctx *ozur;
    struct ozur_iz_state s;
    zoff_t compressed;
    zoff_t consumed;
    int engine_error;
    unsigned int factor;

    if (G.lrec.compression_method < REDUCED1 ||
        G.lrec.compression_method > REDUCED4)
        return PK_ERR;
    factor = (unsigned int)(G.lrec.compression_method - REDUCED1 + 1);

    compressed = G.csize + (zoff_t)G.incnt;
    if (compressed < 0)
        return PK_ERR;

    ozur = (ozur_ctx *)malloc(sizeof(ozur_ctx));
    if (ozur == NULL)
        return PK_MEM3;
    memzero(ozur, sizeof(ozur_ctx));
    memzero(&s, sizeof(s));

#ifdef REENTRANT
    s.pG = pG;
#endif
    s.remaining = compressed;
    s.expected = G.lrec.ucsize;

    ozur->userdata = (void *)&s;
    ozur->cmpr_factor = factor;
    ozur->cmpr_size = compressed;
    ozur->uncmpr_size = (zoff_t)G.lrec.ucsize;
    ozur->cb_read = ozur_iz_read;
    ozur->cb_write = ozur_iz_write;

    ozur_run(ozur);
    consumed = ozur->cmpr_nbytes_consumed;
    engine_error = ozur->error_code;

    ozur_iz_drain(__G__ &s);

    if (s.output_error != 0) {
        int r;
        r = s.output_error;
        free(ozur);
        return r;
    }

    if (engine_error != OZUR_ERRCODE_OK || s.total != s.expected ||
        consumed != compressed || s.remaining != 0) {
        free(ozur);
        return PK_ERR;
    }

    free(ozur);
    return PK_COOL;
}
