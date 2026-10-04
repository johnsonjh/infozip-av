/*
 * explode.c - ZIP Implode (method 6) and PKWARE DCL Implode (method 10)
 *
 * Method 6 is decoded by the OldUnzip unimplode6a engine from Jason Summers,
 * adapted to strict ANSI C89 in unimplode6a.h.  Method 10 is decoded by the
 * existing included PKDCLX engine and is intentionally unchanged below.
 */

#define __EXPLODE_C
#define UNZIP_INTERNAL
#include "unzip.h"

#define UI6A_UINT8  uch
#define UI6A_UINT16 ush
#define UI6A_UINT32 ulg
#define UI6A_OFF_T   zoff_t
#define UI6A_ZEROMEM(ptr, size) memzero((ptr), (size))
#include "unimplode6a.h"

#include "pkdcl.h"
/* Keep pkdcl.c unchanged and compile it with explode.c. */
#include "pkdcl.c"

struct ui6a_iz_state {
#ifdef REENTRANT
    Uz_Globs *pG;
#endif
    zoff_t remaining;
    zusz_t total;
    zusz_t expected;
    int output_error;
};

static size_t ui6a_iz_read(ui6a_ctx *ui6a, UI6A_UINT8 *buf, size_t size)
{
    struct ui6a_iz_state *s;
    size_t want;
    size_t got;
    int c;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct ui6a_iz_state *)ui6a->userdata;
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
        buf[got++] = (UI6A_UINT8)c;
    }
    s->remaining -= (zoff_t)got;
    return got;
}

static size_t ui6a_iz_write(ui6a_ctx *ui6a, const UI6A_UINT8 *buf,
                            size_t size)
{
    struct ui6a_iz_state *s;
    int r;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct ui6a_iz_state *)ui6a->userdata;
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

static void ui6a_iz_drain(__GPRO__ struct ui6a_iz_state *s)
{
    int c;

    while (s->remaining > 0) {
        c = NEXTBYTE;
        if (c == EOF)
            break;
        --s->remaining;
    }
}

int explode(__G)
    __GDEF
{
    ui6a_ctx *ui6a;
    struct ui6a_iz_state s;
    zoff_t compressed;
    zoff_t consumed;
    int engine_error;

    compressed = G.csize + (zoff_t)G.incnt;
    if (compressed < 0)
        return PK_ERR;

    ui6a = (ui6a_ctx *)malloc(sizeof(ui6a_ctx));
    if (ui6a == NULL)
        return PK_MEM3;
    memzero(ui6a, sizeof(ui6a_ctx));
    memzero(&s, sizeof(s));

#ifdef REENTRANT
    s.pG = pG;
#endif
    s.remaining = compressed;
    s.expected = G.lrec.ucsize;

    ui6a->userdata = (void *)&s;
    ui6a->cmpr_size = compressed;
    ui6a->uncmpr_size = (zoff_t)G.lrec.ucsize;
    ui6a->bit_flags = (UI6A_UINT16)G.lrec.general_purpose_bit_flag;
    /* Decode the documented method-6 format.  OldUnzip's compatibility
     * switch deliberately recreates a PKZIP 1.01/1.02 minimum-match-length
     * bug for two Implode variants and can reject otherwise valid streams. */
    ui6a->emulate_pkzip10x = 0;
    ui6a->cb_read = ui6a_iz_read;
    ui6a->cb_write = ui6a_iz_write;

    ui6a_unimplode(ui6a);
    consumed = ui6a->cmpr_nbytes_consumed;
    engine_error = ui6a->error_code;

    /* ui6a buffers compressed input internally.  Always consume the rest of
     * this ZIP member before returning, even when malformed input is found. */
    ui6a_iz_drain(__G__ &s);

    if (s.output_error != 0) {
        int r;
        r = s.output_error;
        free(ui6a);
        return r;
    }

    if (engine_error != UI6A_ERRCODE_OK || s.total != s.expected ||
        s.remaining != 0) {
        free(ui6a);
        return PK_ERR;
    }

    if (consumed != compressed) {
        G.used_csize = consumed;
        free(ui6a);
        return 5;
    }

    free(ui6a);
    return PK_COOL;
}
/* -------------------------------------------------------------------------
 * PKWARE Data Compression Library (DCL) implode decoder, ZIP method 10.
 *
 * The actual DCL engine is pkdcl.c, from PKDCLX.
 *
 * Output is passed directly to Info-ZIP flush().  In particular, this does
 * not use redirSlide as the DCL history buffer.  pkdcl uses the ordinary
 * internal slide[] storage as its work area, and flush() remains responsible
 * for normal output handling, including Windows DLL redirection.
 * ------------------------------------------------------------------------- */

struct dcl_pk_state {
#ifdef REENTRANT
    Uz_Globs *pG;
#endif
    zoff_t remaining;
    zusz_t total;
    zusz_t expected;
    int output_error;
    int first_read;
    int saw_eof;
    unsigned header_used;
    uch header[2];
};

static unsigned short dcl_pk_read(unsigned char *buffer,
                                  unsigned short *size, void *opaque)
{
    struct dcl_pk_state *s;
    unsigned want;
    unsigned got;
    int byte;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct dcl_pk_state *)opaque;
#ifdef REENTRANT
    pG = s->pG;
#endif

    if (s->remaining <= 0) {
        s->saw_eof = 1;
        return 0;
    }

    want = (unsigned)*size;
    if (s->first_read) {
        if (want > 5U)
            want = 5U;
    } else if (want > 1U) {
        /* Avoid read-ahead past the DCL end code.  This preserves the old
         * ZIP-member check which rejects unused whole compressed bytes. */
        want = 1U;
    }
    if ((zoff_t)want > s->remaining)
        want = (unsigned)s->remaining;

    got = 0;
    while (got < want) {
        byte = NEXTBYTE;
        if (byte == EOF)
            break;
        buffer[got++] = (unsigned char)byte;
        if (s->header_used < 2U)
            s->header[s->header_used++] = (uch)byte;
    }
    s->remaining -= (zoff_t)got;
    s->first_read = 0;
    return (unsigned short)got;
}

static void dcl_pk_write(unsigned char *buffer, unsigned short *size,
                         void *opaque)
{
    struct dcl_pk_state *s;
    ulg count;
    int r;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (struct dcl_pk_state *)opaque;
#ifdef REENTRANT
    pG = s->pG;
#endif

    count = (ulg)*size;
    if (count == 0 || s->output_error != 0)
        return;

    if (s->total > s->expected ||
        (zusz_t)count > s->expected - s->total) {
        s->output_error = PK_ERR;
        return;
    }

    r = flush(__G__ (uch *)buffer, count, 0);
    if (r != PK_COOL) {
        s->output_error = r;
        return;
    }
    s->total += (zusz_t)count;
}

int dcl_explode(__G)
    __GDEF
{
    struct dcl_pk_state s;
    unsigned short r;
    zoff_t compressed;

#if PKDCL_EXPLODE_WORK_SIZE > WSIZE
# error PKDCL explode work area does not fit in Info-ZIP slide buffer
#endif

    compressed = G.csize + (zoff_t)G.incnt;
    if (compressed < 0)
        return PK_ERR;

#ifdef REENTRANT
    s.pG = pG;
#endif
    s.remaining = compressed;
    s.total = 0;
    s.expected = G.lrec.ucsize;
    s.output_error = 0;
    s.first_read = 1;
    s.saw_eof = 0;
    s.header_used = 0;
    s.header[0] = s.header[1] = 0;

    /* pkdcl_explode() intentionally follows the original PKWARE streaming
     * API, whose initial fill rejects a four-byte stream.  A valid empty DCL
     * member is exactly four bytes, so use the extended decoder only for that
     * one case.  Header validation below still forbids extended dictionaries. */
    if (s.expected == 0) {
        if (compressed != 4)
            return PK_ERR;
        r = pkdcl_explode_ex(dcl_pk_read, dcl_pk_write, &s);
    } else {
        r = pkdcl_explode(dcl_pk_read, dcl_pk_write, slide, &s);
    }

    if (s.output_error != 0)
        return s.output_error;
    if (r != PKDCL_CMP_NO_ERROR)
        return PK_ERR;

    /* ZIP method 10 is standard DCL only.  Type 0/1 and dictionary bits 4..6
     * correspond to binary/ASCII literals and 1K/2K/4K dictionaries. */
    if (s.header_used != 2U || s.header[0] > 1U ||
        s.header[1] < 4U || s.header[1] > 6U)
        return PK_ERR;

    if (s.remaining != 0 || !s.saw_eof ||
        G.csize + (zoff_t)G.incnt != 0)
        return PK_ERR;
    if (s.total != s.expected)
        return PK_ERR;

    return PK_COOL;
}
