/*
 * unimplode6a.h - ZIP Implode (method 6) decompressor
 *
 * ANSI C89 adaptation for Info-ZIP AV, based on Jason Summers' OldUnzip
 * unimplode6a library. The OldUnzip version was in turn derived from the
 * public-domain method-6 explode/inflate work by Mark Adler and was heavily
 * revised by Jason Summers.
 *
 * Copyright (C) 2019-2021 Jason Summers
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
 * Upstream version: UI6A_VERSION 20210124.
 *
 * This adaptation keeps the OldUnzip callback API and method-6 semantics,
 * but uses a compact canonical-Huffman decode tree rather than the upstream
 * multi-level huft lookup tables. It contains no C99 syntax or stdint types.
 */

#ifndef UNIMPLODE6A_H_INCLUDED
#define UNIMPLODE6A_H_INCLUDED

#include <stddef.h>
#include <string.h>

#define UI6A_VERSION 20210124

#ifndef UI6A_UINT8
#  define UI6A_UINT8 unsigned char
#endif
#ifndef UI6A_UINT16
#  define UI6A_UINT16 unsigned short
#endif
#ifndef UI6A_UINT32
#  define UI6A_UINT32 unsigned long
#endif
#ifndef UI6A_OFF_T
#  define UI6A_OFF_T long
#endif
#ifndef UI6A_ZEROMEM
#  define UI6A_ZEROMEM(ptr, size) memset((ptr), 0, (size))
#endif
#ifndef UI6A_API
#  define UI6A_API(ty) static ty
#endif

#define UI6A_ERRCODE_OK                  0
#define UI6A_ERRCODE_GENERIC_ERROR       1
#define UI6A_ERRCODE_BAD_CDATA           2
#define UI6A_ERRCODE_MALLOC_FAILED       3
#define UI6A_ERRCODE_READ_FAILED         6
#define UI6A_ERRCODE_WRITE_FAILED        7
#define UI6A_ERRCODE_INSUFFICIENT_CDATA  8

#define UI6A_FLAG_4KDICT 0x0000
#define UI6A_FLAG_8KDICT 0x0002
#define UI6A_FLAG_2TREES 0x0000
#define UI6A_FLAG_3TREES 0x0004

#define UI6A_WSIZE 0x2000
#define UI6A_INBUF_SIZE 4096
#define UI6A_MAX_BITS 16
#define UI6A_MAX_TREE_NODES 511

struct ui6a_htable {
    int b;
    const char *tblname;
};

struct ui6a_htables {
    struct ui6a_htable b;
    struct ui6a_htable l;
    struct ui6a_htable d;
};

struct ui6a_ctx_struct;
typedef struct ui6a_ctx_struct ui6a_ctx;
typedef size_t (*ui6a_cb_read_type)(ui6a_ctx *, UI6A_UINT8 *, size_t);
typedef size_t (*ui6a_cb_write_type)(ui6a_ctx *, const UI6A_UINT8 *, size_t);
typedef void (*ui6a_cb_post_read_trees_type)(ui6a_ctx *,
                                              struct ui6a_htables *);

struct ui6a_dnode {
    short child[2];
    short symbol;
};

struct ui6a_dtree {
    unsigned int nnodes;
    unsigned int maxbits;
    struct ui6a_dnode node[UI6A_MAX_TREE_NODES];
};

struct ui6a_ctx_struct {
    void *userdata;
    UI6A_OFF_T cmpr_size;
    UI6A_OFF_T uncmpr_size;
    UI6A_UINT16 bit_flags;
    UI6A_UINT8 emulate_pkzip10x;
    ui6a_cb_read_type cb_read;
    ui6a_cb_write_type cb_write;
    ui6a_cb_post_read_trees_type cb_post_read_trees;

    int error_code;
    UI6A_OFF_T uncmpr_nbytes_written;
    UI6A_OFF_T cmpr_nbytes_consumed;

    UI6A_OFF_T cmpr_nbytes_read;
    size_t inbuf_nbytes_consumed;
    size_t inbuf_nbytes_total;
    UI6A_UINT32 bitreader_buf;
    unsigned int bitreader_nbits_in_buf;
    UI6A_UINT8 Slide[UI6A_WSIZE];
    UI6A_UINT8 inbuf[UI6A_INBUF_SIZE];
    struct ui6a_dtree literal_tree;
    struct ui6a_dtree length_tree;
    struct ui6a_dtree distance_tree;
};

UI6A_API(void) ui6a_set_error(ui6a_ctx *ui6a, int error_code)
{
    if (ui6a->error_code == UI6A_ERRCODE_OK)
        ui6a->error_code = error_code;
}

UI6A_API(int) ui6a_nextbyte(ui6a_ctx *ui6a)
{
    size_t ret;
    size_t nbytes_to_read;
    UI6A_OFF_T left;
    UI6A_UINT8 ch;

    if (ui6a->error_code != UI6A_ERRCODE_OK)
        return -1;

    if (ui6a->inbuf_nbytes_consumed < ui6a->inbuf_nbytes_total) {
        ch = ui6a->inbuf[ui6a->inbuf_nbytes_consumed++];
        ++ui6a->cmpr_nbytes_consumed;
        return (int)ch;
    }

    ui6a->inbuf_nbytes_consumed = 0;
    ui6a->inbuf_nbytes_total = 0;
    if (ui6a->cmpr_nbytes_consumed >= ui6a->cmpr_size) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_INSUFFICIENT_CDATA);
        return -1;
    }

    left = ui6a->cmpr_size - ui6a->cmpr_nbytes_read;
    if (left > (UI6A_OFF_T)UI6A_INBUF_SIZE)
        nbytes_to_read = UI6A_INBUF_SIZE;
    else if (left > 0)
        nbytes_to_read = (size_t)left;
    else {
        ui6a_set_error(ui6a, UI6A_ERRCODE_INSUFFICIENT_CDATA);
        return -1;
    }

    ret = ui6a->cb_read(ui6a, ui6a->inbuf, nbytes_to_read);
    if (ret != nbytes_to_read) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_READ_FAILED);
        return -1;
    }
    ui6a->cmpr_nbytes_read += (UI6A_OFF_T)nbytes_to_read;
    ui6a->inbuf_nbytes_total = nbytes_to_read;

    ch = ui6a->inbuf[ui6a->inbuf_nbytes_consumed++];
    ++ui6a->cmpr_nbytes_consumed;
    return (int)ch;
}

UI6A_API(unsigned int) ui6a_getbits(ui6a_ctx *ui6a, unsigned int nbits)
{
    UI6A_UINT32 mask;
    unsigned int value;

    if (nbits == 0 || nbits > 16) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_GENERIC_ERROR);
        return 0;
    }

    while (ui6a->bitreader_nbits_in_buf < nbits) {
        int ch;
        ch = ui6a_nextbyte(ui6a);
        if (ch < 0)
            return 0;
        ui6a->bitreader_buf |= ((UI6A_UINT32)(UI6A_UINT8)ch) <<
                               ui6a->bitreader_nbits_in_buf;
        ui6a->bitreader_nbits_in_buf += 8;
    }

    mask = (((UI6A_UINT32)1 << nbits) - 1U);
    value = (unsigned int)(ui6a->bitreader_buf & mask);
    ui6a->bitreader_buf >>= nbits;
    ui6a->bitreader_nbits_in_buf -= nbits;
    return value;
}

UI6A_API(void) ui6a_flush(ui6a_ctx *ui6a,
                          const UI6A_UINT8 *rawbuf, size_t size)
{
    size_t ret;

    if (ui6a->error_code != UI6A_ERRCODE_OK || size == 0)
        return;
    if (ui6a->uncmpr_nbytes_written + (UI6A_OFF_T)size >
        ui6a->uncmpr_size) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
        return;
    }

    ret = ui6a->cb_write(ui6a, rawbuf, size);
    if (ret != size) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_WRITE_FAILED);
        return;
    }
    ui6a->uncmpr_nbytes_written += (UI6A_OFF_T)size;
}

UI6A_API(void) ui6a_get_tree(ui6a_ctx *ui6a,
                             unsigned int *lengths, unsigned int n)
{
    unsigned int i;
    unsigned int k;

    i = (unsigned int)ui6a_nextbyte(ui6a);
    if (ui6a->error_code != UI6A_ERRCODE_OK)
        return;
    ++i;
    k = 0;

    do {
        int ch;
        unsigned int count;
        unsigned int bits;

        ch = ui6a_nextbyte(ui6a);
        if (ch < 0)
            return;
        bits = ((unsigned int)ch & 0x0fU) + 1U;
        count = (((unsigned int)ch >> 4) & 0x0fU) + 1U;
        if (k + count > n) {
            ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
            return;
        }
        while (count-- != 0)
            lengths[k++] = bits;
    } while (--i != 0);

    if (k != n)
        ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
}

UI6A_API(unsigned long) ui6a_reverse_bits(unsigned long code,
                                           unsigned int nbits)
{
    unsigned long r;
    unsigned int i;

    r = 0;
    for (i = 0; i < nbits; ++i) {
        r = (r << 1) | (code & 1UL);
        code >>= 1;
    }
    return r;
}

UI6A_API(void) ui6a_tree_init(struct ui6a_dtree *tree)
{
    unsigned int i;

    tree->nnodes = 1;
    tree->maxbits = 0;
    for (i = 0; i < UI6A_MAX_TREE_NODES; ++i) {
        tree->node[i].child[0] = -1;
        tree->node[i].child[1] = -1;
        tree->node[i].symbol = -1;
    }
}

UI6A_API(int) ui6a_tree_new_node(ui6a_ctx *ui6a,
                                 struct ui6a_dtree *tree)
{
    unsigned int n;

    n = tree->nnodes;
    if (n >= UI6A_MAX_TREE_NODES) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
        return -1;
    }
    ++tree->nnodes;
    tree->node[n].child[0] = -1;
    tree->node[n].child[1] = -1;
    tree->node[n].symbol = -1;
    return (int)n;
}

UI6A_API(void) ui6a_build_tree(ui6a_ctx *ui6a,
                               struct ui6a_dtree *tree,
                               const unsigned int *lengths,
                               unsigned int nsym)
{
    unsigned int count[UI6A_MAX_BITS + 1];
    unsigned long next_code[UI6A_MAX_BITS + 1];
    unsigned long code;
    long left;
    unsigned int bits;
    unsigned int sym;

    for (bits = 0; bits <= UI6A_MAX_BITS; ++bits) {
        count[bits] = 0;
        next_code[bits] = 0;
    }

    for (sym = 0; sym < nsym; ++sym) {
        bits = lengths[sym];
        if (bits < 1 || bits > UI6A_MAX_BITS) {
            ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
            return;
        }
        ++count[bits];
    }

    left = 1;
    for (bits = 1; bits <= UI6A_MAX_BITS; ++bits) {
        left = (left << 1) - (long)count[bits];
        if (left < 0) {
            ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
            return;
        }
    }
    if (left != 0) {
        ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
        return;
    }

    code = 0;
    for (bits = 1; bits <= UI6A_MAX_BITS; ++bits) {
        code = (code + (unsigned long)count[bits - 1]) << 1;
        next_code[bits] = code;
        if (count[bits] != 0)
            tree->maxbits = bits;
    }

    ui6a_tree_init(tree);
    for (bits = 1; bits <= UI6A_MAX_BITS; ++bits) {
        if (count[bits] != 0)
            tree->maxbits = bits;
    }

    for (sym = 0; sym < nsym; ++sym) {
        unsigned int len;
        unsigned long canonical;
        unsigned long reversed;
        unsigned long transmitted;
        unsigned long mask;
        unsigned int j;
        int node;

        len = lengths[sym];
        canonical = next_code[len]++;
        reversed = ui6a_reverse_bits(canonical, len);
        mask = ((1UL << len) - 1UL);
        transmitted = (~reversed) & mask;
        node = 0;

        for (j = 0; j < len; ++j) {
            unsigned int bit;
            int child;

            bit = (unsigned int)((transmitted >> j) & 1UL);
            child = (int)tree->node[node].child[bit];

            if (j + 1 == len) {
                if (child >= 0) {
                    ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
                    return;
                }
                child = ui6a_tree_new_node(ui6a, tree);
                if (child < 0)
                    return;
                tree->node[node].child[bit] = (short)child;
                tree->node[child].symbol = (short)sym;
            }
            else {
                if (child < 0) {
                    child = ui6a_tree_new_node(ui6a, tree);
                    if (child < 0)
                        return;
                    tree->node[node].child[bit] = (short)child;
                }
                else if (tree->node[child].symbol >= 0) {
                    ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
                    return;
                }
                node = child;
            }
        }
    }
}

UI6A_API(int) ui6a_decode_symbol(ui6a_ctx *ui6a,
                                 const struct ui6a_dtree *tree)
{
    int node;
    unsigned int depth;

    node = 0;
    for (depth = 0; depth < tree->maxbits; ++depth) {
        unsigned int bit;
        int child;

        bit = ui6a_getbits(ui6a, 1);
        if (ui6a->error_code != UI6A_ERRCODE_OK)
            return -1;
        child = (int)tree->node[node].child[bit];
        if (child < 0 || (unsigned int)child >= tree->nnodes) {
            ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
            return -1;
        }
        node = child;
        if (tree->node[node].symbol >= 0)
            return (int)tree->node[node].symbol;
    }

    ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
    return -1;
}

UI6A_API(void) ui6a_unimplode_internal(ui6a_ctx *ui6a,
                                       int has_8k_window,
                                       int has_literal_tree,
                                       unsigned int min_match)
{
    UI6A_OFF_T remaining;
    size_t w;

    remaining = ui6a->uncmpr_size;
    w = 0;

    while (remaining > 0 && ui6a->error_code == UI6A_ERRCODE_OK) {
        unsigned int is_literal;

        is_literal = ui6a_getbits(ui6a, 1);
        if (ui6a->error_code != UI6A_ERRCODE_OK)
            break;

        if (is_literal != 0) {
            unsigned int value;

            if (has_literal_tree) {
                int symbol;
                symbol = ui6a_decode_symbol(ui6a, &ui6a->literal_tree);
                if (symbol < 0)
                    break;
                value = (unsigned int)symbol;
            }
            else {
                value = ui6a_getbits(ui6a, 8);
                if (ui6a->error_code != UI6A_ERRCODE_OK)
                    break;
            }

            ui6a->Slide[w++] = (UI6A_UINT8)value;
            --remaining;
            if (w == UI6A_WSIZE) {
                ui6a_flush(ui6a, ui6a->Slide, w);
                w = 0;
            }
        }
        else {
            unsigned int lowbits;
            unsigned int low;
            int dsym;
            int lsym;
            unsigned int distance;
            unsigned int length;
            size_t src;

            lowbits = has_8k_window ? 7U : 6U;
            low = ui6a_getbits(ui6a, lowbits);
            if (ui6a->error_code != UI6A_ERRCODE_OK)
                break;

            dsym = ui6a_decode_symbol(ui6a, &ui6a->distance_tree);
            if (dsym < 0)
                break;
            distance = 1U + (unsigned int)dsym *
                       (has_8k_window ? 128U : 64U) + low;
            if (distance == 0 || distance > (has_8k_window ? 8192U : 4096U)) {
                ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
                break;
            }

            lsym = ui6a_decode_symbol(ui6a, &ui6a->length_tree);
            if (lsym < 0)
                break;
            length = (unsigned int)lsym + min_match;
            if (lsym == 63) {
                length += ui6a_getbits(ui6a, 8);
                if (ui6a->error_code != UI6A_ERRCODE_OK)
                    break;
            }

            if ((UI6A_OFF_T)length > remaining) {
                ui6a_set_error(ui6a, UI6A_ERRCODE_BAD_CDATA);
                break;
            }

            src = (w + UI6A_WSIZE - (size_t)distance) &
                  (UI6A_WSIZE - 1U);
            while (length-- != 0) {
                ui6a->Slide[w++] = ui6a->Slide[src++];
                src &= UI6A_WSIZE - 1U;
                --remaining;
                if (w == UI6A_WSIZE) {
                    ui6a_flush(ui6a, ui6a->Slide, w);
                    w = 0;
                }
                if (ui6a->error_code != UI6A_ERRCODE_OK)
                    break;
            }
        }
    }

    if (ui6a->error_code == UI6A_ERRCODE_OK && w != 0)
        ui6a_flush(ui6a, ui6a->Slide, w);
}

UI6A_API(void) ui6a_unimplode(ui6a_ctx *ui6a)
{
    unsigned int lengths[256];
    int has_literal_tree;
    int has_8k_window;
    unsigned int min_match;
    struct ui6a_htables tbls;

    if (ui6a == NULL || ui6a->cb_read == NULL || ui6a->cb_write == NULL ||
        ui6a->cmpr_size < 0 || ui6a->uncmpr_size < 0) {
        if (ui6a != NULL)
            ui6a_set_error(ui6a, UI6A_ERRCODE_GENERIC_ERROR);
        return;
    }

    has_8k_window = (ui6a->bit_flags & UI6A_FLAG_8KDICT) != 0;
    has_literal_tree = (ui6a->bit_flags & UI6A_FLAG_3TREES) != 0;

    UI6A_ZEROMEM(&tbls, sizeof(tbls));
    tbls.b.tblname = "B";
    tbls.l.tblname = "L";
    tbls.d.tblname = "D";

    if (has_literal_tree) {
        ui6a_get_tree(ui6a, lengths, 256);
        if (ui6a->error_code != UI6A_ERRCODE_OK)
            return;
        ui6a_build_tree(ui6a, &ui6a->literal_tree, lengths, 256);
        if (ui6a->error_code != UI6A_ERRCODE_OK)
            return;
        tbls.b.b = (int)ui6a->literal_tree.maxbits;
    }

    ui6a_get_tree(ui6a, lengths, 64);
    if (ui6a->error_code != UI6A_ERRCODE_OK)
        return;
    ui6a_build_tree(ui6a, &ui6a->length_tree, lengths, 64);
    if (ui6a->error_code != UI6A_ERRCODE_OK)
        return;
    tbls.l.b = (int)ui6a->length_tree.maxbits;

    ui6a_get_tree(ui6a, lengths, 64);
    if (ui6a->error_code != UI6A_ERRCODE_OK)
        return;
    ui6a_build_tree(ui6a, &ui6a->distance_tree, lengths, 64);
    if (ui6a->error_code != UI6A_ERRCODE_OK)
        return;
    tbls.d.b = (int)ui6a->distance_tree.maxbits;

    if (ui6a->cb_post_read_trees != NULL)
        ui6a->cb_post_read_trees(ui6a, &tbls);

    if (ui6a->emulate_pkzip10x)
        min_match = has_8k_window ? 3U : 2U;
    else
        min_match = has_literal_tree ? 3U : 2U;

    ui6a_unimplode_internal(ui6a, has_8k_window,
                            has_literal_tree, min_match);
}

#endif /* UNIMPLODE6A_H_INCLUDED */
