/*
  Copyright (c) 1990-2014 Info-ZIP.  All rights reserved.

  See the accompanying file LICENSE, version 2009-Jan-02 or later
  (the contents of which are also included in unzip.h) for terms of use.
  If, for some reason, all these files are missing, the Info-ZIP license
  also may be found at:  ftp://ftp.info-zip.org/pub/infozip/license.html
*/
/*---------------------------------------------------------------------------

  extract.c

  This file contains the high-level routines ("driver routines") for extrac-
  ting and testing zipfile members.  It calls the low-level routines in files
  explode.c, inflate.c, unreduce.c and unshrink.c.

  Contains:  extract_or_test_files()
             store_info()
             find_compr_idx()
             extract_or_test_entrylist()
             extract_or_test_member()
             TestExtraField()
             test_compr_eb()
             memextract()
             memflush()
             extract_izvms_block()    (VMS or VMS_TEXT_CONV)
             set_deferred_symlink()   (SYMLINKS only)
             fnfilter()
             dircomp()                (SET_DIR_ATTRIB only)
             UZbunzip2()              (USE_BZIP2 only)

  ---------------------------------------------------------------------------*/


#define __EXTRACT_C     /* identifies this source module */
#define UNZIP_INTERNAL
#include "unzip.h"
#ifdef WINDLL
#  ifdef POCKET_UNZIP
#    include "wince/intrface.h"
#  else
#    include "windll/windll.h"
#  endif
#endif
#include "crc32.h"
#include "crypt.h"

#ifndef NO_AES
/* The whole ciphertext is authenticated before the decompressor sees any
 * plaintext.  Pre-auth uses the existing seekable ZIP input and rewinds to
 * the first ciphertext byte only after verifying HMAC.  A password-verifier
 * match alone is NOT authentication.  CRC is also checked for AE-1. */
static int iz_aes_authenticate(__G)
    __GDEF
{
    unsigned char salt[16],check[2],ver[2],tag[10],actual[10];
    unsigned sl,i;
    zoff_t start,encrypted_start,cipher_len,remaining;
    iz_wzaes mac_ctx;
    const char *pw=NULL;
    int n=0,r,j,attempts;
    unsigned char diff;

    G.aes_active=0;
    iz_aes_wipe(&G.aes_ctx,sizeof(G.aes_ctx));
    sl=iz_aes_salt_size(G.pInfo->aes_strength);
    if(sl==0 || G.csize<(zoff_t)(sl+12U))return PK_ERR;
    start=G.cur_zipfile_bufstart+(G.inptr-G.inbuf);
    encrypted_start=start+(zoff_t)sl+2;
    cipher_len=G.csize-(zoff_t)(sl+12U);
    /* Suspend ZipCrypto: AES uses an entirely different key schedule. */
    G.pInfo->encrypted=FALSE;
    defer_leftover_input(__G);
    for(i=0;i<sl;i++) {
        j=NEXTBYTE;if(j==EOF){undefer_input(__G);return PK_ERR;}
        salt[i]=(unsigned char)j;
    }
    for(i=0;i<2;i++) {
        j=NEXTBYTE;if(j==EOF){undefer_input(__G);return PK_ERR;}
        check[i]=(unsigned char)j;
    }

    /* Reuse the ZipCrypto callback/password cache so `unzip -P` and the
     * normal interactive password UI have identical user-visible behavior. */
    if(uO.pwdarg)pw=uO.pwdarg;
    else if(G.key && *G.key)pw=G.key;
    for(attempts=0;attempts<3;attempts++) {
        if(!pw) {
            if(G.nopwd)break;
            if(!G.key && (G.key=(char *)malloc(81))==NULL) {
                undefer_input(__G);return PK_MEM2;
            }
            r=(*G.decr_passwd)((zvoid *)&G,&n,G.key,81,
                                G.zipfn,G.filename);
            if(r!=IZ_PW_ENTERED){
                if(r==IZ_PW_CANCELALL)G.nopwd=TRUE;
                break;
            }
            pw=G.key;
        }
        if(!iz_aes_init(&mac_ctx,pw,salt,G.pInfo->aes_strength,ver)) {
            undefer_input(__G);return PK_ERR;
        }
        diff=(unsigned char)((ver[0]^check[0])|(ver[1]^check[1]));
        iz_aes_wipe(&mac_ctx,sizeof(mac_ctx));
        if(!diff)break;
        if(uO.pwdarg || G.nopwd)break;
        pw=NULL;
    }
    if(attempts>=3 || !pw || diff) {
        undefer_input(__G);iz_aes_wipe(salt,sizeof(salt));return PK_WARN;
    }
    if(!iz_aes_init(&mac_ctx,pw,salt,G.pInfo->aes_strength,ver)) {
        undefer_input(__G);return PK_ERR;
    }
    remaining=cipher_len;
    while(remaining>0) {
        unsigned chunk;
        if(G.incnt<=0) {
            if(G.csize<=0 || fillinbuf(__G)==0) {
                undefer_input(__G);
                iz_aes_wipe(&mac_ctx,sizeof(mac_ctx));
                iz_aes_wipe(salt,sizeof(salt));
                return PK_ERR;
            }
        }
        chunk=(unsigned)((zoff_t)G.incnt<remaining?G.incnt:remaining);
        iz_aes_mac_update(&mac_ctx,G.inptr,chunk);
        G.inptr+=chunk;G.incnt-=(int)chunk;remaining-=(zoff_t)chunk;
    }
    for(i=0;i<10;i++) {
        j=NEXTBYTE;
        if(j==EOF){
            undefer_input(__G);
            iz_aes_wipe(&mac_ctx,sizeof(mac_ctx));
            iz_aes_wipe(salt,sizeof(salt));
            return PK_ERR;
        }
        tag[i]=(unsigned char)j;
    }
    iz_aes_auth(&mac_ctx,actual);
    iz_aes_wipe(&mac_ctx,sizeof(mac_ctx));
    diff=0;
    for(i=0;i<10;i++)diff|=(unsigned char)(tag[i]^actual[i]);
    iz_aes_wipe(tag,sizeof(tag));iz_aes_wipe(actual,sizeof(actual));
    if(diff) {
        undefer_input(__G);iz_aes_wipe(salt,sizeof(salt));
        Info(slide,0x401,((char *)slide,"AES authentication failed: %s\n", FnFilter1(G.filename)));
        return PK_ERR;
    }
    undefer_input(__G);
    /* seek_zipf takes the logical (unadjusted) position. */
    r=seek_zipf(__G__ encrypted_start-G.extra_bytes);
    if(r!=PK_OK){iz_aes_wipe(salt,sizeof(salt));return r;}
    G.csize=cipher_len;
    if(!iz_aes_init(&G.aes_ctx,pw,salt,G.pInfo->aes_strength,ver)) {
        iz_aes_wipe(salt,sizeof(salt));return PK_ERR;
    }
    iz_aes_wipe(salt,sizeof(salt));
    G.aes_active=1;
    /* seek_zipf preloads the first encrypted block.  The normal input
     * refill decrypts only newly read blocks, so decrypt that span now,
     * without touching any bytes following the compressed ciphertext. */
    defer_leftover_input(__G);
    if(G.incnt>0)
        iz_aes_decrypt(&G.aes_ctx,G.inptr,(size_t)G.incnt);
    undefer_input(__G);
    return PK_COOL;
}
#endif /* !NO_AES */

#ifdef USE_PPMD
#  include "ppmd8.c"
#  include "ppmd8dec.c"

typedef struct {
    IByteIn vt;
    zoff_t remaining;
    int input_error;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif
} uz_ppmd_in;

static void *uz_ppmd_alloc(ISzAllocPtr a, size_t size)
{
    (void)a;
    return malloc(size);
}

static void uz_ppmd_free(ISzAllocPtr a, void *address)
{
    (void)a;
    free(address);
}

static ISzAlloc uz_ppmd_allocator = { uz_ppmd_alloc, uz_ppmd_free };

static Byte uz_ppmd_read(IByteInPtr stream)
{
    uz_ppmd_in *s;
    int c;
#ifdef REENTRANT
    Uz_Globs *pG;
#endif

    s = (uz_ppmd_in *)stream;
#ifdef REENTRANT
    pG = s->pG;
#endif
    if (s->remaining <= 0) {
        s->input_error = 1;
        return 0;
    }
    c = NEXTBYTE;
    if (c == EOF) {
        s->input_error = 1;
        s->remaining = 0;
        return 0;
    }
    --s->remaining;
    return (Byte)c;
}

/* Decode ZIP method 98 (PPMd Variant I, revision 1).  The two-byte ZIP
 * properties word is part of the compressed data and is therefore read via
 * NEXTBYTE, which also preserves traditional ZipCrypto handling. */
static int uz_ppmd_decompress(__G)
    __GDEF
{
    CPpmd8 model;
    uz_ppmd_in input;
    zoff_t compressed;
    zusz_t total;
    ulg outcnt;
    unsigned props, order, mem_mb, restore;
    int sym, r;

    compressed = G.csize + (zoff_t)G.incnt;
    if (compressed < 2)
        return PK_ERR;

    input.vt.Read = uz_ppmd_read;
    input.remaining = compressed;
    input.input_error = 0;
#ifdef REENTRANT
    input.pG = pG;
#endif

    props = (unsigned)uz_ppmd_read(&input.vt);
    props |= (unsigned)uz_ppmd_read(&input.vt) << 8;
    if (input.input_error)
        return PK_ERR;

    order = (props & 0x0fU) + 1U;
    mem_mb = ((props >> 4) & 0xffU) + 1U;
    restore = props >> 12;
    if (order < PPMD8_MIN_ORDER || order > PPMD8_MAX_ORDER ||
        mem_mb < 1U || mem_mb > 256U ||
        restore > PPMD8_RESTORE_METHOD_FREEZE)
        return PK_ERR;

    Ppmd8_Construct(&model);
    /* ZIP method 98 specifies PPMd Variant I revision 1.  FREEZE streams
     * therefore need the original rev.1 bitstream behavior; restart and
     * cut-off use the corrected 26.03 model unchanged. */
    Ppmd8_SetLegacyFreeze(&model,
        restore == PPMD8_RESTORE_METHOD_FREEZE);
    if (!Ppmd8_Alloc(&model, (UInt32)mem_mb << 20, &uz_ppmd_allocator))
        return PK_MEM3;

    model.Stream.In = &input.vt;
    if (!Ppmd8_Init_RangeDec(&model)) {
        Ppmd8_Free(&model, &uz_ppmd_allocator);
        return PK_ERR;
    }
    Ppmd8_Init(&model, order, restore);

    total = 0;
    outcnt = 0;
    r = PK_COOL;
    while (total < G.lrec.ucsize) {
        sym = Ppmd8_DecodeSymbol(&model);
        if (sym < 0) {
            r = PK_ERR;
            break;
        }
        slide[outcnt++] = (uch)sym;
        ++total;
        if (outcnt == WSIZE) {
            r = flush(__G__ slide, outcnt, 0);
            outcnt = 0;
            if (r != PK_COOL)
                break;
        }
    }

    if (r == PK_COOL && outcnt != 0)
        r = flush(__G__ slide, outcnt, 0);
    if (r == PK_COOL) {
        sym = Ppmd8_DecodeSymbol(&model);
        if (sym != PPMD8_SYM_END || input.input_error ||
            !Ppmd8_RangeDec_IsFinishedOK(&model) ||
            input.remaining != 0 || G.csize + (zoff_t)G.incnt != 0)
            r = PK_ERR;
    }

    Ppmd8_Free(&model, &uz_ppmd_allocator);
    return r;
}
#endif /* USE_PPMD */

#ifdef USE_LZMA
/* Decode ZIP method 14.
 * The ZIP-specific properties header is part of the compressed/encrypted
 * byte stream, so all input is consumed through the normal UnZip input
 * buffer after defer_leftover_input() */
static int uz_lzma_decompress(__G)
    __GDEF
{
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_filter filters[2];
    lzma_options_lzma *options;
    uch *props;
    unsigned props_size;
    unsigned i;
    unsigned produced;
    unsigned outsize;
    zusz_t expected_size;
    int c;
    int r;
    int eos;
    lzma_ret lr;

    if (G.csize + (zoff_t)G.incnt < 4)
        return PK_ERR;

    /* SDK version bytes are informational */
    c = NEXTBYTE;
    if (c == EOF) return PK_ERR;
    c = NEXTBYTE;
    if (c == EOF) return PK_ERR;
    c = NEXTBYTE;
    if (c == EOF) return PK_ERR;
    props_size = (unsigned)c;
    c = NEXTBYTE;
    if (c == EOF) return PK_ERR;
    props_size |= (unsigned)c << 8;

    if ((zoff_t)props_size > G.csize + (zoff_t)G.incnt)
        return PK_ERR;
    props = (uch *)malloc(props_size == 0 ? 1U : (size_t)props_size);
    if (props == NULL)
        return PK_MEM3;
    for (i = 0; i < props_size; ++i) {
        c = NEXTBYTE;
        if (c == EOF) {
            free(props);
            return PK_ERR;
        }
        props[i] = (uch)c;
    }

    eos = (G.lrec.general_purpose_bit_flag & 2) != 0;
    filters[0].id = eos ? LZMA_FILTER_LZMA1 : LZMA_FILTER_LZMA1EXT;
    filters[0].options = NULL;
    filters[1].id = LZMA_VLI_UNKNOWN;
    filters[1].options = NULL;
    lr = lzma_properties_decode(&filters[0], NULL,
                                (const uint8_t *)props, (size_t)props_size);
    free(props);
    if (lr == LZMA_MEM_ERROR)
        return PK_MEM3;
    if (lr != LZMA_OK)
        return PK_ERR;

    options = (lzma_options_lzma *)filters[0].options;
    if (!eos) {
        options->ext_flags = 0;
        lzma_set_ext_size((*options), (uint64_t)G.lrec.ucsize);
    }

    lr = lzma_raw_decoder(&strm, filters);
    if (lr != LZMA_OK) {
        free(filters[0].options);
        return lr == LZMA_MEM_ERROR ? PK_MEM3 : PK_ERR;
    }

#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
    if (G.redirect_slide) {
        outsize = G.redirect_size;
        redirSlide = G.redirect_buffer;
    } else {
        outsize = WSIZE;
        redirSlide = slide;
    }
#else
    outsize = WSIZE;
#endif

    strm.next_in = NULL;
    strm.avail_in = 0;
    strm.next_out = (uint8_t *)redirSlide;
    strm.avail_out = (size_t)outsize;
    expected_size = G.lrec.ucsize;
    r = PK_COOL;

    for (;;) {
        if (strm.avail_in == 0) {
            if (G.incnt <= 0 && G.csize > 0 && fillinbuf(__G) == 0) {
                r = PK_ERR;
                break;
            }
            if (G.incnt > 0) {
                strm.next_in = (const uint8_t *)G.inptr;
                strm.avail_in = (size_t)G.incnt;
            }
        }

        {
            const uint8_t *before_in;
            size_t before_avail;
            before_in = strm.next_in;
            before_avail = strm.avail_in;
            lr = lzma_code(&strm, LZMA_RUN);
            if (before_avail != 0) {
                unsigned consumed;
                consumed = (unsigned)(strm.next_in - before_in);
                G.inptr += consumed;
                G.incnt -= (int)consumed;
            }
        }

        produced = outsize - (unsigned)strm.avail_out;
        if (produced != 0 && (strm.avail_out == 0 || lr == LZMA_STREAM_END)) {
            r = FLUSH(produced);
            if (r != PK_COOL)
                break;
            strm.next_out = (uint8_t *)redirSlide;
            strm.avail_out = (size_t)outsize;
        }

        if (lr == LZMA_STREAM_END)
            break;
        if (lr == LZMA_MEM_ERROR) {
            r = PK_MEM3;
            break;
        }
        if (lr != LZMA_OK) {
            r = PK_ERR;
            break;
        }
        if (strm.avail_in == 0 && G.incnt <= 0 && G.csize <= 0) {
            r = PK_ERR;
            break;
        }
    }

    /* payload must occupy the compressed-data segment and
     * produce exactly the size recorded in the ZIP header */
    if (r == PK_COOL &&
        ((zusz_t)strm.total_out != expected_size ||
         G.csize + (zoff_t)G.incnt != 0))
        r = PK_ERR;

    lzma_end(&strm);
    free(filters[0].options);
    return r;
}
#endif /* USE_LZMA */

#ifdef USE_XZ
/* Decode ZIP method 95.  Each ZIP member contains exactly one complete XZ
 * stream.  The XZ stream uses LZMA2 and carries its own stream/block framing.
 * Accept any single XZ stream and integrity-check type supported by liblzma
 * (None, CRC32, CRC64, SHA-256, etc.).  Do not enable LZMA_CONCATENATED:
 * the method-95 interoperability model is one ZIP member -> one XZ stream.
 * The final compressed-segment check below also rejects trailing/concatenated
 * streams.
 *
 * Writer-profile note: the available 7-Zip method-95 sample uses XZ CRC32.
 * Our Zip writer currently emits Check=None by explicit project policy pending
 * a genuine WinZip reference archive; revisit that creation choice when one is
 * available. */
static int uz_xz_decompress(__G)
    __GDEF
{
    lzma_stream strm = LZMA_STREAM_INIT;
    unsigned produced;
    unsigned outsize;
    zusz_t expected_size;
    int r;
    lzma_ret lr;

    lr = lzma_stream_decoder(&strm, UINT64_MAX, 0);
    if (lr != LZMA_OK)
        return lr == LZMA_MEM_ERROR ? PK_MEM3 : PK_ERR;

#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
    if (G.redirect_slide) {
        outsize = G.redirect_size;
        redirSlide = G.redirect_buffer;
    } else {
        outsize = WSIZE;
        redirSlide = slide;
    }
#else
    outsize = WSIZE;
#endif

    strm.next_in = NULL;
    strm.avail_in = 0;
    strm.next_out = (uint8_t *)redirSlide;
    strm.avail_out = (size_t)outsize;
    expected_size = G.lrec.ucsize;
    r = PK_COOL;

    for (;;) {
        if (strm.avail_in == 0) {
            if (G.incnt <= 0 && G.csize > 0 && fillinbuf(__G) == 0) {
                r = PK_ERR;
                break;
            }
            if (G.incnt > 0) {
                strm.next_in = (const uint8_t *)G.inptr;
                strm.avail_in = (size_t)G.incnt;
            }
        }

        {
            const uint8_t *before_in;
            size_t before_avail;
            before_in = strm.next_in;
            before_avail = strm.avail_in;
            lr = lzma_code(&strm, LZMA_RUN);
            if (before_avail != 0) {
                unsigned consumed;
                consumed = (unsigned)(strm.next_in - before_in);
                G.inptr += consumed;
                G.incnt -= (int)consumed;
            }
        }

        produced = outsize - (unsigned)strm.avail_out;
        if (produced != 0 && (strm.avail_out == 0 || lr == LZMA_STREAM_END)) {
            r = FLUSH(produced);
            if (r != PK_COOL)
                break;
            strm.next_out = (uint8_t *)redirSlide;
            strm.avail_out = (size_t)outsize;
        }

        if (lr == LZMA_STREAM_END)
            break;
        if (lr == LZMA_MEM_ERROR) {
            r = PK_MEM3;
            break;
        }
        if (lr != LZMA_OK) {
            r = PK_ERR;
            break;
        }
        if (strm.avail_in == 0 && G.incnt <= 0 && G.csize <= 0) {
            r = PK_ERR;
            break;
        }
    }

    if (r == PK_COOL &&
        ((zusz_t)strm.total_out != expected_size ||
         G.csize + (zoff_t)G.incnt != 0))
        r = PK_ERR;

    lzma_end(&strm);
    return r;
}
#endif /* USE_XZ */

#ifdef USE_ZSTD
/* Decode deprecated ZIP method 20 and current method 93.  The compressed
 * member is exactly one ordinary Zstandard frame.  Accept frames with or
 * without the optional Zstd content checksum, but reject skippable frames,
 * concatenated frames, and any trailing compressed bytes.  The first four
 * bytes are checked explicitly for the standard frame magic before feeding
 * them to libzstd so that skippable-frame magic cannot be accepted as a ZIP
 * member payload. */
static int uz_zstd_decompress(__G)
    __GDEF
{
    ZSTD_DCtx *dctx;
    ZSTD_inBuffer input;
    ZSTD_outBuffer output;
    uch prefix[4];
    unsigned prefix_pos;
    unsigned outsize;
    zusz_t expected_size;
    zusz_t total_out;
    int c;
    int i;
    int r;
    int using_prefix;
    size_t zr;

    if (G.csize + (zoff_t)G.incnt < 4)
        return PK_ERR;
    for (i = 0; i < 4; ++i) {
        c = NEXTBYTE;
        if (c == EOF)
            return PK_ERR;
        prefix[i] = (uch)c;
    }
    if (prefix[0] != 0x28 || prefix[1] != 0xb5 ||
        prefix[2] != 0x2f || prefix[3] != 0xfd)
        return PK_ERR;

    dctx = ZSTD_createDCtx();
    if (dctx == NULL)
        return PK_MEM3;

#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
    if (G.redirect_slide) {
        outsize = G.redirect_size;
        redirSlide = G.redirect_buffer;
    } else {
        outsize = WSIZE;
        redirSlide = slide;
    }
#else
    outsize = WSIZE;
#endif

    prefix_pos = 0;
    expected_size = G.lrec.ucsize;
    total_out = 0;
    r = PK_COOL;
    zr = 1;

    while (zr != 0) {
        using_prefix = prefix_pos < 4;
        if (using_prefix) {
            input.src = (const void *)prefix;
            input.size = 4;
            input.pos = prefix_pos;
        } else {
            if (G.incnt <= 0 && G.csize > 0 && fillinbuf(__G) == 0) {
                r = PK_ERR;
                break;
            }
            if (G.incnt <= 0) {
                r = PK_ERR;
                break;
            }
            input.src = (const void *)G.inptr;
            input.size = (size_t)G.incnt;
            input.pos = 0;
        }

        output.dst = (void *)redirSlide;
        output.size = (size_t)outsize;
        output.pos = 0;
        zr = ZSTD_decompressStream(dctx, &output, &input);
        if (ZSTD_isError(zr)) {
            r = PK_ERR;
            break;
        }

        if (using_prefix) {
            prefix_pos = (unsigned)input.pos;
        } else if (input.pos != 0) {
            G.inptr += (unsigned)input.pos;
            G.incnt -= (int)input.pos;
        }

        if (output.pos != 0) {
            total_out += (zusz_t)output.pos;
            r = FLUSH((unsigned)output.pos);
            if (r != PK_COOL)
                break;
        }
    }

    /* A valid ZIP Zstandard member is exactly one frame occupying the whole
     * compressed-data segment and producing exactly the advertised size. */
    if (r == PK_COOL &&
        (total_out != expected_size || G.csize + (zoff_t)G.incnt != 0))
        r = PK_ERR;

    ZSTD_freeDCtx(dctx);
    return r;
}
#endif /* USE_ZSTD */

#define GRRDUMP(buf,len) { \
    int i, j; \
 \
    for (j = 0;  j < (len)/16;  ++j) { \
        printf("        "); \
        for (i = 0;  i < 16;  ++i) \
            printf("%02x ", (uch)(buf)[i+(j<<4)]); \
        printf("\n        "); \
        for (i = 0;  i < 16;  ++i) { \
            char c = (char)(buf)[i+(j<<4)]; \
 \
            if (c == '\n') \
                printf("\\n "); \
            else if (c == '\r') \
                printf("\\r "); \
            else \
                printf(" %c ", c); \
        } \
        printf("\n"); \
    } \
    if ((len) % 16) { \
        printf("        "); \
        for (i = j<<4;  i < (len);  ++i) \
            printf("%02x ", (uch)(buf)[i]); \
        printf("\n        "); \
        for (i = j<<4;  i < (len);  ++i) { \
            char c = (char)(buf)[i]; \
 \
            if (c == '\n') \
                printf("\\n "); \
            else if (c == '\r') \
                printf("\\r "); \
            else \
                printf(" %c ", c); \
        } \
        printf("\n"); \
    } \
}

#ifdef PKAV_SUPPORT
#define PKAV_GENERATION_1  1
#define PKAV_GENERATION_2  2
#define PKAV1_GPBF         0x2000

static void pkav_reset(__G)
    __GDEF
{
    int show_avextra_on_fail = G.pkav.show_avextra_on_fail;

    if (G.pkav.payload != (uch *)NULL)
        free(G.pkav.payload);
    if (G.pkav.v1_payload != (uch *)NULL)
        free(G.pkav.v1_payload);
    memset((char *)&G.pkav, 0, sizeof(G.pkav));
    G.pkav.show_avextra_on_fail = show_avextra_on_fail;
}

static int pkav_note_cdir(__G)
    __GDEF
{
    uch *ef = G.extra_field;
    unsigned left = G.crec.extra_field_length;
    int v2_member = (G.crec.internal_file_attributes & 0x0006) != 0;
    /* PKAV 1 uses DOS GPBF bit 13 instead of the PKAV 2 attribute marker */
    int v1_member = (G.pInfo->hostnum == FS_FAT_ &&
                     (G.crec.general_purpose_bit_flag & PKAV1_GPBF) != 0);

    if (v2_member) {
        ++G.pkav.members;
        G.pkav.stored_accumulator += (z_uint4)G.crec.crc32;
        if (G.crec.internal_file_attributes & 0x0004)
            G.pkav.stored_accumulator +=
                (z_uint4)G.crec.external_file_attributes;
        else
            G.pkav.stored_accumulator +=
                (z_uint4)G.crec.last_mod_dos_datetime;
        G.pkav.generation = PKAV_GENERATION_2;
    }
    if (v1_member) {
        ++G.pkav.v1_members;
        if (!v2_member)
            ++G.pkav.v1_only_members;
        G.pkav.v1_stored_accumulator += (z_uint4)G.crec.crc32;
        G.pkav.v1_stored_accumulator +=
            (z_uint4)G.crec.last_mod_dos_datetime;
    }
    if (!G.pInfo->vollabel) {
        unsigned fnlen = (unsigned)strlen(G.filename);

        if (fnlen == 0 ||
            (G.filename[fnlen - 1] != '/' &&
             !(G.pInfo->hostnum == FS_FAT_ && G.filename[fnlen - 1] == '\\'))) {
            if (!v2_member)
                ++G.pkav.uncovered;
            if (!v1_member)
                ++G.pkav.v1_uncovered;
        }
    }
    if (G.crec.internal_file_attributes & 0x0004)
        G.pkav.marker_seen = TRUE;

    while (ef != (uch *)NULL && left >= EB_HEADSIZE) {
        ush id = makeword(ef + EB_ID);
        unsigned len = (unsigned)makeword(ef + EB_LEN);

        if (len > left - EB_HEADSIZE) {
            if (id == EF_AV) {
                ++G.pkav.av_count;
                G.pkav.malformed = TRUE;
                if (v1_member) {
                    ++G.pkav.v1_av_count;
                    G.pkav.v1_malformed = TRUE;
                }
            }
            break;
        }
        if (id == EF_AV) {
            ++G.pkav.av_count;
            if (G.pkav.av_count == 1) {
                G.pkav.payload_len = len;
                if (len == 0) {
                    G.pkav.malformed = TRUE;
                } else {
                    G.pkav.payload = (uch *)malloc(len);
                    if (G.pkav.payload == (uch *)NULL)
                        return PK_MEM;
                    memcpy(G.pkav.payload, ef + EB_HEADSIZE, len);
                }
            }
            if (v1_member) {
                ++G.pkav.v1_av_count;
                if (G.pkav.v1_av_count == 1) {
                    G.pkav.v1_payload_len = len;
                    if (len == 0) {
                        G.pkav.v1_malformed = TRUE;
                    } else {
                        G.pkav.v1_payload = (uch *)malloc(len);
                        if (G.pkav.v1_payload == (uch *)NULL)
                            return PK_MEM;
                        memcpy(G.pkav.v1_payload, ef + EB_HEADSIZE, len);
                    }
                }
            }
        }
        ef += EB_HEADSIZE + len;
        left -= EB_HEADSIZE + len;
    }
    if (G.pkav.generation == 0 && G.pkav.v1_av_count != 0 &&
        G.pkav.v1_members != 0)
        G.pkav.generation = PKAV_GENERATION_1;
    return PK_COOL;
}

static z_uint4 pkav_crc_byte(crc, c)
    z_uint4 crc;
    uch c;
{
    int i;

    crc ^= c;
    for (i = 0; i < 8; ++i)
        crc = (crc >> 1) ^ ((crc & 1) ? (z_uint4)0xedb88320UL : 0);
    return crc;
}

static z_uint4 pkav_rol32(v, n)
    z_uint4 v;
    unsigned n;
{
    n &= 31;
    return n ? (z_uint4)((v << n) | (v >> (32 - n))) : v;
}

static void pkav_key_update(k0, k1, k2, c)
    z_uint4 *k0;
    z_uint4 *k1;
    z_uint4 *k2;
    uch c;
{
    *k0 = pkav_crc_byte(*k0, c);
    *k1 = (z_uint4)((*k1 + (*k0 & 0xff)) * (z_uint4)0x08088405UL + 1);
    *k2 = pkav_crc_byte(*k2, (uch)(*k1 >> 24));
}

static void pkav_decrypt(buf, len, acc, generation)
    uch *buf;
    unsigned len;
    z_uint4 acc;
    int generation;
{
    z_uint4 k0 = (z_uint4)0x12345678UL;
    z_uint4 k1 = (z_uint4)0x23456789UL;
    z_uint4 k2 = (z_uint4)0x34567890UL;
    unsigned i;

    for (i = 0; i < 8; ++i) {
        uch c = (uch)(((acc >> (4 * i)) & 0x0f) +
                      (generation == PKAV_GENERATION_1 ? 0x12 : 0x13));
        pkav_key_update(&k0, &k1, &k2, c);
    }
    for (i = 0; i < len; ++i) {
        z_uint4 t;
        uch c;

        buf[i] ^= (uch)((len - i) & 0xff);
        t = (z_uint4)((k2 | 2) & 0xffff);
        c = (uch)(buf[i] ^ (uch)(((t * (t ^ 1)) >> 8) & 0xff));
        buf[i] = c;
        pkav_key_update(&k0, &k1, &k2, c);
    }
}

static int pkav_seed_valid(seed)
    z_uint4 seed;
{
    z_uint4 x;
    unsigned sum = 0;
    int i;

    if ((z_uint4)(seed - 26) % 157 != 0)
        return FALSE;
    x = seed;
    for (i = 0; i < 10; ++i) {
        sum += (unsigned)(x % 10);
        x /= 10;
    }
    return sum == 62;
}

static z_uint4 pkav_expected_h1(seed, company, len)
    z_uint4 seed;
    ZCONST uch *company;
    unsigned len;
{
    z_uint4 crc = seed;
    unsigned i;

    for (i = 0; i < len; ++i)
        crc = pkav_crc_byte(crc, company[i]);
    crc = (z_uint4)~crc;
    return pkav_rol32(crc, (unsigned)(seed & 31));
}

static void pkav_stamp(seed, stamp)
    z_uint4 seed;
    char stamp[7];
{
    z_uint4 r = pkav_rol32(seed, 7);
    unsigned letters = (unsigned)((r >> 18) & 0x3fff);
    unsigned digits = (unsigned)((r & 0x3ffff) / 0x107);

    stamp[0] = (char)('A' + letters / 676);
    stamp[1] = (char)('A' + (letters / 26) % 26);
    stamp[2] = (char)('A' + letters % 26);
    stamp[3] = (char)('0' + digits / 100);
    stamp[4] = (char)('0' + (digits / 10) % 10);
    stamp[5] = (char)('0' + digits % 10);
    stamp[6] = '\0';
}

static void pkav_begin_member(__G)
    __GDEF
{
    G.pkav.current_member = G.pInfo->pkav_member;
    G.pkav.current_v1_member = G.pInfo->pkav_v1_member;
    G.pkav.current_extcheck = G.pInfo->pkav_extcheck;
    G.pkav.current_sum = 0;
    G.pkav.current_xor = 0;
}

void pkav_update(__G__ buf, size)
    __GDEF
    ZCONST uch *buf;
    ulg size;
{
    ulg i;
    z_uint4 sum;
    uch x;

    if (!G.pkav.current_member || !G.pkav.current_extcheck || size == 0)
        return;
    sum = G.pkav.current_sum;
    x = G.pkav.current_xor;
    for (i = 0; i < size; ++i) {
        sum += buf[i];
        x ^= buf[i];
    }
    G.pkav.current_sum = (z_uint4)(sum & 0xffff);
    G.pkav.current_xor = x;
}

static void pkav_complete_member(__G)
    __GDEF
{
    z_uint4 aux;

    if (G.pkav.current_member) {
        G.pkav.accumulator += (z_uint4)G.crc32val;
        if (G.pkav.current_extcheck) {
            aux = ((z_uint4)G.pkav.current_xor << 24) |
                  ((z_uint4)(G.pkav.current_sum & 0xffff) << 8) |
                  (z_uint4)G.pInfo->pkav_dos_attr;
        } else {
            aux = (z_uint4)G.pInfo->pkav_dos_datetime;
        }
        G.pkav.accumulator += aux;
        ++G.pkav.processed;
        G.pkav.current_member = FALSE;
    }
    if (G.pkav.current_v1_member) {
        G.pkav.v1_accumulator += (z_uint4)G.crc32val;
        G.pkav.v1_accumulator += (z_uint4)G.pInfo->pkav_dos_datetime;
        ++G.pkav.v1_processed;
        G.pkav.current_v1_member = FALSE;
    }
}

static int pkav_active_member(__G)
    __GDEF
{
    if (G.pkav.members != 0 && G.pkav.v1_only_members != 0)
        return FALSE;
    if (G.pInfo->pkav_member)
        return TRUE;
    return G.pkav.generation == PKAV_GENERATION_1 &&
           G.pInfo->pkav_v1_member;
}

static int pkav_parse_plain(buf, len, p_company_len, p_avextra, p_avextra_len,
                            p_h1, p_seed)
    ZCONST uch *buf;
    unsigned len;
    unsigned *p_company_len;
    ZCONST uch **p_avextra;
    unsigned *p_avextra_len;
    z_uint4 *p_h1;
    z_uint4 *p_seed;
{
    unsigned i;

    if (len < 14)
        return FALSE;
    for (i = 12; i < len && buf[i] != 0; ++i)
        ;
    if (i == 12 || i == len)
        return FALSE;
    *p_company_len = i - 12;
    *p_avextra = buf + i + 1;
    *p_avextra_len = len - i - 1;
    *p_h1 = (z_uint4)makelong(buf + 4);
    *p_seed = (z_uint4)makelong(buf + 8);
    return TRUE;
}

static int pkav_emit_filtered(__G__ buf, len, flags, preserve_formatting)
    __GDEF
    ZCONST uch *buf;
    unsigned len;
    int flags;
    int preserve_formatting;
{
    uch *raw, *filtered;
    char *shown;
    extent filtered_size;
    unsigned start, pos, n, i, raw_len;

    if (len == 0)
        return PK_COOL;

    if ((extent)len > (((extent)-1) - 1) / 2)
        return PK_MEM;
    filtered_size = (extent)len * 2 + 1;

    raw = (uch *)malloc(filtered_size);
    filtered = (uch *)malloc(filtered_size);
    if (raw == (uch *)NULL || filtered == (uch *)NULL) {
        if (raw != (uch *)NULL)
            free(raw);
        if (filtered != (uch *)NULL)
            free(filtered);
        return PK_MEM;
    }

    pos = 0;
    while (pos < len) {
        start = pos;
        while (pos < len && buf[pos] != 0 &&
               !(preserve_formatting &&
                 (buf[pos] == '\t' || buf[pos] == '\r' ||
                  buf[pos] == '\n')))
            ++pos;

        n = pos - start;
        if (n != 0) {
            /*
             * NB: Make the input to fnfilter 'safe' before calling.
             * Some fnfilter multibyte paths can fallback to copying
             * input unchanged if internal allocations fail. Escape C0
             * controls and DEL here so that fallback is safe.
             */
            raw_len = 0;
            for (i = 0; i < n; ++i) {
                uch c = buf[start + i];

                if (c < 0x20 || c == 0x7f) {
                    raw[raw_len++] = '^';
                    raw[raw_len++] =
                        (uch)(c == 0x7f ? '?' : (unsigned)c + '@');
                } else {
                    raw[raw_len++] = c;
                }
            }
            raw[raw_len] = 0;
            shown = fnfilter((ZCONST char *)raw, filtered, filtered_size);
            (*G.message)((zvoid *)&G, (uch *)shown, (ulg)strlen(shown), flags);
        }

        if (pos < len) {
            if (buf[pos] == 0) {
                (*G.message)((zvoid *)&G, (uch *)"^@", 2, flags);
                ++pos;
            } else if (buf[pos] == '\r') {
                /* Preserve line formatting without emitting a raw CR. */
                (*G.message)((zvoid *)&G, (uch *)"\n", 1, flags);
                ++pos;
                if (pos < len && buf[pos] == '\n')
                    ++pos;
            } else {
                /* TAB and LF are the only formatting controls emitted raw. */
                (*G.message)((zvoid *)&G, (uch *)(buf + pos), 1, flags);
                ++pos;
            }
        }
    }

    free(filtered);
    free(raw);
    return PK_COOL;
}

static int pkav_finish_archive(__G)
    __GDEF
{
    uch *plain, *diag;
    ZCONST uch *avextra, *diag_avextra;
    unsigned company_len, avextra_len, diag_company_len, diag_avextra_len;
    z_uint4 h1, seed, expected, diag_h1, diag_seed, diag_expected;
    int framed, diag_framed, emit_error;
    int generation, valid, diag_valid;
    z_uint4 accumulator, stored_accumulator;
    ulg members, uncovered, processed;
    uch *payload;
    unsigned payload_len, av_count;
    int malformed;
    char stamp[7];

    if (G.pkav.members != 0 && G.pkav.v1_only_members != 0) {
        Info(slide, 0x401, ((char *)slide,
          "warning: mixed PKAV 1/2 Authenticity Verification; "
          "authenticity NOT verified\n"));
        return PK_WARN;
    }

    if (G.pkav.av_count == 0 && !G.pkav.marker_seen)
        return PK_COOL;

    if (G.pkav.members != 0)
        generation = PKAV_GENERATION_2;
    else if (G.pkav.v1_members != 0 && G.pkav.v1_av_count != 0)
        generation = PKAV_GENERATION_1;
    else
        generation = 0;

    if (generation == PKAV_GENERATION_1) {
        accumulator = G.pkav.v1_accumulator;
        stored_accumulator = G.pkav.v1_stored_accumulator;
        members = G.pkav.v1_members;
        uncovered = G.pkav.v1_uncovered;
        processed = G.pkav.v1_processed;
        payload = G.pkav.v1_payload;
        payload_len = G.pkav.v1_payload_len;
        av_count = G.pkav.v1_av_count;
        malformed = G.pkav.v1_malformed;
    } else {
        accumulator = G.pkav.accumulator;
        stored_accumulator = G.pkav.stored_accumulator;
        members = G.pkav.members;
        uncovered = G.pkav.uncovered;
        processed = G.pkav.processed;
        payload = G.pkav.payload;
        payload_len = G.pkav.payload_len;
        av_count = G.pkav.av_count;
        malformed = G.pkav.malformed;
    }

    if (malformed || av_count != 1 ||
        payload == (uch *)NULL || payload_len < 14 ||
        members == 0) {
        Info(slide, 0x401, ((char *)slide,
          "warning: malformed PKAV Authenticity Verification information\n"));
        return PK_WARN;
    }

    if (processed != members) {
        Info(slide, 0x401, ((char *)slide,
          "warning: PKAV information present; authenticity was not fully verified\n"));
        return PK_WARN;
    }

    plain = (uch *)malloc(payload_len);
    if (plain == (uch *)NULL)
        return PK_MEM;
    memcpy(plain, payload, payload_len);
    pkav_decrypt(plain, payload_len, accumulator, generation);

    framed = pkav_parse_plain(plain, payload_len, &company_len,
                              &avextra, &avextra_len, &h1, &seed);
    if (framed) {
        if (generation == PKAV_GENERATION_1 && avextra_len != 0 &&
            avextra[avextra_len - 1] == 0x1a)
            --avextra_len;
        valid = pkav_seed_valid(seed);
        if (generation == PKAV_GENERATION_2) {
            expected = pkav_expected_h1(seed, plain + 12, company_len);
            valid = valid && h1 == expected;
        }
        if (valid) {
            pkav_stamp(seed, stamp);
            if (uO.qflag < 2 && !uO.cflag) {
                Info(slide, 0, ((char *)slide,
                  "Authentic files Verified!   # %s\n", stamp));
                if (uncovered != 0)
                    Info(slide, 0, ((char *)slide,
                      "warning: PKAV verified %lu authenticated entr%s; "
                      "%lu archive entr%s %s not covered by PKAV.\n",
                      members,
                      (members == 1L)? "y" : "ies",
                      uncovered,
                      (uncovered == 1L)? "y" : "ies",
                      (uncovered == 1L)? "is" : "are"));
                emit_error = pkav_emit_filtered(__G__ plain + 12,
                                                company_len, 0, FALSE);
                if (emit_error == PK_COOL)
                    (*G.message)((zvoid *)&G, (uch *)"\n", 1, 0);
                if (emit_error == PK_COOL)
                    emit_error = pkav_emit_filtered(__G__ avextra,
                                                    avextra_len, 0, TRUE);
                if (emit_error != PK_COOL) {
                    free(plain);
                    return emit_error;
                }
            }
            free(plain);
            return PK_COOL;
        }
    }

    Info(slide, 0x401, ((char *)slide,
      "warning: PKAV Authenticity Verification failed\n"));

    diag = (uch *)malloc(payload_len);
    if (diag == (uch *)NULL) {
        free(plain);
        return PK_MEM;
    }
    memcpy(diag, payload, payload_len);
    pkav_decrypt(diag, payload_len, stored_accumulator, generation);
    diag_framed = pkav_parse_plain(diag, payload_len,
                                   &diag_company_len, &diag_avextra,
                                   &diag_avextra_len, &diag_h1, &diag_seed);
    if (diag_framed && generation == PKAV_GENERATION_1 &&
        diag_avextra_len != 0 && diag_avextra[diag_avextra_len - 1] == 0x1a)
        --diag_avextra_len;
    if (diag_framed && diag_avextra_len != 0 && pkav_seed_valid(diag_seed)) {
        diag_valid = TRUE;
        if (generation == PKAV_GENERATION_2) {
            diag_expected = pkav_expected_h1(diag_seed, diag + 12,
                                             diag_company_len);
            diag_valid = diag_h1 == diag_expected;
        }
        if (diag_valid) {
            if (G.pkav.show_avextra_on_fail) {
                Info(slide, 0x401, ((char *)slide,
                  "warning: displaying unverified PKAV AVEXTRA data:\n"));
                emit_error = pkav_emit_filtered(__G__ diag_avextra,
                                                 diag_avextra_len, 0x401, TRUE);
                if (emit_error != PK_COOL) {
                    free(diag);
                    free(plain);
                    return emit_error;
                }
            } else {
                Info(slide, 0x401, ((char *)slide,
                  "warning: unverified PKAV AVEXTRA data is present; "
                  "use --show-avextra-on-fail to display it\n"));
            }
        }
    }

    free(diag);
    free(plain);
    return PK_WARN;
}
#endif /* PKAV_SUPPORT */

static int store_info OF((__GPRO));
#ifdef SET_DIR_ATTRIB
static int extract_or_test_entrylist OF((__GPRO__ unsigned numchunk,
                ulg *pfilnum, ulg *pnum_bad_pwd, zoff_t *pold_extra_bytes,
                unsigned *pnum_dirs, direntry **pdirlist,
                int error_in_archive));
#else
static int extract_or_test_entrylist OF((__GPRO__ unsigned numchunk,
                ulg *pfilnum, ulg *pnum_bad_pwd, zoff_t *pold_extra_bytes,
                int error_in_archive));
#endif
static int extract_or_test_member OF((__GPRO));
#ifndef SFX
   static int TestExtraField OF((__GPRO__ uch *ef, unsigned ef_len));
   static int test_compr_eb OF((__GPRO__ uch *eb, unsigned eb_size,
        unsigned compr_offset,
        int (*test_uc_ebdata)(__GPRO__ uch *eb, unsigned eb_size,
                              uch *eb_ucptr, ulg eb_ucsize)));
#endif
#if (defined(VMS) || defined(VMS_TEXT_CONV))
   static void decompress_bits OF((uch *outptr, unsigned needlen,
                                   ZCONST uch *bitptr));
#endif
#ifdef SYMLINKS
   static void set_deferred_symlink OF((__GPRO__ slinkentry *slnk_entry));
#endif
#ifdef SET_DIR_ATTRIB
   static int Cdecl dircomp OF((ZCONST zvoid *a, ZCONST zvoid *b));
#endif

static int fwkcs_note_cdir(__G)
    __GDEF
{
    uch *ef = G.extra_field;
    unsigned left = G.crec.extra_field_length;
    unsigned idx = (unsigned)(G.pInfo - G.info);
    int count = 0, valid = FALSE, bad = FALSE;

    G.pInfo->fwkcs_md5 = FALSE;
    G.pInfo->fwkcs_bad = FALSE;

    while (ef != (uch *)NULL && left >= EB_HEADSIZE) {
        ush id = makeword(ef + EB_ID);
        unsigned len = (unsigned)makeword(ef + EB_LEN);

        if (len > left - EB_HEADSIZE) {
            if (id == EF_MD5) {
                ++count;
                bad = TRUE;
            }
            break;
        }
        if (id == EF_MD5) {
            ++count;
            if (len == 19 && ef[EB_HEADSIZE] == 'M' &&
                ef[EB_HEADSIZE+1] == 'D' && ef[EB_HEADSIZE+2] == '5') {
                if (G.fwkcs_expected == (uch *)NULL) {
                    G.fwkcs_expected = (uch *)malloc(DIR_BLKSIZ * 16U);
                    if (G.fwkcs_expected == (uch *)NULL)
                        return PK_MEM;
                }
                memcpy(G.fwkcs_expected + idx * 16U,
                       ef + EB_HEADSIZE + 3, 16);
                valid = TRUE;
            } else {
                bad = TRUE;
            }
        }
        ef += EB_HEADSIZE + len;
        left -= EB_HEADSIZE + len;
    }
    if (count > 1)
        bad = TRUE;
    if (bad) {
        G.pInfo->fwkcs_bad = TRUE;
    } else if (count == 1 && valid) {
        G.pInfo->fwkcs_md5 = TRUE;
    }
    return PK_COOL;
}



/*******************************/
/*  Strings used in extract.c  */
/*******************************/

static ZCONST char Far VersionMsg[] =
  "   skipping: %-22s  need %s compat. v%u.%u (can do v%u.%u)\n";
static ZCONST char Far ComprMsgNum[] =
  "   skipping: %-22s  unsupported compression method %u\n";
#ifndef SFX
   static ZCONST char Far ComprMsgName[] =
     "   skipping: %-22s  `%s' method not supported\n";
   static ZCONST char Far CmprNone[]       = "store";
   static ZCONST char Far CmprShrink[]     = "shrink";
   static ZCONST char Far CmprReduce[]     = "reduce";
   static ZCONST char Far CmprImplode[]    = "implode";
   static ZCONST char Far CmprTokenize[]   = "tokenize";
   static ZCONST char Far CmprDeflate[]    = "deflate";
   static ZCONST char Far CmprDeflat64[]   = "deflate64";
   static ZCONST char Far CmprDCLImplode[] = "DCL implode";
   static ZCONST char Far CmprBzip[]       = "bzip2";
   static ZCONST char Far CmprLZMA[]       = "LZMA";
   static ZCONST char Far CmprZstd[]       = "Zstd";
   static ZCONST char Far CmprXZ[]         = "XZ";
   static ZCONST char Far CmprIBMTerse[]   = "IBM/Terse";
   static ZCONST char Far CmprIBMLZ77[]    = "IBM LZ77";
   static ZCONST char Far CmprWavPack[]    = "WavPack";
   static ZCONST char Far CmprPPMd[]       = "PPMd";
   static ZCONST char Far *ComprNames[NUM_METHODS] = {
     CmprNone, CmprShrink, CmprReduce, CmprReduce, CmprReduce, CmprReduce,
     CmprImplode, CmprTokenize, CmprDeflate, CmprDeflat64, CmprDCLImplode,
     CmprBzip, CmprLZMA, CmprIBMTerse, CmprIBMLZ77, CmprZstd, CmprZstd,
     CmprXZ, CmprWavPack, CmprPPMd
   };
   static ZCONST unsigned ComprIDs[NUM_METHODS] = {
     STORED, SHRUNK, REDUCED1, REDUCED2, REDUCED3, REDUCED4,
     IMPLODED, TOKENIZED, DEFLATED, ENHDEFLATED, DCLIMPLODED,
     BZIPPED, LZMAED, IBMTERSED, IBMLZ77ED, ZSTD_OLD, ZSTDED,
     XZED, WAVPACKED, PPMDED
   };
#endif /* !SFX */
static ZCONST char Far FilNamMsg[] =
  "%s:  bad filename length (%s)\n";
static ZCONST char Far EmptyFilNamMsg[] =
  "error:  empty filename in central directory\n";
#ifndef SFX
   static ZCONST char Far WarnNoMemCFName[] =
     "%s:  warning, no memory for comparison with local header\n";
   static ZCONST char Far LvsCFNamMsg[] =
     "%s:  mismatching \"local\" filename (%s),\n\
         continuing with \"central\" filename version\n";
#endif /* !SFX */
#if (!defined(SFX) && defined(UNICODE_SUPPORT))
   static ZCONST char Far GP11FlagsDiffer[] =
     "file #%lu (%s):\n\
         mismatch between local and central GPF bit 11 (\"UTF-8\"),\n\
         continuing with central flag (IsUTF8 = %d)\n";
#endif /* !SFX && UNICODE_SUPPORT */
static ZCONST char Far WrnStorUCSizCSizDiff[] =
  "%s:  ucsize %s <> csize %s for STORED entry\n\
         continuing with \"compressed\" size value\n";
static ZCONST char Far LvsCMethodMsg[] =
  "%s:  local compression method %u does not match central method %u\n";
static ZCONST char Far LvsCDataMsg[] =
  "%s:  local CRC or size fields do not match central directory\n";
static ZCONST char Far ExtFieldMsg[] =
  "%s:  bad extra field length (%s)\n";
static ZCONST char Far OffsetMsg[] =
  "file #%lu:  bad zipfile offset (%s):  %ld\n";
static ZCONST char Far ExtractMsg[] =
  "%8sing: %-22s  %s%s%s%s";
#ifndef SFX
   static ZCONST char Far LengthMsg[] =
     "%s  %s:  %s bytes required to uncompress to %s bytes;\n    %s\
      supposed to require %s bytes%s%s%s\n";
#endif

static ZCONST char Far BadFileCommLength[] = "%s:  bad file comment length\n";
static ZCONST char Far LocalHdrSig[] = "local header sig";
static ZCONST char Far BadLocalHdr[] = "file #%lu:  bad local header\n";
static ZCONST char Far AttemptRecompensate[] =
  "  (attempting to re-compensate)\n";
#ifndef SFX
   static ZCONST char Far BackslashPathSep[] =
     "warning:  %s appears to use backslashes as path separators\n";
#endif
static ZCONST char Far AbsolutePathWarning[] =
  "warning:  stripped absolute path spec from %s\n";
static ZCONST char Far SkipVolumeLabel[] =
  "   skipping: %-22s  %svolume label\n";

#ifdef SET_DIR_ATTRIB   /* messages of code for setting directory attributes */
   static ZCONST char Far DirlistEntryNoMem[] =
     "warning:  cannot alloc memory for dir times/permissions/UID/GID\n";
   static ZCONST char Far DirlistSortNoMem[] =
     "warning:  cannot alloc memory to sort dir times/perms/etc.\n";
   static ZCONST char Far DirlistSetAttrFailed[] =
     "warning:  set times/attribs failed for %s\n";
   static ZCONST char Far DirlistFailAttrSum[] =
     "     failed setting times/attribs for %lu dir entries";
#endif

#ifdef SYMLINKS         /* messages of the deferred symlinks handler */
   static ZCONST char Far SymLnkWarnNoMem[] =
     "warning:  deferred symlink (%s) failed:\n\
          out of memory\n";
   static ZCONST char Far SymLnkWarnInvalid[] =
     "warning:  deferred symlink (%s) failed:\n\
          invalid placeholder file\n";
   static ZCONST char Far SymLnkDeferred[] =
     "finishing deferred symbolic links:\n";
   static ZCONST char Far SymLnkFinish[] =
     "  %-22s -> %s\n";
#endif

#ifndef WINDLL
   static ZCONST char Far ReplaceQuery[] =
# ifdef VMS
     "new version of %s? [y]es, [n]o, [A]ll, [N]one, [r]ename: ";
# else
     "replace %s? [y]es, [n]o, [A]ll, [N]one, [r]ename: ";
# endif
   static ZCONST char Far AssumeNone[] =
     " NULL\n(EOF or read error, treating as \"[N]one\" ...)\n";
   static ZCONST char Far NewNameQuery[] = "new name: ";
   static ZCONST char Far InvalidResponse[] =
     "error:  invalid response [%s]\n";
#endif /* !WINDLL */

static ZCONST char Far ErrorInArchive[] =
  "At least one %serror was detected in %s.\n";
static ZCONST char Far ZeroFilesTested[] =
  "Caution:  zero files tested in %s.\n";

#ifndef VMS
   static ZCONST char Far VMSFormatQuery[] =
     "\n%s:  stored in VMS format.  Extract anyway? (y/n) ";
#endif

#if CRYPT || !defined(NO_AES)
   static ZCONST char Far SkipCannotGetPasswd[] =
     "   skipping: %-22s  unable to get password\n";
   static ZCONST char Far SkipIncorrectPasswd[] =
     "   skipping: %-22s  incorrect password\n";
   static ZCONST char Far FilesSkipBadPasswd[] =
     "%lu file%s skipped because of incorrect password.\n";
   static ZCONST char Far MaybeBadPasswd[] =
     "    (may instead be incorrect password)\n";
#endif
#if !CRYPT
   static ZCONST char Far SkipEncrypted[] =
     "   skipping: %-22s  encrypted (not supported)\n";
#endif

static ZCONST char Far NoErrInCompData[] =
  "No errors detected in compressed data of %s.\n";
static ZCONST char Far NoErrInTestedFiles[] =
  "No errors detected in %s for the %lu file%s tested.\n";
static ZCONST char Far FilesSkipped[] =
  "%lu file%s skipped because of unsupported compression or encoding.\n";

static ZCONST char Far ErrUnzipFile[] = "  error:  %s%s %s\n";
static ZCONST char Far ErrUnzipNoFile[] = "\n  error:  %s%s\n";
static ZCONST char Far NotEnoughMem[] = "not enough memory to ";
static ZCONST char Far InvalidComprData[] = "invalid compressed data to ";
static ZCONST char Far Inflate[] = "inflate";
#ifdef USE_BZIP2
  static ZCONST char Far BUnzip[] = "bunzip";
#endif

#ifndef SFX
   static ZCONST char Far Explode[] = "explode";
# ifdef USE_OLDUNZIP
   static ZCONST char Far Unshrink[] = "unshrink";
   static ZCONST char Far Unreduce[] = "unreduce";
# endif
#endif

#if (!defined(DELETE_IF_FULL) || !defined(HAVE_UNLINK))
   static ZCONST char Far FileTruncated[] =
     "warning:  %s is probably truncated\n";
#endif

static ZCONST char Far FileUnknownCompMethod[] =
  "%s:  unknown compression method\n";
static ZCONST char Far BadCRC[] = " bad CRC %08lx  (should be %08lx)%s\n";

      /* TruncEAs[] also used in OS/2 mapname(), close_outfile() */
char ZCONST Far TruncEAs[] = " compressed EA data missing (%d bytes)%s";
char ZCONST Far TruncNTSD[] =
  " compressed WinNT security data missing (%d bytes)%s";

#ifndef SFX
   static ZCONST char Far InconsistEFlength[] = "bad extra-field entry:\n \
     EF block length (%u bytes) exceeds remaining EF data (%u bytes)\n";
   static ZCONST char Far TooSmallEBlength[] = "bad extra-field entry:\n \
     EF block length (%u bytes) invalid (< %d)\n";
   static ZCONST char Far InvalidComprDataEAs[] =
     " invalid compressed data for EAs\n";
#  if (defined(WIN32) && defined(NTSD_EAS))
     static ZCONST char Far InvalidSecurityEAs[] =
       " EAs fail security check\n";
#  endif
   static ZCONST char Far UnsuppNTSDVersEAs[] =
     " unsupported NTSD EAs version %d\n";
   static ZCONST char Far BadCRC_EAs[] = " bad CRC for extended attributes\n";
   static ZCONST char Far UnknComprMethodEAs[] =
     " unknown compression method for EAs (%u)\n";
   static ZCONST char Far NotEnoughMemEAs[] =
     " out of memory while inflating EAs\n";
   static ZCONST char Far UnknErrorEAs[] =
     " unknown error on extended attributes\n";
#endif /* !SFX */

static ZCONST char Far UnsupportedExtraField[] =
  "\nerror:  unsupported extra-field compression type (%u)--skipping\n";
static ZCONST char Far BadExtraFieldCRC[] =
  "error [%s]:  bad extra-field CRC %08lx (should be %08lx)\n";
static ZCONST char Far NotEnoughMemCover[] =
  "error: not enough memory for bomb detection\n";
static ZCONST char Far OverlappedComponents[] =
  "error: invalid zip file with overlapped components (possible zip bomb)\n \
To unzip the file anyway, rerun the command with UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE environmnent variable\n";





/* A growable list of spans. */
typedef zoff_t bound_t;
typedef struct {
    bound_t beg;        /* start of the span */
    bound_t end;        /* one past the end of the span */
} span_t;
typedef struct {
    span_t *span;       /* allocated, distinct, and sorted list of spans */
    size_t num;         /* number of spans in the list */
    size_t max;         /* allocated number of spans (num <= max) */
} cover_t;

/*
 * Return the index of the first span in cover whose beg is greater than val.
 * If there is no such span, then cover->num is returned.
 */
static size_t cover_find(cover, val)
    cover_t *cover;
    bound_t val;
{
    size_t lo = 0, hi = cover->num;
    while (lo < hi) {
        size_t mid = (lo + hi) >> 1;
        if (val < cover->span[mid].beg)
            hi = mid;
        else
            lo = mid + 1;
    }
    return hi;
}

/* Return true if val lies within any one of the spans in cover. */
static int cover_within(cover, val)
    cover_t *cover;
    bound_t val;
{
    size_t pos = cover_find(cover, val);
    return pos > 0 && val < cover->span[pos - 1].end;
}

/*
 * Add a new span to the list, but only if the new span does not overlap any
 * spans already in the list. The new span covers the values beg..end-1. beg
 * must be less than end.
 *
 * Keep the list sorted and merge adjacent spans. Grow the allocated space for
 * the list as needed. On success, 0 is returned. If the new span overlaps any
 * existing spans, then 1 is returned and the new span is not added to the
 * list. If the new span is invalid because beg is greater than or equal to
 * end, then -1 is returned. If the list needs to be grown but the memory
 * allocation fails, then -2 is returned.
 */
static int cover_add(cover, beg, end)
    cover_t *cover;
    bound_t beg;
    bound_t end;
{
    size_t pos;
    int prec, foll;

    if (beg >= end)
    /* The new span is invalid. */
        return -1;

    /* Find where the new span should go, and make sure that it does not
       overlap with any existing spans. */
    pos = cover_find(cover, beg);
    if ((pos > 0 && beg < cover->span[pos - 1].end) ||
        (pos < cover->num && end > cover->span[pos].beg))
        return 1;

    /* Check for adjacencies. */
    prec = pos > 0 && beg == cover->span[pos - 1].end;
    foll = pos < cover->num && end == cover->span[pos].beg;
    if (prec && foll) {
        /* The new span connects the preceding and following spans. Merge the
           following span into the preceding span, and delete the following
           span. */
        cover->span[pos - 1].end = cover->span[pos].end;
        cover->num--;
        memmove(cover->span + pos, cover->span + pos + 1,
                (cover->num - pos) * sizeof(span_t));
    }
    else if (prec)
        /* The new span is adjacent only to the preceding span. Extend the end
           of the preceding span. */
        cover->span[pos - 1].end = end;
    else if (foll)
        /* The new span is adjacent only to the following span. Extend the
           beginning of the following span. */
        cover->span[pos].beg = beg;
    else {
        /* The new span has gaps between both the preceding and the following
           spans. Assure that there is room and insert the span.  */
        if (cover->num == cover->max) {
            size_t max = cover->max == 0 ? 16 : cover->max << 1;
            span_t *span = realloc(cover->span, max * sizeof(span_t));
            if (span == NULL)
                return -2;
            cover->span = span;
            cover->max = max;
        }
        memmove(cover->span + pos + 1, cover->span + pos,
                (cover->num - pos) * sizeof(span_t));
        cover->num++;
        cover->span[pos].beg = beg;
        cover->span[pos].end = end;
    }
    return 0;
}





/**************************************/
/*  Function extract_or_test_files()  */
/**************************************/

int extract_or_test_files(__G)    /* return PK-type error code */
     __GDEF
{
    unsigned i, j;
    zoff_t cd_bufstart;
    uch *cd_inptr;
    int cd_incnt;
    ulg filnum=0L, blknum=0L;
    int reached_end;
#ifndef SFX
    int no_endsig_found;
#endif
    int error, error_in_archive=PK_COOL;
    int *fn_matched=NULL, *xn_matched=NULL;
    zucn_t members_processed;
    ulg num_skipped=0L, num_bad_pwd=0L;
    zoff_t old_extra_bytes = 0L;
#ifdef SET_DIR_ATTRIB
    unsigned num_dirs=0;
    direntry *dirlist=(direntry *)NULL, **sorted_dirlist=(direntry **)NULL;
#endif

    /*
     * First, two general initializations are applied. These have been moved
     * here from process_zipfiles() because they are only needed for accessing
     * and/or extracting the data content of the zip archive.
     */

    /* a) initialize the CRC table pointer (once) */
    if (CRC_32_TAB == NULL) {
        if ((CRC_32_TAB = get_crc_table()) == NULL) {
            return PK_MEM;
        }
    }

#if (!defined(SFX) || defined(SFX_EXDIR))
    /* b) check out if specified extraction root directory exists */
    if (uO.exdir != (char *)NULL && G.extract_flag) {
        G.create_dirs = !uO.fflag;
        if ((error = checkdir(__G__ uO.exdir, ROOT)) > MPN_INF_SKIP) {
            /* out of memory, or file in way */
            return (error == MPN_NOMEM ? PK_MEM : PK_ERR);
        }
    }
#endif /* !SFX || SFX_EXDIR */

    /* One more: initialize cover structure for bomb detection. Start with
       spans that cover any extra bytes at the start, the central directory,
       the end of central directory record (including the Zip64 end of central
       directory locator, if present), and the Zip64 end of central directory
       record, if present. */
    if (uO.zipbomb == TRUE) {
      if (G.cover == NULL) {
        G.cover = malloc(sizeof(cover_t));
        if (G.cover == NULL) {
            Info(slide, 0x401, ((char *)slide,
              LoadFarString(NotEnoughMemCover)));
            return PK_MEM;
        }
        ((cover_t *)G.cover)->span = NULL;
        ((cover_t *)G.cover)->max = 0;
    }
    ((cover_t *)G.cover)->num = 0;
    if (cover_add((cover_t *)G.cover,
                  G.extra_bytes + G.ecrec.offset_start_central_directory,
                  G.extra_bytes + G.ecrec.offset_start_central_directory +
                  G.ecrec.size_central_directory) != 0) {
        Info(slide, 0x401, ((char *)slide,
          LoadFarString(NotEnoughMemCover)));
        return PK_MEM;
    }
    if ((G.extra_bytes != 0 &&
         cover_add((cover_t *)G.cover, 0, G.extra_bytes) != 0) ||
        (G.ecrec.have_ecr64 &&
         cover_add((cover_t *)G.cover, G.ecrec.ec64_start,
                   G.ecrec.ec64_end) != 0) ||
        cover_add((cover_t *)G.cover, G.ecrec.ec_start,
                  G.ecrec.ec_end) != 0) {
        Info(slide, 0x401, ((char *)slide,
          LoadFarString(OverlappedComponents)));
        return PK_BOMB;
      }
    }

/*---------------------------------------------------------------------------
    The basic idea of this function is as follows.  Since the central di-
    rectory lies at the end of the zipfile and the member files lie at the
    beginning or middle or wherever, it is not very desirable to simply
    read a central directory entry, jump to the member and extract it, and
    then jump back to the central directory.  In the case of a large zipfile
    this would lead to a whole lot of disk-grinding, especially if each mem-
    ber file is small.  Instead, we read from the central directory the per-
    tinent information for a block of files, then go extract/test the whole
    block.  Thus this routine contains two small(er) loops within a very
    large outer loop:  the first of the small ones reads a block of files
    from the central directory; the second extracts or tests each file; and
    the outer one loops over blocks.  There's some file-pointer positioning
    stuff in between, but that's about it.  Btw, it's because of this jump-
    ing around that we can afford to be lenient if an error occurs in one of
    the member files:  we should still be able to go find the other members,
    since we know the offset of each from the beginning of the zipfile.
  ---------------------------------------------------------------------------*/

#ifdef PKAV_SUPPORT
    pkav_reset(__G);
#endif
    G.pInfo = G.info;

#if CRYPT
    G.newzip = TRUE;
#endif
#ifndef SFX
    G.reported_backslash = FALSE;
#endif

    /* malloc space for check on unmatched filespecs (OK if one or both NULL) */
    if (G.filespecs > 0  &&
        (fn_matched=(int *)malloc(G.filespecs*sizeof(int))) != (int *)NULL)
        for (i = 0;  i < G.filespecs;  ++i)
            fn_matched[i] = FALSE;
    if (G.xfilespecs > 0  &&
        (xn_matched=(int *)malloc(G.xfilespecs*sizeof(int))) != (int *)NULL)
        for (i = 0;  i < G.xfilespecs;  ++i)
            xn_matched[i] = FALSE;

/*---------------------------------------------------------------------------
    Begin main loop over blocks of member files.  We know the entire central
    directory is on this disk:  we would not have any of this information un-
    less the end-of-central-directory record was on this disk, and we would
    not have gotten to this routine unless this is also the disk on which
    the central directory starts.  In practice, this had better be the ONLY
    disk in the archive, but we'll add multi-disk support soon.
  ---------------------------------------------------------------------------*/

    members_processed = 0;
#ifndef SFX
    no_endsig_found = FALSE;
#endif
    reached_end = FALSE;
    G.fwkcs_expected = (uch *)NULL;
    G.fwkcs_verified = 0;
    while (!reached_end) {
        j = 0;
#ifdef AMIGA
        memzero(G.filenotes, DIR_BLKSIZ * sizeof(char *));
#endif

        /*
         * Loop through files in central directory, storing offsets, file
         * attributes, case-conversion and text-conversion flags until block
         * size is reached.
         */

        while ((j < DIR_BLKSIZ)) {
            G.pInfo = &G.info[j];

            if (readbuf(__G__ G.sig, 4) == 0) {
                error_in_archive = PK_EOF;
                reached_end = TRUE;     /* ...so no more left to do */
                break;
            }
            if (memcmp(G.sig, central_hdr_sig, 4)) {  /* is it a new entry? */
                /* no new central directory entry
                 * -> is the number of processed entries compatible with the
                 *    number of entries as stored in the end_central record?
                 */
                if ((members_processed
                     & (G.ecrec.have_ecr64 ? MASK_ZUCN64 : MASK_ZUCN16))
                    == G.ecrec.total_entries_central_dir) {
#ifndef SFX
                    /* yes, so look if we ARE back at the end_central record
                     */
                    no_endsig_found =
                      ( (memcmp(G.sig,
                                (G.ecrec.have_ecr64 ?
                                 end_central64_sig : end_central_sig),
                                4) != 0)
                       && (!G.ecrec.is_zip64_archive)
                       && (memcmp(G.sig, end_central_sig, 4) != 0)
                      );
#endif /* !SFX */
                } else {
                    /* no; we have found an error in the central directory
                     * -> report it and stop searching for more Zip entries
                     */
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(CentSigMsg), j + blknum*DIR_BLKSIZ + 1));
                    Info(slide, 0x401,
                         ((char *)slide,"%s", LoadFarString(ReportMsg)));
                    error_in_archive = PK_BADERR;
                }
                reached_end = TRUE;     /* ...so no more left to do */
                break;
            }
            /* process_cdir_file_hdr() sets pInfo->hostnum, pInfo->lcflag */
            if ((error = process_cdir_file_hdr(__G)) != PK_COOL) {
                error_in_archive = error;   /* only PK_EOF defined */
                reached_end = TRUE;     /* ...so no more left to do */
                break;
            }
            if ((error = do_string(__G__ G.crec.filename_length, DS_FN)) !=
                 PK_COOL)
            {
                if (error > error_in_archive)
                    error_in_archive = error;
                if (error > PK_WARN) {  /* fatal:  no more left to do */
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(FilNamMsg),
                      FnFilter1(G.filename), "central"));
                    reached_end = TRUE;
                    break;
                }
            }
            if (G.crec.filename_length == 0) {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(EmptyFilNamMsg)));
                if (error_in_archive < PK_ERR)
                    error_in_archive = PK_ERR;
                reached_end = TRUE;
                break;
            }
            G.pInfo->zip64 = FALSE;
            if ((error = do_string(__G__ G.crec.extra_field_length,
                EXTRA_FIELD)) != 0)
            {
                if (error > error_in_archive)
                    error_in_archive = error;
                if (error > PK_WARN) {  /* fatal */
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(ExtFieldMsg),
                      FnFilter1(G.filename), "central"));
                    reached_end = TRUE;
                    break;
                }
            }
            if ((error = fwkcs_note_cdir(__G)) != PK_COOL) {
                if (error > error_in_archive)
                    error_in_archive = error;
                reached_end = TRUE;
                break;
            }
#ifdef PKAV_SUPPORT
            if ((error = pkav_note_cdir(__G)) != PK_COOL) {
                if (error > error_in_archive)
                    error_in_archive = error;
                reached_end = TRUE;
                break;
            }
#endif
#ifdef AMIGA
            G.filenote_slot = j;
            if ((error = do_string(__G__ G.crec.file_comment_length,
                                   uO.N_flag ? FILENOTE : SKIP)) != PK_COOL)
#else
            if ((error = do_string(__G__ G.crec.file_comment_length, SKIP))
                != PK_COOL)
#endif
            {
                if (error > error_in_archive)
                    error_in_archive = error;
                if (error > PK_WARN) {  /* fatal */
                    Info(slide, 0x421, ((char *)slide,
                      LoadFarString(BadFileCommLength),
                      FnFilter1(G.filename)));
                    reached_end = TRUE;
                    break;
                }
            }
            if (G.process_all_files) {
                if (store_info(__G))
                    ++j;  /* file is OK; info[] stored; continue with next */
                else
                    ++num_skipped;
            } else {
                int   do_this_file;

                if (G.filespecs == 0)
                    do_this_file = TRUE;
                else {  /* check if this entry matches an `include' argument */
                    do_this_file = FALSE;
                    for (i = 0; i < G.filespecs; i++)
                        if (match(G.filename, G.pfnames[i], uO.C_flag WISEP)) {
                            do_this_file = TRUE;  /* ^-- ignore case or not? */
                            if (fn_matched)
                                fn_matched[i] = TRUE;
                            break;       /* found match, so stop looping */
                        }
                }
                if (do_this_file) {  /* check if this is an excluded file */
                    for (i = 0; i < G.xfilespecs; i++)
                        if (match(G.filename, G.pxnames[i], uO.C_flag WISEP)) {
                            do_this_file = FALSE; /* ^-- ignore case or not? */
                            if (xn_matched)
                                xn_matched[i] = TRUE;
                            break;
                        }
                }
                if (do_this_file) {
                    if (store_info(__G))
                        ++j;            /* file is OK */
                    else
                        ++num_skipped;  /* unsupp. compression or encryption */
                }
            } /* end if (process_all_files) */

            members_processed++;

        } /* end while-loop (adding files to current block) */

        /* save position in central directory so can come back later */
        cd_bufstart = G.cur_zipfile_bufstart;
        cd_inptr = G.inptr;
        cd_incnt = G.incnt;

    /*-----------------------------------------------------------------------
        Second loop:  process files in current block, extracting or testing
        each one.
      -----------------------------------------------------------------------*/

        error = extract_or_test_entrylist(__G__ j,
                        &filnum, &num_bad_pwd, &old_extra_bytes,
#ifdef SET_DIR_ATTRIB
                        &num_dirs, &dirlist,
#endif
                        error_in_archive);
        if (G.fwkcs_expected != (uch *)NULL) {
            free(G.fwkcs_expected);
            G.fwkcs_expected = (uch *)NULL;
        }
        if (error != PK_COOL) {
            if (error > error_in_archive)
                error_in_archive = error;
            /* ...and keep going (unless disk full or user break) */
            if (G.disk_full > 1 || error_in_archive == IZ_CTRLC ||
                error == PK_BOMB) {
                /* clear reached_end to signal premature stop ... */
                reached_end = FALSE;
                /* ... and cancel scanning the central directory */
                break;
            }
        }


        /*
         * Jump back to where we were in the central directory, then go and do
         * the next batch of files.
         */

#ifdef USE_STRM_INPUT
        zfseeko(G.zipfd, cd_bufstart, SEEK_SET);
        G.cur_zipfile_bufstart = zftello(G.zipfd);
#else /* !USE_STRM_INPUT */
        G.cur_zipfile_bufstart =
          zlseek(G.zipfd, cd_bufstart, SEEK_SET);
#endif /* ?USE_STRM_INPUT */
        read(G.zipfd, (char *)G.inbuf, INBUFSIZ);  /* been here before... */
        G.inptr = cd_inptr;
        G.incnt = cd_incnt;
        ++blknum;

#ifdef TEST
        printf("\ncd_bufstart = %ld (%.8lXh)\n", cd_bufstart, cd_bufstart);
        printf("cur_zipfile_bufstart = %ld (%.8lXh)\n", cur_zipfile_bufstart,
          cur_zipfile_bufstart);
        printf("inptr-inbuf = %d\n", G.inptr-G.inbuf);
        printf("incnt = %d\n\n", G.incnt);
#endif

    } /* end while-loop (blocks of files in central directory) */

/*---------------------------------------------------------------------------
    Process the list of deferred symlink extractions and finish up
    the symbolic links.
  ---------------------------------------------------------------------------*/

#ifdef SYMLINKS
    if (G.slink_last != NULL) {
        if (QCOND2)
            Info(slide, 0, ((char *)slide, LoadFarString(SymLnkDeferred)));
        while (G.slink_head != NULL) {
           set_deferred_symlink(__G__ G.slink_head);
           /* remove the processed entry from the chain and free its memory */
           G.slink_last = G.slink_head;
           G.slink_head = G.slink_last->next;
           free(G.slink_last);
       }
       G.slink_last = NULL;
    }
#endif /* SYMLINKS */

/*---------------------------------------------------------------------------
    Go back through saved list of directories, sort and set times/perms/UIDs
    and GIDs from the deepest level on up.
  ---------------------------------------------------------------------------*/

#ifdef SET_DIR_ATTRIB
    if (num_dirs > 0) {
        sorted_dirlist = (direntry **)malloc(num_dirs*sizeof(direntry *));
        if (sorted_dirlist == (direntry **)NULL) {
            Info(slide, 0x401, ((char *)slide,
              LoadFarString(DirlistSortNoMem)));
            while (dirlist != (direntry *)NULL) {
                direntry *d = dirlist;

                dirlist = dirlist->next;
                free(d);
            }
        } else {
            ulg ndirs_fail = 0;

            if (num_dirs == 1)
                sorted_dirlist[0] = dirlist;
            else {
                for (i = 0;  i < num_dirs;  ++i) {
                    sorted_dirlist[i] = dirlist;
                    dirlist = dirlist->next;
                }
                qsort((char *)sorted_dirlist, num_dirs, sizeof(direntry *),
                  dircomp);
            }

            Trace((stderr, "setting directory times/perms/attributes\n"));
            for (i = 0;  i < num_dirs;  ++i) {
                direntry *d = sorted_dirlist[i];

                Trace((stderr, "dir = %s\n", d->fn));
                if ((error = set_direc_attribs(__G__ d)) != PK_OK) {
                    ndirs_fail++;
                    Info(slide, 0x201, ((char *)slide,
                      LoadFarString(DirlistSetAttrFailed), d->fn));
                    if (!error_in_archive)
                        error_in_archive = error;
                }
                free(d);
            }
            free(sorted_dirlist);
            if (!uO.tflag && QCOND2) {
                if (ndirs_fail > 0)
                    Info(slide, 0, ((char *)slide,
                      LoadFarString(DirlistFailAttrSum), ndirs_fail));
            }
        }
    }
#endif /* SET_DIR_ATTRIB */

/*---------------------------------------------------------------------------
    Check for unmatched filespecs on command line and print warning if any
    found.  Free allocated memory.  (But suppress check when central dir
    scan was interrupted prematurely.)
  ---------------------------------------------------------------------------*/

    if (fn_matched) {
        if (reached_end) for (i = 0;  i < G.filespecs;  ++i)
            if (!fn_matched[i]) {
#ifdef DLL
                if (!G.redirect_data && !G.redirect_text)
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(FilenameNotMatched), G.pfnames[i]));
                else
                    setFileNotFound(__G);
#else
                Info(slide, 1, ((char *)slide,
                  LoadFarString(FilenameNotMatched), G.pfnames[i]));
#endif
                if (error_in_archive <= PK_WARN)
                    error_in_archive = PK_FIND;   /* some files not found */
            }
        free((zvoid *)fn_matched);
    }
    if (xn_matched) {
        if (reached_end) for (i = 0;  i < G.xfilespecs;  ++i)
            if (!xn_matched[i])
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(ExclFilenameNotMatched), G.pxnames[i]));
        free((zvoid *)xn_matched);
    }

/*---------------------------------------------------------------------------
    Now, all locally allocated memory has been released.  When the central
    directory processing has been interrupted prematurely, it is safe to
    return immediately.  All completeness checks and summary messages are
    skipped in this case.
  ---------------------------------------------------------------------------*/
    if (!reached_end) {
#ifdef PKAV_SUPPORT
        pkav_reset(__G);
#endif
        return error_in_archive;
    }

#ifdef PKAV_SUPPORT
    error = pkav_finish_archive(__G);
    if (error > error_in_archive)
        error_in_archive = error;
#endif

/*---------------------------------------------------------------------------
    Double-check that we're back at the end-of-central-directory record, and
    print quick summary of results, if we were just testing the archive.  We
    send the summary to stdout so that people doing the testing in the back-
    ground and redirecting to a file can just do a "tail" on the output file.
  ---------------------------------------------------------------------------*/

#ifndef SFX
    if (no_endsig_found) {                      /* just to make sure */
        Info(slide, 0x401, ((char *)slide,"%s", LoadFarString(EndSigMsg)));
        Info(slide, 0x401, ((char *)slide,"%s", LoadFarString(ReportMsg)));
        if (!error_in_archive)       /* don't overwrite stronger error */
            error_in_archive = PK_WARN;
    }
#endif /* !SFX */
    if (uO.tflag) {
        ulg num = filnum - num_bad_pwd;

        if (uO.qflag < 2) {        /* GRR 930710:  was (uO.qflag == 1) */
            if (!error_in_archive && G.fwkcs_verified != 0)
                Info(slide, 0, ((char *)slide,
                  "FWKCS MD5 checksums verified for %lu entr%s.\n",
                  G.fwkcs_verified,
                  (G.fwkcs_verified == 1L)? "y" : "ies"));
            if (error_in_archive)
                Info(slide, 0, ((char *)slide, LoadFarString(ErrorInArchive),
                  (error_in_archive == PK_WARN)? "warning-" : "", G.zipfn));
            else if (num == 0L)
                Info(slide, 0, ((char *)slide, LoadFarString(ZeroFilesTested),
                  G.zipfn));
            else if (G.process_all_files && (num_skipped+num_bad_pwd == 0L))
                Info(slide, 0, ((char *)slide, LoadFarString(NoErrInCompData),
                  G.zipfn));
            else
                Info(slide, 0, ((char *)slide, LoadFarString(NoErrInTestedFiles)
                  , G.zipfn, num, (num==1L)? "":"s"));
            if (num_skipped > 0L)
                Info(slide, 0, ((char *)slide, LoadFarString(FilesSkipped),
                  num_skipped, (num_skipped==1L)? "":"s"));
#if CRYPT || !defined(NO_AES)
            if (num_bad_pwd > 0L)
                Info(slide, 0, ((char *)slide, LoadFarString(FilesSkipBadPasswd)
                  , num_bad_pwd, (num_bad_pwd==1L)? "":"s"));
#endif /* CRYPT */
        }
    }

    /* give warning if files not tested or extracted (first condition can still
     * happen if zipfile is empty and no files specified on command line) */

    if ((filnum == 0) && error_in_archive <= PK_WARN) {
        if (num_skipped > 0L)
            error_in_archive = IZ_UNSUP; /* unsupport. compression/encryption */
        else
            error_in_archive = PK_FIND;  /* no files found at all */
    }
#if CRYPT || !defined(NO_AES)
    else if ((filnum == num_bad_pwd) && error_in_archive <= PK_WARN)
        error_in_archive = IZ_BADPWD;    /* bad passwd => all files skipped */
#endif
    else if ((num_skipped > 0L) && error_in_archive <= PK_WARN)
        error_in_archive = IZ_UNSUP;     /* was PK_WARN; Jean-loup complained */
#if CRYPT || !defined(NO_AES)
    else if ((num_bad_pwd > 0L) && !error_in_archive)
        error_in_archive = PK_WARN;
#endif

#ifdef PKAV_SUPPORT
    pkav_reset(__G);
#endif
    return error_in_archive;

} /* end function extract_or_test_files() */





/***************************/
/*  Function store_info()  */
/***************************/

static int store_info(__G)   /* return 0 if skipping, 1 if OK */
    __GDEF
{
#ifdef USE_BZIP2
#  define UNKN_BZ2 (G.crec.compression_method!=BZIPPED)
#else
#  define UNKN_BZ2 TRUE       /* bzip2 unknown */
#endif

#ifdef USE_LZMA
#  define UNKN_LZMA (G.crec.compression_method!=LZMAED)
#else
#  define UNKN_LZMA TRUE      /* LZMA unknown */
#endif

#ifdef USE_XZ
#  define UNKN_XZ (G.crec.compression_method!=XZED)
#else
#  define UNKN_XZ TRUE        /* XZ unknown */
#endif

#ifdef USE_ZSTD
#  define UNKN_ZSTD (G.crec.compression_method!=ZSTD_OLD && \
                     G.crec.compression_method!=ZSTDED)
#else
#  define UNKN_ZSTD TRUE      /* Zstandard unknown */
#endif

#ifdef USE_WAVP
#  define UNKN_WAVP (G.crec.compression_method!=WAVPACKED)
#else
#  define UNKN_WAVP TRUE      /* WavPack unknown */
#endif

#ifdef USE_PPMD
#  define UNKN_PPMD (G.crec.compression_method!=PPMDED)
#else
#  define UNKN_PPMD TRUE      /* PPMd unknown */
#endif

#ifdef SFX
#  ifdef USE_DEFLATE64
#    define UNKN_COMPR \
     (G.crec.compression_method!=STORED && G.crec.compression_method<DEFLATED \
      && G.crec.compression_method>ENHDEFLATED \
      && UNKN_BZ2 && UNKN_LZMA && UNKN_XZ && UNKN_ZSTD && UNKN_WAVP && UNKN_PPMD)
#  else
#    define UNKN_COMPR \
     (G.crec.compression_method!=STORED && G.crec.compression_method!=DEFLATED\
      && UNKN_BZ2 && UNKN_LZMA && UNKN_XZ && UNKN_ZSTD && UNKN_WAVP && UNKN_PPMD)
#  endif
#else
#  ifdef USE_OLDUNZIP
#    define UNKN_RED  FALSE  /* OldUnzip Reduce methods 2..5 */
#    define UNKN_SHR  FALSE  /* OldUnzip Shrink method 1 */
#  else
#    define UNKN_RED (G.crec.compression_method >= REDUCED1 && \
                      G.crec.compression_method <= REDUCED4)
#    define UNKN_SHR (G.crec.compression_method == SHRUNK)
#  endif
#  ifdef USE_DEFLATE64
#    define UNKN_COMPR (UNKN_RED || UNKN_SHR || \
     G.crec.compression_method==TOKENIZED || \
     (G.crec.compression_method>ENHDEFLATED && \
      G.crec.compression_method!=DCLIMPLODED && UNKN_BZ2 && UNKN_LZMA && UNKN_XZ && UNKN_ZSTD \
      && UNKN_WAVP && UNKN_PPMD))
#  else
#    define UNKN_COMPR (UNKN_RED || UNKN_SHR || \
     G.crec.compression_method==TOKENIZED || \
     (G.crec.compression_method>DEFLATED && \
      G.crec.compression_method!=DCLIMPLODED && UNKN_BZ2 && UNKN_LZMA && UNKN_XZ && UNKN_ZSTD \
      && UNKN_WAVP && UNKN_PPMD))
#  endif
#endif

    int unzvers_support = UNZIP_VERSION;
#ifndef NO_AES
    if (G.crec.compression_method==99) {
        unsigned v=0,strength=0,m=0;
        int r=ef_scan_for_wzaes(G.extra_field,
                G.crec.extra_field_length,&v,&strength,&m);
        if(r!=1 || !(G.crec.general_purpose_bit_flag&1) ||
           (G.crec.general_purpose_bit_flag&0x2040))return 0;
        G.pInfo->aes_strength=strength;
        G.pInfo->aes_version=v;
        G.pInfo->aes_method=m;
        G.crec.compression_method=(ush)m;
    } else {
        G.pInfo->aes_strength=0;
        G.pInfo->aes_version=0;
        G.pInfo->aes_method=0;
    }
#endif
#define UNZVERS_SUPPORT unzvers_support

#ifndef NO_AES
    /* WinZip normally inherits the version-needed value from the real
     * compression method, but other AES writers may use 5.1 for method 99.
     * Accept that on input without changing our WinZip-compatible writer. */
    if (G.pInfo->aes_strength && unzvers_support < 51)
        unzvers_support = 51;
#endif

#ifdef USE_BZIP2
    if (!UNKN_BZ2 && unzvers_support < UNZIP_BZ2VERS)
        unzvers_support = UNZIP_BZ2VERS;
#endif
#ifdef USE_LZMA
    if (!UNKN_LZMA && unzvers_support < UNZIP_LZMAVERS)
        unzvers_support = UNZIP_LZMAVERS;
#endif
#ifdef USE_ZSTD
    /* WinZip writes version-needed 2.0 for method 93, while Python 3.14
     * writes 6.3.  Accept both on extraction when the codec is present. */
    if (!UNKN_ZSTD && unzvers_support < UNZIP_ZSTDVERS)
        unzvers_support = UNZIP_ZSTDVERS;
#endif
#ifdef USE_PPMD
    if (!UNKN_PPMD && unzvers_support < UNZIP_PPMDVERS)
        unzvers_support = UNZIP_PPMDVERS;
#endif

/*---------------------------------------------------------------------------
    Check central directory info for version/compatibility requirements.
  ---------------------------------------------------------------------------*/

    G.pInfo->encrypted = G.crec.general_purpose_bit_flag & 1;   /* bit field */
    G.pInfo->ExtLocHdr = (G.crec.general_purpose_bit_flag & 8) == 8;  /* bit */
    G.pInfo->textfile = G.crec.internal_file_attributes & 1;    /* bit field */
    G.pInfo->crc = G.crec.crc32;
    G.pInfo->compression_method = G.crec.compression_method;
    G.pInfo->compr_size = G.crec.csize;
    G.pInfo->uncompr_size = G.crec.ucsize;
#ifdef PKAV_SUPPORT
    G.pInfo->pkav_member = (G.crec.internal_file_attributes & 0x0006) != 0;
    G.pInfo->pkav_v1_member = (G.pInfo->hostnum == FS_FAT_ &&
        (G.crec.general_purpose_bit_flag & PKAV1_GPBF) != 0);
    G.pInfo->pkav_extcheck = (G.crec.internal_file_attributes & 0x0004) != 0;
    G.pInfo->pkav_dos_datetime = G.crec.last_mod_dos_datetime;
    G.pInfo->pkav_dos_attr = (uch)(G.crec.external_file_attributes & 0xff);
#endif

    switch (uO.aflag) {
        case 0:
            G.pInfo->textmode = FALSE;   /* bit field */
            break;
        case 1:
            G.pInfo->textmode = G.pInfo->textfile;   /* auto-convert mode */
            break;
        default:  /* case 2: */
            G.pInfo->textmode = TRUE;
            break;
    }

    if (G.crec.version_needed_to_extract[1] == VMS_) {
        if (G.crec.version_needed_to_extract[0] > VMS_UNZIP_VERSION) {
            if (!((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2)))
                Info(slide, 0x401, ((char *)slide, LoadFarString(VersionMsg),
                  FnFilter1(G.filename), "VMS",
                  G.crec.version_needed_to_extract[0] / 10,
                  G.crec.version_needed_to_extract[0] % 10,
                  VMS_UNZIP_VERSION / 10, VMS_UNZIP_VERSION % 10));
            return 0;
        }
#ifndef VMS   /* won't be able to use extra field, but still have data */
        else if (!uO.tflag && !IS_OVERWRT_ALL) { /* if -o, extract anyway */
            Info(slide, 0x481, ((char *)slide, LoadFarString(VMSFormatQuery),
              FnFilter1(G.filename)));
            fgets(G.answerbuf, sizeof(G.answerbuf), stdin);
            if ((*G.answerbuf != 'y') && (*G.answerbuf != 'Y'))
                return 0;
        }
#endif /* !VMS */
    /* usual file type:  don't need VMS to extract */
    } else if (G.crec.version_needed_to_extract[0] > UNZVERS_SUPPORT) {
        if (!((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2)))
            Info(slide, 0x401, ((char *)slide, LoadFarString(VersionMsg),
              FnFilter1(G.filename), "PK",
              G.crec.version_needed_to_extract[0] / 10,
              G.crec.version_needed_to_extract[0] % 10,
              UNZVERS_SUPPORT / 10, UNZVERS_SUPPORT % 10));
        return 0;
    }

    if (UNKN_COMPR) {
        if (!((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))) {
#ifndef SFX
            unsigned cmpridx;

            if ((cmpridx = find_compr_idx(G.crec.compression_method))
                < NUM_METHODS)
                Info(slide, 0x401, ((char *)slide, LoadFarString(ComprMsgName),
                  FnFilter1(G.filename),
                  LoadFarStringSmall(ComprNames[cmpridx])));
            else
#endif
                Info(slide, 0x401, ((char *)slide, LoadFarString(ComprMsgNum),
                  FnFilter1(G.filename),
                  G.crec.compression_method));
        }
        return 0;
    }
#if (!CRYPT)
    if (G.pInfo->encrypted
#ifndef NO_AES
        && !G.pInfo->aes_strength
#endif
       ) {
        if (!((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2)))
            Info(slide, 0x401, ((char *)slide, LoadFarString(SkipEncrypted),
              FnFilter1(G.filename)));
        return 0;
    }
#endif /* !CRYPT */

#ifndef SFX
    /* store a copy of the central header filename for later comparison */
    if ((G.pInfo->cfilname = zfmalloc(strlen(G.filename) + 1)) == NULL) {
        Info(slide, 0x401, ((char *)slide, LoadFarString(WarnNoMemCFName),
          FnFilter1(G.filename)));
    } else
        zfstrcpy(G.pInfo->cfilname, G.filename);
#endif /* !SFX */

    /* map whatever file attributes we have into the local format.  PKAV
       uses the upper 24 external-attribute bits as XOR/sum verification data,
       so never expose those bytes as Unix mode/type bits. */
#ifdef PKAV_SUPPORT
    if (G.crec.internal_file_attributes & 0x0004) {
        ulg pkav_external_attr = G.crec.external_file_attributes;
        uch pkav_hostnum = G.pInfo->hostnum;

        /* PKAV checksums occupies the same bytes UNIX systems normally use
           for mode/type information.  Interpret ONLY the surviving low DOS
           attribute byte here regardless of the advertised creation OS. */
        G.crec.external_file_attributes &= 0xff;
        G.pInfo->hostnum = FS_FAT_;
        mapattr(__G);
        G.pInfo->hostnum = pkav_hostnum;
        G.crec.external_file_attributes = pkav_external_attr;
    } else
#endif
        mapattr(__G);   /* GRR:  worry about return value later */

    G.pInfo->diskstart = G.crec.disk_number_start;
    G.pInfo->offset = (zoff_t)G.crec.relative_offset_local_header;
    return 1;

} /* end function store_info() */





#ifndef SFX
/*******************************/
/*  Function find_compr_idx()  */
/*******************************/

unsigned find_compr_idx(compr_methodnum)
    unsigned compr_methodnum;
{
    unsigned i;

    for (i = 0; i < NUM_METHODS; i++) {
        if (ComprIDs[i] == compr_methodnum) break;
    }
    return i;
}
#endif /* !SFX */





/******************************************/
/*  Function extract_or_test_entrylist()  */
/******************************************/

static int extract_or_test_entrylist(__G__ numchunk,
                pfilnum, pnum_bad_pwd, pold_extra_bytes,
#ifdef SET_DIR_ATTRIB
                pnum_dirs, pdirlist,
#endif
                error_in_archive)    /* return PK-type error code */
    __GDEF
    unsigned numchunk;
    ulg *pfilnum;
    ulg *pnum_bad_pwd;
    zoff_t *pold_extra_bytes;
#ifdef SET_DIR_ATTRIB
    unsigned *pnum_dirs;
    direntry **pdirlist;
#endif
    int error_in_archive;
{
    unsigned i;
    int renamed, query;
    int skip_entry;
    zoff_t bufstart, inbuf_offset, request;
    int error, errcode;

/* possible values for local skip_entry flag: */
#define SKIP_NO         0       /* do not skip this entry */
#define SKIP_Y_EXISTING 1       /* skip this entry, do not overwrite file */
#define SKIP_Y_NONEXIST 2       /* skip this entry, do not create new file */

    /*-----------------------------------------------------------------------
        Second loop:  process files in current block, extracting or testing
        each one.
      -----------------------------------------------------------------------*/

    for (i = 0; i < numchunk; ++i) {
        (*pfilnum)++;   /* *pfilnum = i + blknum*DIR_BLKSIZ + 1; */
        G.pInfo = &G.info[i];
#ifdef NOVELL_BUG_FAILSAFE
        G.dne = FALSE;  /* assume file exists until stat() says otherwise */
#endif

        /* if the target position is not within the current input buffer
         * (either haven't yet read far enough, or (maybe) skipping back-
         * ward), skip to the target position and reset readbuf(). */

        /* seek_zipf(__G__ pInfo->offset);  */
        request = G.pInfo->offset + G.extra_bytes;
        if (uO.zipbomb == TRUE) {
          if (cover_within((cover_t *)G.cover, request)) {
            Info(slide, 0x401, ((char *)slide,
              LoadFarString(OverlappedComponents)));
            return PK_BOMB;
          }
        }
        inbuf_offset = request % INBUFSIZ;
        bufstart = request - inbuf_offset;

        Trace((stderr, "\ndebug: request = %ld, inbuf_offset = %ld\n",
          (long)request, (long)inbuf_offset));
        Trace((stderr,
          "debug: bufstart = %ld, cur_zipfile_bufstart = %ld\n",
          (long)bufstart, (long)G.cur_zipfile_bufstart));
        if (request < 0) {
            Info(slide, 0x401, ((char *)slide, LoadFarStringSmall(SeekMsg),
              G.zipfn, LoadFarString(ReportMsg)));
            error_in_archive = PK_ERR;
            if (*pfilnum == 1 && G.extra_bytes != 0L) {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(AttemptRecompensate)));
                *pold_extra_bytes = G.extra_bytes;
                G.extra_bytes = 0L;
                request = G.pInfo->offset;  /* could also check if != 0 */
                inbuf_offset = request % INBUFSIZ;
                bufstart = request - inbuf_offset;
                Trace((stderr, "debug: request = %ld, inbuf_offset = %ld\n",
                  (long)request, (long)inbuf_offset));
                Trace((stderr,
                  "debug: bufstart = %ld, cur_zipfile_bufstart = %ld\n",
                  (long)bufstart, (long)G.cur_zipfile_bufstart));
                /* try again */
                if (request < 0) {
                    Trace((stderr,
                      "debug: recompensated request still < 0\n"));
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarStringSmall(SeekMsg),
                      G.zipfn, LoadFarString(ReportMsg)));
                    error_in_archive = PK_BADERR;
                    continue;
                }
            } else {
                error_in_archive = PK_BADERR;
                continue;  /* this one hosed; try next */
            }
        }

        if (bufstart != G.cur_zipfile_bufstart) {
            Trace((stderr, "debug: bufstart != cur_zipfile_bufstart\n"));
#ifdef USE_STRM_INPUT
            zfseeko(G.zipfd, bufstart, SEEK_SET);
            G.cur_zipfile_bufstart = zftello(G.zipfd);
#else /* !USE_STRM_INPUT */
            G.cur_zipfile_bufstart =
              zlseek(G.zipfd, bufstart, SEEK_SET);
#endif /* ?USE_STRM_INPUT */
            if ((G.incnt = read(G.zipfd, (char *)G.inbuf, INBUFSIZ)) <= 0)
            {
                Info(slide, 0x401, ((char *)slide, LoadFarString(OffsetMsg),
                  *pfilnum, "lseek", (long)bufstart));
                error_in_archive = PK_BADERR;
                continue;   /* can still do next file */
            }
            G.inptr = G.inbuf + (int)inbuf_offset;
            G.incnt -= (int)inbuf_offset;
        } else {
            G.incnt += (int)(G.inptr-G.inbuf) - (int)inbuf_offset;
            G.inptr = G.inbuf + (int)inbuf_offset;
        }

        /* should be in proper position now, so check for sig */
        if (readbuf(__G__ G.sig, 4) == 0) {  /* bad offset */
            Info(slide, 0x401, ((char *)slide, LoadFarString(OffsetMsg),
              *pfilnum, "EOF", (long)request));
            error_in_archive = PK_BADERR;
            continue;   /* but can still try next one */
        }
        if (memcmp(G.sig, local_hdr_sig, 4)) {
            Info(slide, 0x401, ((char *)slide, LoadFarString(OffsetMsg),
              *pfilnum, LoadFarStringSmall(LocalHdrSig), (long)request));
            /*
                GRRDUMP(G.sig, 4)
                GRRDUMP(local_hdr_sig, 4)
             */
            error_in_archive = PK_ERR;
            if ((*pfilnum == 1 && G.extra_bytes != 0L) ||
                (G.extra_bytes == 0L && *pold_extra_bytes != 0L)) {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(AttemptRecompensate)));
                if (G.extra_bytes) {
                    *pold_extra_bytes = G.extra_bytes;
                    G.extra_bytes = 0L;
                } else
                    G.extra_bytes = *pold_extra_bytes; /* third attempt */
                if (((error = seek_zipf(__G__ G.pInfo->offset)) != PK_OK) ||
                    (readbuf(__G__ G.sig, 4) == 0)) {  /* bad offset */
                    if (error != PK_BADERR)
                      Info(slide, 0x401, ((char *)slide,
                        LoadFarString(OffsetMsg), *pfilnum, "EOF",
                        (long)request));
                    error_in_archive = PK_BADERR;
                    continue;   /* but can still try next one */
                }
                if (memcmp(G.sig, local_hdr_sig, 4)) {
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(OffsetMsg), *pfilnum,
                      LoadFarStringSmall(LocalHdrSig), (long)request));
                    error_in_archive = PK_BADERR;
                    continue;
                }
            } else
                continue;  /* this one hosed; try next */
        }
        if ((error = process_local_file_hdr(__G)) != PK_COOL) {
            Info(slide, 0x421, ((char *)slide, LoadFarString(BadLocalHdr),
              *pfilnum));
            error_in_archive = error;   /* only PK_EOF defined */
            continue;   /* can still try next one */
        }
#if (!defined(SFX) && defined(UNICODE_SUPPORT))
        if (((G.lrec.general_purpose_bit_flag & (1 << 11)) == (1 << 11))
            != (G.pInfo->GPFIsUTF8 != 0)) {
            if (QCOND2) {
#  ifdef SMALL_MEM
                char *temp_cfilnam = slide + (7 * (WSIZE>>3));

                zfstrcpy((char Far *)temp_cfilnam, G.pInfo->cfilname);
#    define  cFile_PrintBuf  temp_cfilnam
#  else
#    define  cFile_PrintBuf  G.pInfo->cfilname
#  endif
                Info(slide, 0x421, ((char *)slide,
                  LoadFarStringSmall2(GP11FlagsDiffer),
                  *pfilnum, FnFilter1(cFile_PrintBuf), G.pInfo->GPFIsUTF8));
#  undef    cFile_PrintBuf
            }
            if (error_in_archive < PK_WARN)
                error_in_archive = PK_WARN;
        }
#endif /* !SFX && UNICODE_SUPPORT */
        if ((error = do_string(__G__ G.lrec.filename_length, DS_FN_L)) !=
             PK_COOL)
        {
            if (error > error_in_archive)
                error_in_archive = error;
            if (error > PK_WARN) {
                Info(slide, 0x401, ((char *)slide, LoadFarString(FilNamMsg),
                  FnFilter1(G.filename), "local"));
                continue;   /* go on to next one */
            }
        }
        if (G.extra_field != (uch *)NULL) {
            free(G.extra_field);
            G.extra_field = (uch *)NULL;
        }
        if ((error =
             do_string(__G__ G.lrec.extra_field_length, EXTRA_FIELD)) != 0)
        {
            if (error > error_in_archive)
                error_in_archive = error;
            if (error > PK_WARN) {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(ExtFieldMsg),
                  FnFilter1(G.filename), "local"));
                continue;   /* go on */
            }
        }
#ifndef SFX
        /* Filename consistency checks must come after reading in the local
         * extra field, so that a UTF-8 entry name e.f. block has already
         * been processed.
         */
        if (G.pInfo->cfilname != (char Far *)NULL) {
            if (zfstrcmp(G.pInfo->cfilname, G.filename) != 0) {
#  ifdef SMALL_MEM
                char *temp_cfilnam = slide + (7 * (WSIZE>>3));

                zfstrcpy((char Far *)temp_cfilnam, G.pInfo->cfilname);
#    define  cFile_PrintBuf  temp_cfilnam
#  else
#    define  cFile_PrintBuf  G.pInfo->cfilname
#  endif
                Info(slide, 0x401, ((char *)slide,
                  LoadFarStringSmall2(LvsCFNamMsg),
                  FnFilter2(cFile_PrintBuf), FnFilter1(G.filename)));
#  undef    cFile_PrintBuf
                zfstrcpy(G.filename, G.pInfo->cfilname);
                if (error_in_archive < PK_WARN)
                    error_in_archive = PK_WARN;
            }
            zffree(G.pInfo->cfilname);
            G.pInfo->cfilname = (char Far *)NULL;
        }
#endif /* !SFX */
#ifndef NO_AES
        G.aes_active=0;
        if (G.pInfo->aes_strength) {
            unsigned v=0,strength=0,m=0;
            int ar=ef_scan_for_wzaes(G.extra_field,
                    G.lrec.extra_field_length,&v,&strength,&m);
            /* AE-2 requires CRC32=0, but libzip 1.11.3 writes a real
             * CRC32 while tagging entries AE-2.  Accept on read, and
             * verify any nonzero CRC after authenticated extraction.
             * Our AE-2 writer continues to emit the required zero. */
            if(ar!=1 || G.lrec.compression_method!=99 ||
               v!=G.pInfo->aes_version ||
               strength!=G.pInfo->aes_strength || m!=G.pInfo->aes_method ||
               !(G.lrec.general_purpose_bit_flag&1)) {
                Info(slide,0x401,((char *)slide,
                    "malformed WinZip AES metadata: %s\n",FnFilter1(G.filename)));
                error_in_archive=PK_ERR;continue;
            }
            G.lrec.compression_method=(ush)m;
        } else if (G.lrec.compression_method==99) {
            error_in_archive=PK_ERR;continue;
        }
#endif
        /* The compression method is redundant between the local and central
         * headers and must describe the same data.  For AES entries both
         * values have been translated from method 99 to the real method by
         * this point.
         */
        if (G.lrec.compression_method != G.pInfo->compression_method) {
            Info(slide, 0x401, ((char *)slide,
              LoadFarString(LvsCMethodMsg), FnFilter1(G.filename),
              (unsigned)G.lrec.compression_method,
              (unsigned)G.pInfo->compression_method));
            if (error_in_archive < PK_ERR)
                error_in_archive = PK_ERR;
            continue;
        }

        /* If bit 3 is clear, the CRC and sizes in the local header are not
         * placeholders for a following data descriptor and must agree with
         * the central directory.  Zip64 values have already been expanded.
         */
        if ((G.lrec.general_purpose_bit_flag & 8) == 0 &&
            (G.lrec.crc32 != G.pInfo->crc ||
             G.lrec.csize != G.pInfo->compr_size ||
             G.lrec.ucsize != G.pInfo->uncompr_size)) {
            Info(slide, 0x401, ((char *)slide,
              LoadFarString(LvsCDataMsg), FnFilter1(G.filename)));
            if (error_in_archive < PK_ERR)
                error_in_archive = PK_ERR;
            continue;
        }

        /* Size consistency checks must come after reading in the local extra
         * field, so that any Zip64 extension local e.f. block has already
         * been processed.
         */
        if (G.lrec.compression_method == STORED) {
            zusz_t csiz_decrypted = G.lrec.csize;

            if (G.pInfo->encrypted) {
#ifndef NO_AES
                if(G.pInfo->aes_strength) {
                    zusz_t overhead = (zusz_t)iz_aes_salt_size(
                                          G.pInfo->aes_strength)+12;
                    if(csiz_decrypted < overhead){
                        error_in_archive=PK_ERR;continue;
                    }
                    csiz_decrypted-=overhead;
                } else
#endif
                if (csiz_decrypted < 12) {
                    /* handle the error now to prevent unsigned overflow */
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarStringSmall(ErrUnzipNoFile),
                      LoadFarString(InvalidComprData),
                      LoadFarStringSmall2(Inflate)));
                    return PK_ERR;
                }
#ifndef NO_AES
                if(!G.pInfo->aes_strength)
#endif
                    csiz_decrypted -= 12;
            }
            if (G.lrec.ucsize != csiz_decrypted) {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarStringSmall2(WrnStorUCSizCSizDiff),
                  FnFilter1(G.filename),
                  FmZofft(G.lrec.ucsize, NULL, "u"),
                  FmZofft(csiz_decrypted, NULL, "u")));
                G.lrec.ucsize = csiz_decrypted;
                if (error_in_archive < PK_WARN)
                    error_in_archive = PK_WARN;
            }
        }

#if CRYPT || !defined(NO_AES)
#ifndef NO_AES
        if (G.pInfo->aes_strength) {
            error=iz_aes_authenticate(__G);
        } else
#endif
#if CRYPT
        if (G.pInfo->encrypted) {
            error=decrypt(__G__ uO.pwdarg);
        } else
#endif
        error=PK_COOL;
        if(error != PK_COOL) {
            if (error == PK_WARN) {
                if (!((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2)))
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(SkipIncorrectPasswd),
                      FnFilter1(G.filename)));
                ++(*pnum_bad_pwd);
            } else {  /* (error > PK_WARN) */
                if (error > error_in_archive)
                    error_in_archive = error;
#ifndef NO_AES
                if (!G.pInfo->aes_strength)
#endif
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(SkipCannotGetPasswd),
                      FnFilter1(G.filename)));
            }
            continue;   /* go on to next file */
        }
#endif /* CRYPT || AES */

        /*
         * just about to extract file:  if extracting to disk, check if
         * already exists, and if so, take appropriate action according to
         * fflag/uflag/overwrite_all/etc. (we couldn't do this in upper
         * loop because we don't store the possibly renamed filename[] in
         * info[])
         */
#ifdef DLL
        if (!uO.tflag && !uO.cflag && !G.redirect_data)
#else
        if (!uO.tflag && !uO.cflag)
#endif
        {
            renamed = FALSE;   /* user hasn't renamed output file yet */

startover:
            query = FALSE;
            skip_entry = SKIP_NO;
            /* for files from DOS FAT, check for use of backslash instead
             *  of slash as directory separator (bug in some zipper(s); so
             *  far, not a problem in HPFS, NTFS or VFAT systems)
             */
#ifndef SFX
            if (G.pInfo->hostnum == FS_FAT_ && !MBSCHR(G.filename, '/')) {
                char *p=G.filename;

                if (*p) do {
                    if (*p == '\\') {
                        if (!G.reported_backslash) {
                            Info(slide, 0x21, ((char *)slide,
                              LoadFarString(BackslashPathSep), G.zipfn));
                            G.reported_backslash = TRUE;
                            if (!error_in_archive)
                                error_in_archive = PK_WARN;
                        }
                        *p = '/';
                    }
                } while (*PREINCSTR(p));
            }
#endif /* !SFX */

            if (!renamed) {
               /* remove absolute path specs */
               if (G.filename[0] == '/') {
                   Info(slide, 0x401, ((char *)slide,
                        LoadFarString(AbsolutePathWarning),
                        FnFilter1(G.filename)));
                   if (!error_in_archive)
                       error_in_archive = PK_WARN;
                   do {
                       char *p = G.filename + 1;
                       do {
                           *(p-1) = *p;
                       } while (*p++ != '\0');
                   } while (G.filename[0] == '/');
               }
            }

            /* mapname can create dirs if not freshening or if renamed */
            error = mapname(__G__ renamed);
            if ((errcode = error & ~MPN_MASK) != PK_OK &&
                error_in_archive < errcode)
                error_in_archive = errcode;
            if ((errcode = error & MPN_MASK) > MPN_INF_TRUNC) {
                if (errcode == MPN_CREATED_DIR) {
#ifdef SET_DIR_ATTRIB
                    direntry *d_entry;

                    error = defer_dir_attribs(__G__ &d_entry);
                    if (d_entry == (direntry *)NULL) {
                        /* There may be no dir_attribs info available, or
                         * we have encountered a mem allocation error.
                         * In case of an error, report it and set program
                         * error state to warning level.
                         */
                        if (error) {
                            Info(slide, 0x401, ((char *)slide,
                                 LoadFarString(DirlistEntryNoMem)));
                            if (!error_in_archive)
                                error_in_archive = PK_WARN;
                        }
                    } else {
                        d_entry->next = (*pdirlist);
                        (*pdirlist) = d_entry;
                        ++(*pnum_dirs);
                    }
#endif /* SET_DIR_ATTRIB */
                } else if (errcode == MPN_VOL_LABEL) {
#ifdef DOS_OS2_W32
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarString(SkipVolumeLabel),
                      FnFilter1(G.filename),
                      uO.volflag? "hard disk " : ""));
#else
                    Info(slide, 1, ((char *)slide,
                      LoadFarString(SkipVolumeLabel),
                      FnFilter1(G.filename), ""));
#endif
                } else if (errcode > MPN_INF_SKIP &&
                           error_in_archive < PK_ERR)
                    error_in_archive = PK_ERR;
                Trace((stderr, "mapname(%s) returns error code = %d\n",
                  FnFilter1(G.filename), error));
                continue;   /* go on to next file */
            }

#ifdef QDOS
            QFilename(__G__ G.filename);
#endif
            switch (check_for_newer(__G__ G.filename)) {
                case DOES_NOT_EXIST:
#ifdef NOVELL_BUG_FAILSAFE
                    G.dne = TRUE;   /* stat() says file DOES NOT EXIST */
#endif
                    /* freshen (no new files): skip unless just renamed */
                    if (uO.fflag && !renamed)
                        skip_entry = SKIP_Y_NONEXIST;
                    break;
                case EXISTS_AND_OLDER:
#ifdef UNIXBACKUP
                    if (!uO.B_flag)
#endif
                    {
                        if (IS_OVERWRT_NONE)
                            /* never overwrite:  skip file */
                            skip_entry = SKIP_Y_EXISTING;
                        else if (!IS_OVERWRT_ALL)
                            query = TRUE;
                    }
                    break;
                case EXISTS_AND_NEWER:             /* (or equal) */
#ifdef UNIXBACKUP
                    if ((!uO.B_flag && IS_OVERWRT_NONE) ||
#else
                    if (IS_OVERWRT_NONE ||
#endif
                        (uO.uflag && !renamed)) {
                        /* skip if update/freshen & orig name */
                        skip_entry = SKIP_Y_EXISTING;
                    } else {
#ifdef UNIXBACKUP
                        if (!IS_OVERWRT_ALL && !uO.B_flag)
#else
                        if (!IS_OVERWRT_ALL)
#endif
                            query = TRUE;
                    }
                    break;
            }
#ifdef VMS
            /* 2008-07-24 SMS.
             * On VMS, if the file name includes a version number,
             * and "-V" ("retain VMS version numbers", V_flag) is in
             * effect, then the VMS-specific code will handle any
             * conflicts with an existing file, making this query
             * redundant.  (Implicit "y" response here.)
             */
            if (query && uO.V_flag) {
                /* Not discarding file versions.  Look for one. */
                int cndx = strlen(G.filename) - 1;

                while ((cndx > 0) && (isdigit(G.filename[cndx])))
                    cndx--;
                if (G.filename[cndx] == ';')
                    /* File version found; skip the generic query,
                     * proceeding with its default response "y".
                     */
                    query = FALSE;
            }
#endif /* VMS */
            if (query) {
#ifdef WINDLL
                switch (G.lpUserFunctions->replace != NULL ?
                        (*G.lpUserFunctions->replace)(G.filename, FILNAMSIZ) :
                        IDM_REPLACE_NONE) {
                    case IDM_REPLACE_RENAME:
                        _ISO_INTERN(G.filename);
                        renamed = TRUE;
                        goto startover;
                    case IDM_REPLACE_ALL:
                        G.overwrite_mode = OVERWRT_ALWAYS;
                        /* FALL THROUGH, extract */
                    case IDM_REPLACE_YES:
                        break;
                    case IDM_REPLACE_NONE:
                        G.overwrite_mode = OVERWRT_NEVER;
                        /* FALL THROUGH, skip */
                    case IDM_REPLACE_NO:
                        skip_entry = SKIP_Y_EXISTING;
                        break;
                }
#else /* !WINDLL */
                extent fnlen;
reprompt:
                Info(slide, 0x81, ((char *)slide,
                  LoadFarString(ReplaceQuery),
                  FnFilter1(G.filename)));
                if (fgets(G.answerbuf, sizeof(G.answerbuf), stdin)
                    == (char *)NULL) {
                    Info(slide, 1, ((char *)slide,
                      LoadFarString(AssumeNone)));
                    *G.answerbuf = 'N';
                    if (!error_in_archive)
                        error_in_archive = 1;  /* not extracted:  warning */
                }
                switch (*G.answerbuf) {
                    case 'r':
                    case 'R':
                        do {
                            Info(slide, 0x81, ((char *)slide,
                              LoadFarString(NewNameQuery)));
                            fgets(G.filename, FILNAMSIZ, stdin);
                            /* usually get \n here:  better check for it */
                            fnlen = strlen(G.filename);
                            if (lastchar(G.filename, fnlen) == '\n')
                                G.filename[--fnlen] = '\0';
                        } while (fnlen == 0);
#ifdef WIN32  /* WIN32 fgets( ... , stdin) returns OEM coded strings */
                        _OEM_INTERN(G.filename);
#endif
                        renamed = TRUE;
                        goto startover;   /* sorry for a goto */
                    case 'A':   /* dangerous option:  force caps */
                        G.overwrite_mode = OVERWRT_ALWAYS;
                        /* FALL THROUGH, extract */
                    case 'y':
                    case 'Y':
                        break;
                    case 'N':
                        G.overwrite_mode = OVERWRT_NEVER;
                        /* FALL THROUGH, skip */
                    case 'n':
                        /* skip file */
                        skip_entry = SKIP_Y_EXISTING;
                        break;
                    case '\n':
                    case '\r':
                        /* Improve echo of '\n' and/or '\r'
                           (sizeof(G.answerbuf) == 10 (see globals.h), so
                           there is enough space for the provided text...) */
                        strcpy(G.answerbuf, "{ENTER}");
                        /* fall through ... */
                    default:
                        /* usually get \n here:  remove it for nice display
                           (fnlen can be re-used here, we are outside the
                           "enter new filename" loop) */
                        fnlen = strlen(G.answerbuf);
                        if (lastchar(G.answerbuf, fnlen) == '\n')
                            G.answerbuf[--fnlen] = '\0';
                        Info(slide, 1, ((char *)slide,
                          LoadFarString(InvalidResponse), G.answerbuf));
                        goto reprompt;   /* yet another goto? */
                } /* end switch (*answerbuf) */
#endif /* ?WINDLL */
            } /* end if (query) */
            if (skip_entry != SKIP_NO) {
#ifdef WINDLL
                if (skip_entry == SKIP_Y_EXISTING) {
                    /* report skipping of an existing entry */
                    Info(slide, 0, ((char *)slide,
                      ((IS_OVERWRT_NONE || !uO.uflag || renamed) ?
                       "Target file exists.  Skipping %s\n" :
                       "Target file newer.  Skipping %s\n"),
                      FnFilter1(G.filename)));
                }
#endif /* WINDLL */
                continue;
            }
        } /* end if (extracting to disk) */

#ifdef DLL
        if ((G.statreportcb != NULL) &&
            (*G.statreportcb)(__G__ UZ_ST_START_EXTRACT, G.zipfn,
                              G.filename, NULL)) {
            return IZ_CTRLC;        /* cancel operation by user request */
        }
#endif
#ifdef MACOS  /* MacOS is no preemptive OS, thus call event-handling by hand */
        UserStop();
#endif
#ifdef AMIGA
        G.filenote_slot = i;
#endif
        G.disk_full = 0;
        if ((error = extract_or_test_member(__G)) != PK_COOL) {
            if (error > error_in_archive)
                error_in_archive = error;       /* ...and keep going */
#ifdef DLL
            if (G.disk_full > 1 || error_in_archive == IZ_CTRLC) {
#else
            if (G.disk_full > 1) {
#endif
                return error_in_archive;        /* (unless disk full) */
            }
        }
#ifdef DLL
        if ((G.statreportcb != NULL) &&
            (*G.statreportcb)(__G__ UZ_ST_FINISH_MEMBER, G.zipfn,
                              G.filename, (zvoid *)&G.lrec.ucsize)) {
            return IZ_CTRLC;        /* cancel operation by user request */
        }
#endif
        if (uO.zipbomb == TRUE) {
          error = cover_add((cover_t *)G.cover, request,
                            G.cur_zipfile_bufstart + (G.inptr - G.inbuf));
          if (error < 0) {
            Info(slide, 0x401, ((char *)slide,
                                LoadFarString(NotEnoughMemCover)));
            return PK_MEM;
          }
          if (error != 0) {
            Info(slide, 0x401, ((char *)slide,
                                LoadFarString(OverlappedComponents)));
            return PK_BOMB;
          }
        }
#ifdef MACOS  /* MacOS is no preemptive OS, thus call event-handling by hand */
        UserStop();
#endif
    } /* end for-loop (i:  files in current block) */

    return error_in_archive;

} /* end function extract_or_test_entrylist() */





/* wsize is used in extract_or_test_member() and UZbunzip2() */
#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
#  define wsize G._wsize    /* wsize is a variable */
#else
#  define wsize WSIZE       /* wsize is a constant */
#endif

/***************************************/
/*  Function extract_or_test_member()  */
/***************************************/

static int extract_or_test_member(__G)    /* return PK-type error code */
     __GDEF
{
    char *nul="[empty] ", *txt="[text]  ", *bin="[binary]";
#ifdef PKAV_SUPPORT
    int av_member = pkav_active_member(__G);
    char *avmark = av_member ? "-AV" : "";
    char *avsep = (av_member && uO.aflag == 1) ? " " : "";
    char *test_avmark = av_member ? " -AV" : "";
#else
    char *avmark = "", *avsep = "", *test_avmark = "";
#endif
#ifdef CMS_MVS
    char *ebc="[ebcdic]";
#endif
    register int b;
    int r, error=PK_COOL, fwkcs_error=PK_COOL, crc_bad;
    uch fwkcs_digest[16];
    char fwkcs_actual_hex[33], fwkcs_expected_hex[33];


/*---------------------------------------------------------------------------
    Initialize variables, buffers, etc.
  ---------------------------------------------------------------------------*/

    G.bits_left = 0;
    G.bitbuf = 0L;       /* unreduce and unshrink only */
    G.zipeof = 0;
    G.newfile = TRUE;
    G.crc32val = CRCVAL_INITIAL;
    G.fwkcs_active = G.pInfo->fwkcs_md5;
    if (G.fwkcs_active)
        fwkcs_md5_init(__G);
#ifdef PKAV_SUPPORT
    pkav_begin_member(__G);
#endif

#ifdef SYMLINKS
    /* If file is a (POSIX-compatible) symbolic link and we are extracting
     * to disk, prepare to restore the link. */
    G.symlnk = (G.pInfo->symlink &&
                !uO.tflag && !uO.cflag && (G.lrec.ucsize > 0));
#endif /* SYMLINKS */

    if (uO.tflag) {
        if (!uO.qflag)
            Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg), "test",
              FnFilter1(G.filename), "", "", "", ""));
    } else {
#ifdef DLL
        if (uO.cflag && !G.redirect_data)
#else
        if (uO.cflag)
#endif
        {
#if (defined(OS2) && defined(__IBMC__) && (__IBMC__ >= 200))
            G.outfile = freopen("", "wb", stdout);   /* VAC++ ignores setmode */
#else
            G.outfile = stdout;
#endif
#ifdef DOS_FLX_NLM_OS2_W32
#if (defined(__HIGHC__) && !defined(FLEXOS))
            setmode(G.outfile, _BINARY);
#else /* !(defined(__HIGHC__) && !defined(FLEXOS)) */
            setmode(fileno(G.outfile), O_BINARY);
#endif /* ?(defined(__HIGHC__) && !defined(FLEXOS)) */
#           define NEWLINE "\r\n"
#else /* !DOS_FLX_NLM_OS2_W32 */
#           define NEWLINE "\n"
#endif /* ?DOS_FLX_NLM_OS2_W32 */
#ifdef VMS
            /* VMS:  required even for stdout! */
            if ((r = open_outfile(__G)) != 0)
                switch (r) {
                  case OPENOUT_SKIPOK:
                    return PK_OK;
                  case OPENOUT_SKIPWARN:
                    return PK_WARN;
                  default:
                    return PK_DISK;
                }
        } else if ((r = open_outfile(__G)) != 0)
            switch (r) {
              case OPENOUT_SKIPOK:
                return PK_OK;
              case OPENOUT_SKIPWARN:
                return PK_WARN;
              default:
                return PK_DISK;
            }
#else /* !VMS */
        } else if (open_outfile(__G))
            return PK_DISK;
#endif /* ?VMS */
    }

/*---------------------------------------------------------------------------
    Unpack the file.
  ---------------------------------------------------------------------------*/

    defer_leftover_input(__G);    /* so NEXTBYTE bounds check will work */
    switch (G.lrec.compression_method) {
        case STORED:
            if (!uO.tflag && QCOND2) {
#ifdef SYMLINKS
                if (G.symlnk)   /* can also be deflated, but rarer... */
                    Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                      "link", FnFilter1(G.filename), avmark, "", "", ""));
                else
#endif /* SYMLINKS */
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "extract", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.lrec.ucsize == 0L? nul : (G.pInfo->textfile? txt :
                  bin)), uO.cflag? NEWLINE : ""));
            }
#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
            if (G.redirect_slide) {
                wsize = G.redirect_size; redirSlide = G.redirect_buffer;
            } else {
                wsize = WSIZE; redirSlide = slide;
            }
#endif
            G.outptr = redirSlide;
            G.outcnt = 0L;
            while ((b = NEXTBYTE) != EOF) {
                *G.outptr++ = (uch)b;
                if (++G.outcnt == wsize) {
                    error = flush(__G__ redirSlide, G.outcnt, 0);
                    G.outptr = redirSlide;
                    G.outcnt = 0L;
                    if (error != PK_COOL || G.disk_full) break;
                }
            }
            if (G.outcnt) {        /* flush final (partial) buffer */
                r = flush(__G__ redirSlide, G.outcnt, 0);
                if (error < r) error = r;
            }
            break;

#ifndef SFX
#ifdef USE_OLDUNZIP
        case SHRUNK:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  LoadFarStringSmall(Unshrink), FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.pInfo->textfile? txt : bin), uO.cflag? NEWLINE : ""));
            }
            if ((r = unshrink(__G)) != PK_COOL) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile), r == PK_MEM3 ?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Unshrink),
                          FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile), r == PK_MEM3 ?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Unshrink)));
                }
                error = r;
            }
            break;

        case REDUCED1:
        case REDUCED2:
        case REDUCED3:
        case REDUCED4:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "unreduc", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.pInfo->textfile? txt : bin), uO.cflag? NEWLINE : ""));
            }
            if ((r = unreduce(__G)) != PK_COOL) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile), r == PK_MEM3 ?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Unreduce),
                          FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile), r == PK_MEM3 ?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Unreduce)));
                }
                error = r;
            }
            break;
#endif /* USE_OLDUNZIP */

        case IMPLODED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "explod", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.pInfo->textfile? txt : bin), uO.cflag? NEWLINE : ""));
            }
            if ((r = explode(__G)) != 0) {
                if (r == 5) { /* treat 5 specially */
                    int warning = ((zusz_t)G.used_csize <= G.lrec.csize);

                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarString(LengthMsg),
                          "", warning ? "warning" : "error",
                          FmZofft(G.used_csize, NULL, NULL),
                          FmZofft(G.lrec.ucsize, NULL, "u"),
                          warning ? "  " : "",
                          FmZofft(G.lrec.csize, NULL, "u"),
                          " [", FnFilter1(G.filename), "]"));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarString(LengthMsg),
                          "\n", warning ? "warning" : "error",
                          FmZofft(G.used_csize, NULL, NULL),
                          FmZofft(G.lrec.ucsize, NULL, "u"),
                          warning ? "  " : "",
                          FmZofft(G.lrec.csize, NULL, "u"),
                          "", "", "."));
                    error = warning ? PK_WARN : PK_ERR;
                } else if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile), r == 3?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Explode),
                          FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile), r == 3?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Explode)));
                    error = ((r == 3) ? PK_MEM3 : PK_ERR);
                } else {
                    error = r;
                }
            }
            break;
        case DCLIMPLODED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "explod", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.pInfo->textfile? txt : bin), uO.cflag? NEWLINE : ""));
            }
            if ((r = dcl_explode(__G)) != 0) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile),
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Explode),
                          FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile),
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Explode)));
                    error = PK_ERR;
                } else {
                    error = r;
                }
            }
            break;
#endif /* !SFX */

#ifdef USE_LZMA
        case LZMAED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "decod", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 ? "" : (G.pInfo->textfile ? txt : bin)),
                  uO.cflag ? NEWLINE : ""));
            }
            r = uz_lzma_decompress(__G);
            if (r != PK_COOL) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          "LZMA", FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData), "LZMA"));
                    error = (r == PK_MEM3) ? PK_MEM3 : PK_ERR;
                } else
                    error = r;
            }
            break;
#endif /* USE_LZMA */

#ifdef USE_XZ
        case XZED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "decod", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 ? "" : (G.pInfo->textfile ? txt : bin)),
                  uO.cflag ? NEWLINE : ""));
            }
            r = uz_xz_decompress(__G);
            if (r != PK_COOL) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          "XZ", FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData), "XZ"));
                    error = (r == PK_MEM3) ? PK_MEM3 : PK_ERR;
                } else
                    error = r;
            }
            break;
#endif /* USE_XZ */

#ifdef USE_ZSTD
        case ZSTD_OLD:
        case ZSTDED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "decod", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 ? "" : (G.pInfo->textfile ? txt : bin)),
                  uO.cflag ? NEWLINE : ""));
            }
            r = uz_zstd_decompress(__G);
            if (r != PK_COOL) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          "Zstandard", FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData), "Zstandard"));
                    error = (r == PK_MEM3) ? PK_MEM3 : PK_ERR;
                } else
                    error = r;
            }
            break;
#endif /* USE_ZSTD */

#ifdef USE_PPMD
        case PPMDED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "decod", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 ? "" : (G.pInfo->textfile ? txt : bin)),
                  uO.cflag ? NEWLINE : ""));
            }
            r = uz_ppmd_decompress(__G);
            if (r != PK_COOL) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          "PPMd", FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile),
                          r == PK_MEM3 ? LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData), "PPMd"));
                    error = (r == PK_MEM3) ? PK_MEM3 : PK_ERR;
                } else
                    error = r;
            }
            break;
#endif /* USE_PPMD */

        case DEFLATED:
#ifdef USE_DEFLATE64
        case ENHDEFLATED:
#endif
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "inflat", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.pInfo->textfile? txt : bin), uO.cflag? NEWLINE : ""));
            }
#ifndef USE_ZLIB  /* zlib's function is called inflate(), too */
#  define UZinflate inflate
#endif
            if ((r = UZinflate(__G__
                               (G.lrec.compression_method == ENHDEFLATED)))
                != 0) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile), r == 3?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Inflate),
                          FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile), r == 3?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(Inflate)));
                    error = ((r == 3) ? PK_MEM3 : PK_ERR);
                } else {
                    error = r;
                }
            }
            break;

#ifdef USE_BZIP2
        case BZIPPED:
            if (!uO.tflag && QCOND2) {
                Info(slide, 0, ((char *)slide, LoadFarString(ExtractMsg),
                  "bunzipp", FnFilter1(G.filename), avmark, avsep,
                  (uO.aflag != 1 /* && G.pInfo->textfile==G.pInfo->textmode */)?
                  "" : (G.pInfo->textfile? txt : bin), uO.cflag? NEWLINE : ""));
            }
            if ((r = UZbunzip2(__G)) != 0) {
                if (r < PK_DISK) {
                    if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipFile), r == 3?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(BUnzip),
                          FnFilter1(G.filename)));
                    else
                        Info(slide, 0x401, ((char *)slide,
                          LoadFarStringSmall(ErrUnzipNoFile), r == 3?
                          LoadFarString(NotEnoughMem) :
                          LoadFarString(InvalidComprData),
                          LoadFarStringSmall2(BUnzip)));
                    error = ((r == 3) ? PK_MEM3 : PK_ERR);
                } else {
                    error = r;
                }
            }
            break;
#endif /* USE_BZIP2 */

        default:   /* should never get to this point */
            Info(slide, 0x401, ((char *)slide,
              LoadFarString(FileUnknownCompMethod), FnFilter1(G.filename)));
            /* close and delete file before return? */
            undefer_input(__G);
            return PK_WARN;

    } /* end switch (compression method) */

/*---------------------------------------------------------------------------
    Close the file and set its date and time (not necessarily in that order),
    and make sure the CRC checked out OK.  Logical-AND the CRC for 64-bit
    machines (redundant on 32-bit machines).
  ---------------------------------------------------------------------------*/

#ifdef VMS                  /* VMS:  required even for stdout! (final flush) */
    if (!uO.tflag)           /* don't close NULL file */
        error = close_outfile(__G);
#else
#ifdef DLL
    if (!uO.tflag && (!uO.cflag || G.redirect_data)) {
        if (G.redirect_data)
            FINISH_REDIRECT();
        else
            error = close_outfile(__G);
    }
#else
    if (!uO.tflag && !uO.cflag)   /* don't close NULL file or stdout */
        error = close_outfile(__G);
#endif
#endif /* VMS */

    if (G.disk_full) {            /* set by flush() */
        if (G.disk_full > 1) {
#if (defined(DELETE_IF_FULL) && defined(HAVE_UNLINK))
            /* delete the incomplete file if we can */
            if (unlink(G.filename) != 0)
                Trace((stderr, "extract.c:  could not delete %s\n",
                  FnFilter1(G.filename)));
#else
            /* warn user about the incomplete file */
            Info(slide, 0x421, ((char *)slide, LoadFarString(FileTruncated),
              FnFilter1(G.filename)));
#endif
            error = PK_DISK;
        } else {
            error = PK_WARN;
        }
    }

    if (error > PK_WARN) {/* don't print redundant CRC error if error already */
        undefer_input(__G);
        return error;
    }
#ifdef PKAV_SUPPORT
    pkav_complete_member(__G);
#endif
    if (G.fwkcs_active) {
        unsigned idx = (unsigned)(G.pInfo - G.info);
        fwkcs_md5_final(__G__ fwkcs_digest);
        if (memcmp(fwkcs_digest, G.fwkcs_expected + idx * 16U, 16) != 0) {
            static ZCONST char hex[] = "0123456789abcdef";
            ZCONST uch *expected = G.fwkcs_expected + idx * 16U;
            int i;

            for (i = 0; i < 16; ++i) {
                fwkcs_actual_hex[i << 1] = hex[fwkcs_digest[i] >> 4];
                fwkcs_actual_hex[(i << 1) + 1] = hex[fwkcs_digest[i] & 0x0f];
                fwkcs_expected_hex[i << 1] = hex[expected[i] >> 4];
                fwkcs_expected_hex[(i << 1) + 1] = hex[expected[i] & 0x0f];
            }
            fwkcs_actual_hex[32] = '\0';
            fwkcs_expected_hex[32] = '\0';
            fwkcs_error = PK_ERR;
        } else
            ++G.fwkcs_verified;
    } else if (G.pInfo->fwkcs_bad) {
        fwkcs_error = PK_WARN;
    }
    G.fwkcs_active = FALSE;
#ifndef NO_AES
    G.aes_active=0;
    iz_aes_wipe(&G.aes_ctx,sizeof(G.aes_ctx));
    /* AE-2 normally has CRC32=0 and relies on its verified HMAC.
     * Some third-party AE-2 writers include a real CRC; verify it when
     * present instead of silently ignoring it. */
    if(G.pInfo->aes_strength && G.pInfo->aes_version==2 &&
       G.lrec.crc32==0)
        crc_bad=FALSE;
    else
#endif
    crc_bad = (G.crc32val != G.lrec.crc32);
    if (crc_bad) {
        /* if quiet enough, we haven't output the filename yet:  do it */
        if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
            Info(slide, 0x401, ((char *)slide, "%-22s ",
              FnFilter1(G.filename)));
        Info(slide, 0x401, ((char *)slide, LoadFarString(BadCRC), G.crc32val,
          G.lrec.crc32, test_avmark));
#if CRYPT
        if (G.pInfo->encrypted)
            Info(slide, 0x401, ((char *)slide, LoadFarString(MaybeBadPasswd)));
#endif
        error = PK_ERR;
    }
    if (fwkcs_error != PK_COOL) {
        if (crc_bad) {
            if (fwkcs_error == PK_ERR) {
                Info(slide, 0x401, ((char *)slide,
                  "        FWKCS MD5 mismatch: %s\n", FnFilter1(G.filename)));
                Info(slide, 0x401, ((char *)slide,
                  "        %s (should be %s)\n",
                  fwkcs_actual_hex, fwkcs_expected_hex));
            } else
                Info(slide, 0x401, ((char *)slide,
                  "        warning: malformed FWKCS MD5 extra field: %s\n",
                  FnFilter1(G.filename)));
        } else {
            if ((uO.tflag && uO.qflag) || (!uO.tflag && !QCOND2))
                Info(slide, 0x401, ((char *)slide, "%-22s ",
                  FnFilter1(G.filename)));
            if (fwkcs_error == PK_ERR) {
                Info(slide, 0x401, ((char *)slide,
                  "FWKCS MD5 mismatch%s\n", test_avmark));
                Info(slide, 0x401, ((char *)slide,
                  "        %s (should be %s)\n",
                  fwkcs_actual_hex, fwkcs_expected_hex));
            } else
                Info(slide, 0x401, ((char *)slide,
                  "warning: malformed FWKCS MD5 extra field%s\n",
                  test_avmark));
        }
        if (fwkcs_error > error)
            error = fwkcs_error;
    } else if (!crc_bad && uO.tflag) {
#ifndef SFX
        if (G.extra_field) {
            if ((r = TestExtraField(__G__ G.extra_field,
                                    G.lrec.extra_field_length)) > error)
                error = r;
        } else
#endif /* !SFX */
        if (!uO.qflag)
            Info(slide, 0, ((char *)slide, " OK%s\n", test_avmark));
    } else {
        if (QCOND2 && !error)   /* GRR:  is stdout reset to text mode yet? */
            Info(slide, 0, ((char *)slide, "\n"));
    }

    undefer_input(__G);
#ifndef NO_AES
    /* The already verified 10-byte authentication code is outside the
     * encrypted compressed stream and precedes the ZIP data descriptor. */
    if (G.pInfo->aes_strength) {
        uch auth_after_data[10];
        if (readbuf(__G__ (char *)auth_after_data, 10) != 10)
            error = PK_ERR;
    }
#endif
    if ((G.lrec.general_purpose_bit_flag & 8) != 0) {
        // Read and verify the data descriptor.  Keeping the read pointer just
        // after the descriptor also lets the component-overlap check include
        // the descriptor when zip-bomb detection is enabled.
        //
        // We need to resolve an ambiguity over four possible data descriptor
        // formats. We check for all four, and pick the longest match. The data
        // descriptor can have a signature or not, and it can use four or
        // eight-byte lengths. The zip format requires resolving the ambiguity
        // of a signature or not, but it uses the zip64 flag to determine
        // whether the lengths are four or eight bytes. However there is a bug
        // in the Java zip library that applies the wrong value of that flag.
        // This works around that bug by always trying both length formats.
        //
        // So why the longest match? And does this resolve the ambiguity? No,
        // it doesn't definitively resolve the ambiguity. However choosing the
        // longest match at least resolves it for a normal zip file, where the
        // bytes following the data descriptor must be another zip signature
        // that is not a data descriptor signature. There are a few specific
        // cases for which more than one of the formats will match the given
        // CRC and lengths. The most plausible is between four and eight-byte
        // lengths, either with or without a signature. That only occurs for an
        // entry with an uncompressed size of zero. We consider the data
        // descriptor to be a vector of four-byte values. Then the possible
        // data descriptors are [(s) 0 c 0] and [(s) 0 c 0 0 0], where (s) is
        // the optional signature, and c is the compressed length. c would be
        // two for the Deflate compressed data format. These look the same, so
        // if the file contains [(s) 0 c 0 0 0], then we cannot discriminate
        // them. However if the data descriptor was intended to be [(s) 0 c 0],
        // then it has been followed by eight zero bytes in the zip file for
        // some reason. For a normal zip file this cannot be the case. The data
        // descriptor would always be immediately followed by another zip file
        // signature, which is four bytes that are not zeros. The other cases
        // where more than one format matches are vanishingly unlikely, but the
        // longest match strategy resolves those as well in a normal zip file.
        // Those pairs are [s s s] vs. [s s s s], [s s s] vs. [s s s 0 s 0],
        // and [s s s s s] vs. [s s s s s s]. For all, s is the signature for a
        // data descriptor. For the first two we have an entry whose CRC,
        // compressed length, and uncompressed length are all equal (!), and
        // are all equal to the signature (!!). If this occurs, clearly someone
        // is messing with us. However the strategy works nonetheless. We see
        // that if the shorter descriptor, [s s s] were what was intended, then
        // it has been followed by either four zero bytes or a data descriptor
        // signature. Neither can occur for a normal zip file, where it must be
        // followed by a signature that is not a data descriptor signature. So
        // the longest match is the correct choice. The final case is outright
        // insane, since the compressed and uncompressed lengths are the data
        // descriptor signature repeated twice to make a 64-bit length, which
        // is about 6e17. The largest drive available as I write this is 100TB,
        // which is one six thousandth of that length. If I apply Moore's law
        // to drive capacity, we might get to 6e17 about 25 years from now. If
        // this code is still in use then (I've seen other code I've written in
        // use for over 30 years), then we're still in luck. A data descriptor
        // cannot be followed by a data descriptor signature in a normal zip
        // file. The longest match strategy continues to work.
        //
        // So what is a not normal zip file, where these assumptions might fall
        // apart? zip files have been used in a non-standard way as a poor
        // substitute for a file system, with entries deleted and perhaps
        // others replacing them partially, with fragmented zip files being the
        // result. Then all bets are off as to what might or might not follow a
        // data descriptor. Though if this sort of data descriptor ambiguity
        // falls in one of those gaps, then there should be no adverse
        // consequences for picking the unintended one.
        int len = 0;
#       define SIG 0x08074b50           // optional data descriptor signature
#ifdef LARGE_FILE_SUPPORT
        uch buf[24];
        int got = readbuf(__G__ (char *)buf, sizeof(buf));
        if (got >= 24 && makelong(buf) == SIG &&
                         makelong(buf + 4) == G.lrec.crc32 &&
                         makeint64(buf + 8) == G.lrec.csize &&
                         makeint64(buf + 16) == G.lrec.ucsize)
            // Have a data descriptor with a signature and 64-bit lengths.
            len = 24;
        else if (got >= 20 && makelong(buf) == G.lrec.crc32 &&
                              makeint64(buf + 4) == G.lrec.csize &&
                              makeint64(buf + 12) == G.lrec.ucsize)
            // Have a data descriptor with no signature and 64-bit lengths.
            len = 20;
        else if ((G.lrec.csize >> 32) == 0 && (G.lrec.ucsize >> 32) == 0)
            // Both lengths are short enough to fit in 32 bits.
#else
        uch buf[16];
        int got = readbuf(__G__ (char *)buf, sizeof(buf));
#endif
        {
            if (got >= 16 && makelong(buf) == SIG &&
                             makelong(buf + 4) == G.lrec.crc32 &&
                             makelong(buf + 8) == G.lrec.csize &&
                             makelong(buf + 12) == G.lrec.ucsize)
                // Have a data descriptor with a signature and 32-bit lengths.
                len = 16;
            else if (got >= 12 && makelong(buf) == G.lrec.crc32 &&
                                  makelong(buf + 4) == G.lrec.csize &&
                                  makelong(buf + 8) == G.lrec.ucsize)
                // Have a data descriptor with no signature and 32-bit lengths.
                len = 12;
        }
        if (len == 0)
            // There is no data descriptor that matches the entry CRC and
            // length values.
            error = PK_ERR;

        // Back up got-len bytes, to position the read pointer after the data
        // descriptor. Or to where the data descriptor was supposed to be, in
        // the event none was found.
        int back = got - len;
        if (G.incnt + back > INBUFSIZ) {
            // Need to load the preceding buffer. We've been here before.
            G.cur_zipfile_bufstart -= INBUFSIZ;
#ifdef USE_STRM_INPUT
            zfseeko(G.zipfd, G.cur_zipfile_bufstart, SEEK_SET);
#else /* !USE_STRM_INPUT */
            zlseek(G.zipfd, G.cur_zipfile_bufstart, SEEK_SET);
#endif /* ?USE_STRM_INPUT */
            read(G.zipfd, (char *)G.inbuf, INBUFSIZ);
            G.incnt -= INBUFSIZ - back;
            G.inptr += INBUFSIZ - back;
        }
        else {
            // Back up within current buffer.
            G.incnt += back;
            G.inptr -= back;
        }
    }
    return error;

} /* end function extract_or_test_member() */





#ifndef SFX

/*******************************/
/*  Function TestExtraField()  */
/*******************************/

static int TestExtraField(__G__ ef, ef_len)
    __GDEF
    uch *ef;
    unsigned ef_len;
{
    ush ebID;
    unsigned ebLen;
    unsigned eb_cmpr_offs = 0;
    int r;

    /* we know the regular compressed file data tested out OK, or else we
     * wouldn't be here ==> print filename if any extra-field errors found
     */
    while (ef_len >= EB_HEADSIZE) {
        ebID = makeword(ef);
        ebLen = (unsigned)makeword(ef+EB_LEN);

        if (ebLen > (ef_len - EB_HEADSIZE))
        {
           /* Discovered some extra field inconsistency! */
            if (uO.qflag)
                Info(slide, 1, ((char *)slide, "%-22s ",
                  FnFilter1(G.filename)));
            Info(slide, 1, ((char *)slide, LoadFarString(InconsistEFlength),
              ebLen, (ef_len - EB_HEADSIZE)));
            return PK_ERR;
        }

        switch (ebID) {
            case EF_OS2:
            case EF_ACL:
            case EF_MAC3:
            case EF_BEOS:
            case EF_ATHEOS:
                switch (ebID) {
                  case EF_OS2:
                  case EF_ACL:
                    eb_cmpr_offs = EB_OS2_HLEN;
                    break;
                  case EF_MAC3:
                    if (ebLen >= EB_MAC3_HLEN &&
                        (makeword(ef+(EB_HEADSIZE+EB_FLGS_OFFS))
                         & EB_M3_FL_UNCMPR) &&
                        (makelong(ef+EB_HEADSIZE) == ebLen - EB_MAC3_HLEN))
                        eb_cmpr_offs = 0;
                    else
                        eb_cmpr_offs = EB_MAC3_HLEN;
                    break;
                  case EF_BEOS:
                  case EF_ATHEOS:
                    if (ebLen >= EB_BEOS_HLEN &&
                        (*(ef+(EB_HEADSIZE+EB_FLGS_OFFS)) & EB_BE_FL_UNCMPR) &&
                        (makelong(ef+EB_HEADSIZE) == ebLen - EB_BEOS_HLEN))
                        eb_cmpr_offs = 0;
                    else
                        eb_cmpr_offs = EB_BEOS_HLEN;
                    break;
                }
                if ((r = test_compr_eb(__G__ ef, ebLen, eb_cmpr_offs, NULL))
                    != PK_OK) {
                    if (uO.qflag)
                        Info(slide, 1, ((char *)slide, "%-22s ",
                          FnFilter1(G.filename)));
                    switch (r) {
                        case IZ_EF_TRUNC:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(TruncEAs),
                              ebLen-(eb_cmpr_offs+EB_CMPRHEADLEN), "\n"));
                            break;
                        case PK_ERR:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(InvalidComprDataEAs)));
                            break;
                        case PK_MEM3:
                        case PK_MEM4:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(NotEnoughMemEAs)));
                            break;
                        default:
                            if ((r & 0xff) != PK_ERR)
                                Info(slide, 1, ((char *)slide,
                                  LoadFarString(UnknErrorEAs)));
                            else {
                                ush m = (ush)(r >> 8);
                                if (m == DEFLATED)            /* GRR KLUDGE! */
                                    Info(slide, 1, ((char *)slide,
                                      LoadFarString(BadCRC_EAs)));
                                else
                                    Info(slide, 1, ((char *)slide,
                                      LoadFarString(UnknComprMethodEAs), m));
                            }
                            break;
                    }
                    return r;
                }
                break;

            case EF_NTSD:
                Trace((stderr, "ebID: %i / ebLen: %u\n", ebID, ebLen));
                r = ebLen < EB_NTSD_L_LEN ? IZ_EF_TRUNC :
                    ((ef[EB_HEADSIZE+EB_NTSD_VERSION] > EB_NTSD_MAX_VER) ?
                     (PK_WARN | 0x4000) :
                     test_compr_eb(__G__ ef, ebLen, EB_NTSD_L_LEN, TEST_NTSD));
                if (r != PK_OK) {
                    if (uO.qflag)
                        Info(slide, 1, ((char *)slide, "%-22s ",
                          FnFilter1(G.filename)));
                    switch (r) {
                        case IZ_EF_TRUNC:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(TruncNTSD),
                              ebLen-(EB_NTSD_L_LEN+EB_CMPRHEADLEN), "\n"));
                            break;
#if (defined(WIN32) && defined(NTSD_EAS))
                        case PK_WARN:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(InvalidSecurityEAs)));
                            break;
#endif
                        case PK_ERR:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(InvalidComprDataEAs)));
                            break;
                        case PK_MEM3:
                        case PK_MEM4:
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(NotEnoughMemEAs)));
                            break;
                        case (PK_WARN | 0x4000):
                            Info(slide, 1, ((char *)slide,
                              LoadFarString(UnsuppNTSDVersEAs),
                              (int)ef[EB_HEADSIZE+EB_NTSD_VERSION]));
                            r = PK_WARN;
                            break;
                        default:
                            if ((r & 0xff) != PK_ERR)
                                Info(slide, 1, ((char *)slide,
                                  LoadFarString(UnknErrorEAs)));
                            else {
                                ush m = (ush)(r >> 8);
                                if (m == DEFLATED)            /* GRR KLUDGE! */
                                    Info(slide, 1, ((char *)slide,
                                      LoadFarString(BadCRC_EAs)));
                                else
                                    Info(slide, 1, ((char *)slide,
                                      LoadFarString(UnknComprMethodEAs), m));
                            }
                            break;
                    }
                    return r;
                }
                break;
            case EF_PKVMS:
                /* 2015-01-30 SMS.  Added sufficient-bytes test/message
                 * here.  (Removed defective ebLen test above.)
                 *
                 * If sufficient bytes (EB_PKVMS_MINLEN) are available,
                 * then compare the stored CRC value with the calculated
                 * CRC for the remainder of the data (and complain about
                 * a mismatch).
                 */
                if (ebLen < EB_PKVMS_MINLEN)
                {
                    /* Insufficient bytes available. */
                    Info( slide, 1,
                     ((char *)slide, LoadFarString( TooSmallEBlength),
                     ebLen, EB_PKVMS_MINLEN));
                }
                else if (makelong(ef+ EB_HEADSIZE) !=
                 crc32(CRCVAL_INITIAL,
                 (ef+ EB_HEADSIZE+ EB_PKVMS_MINLEN),
                 (extent)(ebLen- EB_PKVMS_MINLEN)))
                {
                     Info(slide, 1, ((char *)slide,
                       LoadFarString(BadCRC_EAs)));
                }
                break;
            case EF_PKW32:
            case EF_PKUNIX:
            case EF_ASIUNIX:
            case EF_IZVMS:
            case EF_IZUNIX:
            case EF_VMCMS:
            case EF_MVS:
            case EF_SPARK:
            case EF_TANDEM:
            case EF_THEOS:
            case EF_AV:
            default:
                break;
        }
        ef_len -= (ebLen + EB_HEADSIZE);
        ef += (ebLen + EB_HEADSIZE);
    }

    if (!uO.qflag)
        Info(slide, 0, ((char *)slide, " OK%s\n",
#ifdef PKAV_SUPPORT
          pkav_active_member(__G) ? " -AV" : ""
#else
          ""
#endif
          ));

    return PK_COOL;

} /* end function TestExtraField() */





/******************************/
/*  Function test_compr_eb()  */
/******************************/

#ifdef PROTO
static int test_compr_eb(
    __GPRO__
    uch *eb,
    unsigned eb_size,
    unsigned compr_offset,
    int (*test_uc_ebdata)(__GPRO__ uch *eb, unsigned eb_size,
                          uch *eb_ucptr, ulg eb_ucsize))
#else /* !PROTO */
static int test_compr_eb(__G__ eb, eb_size, compr_offset, test_uc_ebdata)
    __GDEF
    uch *eb;
    unsigned eb_size;
    unsigned compr_offset;
    int (*test_uc_ebdata)();
#endif /* ?PROTO */
{
    ulg eb_ucsize;
    uch *eb_ucptr;
    int r;
    ush method;

    if (compr_offset < 4)                /* field is not compressed: */
        return PK_OK;                    /* do nothing and signal OK */

    /* Return no/bad-data error status if any problem is found:
     *    1. eb_size is too small to hold the uncompressed size
     *       (eb_ucsize).  (Else extract eb_ucsize.)
     *    2. eb_ucsize is zero (invalid).  2014-12-04 SMS.
     *    3. eb_ucsize is positive, but eb_size is too small to hold
     *       the compressed data header.
     */
    if ((eb_size < (EB_UCSIZE_P + 4)) ||
     ((eb_ucsize = makelong( eb+ (EB_HEADSIZE+ EB_UCSIZE_P))) == 0L) ||
     ((eb_ucsize > 0L) && (eb_size <= (compr_offset + EB_CMPRHEADLEN))))
        return IZ_EF_TRUNC;             /* no/bad compressed data! */

    method = makeword(eb + (EB_HEADSIZE + compr_offset));
    if ((method == STORED) && (eb_size != compr_offset + EB_CMPRHEADLEN + eb_ucsize))
        return PK_ERR;            /* compressed & uncompressed
                                   * should match in STORED
                                   * method */

    if (
#ifdef INT_16BIT
        (((ulg)(extent)eb_ucsize) != eb_ucsize) ||
#endif
        (eb_ucptr = (uch *)malloc((extent)eb_ucsize)) == (uch *)NULL)
        return PK_MEM4;

    r = memextract(__G__ eb_ucptr, eb_ucsize,
                   eb + (EB_HEADSIZE + compr_offset),
                   (ulg)(eb_size - compr_offset));

    if (r == PK_OK && test_uc_ebdata != NULL)
        r = (*test_uc_ebdata)(__G__ eb, eb_size, eb_ucptr, eb_ucsize);

    free(eb_ucptr);
    return r;

} /* end function test_compr_eb() */

#endif /* !SFX */





/***************************/
/*  Function memextract()  */
/***************************/

int memextract(__G__ tgt, tgtsize, src, srcsize)  /* extract compressed */
    __GDEF                                        /*  extra field block; */
    uch *tgt;                                     /*  return PK-type error */
    ulg tgtsize;                                  /*  level */
    ZCONST uch *src;
    ulg srcsize;
{
    zoff_t old_csize=G.csize;
    uch   *old_inptr=G.inptr;
    int    old_incnt=G.incnt;
    int    r, error=PK_OK;
    ush    method;
    ulg    extra_field_crc;


    method = makeword(src);
    extra_field_crc = makelong(src+2);

    /* compressed extra field exists completely in memory at this location: */
    G.inptr = (uch *)src + (2 + 4);     /* method and extra_field_crc */
    G.incnt = (int)(G.csize = (long)(srcsize - (2 + 4)));
    G.mem_mode = TRUE;
    G.outbufptr = tgt;
    G.outsize = tgtsize;

    switch (method) {
        case STORED:
            memcpy((char *)tgt, (char *)G.inptr, (extent)G.incnt);
            G.outcnt = (ulg)G.csize;    /* for CRC calculation */
            break;
        case DEFLATED:
#ifdef USE_DEFLATE64
        case ENHDEFLATED:
#endif
            G.outcnt = 0L;
            if ((r = UZinflate(__G__ (method == ENHDEFLATED))) != 0) {
                if (!uO.tflag)
                    Info(slide, 0x401, ((char *)slide,
                      LoadFarStringSmall(ErrUnzipNoFile), r == 3?
                      LoadFarString(NotEnoughMem) :
                      LoadFarString(InvalidComprData),
                      LoadFarStringSmall2(Inflate)));
                error = (r == 3)? PK_MEM3 : PK_ERR;
            }
            if (G.outcnt == 0L)   /* inflate's final FLUSH sets outcnt */
                break;
            break;
        default:
            if (uO.tflag)
                error = PK_ERR | ((int)method << 8);
            else {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(UnsupportedExtraField), method));
                error = PK_ERR;  /* GRR:  should be passed on up via SetEAs() */
            }
            break;
    }

    G.inptr = old_inptr;
    G.incnt = old_incnt;
    G.csize = old_csize;
    G.mem_mode = FALSE;

    if (!error) {
        register ulg crcval = crc32(CRCVAL_INITIAL, tgt, (extent)G.outcnt);

        if (crcval != extra_field_crc) {
            if (uO.tflag)
                error = PK_ERR | (DEFLATED << 8);  /* kludge for now */
            else {
                Info(slide, 0x401, ((char *)slide,
                  LoadFarString(BadExtraFieldCRC), G.zipfn, crcval,
                  extra_field_crc));
                error = PK_ERR;
            }
        }
    }
    return error;

} /* end function memextract() */





/*************************/
/*  Function memflush()  */
/*************************/

int memflush(__G__ rawbuf, size)
    __GDEF
    ZCONST uch *rawbuf;
    ulg size;
{
    if (size > G.outsize)
        /* Here, PK_DISK is a bit off-topic, but in the sense of marking
           "overflow of output space", its use may be tolerated. */
        return PK_DISK;   /* more data than output buffer can hold */



    memcpy((char *)G.outbufptr, (char *)rawbuf, (extent)size);
    G.outbufptr += (unsigned int)size;
    G.outsize -= size;
    G.outcnt += size;

    return 0;

} /* end function memflush() */





#if (defined(VMS) || defined(VMS_TEXT_CONV))

/************************************/
/*  Function extract_izvms_block()  */
/************************************/

/*
 * Extracts block from p. If resulting length is less than needed, fill
 * extra space with corresponding bytes from 'init'.
 * Currently understands 3 formats of block compression:
 * - Simple storing
 * - Compression of zero bytes to zero bits
 * - Deflation (see memextract())
 * The IZVMS block data is returned in malloc'd space.
 */
uch *extract_izvms_block(__G__ ebdata, size, retlen, init, needlen)
    __GDEF
    ZCONST uch *ebdata;
    unsigned size;
    unsigned *retlen;
    ZCONST uch *init;
    unsigned needlen;
{
    uch *ucdata;       /* Pointer to block allocated */
    int cmptype;
    unsigned usiz, csiz;

    cmptype = (makeword(ebdata+EB_IZVMS_FLGS) & EB_IZVMS_BCMASK);
    csiz = size - EB_IZVMS_HLEN;
    usiz = (cmptype == EB_IZVMS_BCSTOR ?
            csiz : makeword(ebdata+EB_IZVMS_UCSIZ));

    if (retlen)
        *retlen = usiz;

    if ((ucdata = (uch *)malloc(MAX(needlen, usiz))) == NULL)
        return NULL;

    if (init && (usiz < needlen))
        memcpy((char *)ucdata, (ZCONST char *)init, needlen);

    switch (cmptype)
    {
        case EB_IZVMS_BCSTOR: /* The simplest case */
            memcpy(ucdata, ebdata+EB_IZVMS_HLEN, usiz);
            break;
        case EB_IZVMS_BC00:
            decompress_bits(ucdata, usiz, ebdata+EB_IZVMS_HLEN);
            break;
        case EB_IZVMS_BCDEFL:
            memextract(__G__ ucdata, (ulg)usiz,
                       ebdata+EB_IZVMS_HLEN, (ulg)csiz);
            break;
        default:
            free(ucdata);
            ucdata = NULL;
    }
    return ucdata;

} /* end of extract_izvms_block */





/********************************/
/*  Function decompress_bits()  */
/********************************/
/*
 *  Simple uncompression routine. The compression uses bit stream.
 *  Compression scheme:
 *
 *  if (byte!=0)
 *      putbit(1),putbyte(byte)
 *  else
 *      putbit(0)
 */
static void decompress_bits(outptr, needlen, bitptr)
    uch *outptr;        /* Pointer into output block */
    unsigned needlen;   /* Size of uncompressed block */
    ZCONST uch *bitptr; /* Pointer into compressed data */
{
    ulg bitbuf = 0;
    int bitcnt = 0;

#define _FILL   {       bitbuf |= (*bitptr++) << bitcnt;\
                        bitcnt += 8;                    \
                }

    while (needlen--)
    {
        if (bitcnt <= 0)
            _FILL;

        if (bitbuf & 1)
        {
            bitbuf >>= 1;
            if ((bitcnt -= 1) < 8)
                _FILL;
            *outptr++ = (uch)bitbuf;
            bitcnt -= 8;
            bitbuf >>= 8;
        }
        else
        {
            *outptr++ = '\0';
            bitcnt -= 1;
            bitbuf >>= 1;
        }
    }
} /* end function decompress_bits() */

#endif /* VMS || VMS_TEXT_CONV */





#ifdef SYMLINKS
/***********************************/
/* Function set_deferred_symlink() */
/***********************************/

static void set_deferred_symlink(__G__ slnk_entry)
    __GDEF
    slinkentry *slnk_entry;
{
    extent ucsize = slnk_entry->targetlen;
    char *linkfname = slnk_entry->fname;
    char *linktarget = (char *)malloc(ucsize+1);

    if (!linktarget) {
        Info(slide, 0x201, ((char *)slide,
          LoadFarString(SymLnkWarnNoMem), FnFilter1(linkfname)));
        return;
    }
    linktarget[ucsize] = '\0';
    G.outfile = zfopen(linkfname, FOPR); /* open link placeholder for reading */
    /* Check that the following conditions are all fulfilled:
     * a) the placeholder file exists,
     * b) the placeholder file contains exactly "ucsize" bytes
     *    (read the expected placeholder content length + 1 extra byte, this
     *    should return the expected content length),
     * c) the placeholder content matches the link target specification as
     *    stored in the symlink control structure.
     */
    if (!G.outfile ||
        fread(linktarget, 1, ucsize+1, G.outfile) != ucsize ||
        strcmp(slnk_entry->target, linktarget))
    {
        Info(slide, 0x201, ((char *)slide,
          LoadFarString(SymLnkWarnInvalid), FnFilter1(linkfname)));
        free(linktarget);
        if (G.outfile)
            fclose(G.outfile);
        return;
    }
    fclose(G.outfile);                  /* close "data" file for good... */
    unlink(linkfname);                  /* ...and delete it */
    if (QCOND2)
        Info(slide, 0, ((char *)slide, LoadFarString(SymLnkFinish),
          FnFilter1(linkfname), FnFilter2(linktarget)));
    if (symlink(linktarget, linkfname))  /* create the real link */
        perror("symlink error");
    free(linktarget);
#ifdef SET_SYMLINK_ATTRIBS
    set_symlnk_attribs(__G__ slnk_entry);
#endif
    return;                             /* can't set time on symlinks */

} /* end function set_deferred_symlink() */
#endif /* SYMLINKS */

/*
 * If Unicode is supported, assume we have what we need to do this
 * check using wide characters, avoiding MBCS issues.
 */

#ifndef UZ_FNFILTER_REPLACECHAR
        /* A convenient choice for the replacement of unprintable char codes is
         * the "single char wildcard", as this character is quite unlikely to
         * appear in filenames by itself.  The following default definition
         * sets the replacement char to a question mark as the most common
         * "single char wildcard"; this setting should be overridden in the
         * appropiate system-specific configuration header when needed.
         */
# define UZ_FNFILTER_REPLACECHAR      '?'
#endif

/*************************/
/*  Function fnfilter()  */        /* here instead of in list.c for SFX */
/*************************/

char *fnfilter(raw, space, size)   /* convert name to safely printable form */
    ZCONST char *raw;
    uch *space;
    extent size;
{
#ifndef NATIVE   /* ASCII:  filter ANSI escape codes, etc. */
    ZCONST uch *r; // =(ZCONST uch *)raw;
    uch *s=space;
    uch *slim=NULL;
    uch *se=NULL;
    int have_overflow = FALSE;

# if defined( UNICODE_SUPPORT) && defined( _MBCS)
/* If Unicode support is enabled, and we have multi-byte characters,
 * then do the isprint() checks by first converting to wide characters
 * and checking those.  This avoids our having to parse multi-byte
 * characters for ourselves.  After the wide-char replacements have been
 * made, the wide string is converted back to the local character set.
 */
    wchar_t *wstring;    /* wchar_t version of raw */
    size_t wslen;        /* length of wstring */
    wchar_t *wostring;   /* wchar_t version of output string */
    size_t woslen;       /* length of wostring */
    char *newraw;        /* new raw */

    /* 2012-11-06 SMS.
     * Changed to check the value returned by mbstowcs(), and bypass the
     * Unicode processing if it fails.  This seems to fix a problem
     * reported in the SourceForge forum, but it's not clear that we
     * should be doing any Unicode processing without some evidence that
     * the name actually is Unicode.  (Check bit 11 in the flags before
     * coming here?)
     * http://sourceforge.net/p/infozip/bugs/40/
     */

    if (MB_CUR_MAX <= 1)
    {
        /* There's no point to converting multi-byte chars if there are
         * no multi-byte chars.
         */
        wslen = (size_t)-1;
    }
    else
    {
        /* Get Unicode wide character count (for storage allocation). */
        wslen = mbstowcs( NULL, raw, 0);
    }

    if (wslen != (size_t)-1)
    {
        /* Apparently valid Unicode.  Allocate wide-char storage. */
        wstring = (wchar_t *)malloc((wslen + 1) * sizeof(wchar_t));
        if (wstring == NULL) {
            strcpy( (char *)space, raw);
            return (char *)space;
        }
        wostring = (wchar_t *)malloc(2 * (wslen + 1) * sizeof(wchar_t));
        if (wostring == NULL) {
            free(wstring);
            strcpy( (char *)space, raw);
            return (char *)space;
        }

        /* Convert the multi-byte Unicode to wide chars. */
        wslen = mbstowcs(wstring, raw, wslen + 1);

        /* Filter the wide-character string. */
        fnfilterw( wstring, wostring, (2 * (wslen + 1) * sizeof(wchar_t)));

        /* Convert filtered wide chars back to multi-byte. */
        woslen = wcstombs( NULL, wostring, 0);
        if ((newraw = malloc(woslen + 1)) == NULL) {
            free(wstring);
            free(wostring);
            strcpy( (char *)space, raw);
            return (char *)space;
        }
        woslen = wcstombs( newraw, wostring, woslen + 1);

        if (size > 0) {
            slim = space + size - 4;
        }
        r = (ZCONST uch *)newraw;
        while (*r) {
            if (size > 0 && s >= slim && se == NULL) {
                se = s;
            }
#  ifdef QDOS
            if (qlflag & 2) {
                if (*r == '/' || *r == '.') {
                    if (se != NULL && (s > (space + (size-3)))) {
                        have_overflow = TRUE;
                        break;
                    }
                    ++r;
                    *s++ = '_';
                    continue;
                }
            } else
#  endif
            {
                if (se != NULL && (s > (space + (size-3)))) {
                    have_overflow = TRUE;
                    break;
                }
                *s++ = *r++;
            }
        }
        if (have_overflow) {
            strcpy((char *)se, "...");
        } else {
            *s = '\0';
        }

        free(wstring);
        free(wostring);
        free(newraw);
    }
    else
# endif /* defined( UNICODE_SUPPORT) && defined( _MBCS) */
    {
        /* No Unicode support, or apparently invalid Unicode. */
        r = (ZCONST uch *)raw;

        if (size > 0) {
            slim = space + size
#ifdef _MBCS
                         - (MB_CUR_MAX - 1)
#endif
                         - 4;
        }
        while (*r) {
            if (size > 0 && s >= slim && se == NULL) {
                se = s;
            }
#ifdef QDOS
            if (qlflag & 2) {
                if (*r == '/' || *r == '.') {
                    if (se != NULL && (s > (space + (size-3)))) {
                        have_overflow = TRUE;
                        break;
                    }
                    ++r;
                    *s++ = '_';
                    continue;
                }
            } else
#endif
#ifdef HAVE_WORKING_ISPRINT
            if (!isprint(*r)) {
                if (*r < 32) {
                    /* ASCII control codes are escaped as "^{letter}". */
                    if (se != NULL && (s > (space + (size-4)))) {
                        have_overflow = TRUE;
                        break;
                    }
                    *s++ = '^', *s++ = (uch)(64 + *r++);
                } else {
                    /* Other unprintable codes are replaced by the
                     * placeholder character. */
                    if (se != NULL && (s > (space + (size-3)))) {
                        have_overflow = TRUE;
                        break;
                    }
                    *s++ = UZ_FNFILTER_REPLACECHAR;
                    INCSTR(r);
                }
#else /* !HAVE_WORKING_ISPRINT */
            if (*r < 32) {
                /* ASCII control codes are escaped as "^{letter}". */
                if (se != NULL && (s > (space + (size-4)))) {
                    have_overflow = TRUE;
                    break;
                }
                *s++ = '^', *s++ = (uch)(64 + *r++);
#endif /* ?HAVE_WORKING_ISPRINT */
            } else {
#ifdef _MBCS
                unsigned i = CLEN(r);
                if (se != NULL && (s > (space + (size-i-2)))) {
                    have_overflow = TRUE;
                    break;
                }
                for (; i > 0; i--)
                    *s++ = *r++;
#else
                if (se != NULL && (s > (space + (size-3)))) {
                    have_overflow = TRUE;
                    break;
                }
                *s++ = *r++;
#endif
             }
        }
        if (have_overflow) {
            strcpy((char *)se, "...");
        } else {
            *s = '\0';
        }
    }

#ifdef WINDLL
    INTERN_TO_ISO((char *)space, (char *)space);  /* translate to ANSI */
#else
#if (defined(WIN32) && !defined(_WIN32_WCE))
    /* Win9x console always uses OEM character coding, and
       WinNT console is set to OEM charset by default, too */
    INTERN_TO_OEM((char *)space, (char *)space);
#endif /* (WIN32 && !_WIN32_WCE) */
#endif /* ?WINDLL */

    return (char *)space;

#else /* NATIVE:  EBCDIC or whatever */
    return (char *)raw;
#endif

} /* end function fnfilter() */


#if defined( UNICODE_SUPPORT) && defined( _MBCS)

/****************************/
/*  Function fnfilter[w]()  */  /* (Here instead of in list.c for SFX.) */
/****************************/

/* fnfilterw() - Convert wide name to safely printable form. */

/* fnfilterw() - Convert wide-character name to safely printable form. */

wchar_t *fnfilterw( src, dst, siz)
    ZCONST wchar_t *src;        /* Pointer to source char (string). */
    wchar_t *dst;               /* Pointer to destination char (string). */
    extent siz;                 /* Not used (!). */
{
    wchar_t *dsx = dst;

    /* Filter the wide chars. */
    while (*src)
    {
        if (iswprint( *src))
        {
            /* Printable code.  Copy it. */
            *dst++ = *src;
        }
        else
        {
            /* Unprintable code.  Substitute something printable for it. */
            if (*src < 32)
            {
                /* Replace ASCII control code with "^{letter}". */
                *dst++ = (wchar_t)'^';
                *dst++ = (wchar_t)(64 + *src);
            }
            else
            {
                /* Replace other unprintable code with the placeholder. */
                *dst++ = (wchar_t)UZ_FNFILTER_REPLACECHAR;
            }
        }
        src++;
    }
    *dst = (wchar_t)0;  /* NUL-terminate the destination string. */
    return dsx;
} /* fnfilterw(). */

#endif /* defined( UNICODE_SUPPORT) && defined( _MBCS) */


#ifdef SET_DIR_ATTRIB
/* must sort saved directories so can set perms from bottom up */

/************************/
/*  Function dircomp()  */
/************************/

static int Cdecl dircomp(a, b)  /* used by qsort(); swiped from Zip */
    ZCONST zvoid *a, *b;
{
    /* order is significant:  this sorts in reverse order (deepest first) */
    return strcmp((*(direntry **)b)->fn, (*(direntry **)a)->fn);
 /* return namecmp((*(direntry **)b)->fn, (*(direntry **)a)->fn); */
}

#endif /* SET_DIR_ATTRIB */


#ifdef USE_BZIP2

/**************************/
/*  Function UZbunzip2()  */
/**************************/

int UZbunzip2(__G)
__GDEF
/* decompress a bzipped entry using the libbz2 routines */
{
    int retval = 0;     /* return code: 0 = "no error" */
    int err=BZ_OK;
    int repeated_buf_err;
    bz_stream bstrm;

    if (G.incnt <= 0 && G.csize <= 0L) {
        /* avoid an infinite loop */
        Trace((stderr, "UZbunzip2() got empty input\n"));
        return 2;
    }

#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
    if (G.redirect_slide)
        wsize = G.redirect_size, redirSlide = G.redirect_buffer;
    else
        wsize = WSIZE, redirSlide = slide;
#endif

    bstrm.next_out = (char *)redirSlide;
    bstrm.avail_out = wsize;

    bstrm.next_in = (char *)G.inptr;
    bstrm.avail_in = G.incnt;

    {
        /* local buffer for efficiency */
        /* $TODO Check for BZIP LIB version? */

        bstrm.bzalloc = NULL;
        bstrm.bzfree = NULL;
        bstrm.opaque = NULL;

        Trace((stderr, "initializing bzlib()\n"));
        err = BZ2_bzDecompressInit(&bstrm, 0, 0);

        if (err == BZ_MEM_ERROR)
            return 3;
        else if (err != BZ_OK)
            Trace((stderr, "oops!  (BZ2_bzDecompressInit() err = %d)\n", err));
    }

#ifdef FUNZIP
    while (err != BZ_STREAM_END) {
#else /* !FUNZIP */
    while (G.csize > 0) {
        Trace((stderr, "first loop:  G.csize = %ld\n", G.csize));
#endif /* ?FUNZIP */
        while (bstrm.avail_out > 0) {
            err = BZ2_bzDecompress(&bstrm);

            if (err == BZ_DATA_ERROR) {
                retval = 2; goto uzbunzip_cleanup_exit;
            } else if (err == BZ_MEM_ERROR) {
                retval = 3; goto uzbunzip_cleanup_exit;
            } else if (err != BZ_OK && err != BZ_STREAM_END)
                Trace((stderr, "oops!  (bzip(first loop) err = %d)\n", err));

#ifdef FUNZIP
            if (err == BZ_STREAM_END)    /* "END-of-entry-condition" ? */
#else /* !FUNZIP */
            if (G.csize <= 0L)          /* "END-of-entry-condition" ? */
#endif /* ?FUNZIP */
                break;

            if (bstrm.avail_in == 0) {
                if (fillinbuf(__G) == 0) {
                    /* no "END-condition" yet, but no more data */
                    retval = 2; goto uzbunzip_cleanup_exit;
                }

                bstrm.next_in = (char *)G.inptr;
                bstrm.avail_in = G.incnt;
            }
            Trace((stderr, "     avail_in = %u\n", bstrm.avail_in));
        }
        /* flush slide[] */
        if ((retval = FLUSH(wsize - bstrm.avail_out)) != 0)
            goto uzbunzip_cleanup_exit;
        Trace((stderr, "inside loop:  flushing %ld bytes (ptr diff = %ld)\n",
          (long)(wsize - bstrm.avail_out),
          (long)(bstrm.next_out-(char *)redirSlide)));
        bstrm.next_out = (char *)redirSlide;
        bstrm.avail_out = wsize;
    }

    /* no more input, so loop until we have all output */
    Trace((stderr, "beginning final loop:  err = %d\n", err));
    repeated_buf_err = FALSE;
    while (err != BZ_STREAM_END) {
        err = BZ2_bzDecompress(&bstrm);
        if (err == BZ_DATA_ERROR) {
            retval = 2; goto uzbunzip_cleanup_exit;
        } else if (err == BZ_MEM_ERROR) {
            retval = 3; goto uzbunzip_cleanup_exit;
        } else if (err != BZ_OK && err != BZ_STREAM_END) {
            Trace((stderr, "oops!  (bzip(final loop) err = %d)\n", err));
            DESTROYGLOBALS();
            EXIT(PK_MEM3);
        }
        /* final flush of slide[] */
        if ((retval = FLUSH(wsize - bstrm.avail_out)) != 0)
            goto uzbunzip_cleanup_exit;
        Trace((stderr, "final loop:  flushing %ld bytes (ptr diff = %ld)\n",
          (long)(wsize - bstrm.avail_out),
          (long)(bstrm.next_out-(char *)redirSlide)));
        bstrm.next_out = (char *)redirSlide;
        bstrm.avail_out = wsize;
    }
#ifdef LARGE_FILE_SUPPORT
    Trace((stderr, "total in = %llu, total out = %llu\n",
      (zusz_t)(bstrm.total_in_lo32) + ((zusz_t)(bstrm.total_in_hi32))<<32,
      (zusz_t)(bstrm.total_out_lo32) + ((zusz_t)(bstrm.total_out_hi32))<<32));
#else
    Trace((stderr, "total in = %lu, total out = %lu\n", bstrm.total_in_lo32,
      bstrm.total_out_lo32));
#endif

    G.inptr = (uch *)bstrm.next_in;
    G.incnt -= G.inptr - G.inbuf;       /* reset for other routines */

uzbunzip_cleanup_exit:
    err = BZ2_bzDecompressEnd(&bstrm);
    if (err != BZ_OK)
        Trace((stderr, "oops!  (BZ2_bzDecompressEnd() err = %d)\n", err));

    return retval;
} /* end function UZbunzip2() */
#endif /* USE_BZIP2 */
