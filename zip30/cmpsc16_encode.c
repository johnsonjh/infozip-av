/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/*
 * The expansion dictionary uses the architectural 8-byte unpreceded
 * entry format. Dictionary DEFLATE is independent raw RFC 1951 DEFLATE.
 * The per-member input spool makes stdin and non-seekable inputs work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#if UINT_MAX < 65536UL
# error CMPSC encoder requires at least 32-bit unsigned integers
#endif

#define IZCM_MAXSYM 8192U
#define IZCM_PHRASE 7U
#define IZCM_MAXDSIZE (IZCM_MAXSYM * 8U)
#define IZCM_SLOTS 262144UL
#define IZCM_MASK (IZCM_SLOTS-1UL)
#define IZCM_MAXPROBE 24U

typedef unsigned (*izcm_read_fn)(void *, unsigned char *, unsigned);
typedef int (*izcm_write_fn)(void *, const unsigned char *, unsigned);
typedef struct {
    unsigned char phrase[IZCM_MAXSYM][IZCM_PHRASE];
    unsigned short length[IZCM_MAXSYM];
    unsigned short next[IZCM_MAXSYM];
    unsigned short heads[256];
} izcm_enc;

typedef struct {
    unsigned char bytes[7];
    unsigned char length;
    unsigned long count;
    unsigned long score;
} izcm_gram;

static unsigned long izcm_hash(const unsigned char *p, unsigned n)
{
    unsigned long h=2166136261UL;
    unsigned i;
    for (i=0; i<n; ++i) h=(h ^ (unsigned long)p[i])*16777619UL;
    return h ^ (unsigned long)n;
}

static void izcm_observe(izcm_gram *grams, const unsigned char *p, unsigned n)
{
    unsigned long pos=izcm_hash(p,n)&IZCM_MASK;
    unsigned i;
    izcm_gram *g;
    for (i=0; i<IZCM_MAXPROBE; ++i) {
        g=grams+((pos+(unsigned long)i)&IZCM_MASK);
        if (!g->length) {
            g->length=(unsigned char)n;
            memcpy(g->bytes,p,n);
            g->count=1UL;
            return;
        }
        if (g->length==n && memcmp(g->bytes,p,n)==0) {
            if (g->count<ULONG_MAX) ++g->count;
            return;
        }
    }
    /* Bounded sketch: collisions can cost ratio but never correctness. */
}

/* Scores are stored with each observation; qsort therefore has no
 * global comparison state and is safe for concurrent independent encoders. */
static unsigned long izcm_score(const izcm_gram *g,unsigned width)
{
    unsigned gain=8U*(unsigned)g->length-width;
    if (g->count>ULONG_MAX/(unsigned long)gain) return ULONG_MAX;
    return g->count*(unsigned long)gain;
}

static int izcm_compare(const void *a,const void *b)
{
    const izcm_gram *x=*(const izcm_gram *const *)a;
    const izcm_gram *y=*(const izcm_gram *const *)b;
    int c;
    if (x->score!=y->score) return x->score>y->score ? -1 : 1;
    if (x->count!=y->count) return x->count>y->count ? -1 : 1;
    c=memcmp(x->bytes,y->bytes,x->length<y->length ? x->length:y->length);
    if (c) return -c;
    if (x->length!=y->length) return x->length>y->length ? -1 : 1;
    return 0;
}

/* Read Zip's input exactly once, preserving CRC/size/text accounting. The
 * resulting phrase observations are shared by all auto-width candidates. */
static int izcm_collect(izcm_read_fn reader,void *ctx,FILE *spool,
                        izcm_gram *grams,izcm_gram **rank,
                        unsigned long *used)
{
    unsigned char block[8192],tail[7];
    unsigned tail_len=0U,n,i,l;
    unsigned long k;
    *used=0UL;
    for (;;) {
        n=reader(ctx,block,(unsigned)sizeof block);
        if (n==(unsigned)EOF) return -1;
        if (!n) break;
        if (fwrite(block,1U,n,spool)!=(size_t)n) return -3;
        for (i=0U;i<n;++i) {
            if (tail_len==sizeof tail) {
                memmove(tail,tail+1U,sizeof tail-1U);
                --tail_len;
            }
            tail[tail_len++]=block[i];
            for (l=2U;l<=tail_len;++l)
                izcm_observe(grams,tail+tail_len-l,l);
        }
    }
    if (fflush(spool) || fseek(spool,0L,SEEK_SET)) return -3;
    for (k=0UL;k<IZCM_SLOTS;++k)
        if (grams[k].length>1U && grams[k].count>=2UL)
            rank[(*used)++]=grams+k;
    return 0;
}

static void izcm_make_dict(unsigned width,unsigned char *dict,
                           izcm_gram **rank,unsigned long used)
{
    unsigned nsym=1U<<width;
    unsigned dsize=nsym*8U;
    unsigned selected=0U,i;
    unsigned long k;
    for (k=0UL;k<used;++k)
        rank[k]->score=izcm_score(rank[k],width);
    qsort(rank,(size_t)used,sizeof *rank,izcm_compare);
    memset(dict,0,dsize);
    for (i=0U;i<256U;++i) {
        dict[i*8U]=1U;
        dict[i*8U+1U]=(unsigned char)i;
    }
    for (k=0UL;k<used && selected<nsym-256U;++k) {
        izcm_gram *g=rank[k];
        unsigned index=(256U+selected)*8U;
        dict[index]=g->length;
        memcpy(dict+index+1U,g->bytes,g->length);
        ++selected;
    }
    for (;selected<nsym-256U;++selected)
        dict[(256U+selected)*8U]=1U;
}

/* Bit writer used for a single fixed-Huffman raw-Deflate block. */
typedef struct {
    unsigned char *out;
    unsigned used,cap;
    unsigned long bits;
    unsigned count;
    int error;
} izcm_bits;

static void izcm_putbits(izcm_bits *b,unsigned value,unsigned width)
{
    if (b->error) return;
    b->bits |= (unsigned long)value << b->count;
    b->count += width;
    while (b->count>=8U) {
        if (b->used>=b->cap) { b->error=1; return; }
        b->out[b->used++]=(unsigned char)b->bits;
        b->bits>>=8;
        b->count-=8U;
    }
}
static unsigned izcm_rev(unsigned v,unsigned bits)
{
    unsigned n=0U;
    while (bits--) { n=(n<<1)|(v&1U); v>>=1; }
    return n;
}
static void izcm_fixed(izcm_bits *b,unsigned sym)
{
    unsigned v,n;
    if (sym<=143U) { v=sym+0x30U; n=8U; }
    else if(sym<=255U) { v=sym-144U+0x190U; n=9U; }
    else if(sym<=279U) { v=sym-256U; n=7U; }
    else { v=sym-280U+0xc0U; n=8U; }
    izcm_putbits(b,izcm_rev(v,n),n);
}
static const unsigned short izcm_lbase[29]={
 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
 67,83,99,115,131,163,195,227,258};
static const unsigned char izcm_lextra[29]={
 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const unsigned short izcm_dbase[30]={
 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,
 257,385,513,769,1025,1537,2049,3073,4097,6145,8193,
 12289,16385,24577};
static const unsigned char izcm_dextra[30]={
 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,
 11,11,12,12,13,13};
static void izcm_match(izcm_bits *b,unsigned len,unsigned dist)
{
    unsigned i;
    for (i=0;i<29U;++i)
        if (len<izcm_lbase[i]+(1U<<izcm_lextra[i])) break;
    if (i>=29U) { b->error=1; return; }
    izcm_fixed(b,257U+i);
    izcm_putbits(b,len-izcm_lbase[i],izcm_lextra[i]);
    for (i=0;i<30U;++i)
        if (dist<izcm_dbase[i]+(1U<<izcm_dextra[i])) break;
    if (i>=30U) { b->error=1; return; }
    izcm_putbits(b,izcm_rev(i,5U),5U);
    izcm_putbits(b,dist-izcm_dbase[i],izcm_dextra[i]);
}
#define IZCM_HASH3 4096U
static unsigned izcm_h3(const unsigned char *p)
{
    return ((((unsigned)p[0]*251U) ^ ((unsigned)p[1]*31U) ^
             (unsigned)p[2]) & (IZCM_HASH3-1U));
}
/* Encode the fixed-size dictionary with raw Deflate. This requires no
 * external zlib and works with internal, zlib and native-zlib-ng builds. */
static unsigned izcm_defdict(const unsigned char *dict,unsigned dsize,
                                  unsigned char *dst)
{
    int *head=NULL,*prev=NULL;
    izcm_bits b;
    unsigned i=0U,j,steps,bestlen,bestdist,limit;
    int chain,pos;
    b.out=dst; b.cap=dsize; b.used=0U;
    b.bits=0UL; b.count=0U; b.error=0;
    head=(int *)malloc(IZCM_HASH3*sizeof *head);
    prev=(int *)malloc((size_t)dsize*sizeof *prev);
    if (!head || !prev) { free(head);free(prev);return 0U; }
    for(j=0;j<IZCM_HASH3;++j) head[j]=-1;
    izcm_putbits(&b,3U,3U); /* BFINAL=1, BTYPE=01 (fixed Huffman) */
    while(i<dsize && !b.error) {
        bestlen=0U;bestdist=0U;
        if (i+2U<dsize) {
            unsigned h=izcm_h3(dict+i);
            chain=head[h];
            steps=0U;
            limit=dsize-i;
            if (limit>258U) limit=258U;
            while(chain>=0 && steps++<64U) {
                unsigned cp=(unsigned)chain;
                unsigned n=0U;
                if (dict[cp]==dict[i] && dict[cp+1U]==dict[i+1U] &&
                    dict[cp+2U]==dict[i+2U]) {
                    n=3U;
                    while(n<limit && dict[cp+n]==dict[i+n]) ++n;
                    if(n>bestlen) { bestlen=n;bestdist=i-cp; }
                    if(n==limit) break;
                }
                chain=prev[cp];
            }
        }
        if(bestlen>=3U) {
            izcm_match(&b,bestlen,bestdist);
            j=bestlen;
        } else {
            izcm_fixed(&b,dict[i]);
            j=1U;
        }
        while(j--) {
            if(i+2U<dsize) {
                unsigned h=izcm_h3(dict+i);
                pos=head[h];
                prev[i]=pos;
                head[h]=(int)i;
            }
            ++i;
        }
    }
    izcm_fixed(&b,256U);
    if (b.count && !b.error) {
        if(b.used>=b.cap) b.error=1;
        else b.out[b.used++]=(unsigned char)b.bits;
    }
    free(head);free(prev);
    return b.error ? 0U : b.used;
}

static void izcm_buildindex(izcm_enc *state,const unsigned char *dict,
                              unsigned nsym)
{
    unsigned s,k,n;
    for(s=0U;s<256U;++s) state->heads[s]=0xffffU;
    for(s=0U;s<nsym;++s) {
        n=(s<256U) ? 1U : (unsigned)dict[s*8U];
        if(n>7U || !n) continue;
        if (s<256U) state->phrase[s][0]=(unsigned char)s;
        else memcpy(state->phrase[s],dict+s*8U+1U,n);
        state->length[s]=(unsigned short)n;
        k=(unsigned)state->phrase[s][0];
        state->next[s]=state->heads[k];
        state->heads[k]=(unsigned short)s;
    }
}

/* Count without relying on 64-bit arithmetic (which ANSI C89 lacks).
 * hi increases only when unsigned long wraps; compare lexicographically. */
typedef struct { unsigned long hi,lo; } izcm_size;
static void izcm_add(izcm_size *z,unsigned n)
{
    unsigned long old=z->lo;
    z->lo+=(unsigned long)n;
    if (z->lo<old) ++z->hi;
}
static int izcm_smaller(const izcm_size *a,const izcm_size *b)
{
    return a->hi<b->hi || (a->hi==b->hi && a->lo<b->lo);
}

/* Rewind the input spool and emit packed symbols, or count the exact bytes
 * when writer is NULL. In both modes, decoding uses identical matching.
 * The counter deliberately excludes the six-byte header and dictionary. */
static int izcm_stream(FILE *spool,const izcm_enc *state,unsigned width,
                       izcm_write_fn writer,void *ctx,izcm_size *bytes)
{
    unsigned char look[IZCM_PHRASE],out[4096];
    unsigned len=0U,n,j,best,bestlen,s,used=0U;
    unsigned accum=0U,have=0U,remaining;
    int eof=0;
    bytes->hi=0UL;bytes->lo=0UL;
    if (fseek(spool,0L,SEEK_SET)) return -3;
    while (!eof || len) {
        while(len<IZCM_PHRASE && !eof) {
            n=(unsigned)fread(look+len,1U,IZCM_PHRASE-len,spool);
            if(!n) { if(ferror(spool)) return -3; eof=1; }
            else len+=n;
        }
        if(!len) break;
        best=(unsigned)look[0];bestlen=1U;
        for(s=state->heads[best];s!=0xffffU;s=state->next[s]) {
            unsigned sl=(unsigned)state->length[s];
            if(sl>bestlen && sl<=len &&
               memcmp(state->phrase[s],look,sl)==0) {
                best=s;bestlen=sl;
            }
        }
        for(j=0U;j<width;++j) {
            accum=(accum<<1U)|((best>>(width-1U-j))&1U);
            if(++have==8U) {
                out[used++]=(unsigned char)accum;
                accum=0U;have=0U;
                if(used==(unsigned)sizeof out) {
                    if(writer && writer(ctx,out,used)) return -1;
                    izcm_add(bytes,used);
                    used=0U;
                }
            }
        }
        remaining=len-bestlen;
        if(remaining) memmove(look,look+bestlen,remaining);
        len=remaining;
    }
    if(have) out[used++]=(unsigned char)(accum<<(8U-have));
    if(used) {
        if(writer && writer(ctx,out,used)) return -1;
        izcm_add(bytes,used);
    }
    return 0;
}

/* Return 0 success, -1 input/write callback error, -2 allocation error,
 * -3 temporary file read/write/open error.  Width 0 selects the smallest
 * complete candidate (including the Deflated expansion dictionary).
 * Widths 9..13 force a specific format for interoperability testing. */
static int izcm_encode(izcm_read_fn reader,izcm_write_fn writer,void *ctx,
                       unsigned requested_width)
{
    izcm_enc *state=NULL;
    izcm_gram *grams=NULL,**rank=NULL;
    unsigned char *dict=NULL,*compressed=NULL;
    FILE *spool=NULL;
    unsigned char head[6];
    unsigned long used=0UL;
    unsigned width,begin,end,bestwidth=0U,n,dictlen,dsize;
    izcm_size candidate,bestsize,outputbytes;
    int rc=-2;
    if(requested_width &&
       (requested_width<9U || requested_width>13U)) return -2;
    begin=requested_width ? requested_width : 9U;
    end=requested_width ? requested_width : 13U;
    spool=tmpfile();
    if (!spool) return -3;
    dict=(unsigned char *)malloc(IZCM_MAXDSIZE);
    compressed=(unsigned char *)malloc(IZCM_MAXDSIZE);
    state=(izcm_enc *)calloc(1U,sizeof *state);
    grams=(izcm_gram *)calloc((size_t)IZCM_SLOTS,sizeof *grams);
    rank=(izcm_gram **)malloc((size_t)IZCM_SLOTS*sizeof *rank);
    if(!dict || !compressed || !state || !grams || !rank) goto done;
    rc=izcm_collect(reader,ctx,spool,grams,rank,&used);
    if(rc) goto done;
    rc=-3;
    bestsize.hi=ULONG_MAX;bestsize.lo=ULONG_MAX;
    for(width=begin;width<=end;++width) {
        dsize=(1U<<width)*8U;
        izcm_make_dict(width,dict,rank,used);
        izcm_buildindex(state,dict,1U<<width);
        dictlen=izcm_defdict(dict,dsize,compressed);
        n=(dictlen && dictlen<dsize) ? dictlen : dsize;
        if(izcm_stream(spool,state,width,NULL,NULL,&candidate)) goto done;
        izcm_add(&candidate,n+6U);
        if(bestwidth==0U || izcm_smaller(&candidate,&bestsize)) {
            bestwidth=width;
            bestsize=candidate;
        }
    }
    width=bestwidth;
    dsize=(1U<<width)*8U;
    izcm_make_dict(width,dict,rank,used);
    izcm_buildindex(state,dict,1U<<width);
    dictlen=izcm_defdict(dict,dsize,compressed);
    n=(dictlen && dictlen<dsize) ? dictlen : dsize;
    head[0]=1U;
    head[1]=(unsigned char)((dictlen && dictlen<dsize) ?
                            (0xc0U|width) : (0x80U|width));
    head[2]=(unsigned char)n;
    head[3]=(unsigned char)(n>>8);
    head[4]=(unsigned char)(n>>16);
    head[5]=(unsigned char)(n>>24);
    rc=-1;
    if(writer(ctx,head,6U) || writer(ctx,
        (dictlen && dictlen<dsize) ? compressed : dict,n)) goto done;
    rc=izcm_stream(spool,state,width,writer,ctx,&outputbytes);
done:
    if(spool) fclose(spool);
    free(rank);free(grams);free(state);free(compressed);free(dict);
    return rc;
}
