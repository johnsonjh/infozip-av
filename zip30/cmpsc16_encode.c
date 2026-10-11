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

#define IZCM_NSYM 2048U
#define IZCM_PHRASE 260U
#define IZCM_DSIZE (IZCM_NSYM * 8U)
#define IZCM_SLOTS 262144UL
#define IZCM_MASK (IZCM_SLOTS-1UL)
#define IZCM_MAXPROBE 24U

typedef unsigned (*izcm_read_fn)(void *, unsigned char *, unsigned);
typedef int (*izcm_write_fn)(void *, const unsigned char *, unsigned);
typedef struct {
    unsigned char phrase[IZCM_NSYM][IZCM_PHRASE];
    unsigned short length[IZCM_NSYM];
    unsigned short next[IZCM_NSYM];
    unsigned short heads[256];
} izcm_enc;

typedef struct {
    unsigned char bytes[7];
    unsigned char length;
    unsigned long count;
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

static unsigned long izcm_score(const izcm_gram *g)
{
    unsigned gain=8U*(unsigned)g->length-11U;
    if (g->count>ULONG_MAX/(unsigned long)gain) return ULONG_MAX;
    return g->count*(unsigned long)gain;
}

static int izcm_compare(const void *a, const void *b)
{
    const izcm_gram *x=*(const izcm_gram *const *)a;
    const izcm_gram *y=*(const izcm_gram *const *)b;
    unsigned long ax=izcm_score(x), ay=izcm_score(y);
    int c;
    if (ax!=ay) return ax>ay ? -1 : 1;
    if (x->count!=y->count) return x->count>y->count ? -1 : 1;
    c=memcmp(x->bytes,y->bytes,x->length<y->length ? x->length:y->length);
    if (c) return -c; /* deterministic tie breaker */
    if (x->length!=y->length) return x->length>y->length ? -1 : 1;
    return 0;
}

/* First pass: read through Zip's file_read exactly once. file_read updates
 * CRC, uncompressed length and text/binary detection as usual. */
static int izcm_train(izcm_read_fn reader,void *ctx,FILE *spool,
                      unsigned char *dict)
{
    izcm_gram *grams=NULL;
    izcm_gram **rank=NULL;
    unsigned char block[8192],tail[7];
    unsigned tail_len=0,n,i,l,selected=0;
    unsigned long used=0UL,k;
    int rc=-2;
    grams=(izcm_gram *)calloc((size_t)IZCM_SLOTS,sizeof *grams);
    if (!grams) goto finish;
    rank=(izcm_gram **)malloc((size_t)IZCM_SLOTS*sizeof *rank);
    if (!rank) goto finish;
    for (;;) {
        n=reader(ctx,block,(unsigned)sizeof block);
        if (n==(unsigned)EOF) { rc=-1; goto finish; }
        if (!n) break;
        if (fwrite(block,1U,n,spool)!=(size_t)n) { rc=-3; goto finish; }
        for (i=0;i<n;++i) {
            if (tail_len==sizeof tail) {
                memmove(tail,tail+1U,sizeof tail-1U);
                --tail_len;
            }
            tail[tail_len++]=block[i];
            for (l=2U;l<=tail_len;++l)
                izcm_observe(grams,tail+tail_len-l,l);
        }
    }
    if (fflush(spool) || fseek(spool,0L,SEEK_SET)) { rc=-3; goto finish; }
    memset(dict,0,IZCM_DSIZE);
    for (i=0;i<256U;++i) {
        dict[i*8U]=1U;
        dict[i*8U+1U]=(unsigned char)i;
    }
    for (k=0UL;k<IZCM_SLOTS;++k)
        if (grams[k].length>1U && grams[k].count>=2UL) rank[used++]=grams+k;
    qsort(rank,(size_t)used,sizeof *rank,izcm_compare);
    for (k=0UL;k<used && selected<IZCM_NSYM-256U;++k) {
        izcm_gram *g=rank[k];
        unsigned index=(256U+selected)*8U;
        dict[index]=g->length;
        memcpy(dict+index+1U,g->bytes,g->length);
        ++selected;
    }
    for (;selected<IZCM_NSYM-256U;++selected)
        dict[(256U+selected)*8U]=1U;
    rc=0;
finish:
    free(rank);
    free(grams);
    return rc;
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
static unsigned izcm_defdict(const unsigned char *dict,unsigned char *dst)
{
    int *head=NULL,*prev=NULL;
    izcm_bits b;
    unsigned i=0U,j,steps,bestlen,bestdist,limit;
    int chain,pos;
    b.out=dst; b.cap=IZCM_DSIZE; b.used=0U;
    b.bits=0UL; b.count=0U; b.error=0;
    head=(int *)malloc(IZCM_HASH3*sizeof *head);
    prev=(int *)malloc(IZCM_DSIZE*sizeof *prev);
    if (!head || !prev) { free(head);free(prev);return 0U; }
    for(j=0;j<IZCM_HASH3;++j) head[j]=-1;
    izcm_putbits(&b,3U,3U); /* BFINAL=1, BTYPE=01 (fixed Huffman) */
    while(i<IZCM_DSIZE && !b.error) {
        bestlen=0U;bestdist=0U;
        if (i+2U<IZCM_DSIZE) {
            unsigned h=izcm_h3(dict+i);
            chain=head[h];
            steps=0U;
            limit=IZCM_DSIZE-i;
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
            if(i+2U<IZCM_DSIZE) {
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

static void izcm_buildindex(izcm_enc *state,const unsigned char *dict)
{
    unsigned s,k,n;
    for(s=0U;s<256U;++s) state->heads[s]=0xffffU;
    for(s=0U;s<IZCM_NSYM;++s) {
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

/* Return 0 success, -1 input/write callback error, -2 allocation error,
 * -3 temporary file read/write/open error. */
static int izcm_encode(izcm_read_fn reader,izcm_write_fn writer,void *ctx)
{
    izcm_enc *state=NULL;
    unsigned char *dict=NULL,*compressed=NULL;
    FILE *spool=NULL;
    unsigned char look[IZCM_PHRASE],out[4096],head[6];
    unsigned len=0U,n,j,best,bestlen,s,used=0U;
    unsigned accum=0U,have=0U,dictlen,remaining;
    int eof=0,rc=-2;
    spool=tmpfile();
    if (!spool) { rc=-3; goto done; }
    dict=(unsigned char *)malloc(IZCM_DSIZE);
    compressed=(unsigned char *)malloc(IZCM_DSIZE);
    state=(izcm_enc *)calloc(1U,sizeof *state);
    if (!dict || !compressed || !state) goto done;
    rc=izcm_train(reader,ctx,spool,dict);
    if (rc) goto done;
    izcm_buildindex(state,dict);
    dictlen=izcm_defdict(dict,compressed);
    head[0]=1U;
    head[1]=(unsigned char)((dictlen && dictlen<IZCM_DSIZE) ? 0xcbU : 0x8bU);
    n=(dictlen && dictlen<IZCM_DSIZE) ? dictlen:IZCM_DSIZE;
    head[2]=(unsigned char)n;head[3]=(unsigned char)(n>>8);
    head[4]=0U;head[5]=0U;
    rc=-1;
    if(writer(ctx,head,6U) || writer(ctx,
       (dictlen && dictlen<IZCM_DSIZE)?compressed:dict,n)) goto done;
    while (!eof || len) {
        while(len<IZCM_PHRASE && !eof) {
            n=(unsigned)fread(look+len,1U,IZCM_PHRASE-len,spool);
            if(!n) { if(ferror(spool)) { rc=-3; goto done; } eof=1; }
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
        for(j=0U;j<11U;++j) {
            accum=(accum<<1U)|((best>>(10U-j))&1U);
            if(++have==8U) {
                out[used++]=(unsigned char)accum;
                accum=0U;have=0U;
                if(used==(unsigned)sizeof out) {
                    if(writer(ctx,out,used)) goto done;
                    used=0U;
                }
            }
        }
        remaining=len-bestlen;
        if(remaining) memmove(look,look+bestlen,remaining);
        len=remaining;
    }
    if(have) out[used++]=(unsigned char)(accum<<(8U-have));
    if(used && writer(ctx,out,used)) goto done;
    rc=0;
done:
    if(spool) fclose(spool);
    free(state);free(compressed);free(dict);
    return rc;
}
