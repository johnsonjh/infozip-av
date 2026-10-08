/* SPDX-License-Identifier: MIT-0
 * Standalone adaptive spectral-symbol decoder for WinZip MP3 method 94.
 * Decoder state is archive-local; the bounded range reader rejects EOF.
 * MPEG frame re-encoding is intentionally outside this milestone.
 */
#include "wzmp3_spectral.h"
#include <stdlib.h>
#include <string.h>

/* MPEG-1 Layer III Huffman codebook maximum non-escape symbol and linbits. */
static const unsigned char book_max[32]={
    0,1,2,2,0,3,3,5,5,5,7,7,7,15,0,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15
};
static const unsigned char book_extra[32]={
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,2,3,4,6,8,10,13,4,5,6,7,8,9,11,13
};
static const unsigned char book_master[32]={
    0,1,2,3,0,5,6,7,8,9,10,11,12,13,0,15,
    16,16,16,16,16,16,16,16,24,24,24,24,24,24,24,24
};

static void bin2_init(wzmp3_bin2 *m)
{
    unsigned int a,b;
    memset(m,0,sizeof(*m));
    for(a=0;a<16;a++)for(b=0;b<16;b++)
        m->frequency[a][b][0]=m->frequency[a][b][1]=1;
}
static int bin2_shift(wzmp3_bin2 *m,unsigned int ctx)
{
    if(ctx>=16U)return 0;
    m->previous=m->current;
    m->current=ctx;
    return 1;
}
static int bin2_read(wzmp3_bin2 *m,wzmp3_range *r,unsigned int *symbol)
{
    unsigned short *f=m->frequency[m->previous][m->current];
    unsigned long count,total=(unsigned long)f[0]+f[1];
    unsigned int v;
    if(!wzmp3_range_count(r,total,&count))return 0;
    v=count<(unsigned long)f[0]?0U:1U;
    if(!wzmp3_range_remove(r,total,v?f[0]:0U,v?total:f[0]))return 0;
    ++f[v];
    if(f[v]>=511U){f[0]=(unsigned short)(f[0]>>1);f[1]=(unsigned short)(f[1]>>1);
        if(!f[0])f[0]=1;
        if(!f[1])f[1]=1;
    }
    *symbol=v;
    return 1;
}

static int new_ppm(wzmp3_ppm_model **p,unsigned int syms,
                   unsigned int ctx,unsigned int order,unsigned long maxnodes)
{
    *p=(wzmp3_ppm_model*)calloc(1,sizeof(**p));
    if(!*p)return 0;
    return wzmp3_ppm_init(*p,syms,ctx,order,511U,maxnodes);
}
int wzmp3_spectral_init(wzmp3_spectral *s,const wzmp3_header *h)
{
    unsigned int ch,flag,book,master,maxflag;
    if(!s || !h || h->channels<1U || h->channels>2U)return 0;
    memset(s,0,sizeof(*s));
    s->channels=h->channels;
    s->joint=h->channels==2U && h->channel_mode<2U;
    for(ch=0;ch<s->channels;ch++){
        maxflag=s->joint && ch==1U?8U:2U;
        for(flag=0;flag<maxflag;flag++){
            for(book=1;book<32;book++){
                master=book_master[book];
                if(!master)continue;
                if(s->magnitudes[ch][flag][master]){
                    s->magnitudes[ch][flag][book]=s->magnitudes[ch][flag][master];
                    continue;
                }
                if(!new_ppm(&s->magnitudes[ch][flag][book],
                            (unsigned int)book_max[book]+1U,16U,2U,30000UL))goto fail;
            }
            for(book=0;book<2U;book++){
                s->small[ch][flag][book]=(wzmp3_bin2*)malloc(sizeof(wzmp3_bin2));
                if(!s->small[ch][flag][book])goto fail;
                bin2_init(s->small[ch][flag][book]);
            }
            s->signs[ch][flag]=(wzmp3_bin2*)malloc(sizeof(wzmp3_bin2));
            if(!s->signs[ch][flag])goto fail;
            bin2_init(s->signs[ch][flag]);
        }
        for(book=1;book<=13;book++)
            if(!new_ppm(&s->lengths[ch][book],book+1U,14U,1U,30000UL))goto fail;
    }
    bin2_init(&s->remainder);
    if(!wzmp3_ppm_init(&s->stuffing_count,16U,16U,1U,511U,10000UL))goto fail;
    wzmp3_binary_init(&s->stuffing_bits);
    s->initialized=1;
    return 1;
fail:
    wzmp3_spectral_free(s);
    return 0;
}
void wzmp3_spectral_free(wzmp3_spectral *s)
{
    unsigned int ch,f,b;
    if(!s)return;
    for(ch=0;ch<2;ch++){
        for(f=0;f<8;f++){
            for(b=1;b<32;b++){
                if(s->magnitudes[ch][f][b] && book_master[b]==b){
                    wzmp3_ppm_cleanup(s->magnitudes[ch][f][b]);
                    free(s->magnitudes[ch][f][b]);
                }
            }
            for(b=0;b<2;b++)free(s->small[ch][f][b]);
            free(s->signs[ch][f]);
        }
        for(b=1;b<=13;b++)if(s->lengths[ch][b]){
            wzmp3_ppm_cleanup(s->lengths[ch][b]);free(s->lengths[ch][b]);
        }
    }
    wzmp3_ppm_cleanup(&s->stuffing_count);
    memset(s,0,sizeof(*s));
}

int wzmp3_spectral_read(wzmp3_spectral *s,wzmp3_range *ar,
                        const wzmp3_granule *g,unsigned int small_boundary,
                        unsigned int ch,unsigned int type0,unsigned int other_type,
                        unsigned int ms,wzmp3_spectrum *out)
{
    unsigned int typ,flags,start,k,v,ctxabs=0,ctxpattern=0,region,table,linbits;
    unsigned int i,count=0,b,position,ln,other,mask;
    int p;
    unsigned char *ha,*hs,*hl;
    wzmp3_bin2 *smodel,*gmodel;
    wzmp3_ppm_model *bmodel,*lmodel;
    if(!s || !s->initialized || !ar || !g || !out || ch>=s->channels ||
       g->type>3U || type0>3U || other_type>3U || ms>1U ||
       g->small_table>1U ||
       g->bound[0]>g->bound[1] || g->bound[1]>g->bound[2] ||
       g->bound[2]>small_boundary || small_boundary>576U ||
       ((g->bound[2]|small_boundary)&1U) ||
       (small_boundary-g->bound[2])%4U!=0)return 0;
    typ=g->type==2U?1U:0U;
    flags=typ;
    if(s->joint && ch==1U)flags|=(ms<<1)|((typ^((type0==2U)?1U:0U))<<2);
    if(flags>=8U)return 0;
    ha=&s->history_abs[ch][typ][1];
    hs=&s->history_sign[ch][typ][1];
    hl=&s->history_len[ch][typ][1];
    memset(out,0,sizeof(*out));
    out->small_boundary=small_boundary;
    smodel=s->small[ch][flags][g->small_table];
    gmodel=s->signs[ch][flags];
    if(!smodel || !gmodel)return 0;
    p=(int)small_boundary-1;
    while(p>=(int)g->bound[2]){
        if(!bin2_shift(smodel,ctxpattern) || !bin2_shift(smodel,ha[p]) ||
           !bin2_read(smodel,ar,&v))return 0;
        out->magnitude[p]=(unsigned char)v;
        ctxpattern=((ctxpattern<<1)|v)&15U;
        ctxabs=(2U*v+ctxabs+2U)/3U;
        if(v && (!bin2_shift(gmodel,ha[p]) || !bin2_shift(gmodel,hs[p]) ||
                 !bin2_read(gmodel,ar,&k)))return 0;
        if(v)out->negative[p]=(unsigned char)k;
        --p;
    }
    for(region=3;region>0;){
        --region;
        start=region?g->bound[region-1U]:0U;
        if(p<(int)start)continue;
        table=g->table[region];
        if(table>=32U || table==4U || table==14U)return 0;
        if(table==0U){
            p=(int)start;ctxabs=0;
            continue;
        }
        bmodel=s->magnitudes[ch][flags][table];
        linbits=book_extra[table];
        lmodel=linbits?s->lengths[ch][linbits]:0;
        if(!bmodel || (linbits && !lmodel))return 0;
        while(p>=(int)start){
            if(!wzmp3_ppm_shift(bmodel,ctxabs) ||
               !wzmp3_ppm_shift(bmodel,ha[p]) ||
               !wzmp3_ppm_decode(bmodel,ar,&v) ||
               v>book_max[table])return 0;
            out->magnitude[p]=(unsigned char)v;
            ctxabs=(2U*v+ctxabs+2U)/3U;
            if(v){
            if(!bin2_shift(gmodel,ha[p]) || !bin2_shift(gmodel,hs[p]) ||
               !bin2_read(gmodel,ar,&k))return 0;
            out->negative[p]=(unsigned char)k;
            if(linbits && v==15U){
                if(!wzmp3_ppm_shift(lmodel,hl[p]) ||
                   !wzmp3_ppm_decode(lmodel,ar,&ln) || ln>linbits)return 0;
                out->extra_width[p]=(unsigned char)ln;
                s->retained_width[ch][p]=(unsigned char)ln;
                if(ln){
                    v=1U;
                    for(i=ln-1U;i>0;--i){
                        if(!bin2_shift(&s->remainder,ln) ||
                           !bin2_shift(&s->remainder,i-1U) ||
                           !bin2_read(&s->remainder,ar,&b))return 0;
                        v=(v<<1)|b;
                    }
                    if(v>=(1U<<linbits))return 0;
                    out->extra_bits[p]=(unsigned short)v;
                }
            }
            }
            --p;
        }
    }
    /* Update temporal predictors. Unused coefficient positions have zero
     * magnitudes, so no stale values are carried across granules. */
    for(i=576U;i>0;){
        --i;
        other=out->magnitude[i];
        position=other?out->negative[i]:0U;
        mask=(unsigned int)out->magnitude[i] + (i?out->magnitude[i-1U]:0U);
        mask+=i<575U?out->magnitude[i+1U]:0U;
        ha[i]=(unsigned char)((3U*other+(mask-other)+2U*ha[i]+4U)/7U);
        if(other){
            hs[i]=(unsigned char)(((unsigned int)hs[i]<<1 |position)&15U);
            if(other==15U)hl[i]=(unsigned char)((2U*s->retained_width[ch][i]+hl[i]+2U)/3U);
            else hl[i]=(unsigned char)(hl[i]>>1);
        }else{
            hs[i]=(unsigned char)(((unsigned int)hs[i]<<1)&15U);
            hl[i]=(unsigned char)(hl[i]>>1);
        }
    }
    /* The first channel supplies contextual information to channel 1,
     * even when channel 1 has another block-window type. */
    if(s->joint && ch==0U){
        unsigned int target_type=other_type==2U?1U:0U;
        unsigned char *a=&s->history_abs[1][target_type][1];
        unsigned char *q=&s->history_sign[1][target_type][1];
        unsigned char *l=&s->history_len[1][target_type][1];
        for(i=0;i<576;i++){
            a[i]=out->magnitude[i];
            q[i]=out->magnitude[i]?out->negative[i]:2U;
            l[i]=out->magnitude[i]==15U?s->retained_width[ch][i]:0U;
        }
    }
    /* RLE for granule-specific non-Huffman stuffing, as a byte of bits. */
    for(;;){
        if(!wzmp3_ppm_shift(&s->stuffing_count,s->last_stuff_count) ||
           !wzmp3_ppm_decode(&s->stuffing_count,ar,&v) || v>15U)return 0;
        s->last_stuff_count=v;
        if(count>4096U-v)return 0;
        count+=v;
        if(v!=15U)break;
    }
    out->stuffing_count=count;
    for(i=0;i<count;i++){
        if(!wzmp3_binary_shift(&s->stuffing_bits,s->last_stuff_bit) ||
           !wzmp3_binary_decode(&s->stuffing_bits,ar,&v))return 0;
        s->last_stuff_bit=((s->last_stuff_bit<<1)|v)&15U;
        out->stuffing_bits[i]=(unsigned char)v;
    }
    return 1;
}
