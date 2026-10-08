/* SPDX-License-Identifier: MIT-0
 * Independently written Method 94 scalefactor / region-bound reader.
 * Not a complete MP3 decoder. Spectral symbols follow each scalefactor
 * block and MUST be consumed before the next scalefactor block.
 */
#include "wzmp3_granule.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char factor_width[16][2] = {
    {0,0},{0,1},{0,2},{0,3},{3,0},{1,1},{1,2},{1,3},
    {2,1},{2,2},{2,3},{3,1},{3,2},{3,3},{4,2},{4,3}
};
static const unsigned char group_ends[4] = {6,11,16,21};
static const unsigned char short_ends[2] = {6,12};
#define SF(st,ch,b,g) (st)->scale_models[(ch)*40U+(b)*10U+(g)]

int wzmp3_granule_init(wzmp3_granule_state *st, const wzmp3_header *h)
{
    unsigned int c,b,g;
    if(!st)return 0;
    memset(st,0,sizeof(*st));
    if(!h || h->channels<1U || h->channels>2U ||
       h->frame_count==0 || h->frame_count>ULONG_MAX/(4UL))return 0;
    st->channel_count=h->channels;
    st->total_steps=h->frame_count*2UL*h->channels;
    st->scale_models=(wzmp3_ppm_model*)calloc(80,sizeof(wzmp3_ppm_model));
    if(!st->scale_models)return 0;
    for(c=0;c<h->channels;c++)
        for(b=0;b<4;b++)
            for(g=0;g<10;g++)
                if(!wzmp3_ppm_init(&SF(st,c,b,g),2U<<b,16,2,511,30000)){
                    wzmp3_granule_destroy(st);return 0;
                }
    if(!wzmp3_ppm_init(&st->small_bound,146,146,1,511,30000) ||
       !wzmp3_ppm_init(&st->damaged_bound,289,0,0,511,30000)){
        wzmp3_granule_destroy(st);return 0;
    }
    st->ready=1;
    return 1;
}

int wzmp3_granule_scalefactors(wzmp3_granule_state *st,
                              wzmp3_range *ar, const wzmp3_granule *x,
                              unsigned int ch, unsigned int gr,
                              unsigned char out[36])
{
    unsigned int width,grp,pos,val,previous,window,index;
    const unsigned char *history;
    wzmp3_ppm_model *model;
    if(!st || !st->ready || st->pending_bound || !ar || !x || !out ||
       ch>=st->channel_count || gr>1U || x->slength>15U ||
       st->step>=st->total_steps ||
       st->step%st->channel_count!=ch ||
       (st->step/st->channel_count)%2U!=gr ||
       x->type>3U)return 0;
    memset(out,0,36);
    if(gr==0)
        for(grp=0;grp<4U;grp++)
            st->sharing[ch][grp]=(unsigned char)((x->share>>(3U-grp))&1U);
    if(x->type!=2U){
        history=st->long_history[ch];
        previous=0;pos=0;
        for(grp=0;grp<4;grp++){
            width=factor_width[x->slength][grp<2U?0U:1U];
            if(gr==1U && st->sharing[ch][grp]){
                for(;pos<group_ends[grp];pos++)out[pos]=history[pos];
                previous=out[pos-1U];
            }else if(!width){
                pos=group_ends[grp];
                previous=0;
            }else{
                index=grp|(st->sharing[ch][grp]?4U:0U);
                model=&SF(st,ch,width-1U,index);
                for(;pos<group_ends[grp];pos++){
                    if(!wzmp3_ppm_shift(model,previous) ||
                       !wzmp3_ppm_shift(model,history[pos]) ||
                       !wzmp3_ppm_decode(model,ar,&val) ||
                       val>=(1U<<width))return 0;
                    out[pos]=(unsigned char)val;
                    previous=val;
                }
            }
        }
        memcpy(st->long_history[ch],out,21);
    }else{
        for(window=0;window<3U;window++){
            previous=0;pos=0;
            history=st->short_history[ch];
            for(grp=0;grp<2;grp++){
                width=factor_width[x->slength][grp];
                if(!width){
                    for(;pos<short_ends[grp];pos++)out[window*12U+pos]=0;
                }else{
                    model=&SF(st,ch,width-1U,grp|8U);
                    for(;pos<short_ends[grp];pos++){
                        if(!wzmp3_ppm_shift(model,previous) ||
                           !wzmp3_ppm_shift(model,history[pos]) ||
                           !wzmp3_ppm_decode(model,ar,&val) ||
                           val>=(1U<<width))return 0;
                        out[window*12U+pos]=(unsigned char)val;
                        previous=val;
                    }
                }
            }
            memcpy(st->short_history[ch],out+window*12U,12);
        }
    }
    st->step++;
    st->pending_bound=1;
    return 1;
}

int wzmp3_granule_small_bound(wzmp3_granule_state *st,
                             wzmp3_range *ar,
                             wzmp3_granule *g,unsigned int ch,
                             unsigned int *small_bound)
{
    unsigned int symbol,limit,k;
    if(!st || !st->ready || !st->pending_bound || !ar || !g || !small_bound ||
       ch>=st->channel_count || g->bound[0]>g->bound[1] ||
       g->bound[1]>g->bound[2] || g->bound[2]>576U ||
       (g->bound[2]&1U))return 0;
    if(!wzmp3_ppm_shift(&st->small_bound,
                         g->type==2U?145U:st->last_bound[ch]) ||
       !wzmp3_ppm_decode(&st->small_bound,ar,&symbol))return 0;
    if(symbol<=144U){
        limit=symbol*4U+((g->bound[2]&3U)==2U?2U:0U);
        if(limit<g->bound[2] || limit>576U)return 0;
        if(g->type!=2U)st->last_bound[ch]=symbol;
    }else if(symbol==145U){
        if(!wzmp3_ppm_decode(&st->damaged_bound,ar,&k) ||
           k>g->bound[2]/2U)return 0;
        limit=g->bound[2]-2U*k;
        if((limit&1U)!=0)return 0;
        if(g->bound[2]>limit)g->bound[2]=limit;
        if(g->bound[1]>limit)g->bound[1]=limit;
        if(g->bound[0]>limit)g->bound[0]=limit;
    }else return 0;
    *small_bound=limit;
    st->pending_bound=0;
    return 1;
}

void wzmp3_granule_destroy(wzmp3_granule_state *st)
{
    unsigned int c,b,g;
    if(!st)return;
    if(st->scale_models){
        for(c=0;c<2;c++)for(b=0;b<4;b++)for(g=0;g<10;g++)
            wzmp3_ppm_cleanup(&SF(st,c,b,g));
        free(st->scale_models);
    }
    wzmp3_ppm_cleanup(&st->small_bound);
    wzmp3_ppm_cleanup(&st->damaged_bound);
    memset(st,0,sizeof(*st));
}
