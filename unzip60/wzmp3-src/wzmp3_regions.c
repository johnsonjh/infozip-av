/* SPDX-License-Identifier: MIT-0
 * Reconstruction of the non-spectral MPEG-1 Layer III data sections.
 * No LGPL decoder code or tables are incorporated here. The band edges below
 * are the MPEG-1 Layer III scalefactor-band boundaries (ISO/IEC 11172-3).
 */
#include "wzmp3_regions.h"
#include "wzmp3_binary.h"
#include <limits.h>
#include <string.h>

static const unsigned short long_edges[3][23] = {
    {0,4,8,12,16,20,24,30,36,44,52,62,74,90,110,134,162,196,238,288,342,418,576},
    {0,4,8,12,16,20,24,30,36,42,50,60,72,88,106,128,156,190,230,276,330,384,576},
    {0,4,8,12,16,20,24,30,36,44,54,66,82,102,126,156,194,240,296,364,448,550,576}
};
static const unsigned short short_edges[3][14] = {
    {0,4,8,12,16,22,30,40,52,66,84,106,136,192},
    {0,4,8,12,16,22,28,38,50,64,80,100,126,192},
    {0,4,8,12,16,22,30,42,58,78,104,138,180,192}
};
static int rate_index(unsigned int rate)
{
    if(rate == 44100U)return 0;
    if(rate == 48000U)return 1;
    if(rate == 32000U)return 2;
    return -1;
}
static unsigned int band_of(unsigned int sample, int rate)
{
    unsigned int i;
    for(i=1;i<23;i++)if(sample < long_edges[rate][i])return i-1U;
    return 22;
}
static unsigned int minimum(unsigned int x,unsigned int y)
{
    return x<y?x:y;
}
#define WZMP3_PPM_INIT(model,alpha,ctx,order,limit) \
    wzmp3_ppm_init(&(model),(alpha),(ctx),(order),511U,(limit), \
                   ar->source->memory)
#define SYM(model,context) \
    (wzmp3_ppm_shift(&(model),(context)))
#define NEXT(model,out) \
    (wzmp3_ppm_decode(&(model),ar,&(out)))
static int shift2(wzmp3_ppm_model *m,unsigned int a,unsigned int b)
{
    return wzmp3_ppm_shift(m,a) && wzmp3_ppm_shift(m,b);
}
static int shift3(wzmp3_ppm_model *m,unsigned int a,unsigned int b,unsigned int c)
{
    return wzmp3_ppm_shift(m,a) && wzmp3_ppm_shift(m,b) &&
           wzmp3_ppm_shift(m,c);
}

int wzmp3_regions_decode(wzmp3_range *ar,const wzmp3_header *h,
                         wzmp3_granule *g)
{
    wzmp3_ppm_model m0,m1,m2,mr0,mr1,mb;
    wzmp3_binary ms;
    unsigned int ch, prev0, prev1, prev_size0, ctxsmall;
    unsigned int code, i, r, w, low, best_low;
    unsigned long cnt[256], best, n, total;
    int ok=0;
    if(!ar || !h || !g || rate_index(h->samplerate)<0 ||
       h->frame_count==0 || h->channels<1 || h->channels>2 ||
       h->frame_count>(ULONG_MAX / (2UL*h->channels)) ||
       h->frame_count>((unsigned long)UINT_MAX)/2UL)return 0;
    r=(unsigned int)rate_index(h->samplerate);
    n=h->frame_count*2UL;
    memset(&m0,0,sizeof(m0));memset(&m1,0,sizeof(m1));
    memset(&m2,0,sizeof(m2));wzmp3_binary_init(&ms);
    memset(&mr0,0,sizeof(mr0));memset(&mr1,0,sizeof(mr1));
    memset(&mb,0,sizeof(mb));
    if(!WZMP3_PPM_INIT(m0,32,32,2,220000) ||
       !WZMP3_PPM_INIT(m1,32,32,2,220000) ||
       !WZMP3_PPM_INIT(m2,32,32,2,220000) ||
       !WZMP3_PPM_INIT(mr0,16,22,2,220000) ||
       !WZMP3_PPM_INIT(mr1,8,22,2,220000) ||
       !WZMP3_PPM_INIT(mb,289,2,1,4096))goto done;
    for(ch=0;ch<h->channels;++ch){
        wzmp3_granule *cur=g + (unsigned long)ch*n;
        memset(cnt,0,sizeof(cnt));
        for(i=0;i<n;++i) ++cnt[cur[i].gain];
        total=0;
        for(i=0;i<256;++i){total+=cnt[i];cnt[i]=total;}
        best=0;best_low=0;
        for(i=0;i<240U;++i){
            unsigned long sum=cnt[i+16U]-cnt[i];
            if(sum>=best){best=sum;best_low=i;}
        }
        if(!wzmp3_ppm_flush(&mr0,1) || !wzmp3_ppm_flush(&mr1,1) ||
           !wzmp3_ppm_flush(&mb,1))goto done;
        prev0=prev_size0=ctxsmall=0;
        for(i=0;i<n;++i){
            wzmp3_granule *x=cur+i;
            unsigned int sband;
            if(x->sw && x->type>3U)goto done;
            if(!SYM(mb, x->sw && x->type==2U ? 1U:0U) ||
               !NEXT(mb,code) || code>288U)goto done;
            x->big_values=code;
            if(!x->sw){
                sband=band_of(2U*code,(int)r);
                if(!shift2(&mr0,prev_size0,sband) ||
                   !NEXT(mr0,code) || code>=16U)goto done;
                x->r0=code;
                if(!shift2(&mr1,code,sband) ||
                   !NEXT(mr1,w) || w>=8U || code+w+2U>=23U)goto done;
                x->r1=w;
                x->bound[0]=minimum(long_edges[r][code+1],2U*x->big_values);
                x->bound[1]=minimum(long_edges[r][code+w+2],2U*x->big_values);
                if(x->bound[1]<x->bound[0])x->bound[1]=x->bound[0];
                x->bound[2]=2U*x->big_values;
                prev_size0=code+1U;
            } else {
                x->r0=x->type==2U?9U:8U;
                x->r1=0;
                x->bound[0]=minimum(x->type==2U?3U*short_edges[r][3]:
                                       long_edges[r][8],2U*x->big_values);
                x->bound[1]=x->bound[2]=2U*x->big_values;
                prev_size0=0;
            }
            /* Global gain context is independently derived from each
             * channel's 16-value dense window. */
            low=cur[i].gain >= best_low ? cur[i].gain-best_low:0U;
            if(low>15U)low=15U;
            if(!shift2(&m0,low,prev0) || !NEXT(m0,code) || code>31U)goto done;
            x->table[0]=prev0=code;
            if(!shift2(&m1,prev0,prev_size0) || !NEXT(m1,code) || code>31U)
                goto done;
            x->table[1]=prev1=code;
            if(!x->sw){
                if(!shift2(&m2,prev0,prev1) || !NEXT(m2,code) ||
                   code>31U)goto done;
                x->table[2]=code;
            }else x->table[2]=0;
            if(!wzmp3_binary_shift(&ms,ctxsmall) ||
               !wzmp3_binary_decode(&ms,ar,&code))goto done;
            x->small_table=code;
            ctxsmall=((ctxsmall<<1)|code)&15U;
        }
    }
    ok=1;
done:
    wzmp3_ppm_cleanup(&m0);wzmp3_ppm_cleanup(&m1);
    wzmp3_ppm_cleanup(&m2);
    wzmp3_ppm_cleanup(&mr0);wzmp3_ppm_cleanup(&mr1);
    wzmp3_ppm_cleanup(&mb);
    return ok;
}

int wzmp3_scalefactor_controls_decode(wzmp3_range *ar,
                                     const wzmp3_header *h,
                                     wzmp3_granule *g)
{
    wzmp3_ppm_model m; wzmp3_binary binary;
    unsigned int ch,code,ctx,i,prev,sub;
    unsigned long n,j;
    int ok=0;
    if(!ar || !h || !g || !h->frame_count || h->channels<1 ||
       h->channels>2 || h->frame_count > ULONG_MAX/(2UL*h->channels) ||
       h->frame_count>((unsigned long)UINT_MAX)/2UL)
        return 0;
    n=h->frame_count*2UL;
    if(h->has_scf_sharing){
        memset(&m,0,sizeof(m));
        if(!WZMP3_PPM_INIT(m,16,16,3,40000))return 0;
        for(ch=0;ch<h->channels;++ch){
            if(!wzmp3_ppm_flush(&m,1))goto cleanup;
            prev=0;
            for(j=0;j<n;j+=2){
                wzmp3_granule *x=g+ch*n+j;
                if(!shift3(&m,prev,x[0].slength,x[1].slength)||
                   !NEXT(m,code))goto cleanup;
                x[0].share=prev=code;
            }
        }
        ok=1;
cleanup:
        wzmp3_ppm_cleanup(&m);
        if(!ok)return 0;
    }
    if(h->has_preemphasis || h->has_coarse_scf){
        for(sub=0;sub<2;++sub){
            if(sub==0 && !h->has_preemphasis)continue;
            if(sub==1 && !h->has_coarse_scf)continue;
            wzmp3_binary_init(&binary);
            ok=0;
            for(ch=0;ch<h->channels;++ch){
                wzmp3_binary_flush(&binary,1);
                ctx=0;
                for(j=0;j<n;++j){
                    if(!wzmp3_binary_shift(&binary,ctx) ||
                       !wzmp3_binary_decode(&binary,ar,&code))break;
                    if(sub==0)g[ch*n+j].preflag=code;
                    else g[ch*n+j].coarse=code;
                    ctx=((ctx<<1)|code)&15U;
                }
                if(j<n)break;
            }
            if(ch==h->channels)ok=1;
            if(!ok)return 0;
        }
    }
    if(h->has_subblock_gain){
        memset(&m,0,sizeof(m));
        if(!WZMP3_PPM_INIT(m,8,8,1,4096))return 0;
        if(!SYM(m,0)){wzmp3_ppm_cleanup(&m);return 0;}
        ok=1;
        for(ch=0;ch<h->channels && ok;++ch)
            for(j=0;j<n && ok;++j)
                if(g[ch*n+j].sw){
                    for(i=0;i<3;++i){
                        if(!NEXT(m,code) || code>7U || !SYM(m,code)){
                            ok=0;break;
                        }
                        g[ch*n+j].subgain[i]=code;
                    }
                }
        wzmp3_ppm_cleanup(&m);
        if(!ok)return 0;
    }
    return 1;
}

/* The MPEG joint-stereo mid/side switch is stored per MP3 frame. */
int wzmp3_ms_stereo_decode(wzmp3_range *ar,const wzmp3_header *h,
                           unsigned char *flags)
{
    wzmp3_binary m;
    unsigned int ctx=0,v;
    unsigned long i;
    if(!ar || !h || !flags || !h->frame_count)return 0;
    if(!h->has_ms_stereo){
        memset(flags,0,(size_t)h->frame_count);
        return 1;
    }
    wzmp3_binary_init(&m);
    for(i=0;i<h->frame_count;++i){
        if(!wzmp3_binary_shift(&m,ctx) ||
           !wzmp3_binary_decode(&m,ar,&v))return 0;
        flags[i]=(unsigned char)v;
        ctx=((ctx<<1)|v)&15U;
    }
    return 1;
}
