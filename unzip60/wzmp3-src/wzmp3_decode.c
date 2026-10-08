/* SPDX-License-Identifier: MIT-0
 * MPEG-1 Layer III Method 94 / packMP3 1.0 stream reconstruction.
 * This module is independently authored; ISO codebook source is external.
 */
#include "wzmp3_decode.h"
#include "wzmp3_tail.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define WZMP3_METADATA_MAX ((size_t)16777216U)
#define WZMP3_FRAME_MAX 2048U

typedef struct wzmp3_buf_s {unsigned char *ptr;size_t len,cap; wzmp3_memory *memory;} wzmp3_buf;
static int push(wzmp3_buf *b,unsigned int c)
{
    size_t n;
    unsigned char *p;
    if(!b || c>255U || b->len>=WZMP3_METADATA_MAX)return 0;
    if(b->len==b->cap){
        n=b->cap?b->cap*2U:1024U;
        if(n>WZMP3_METADATA_MAX)n=WZMP3_METADATA_MAX;
        if(n<=b->cap)return 0;
        p=(unsigned char *)wzmp3_memory_realloc(b->memory,b->ptr,n);
        if(!p)return 0;
        b->ptr=p;b->cap=n;
    }
    b->ptr[b->len++]=(unsigned char)c;
    return 1;
}
static int metadata(wzmp3_range *ar,const wzmp3_header *h,
                    wzmp3_buf *prefix,wzmp3_buf *suffix)
{
    wzmp3_ppm_model m;
    unsigned int c,i;
    wzmp3_buf *b;
    memset(&m,0,sizeof(m));
    if(!h->has_leading_bytes && !h->has_trailing_bytes)return 1;
    if(!wzmp3_ppm_init(&m,257U,256U,0U,511U,4096UL,ar->source->memory))return 0;
    for(i=0;i<2U;i++){
        if((i==0U && !h->has_leading_bytes) ||
           (i==1U && !h->has_trailing_bytes))continue;
        b=i?suffix:prefix;
        for(;;){
            if(!wzmp3_ppm_decode(&m,ar,&c))goto bad;
            if(c==256U)break;
            if(!push(b,c))goto bad;
        }
    }
    wzmp3_ppm_cleanup(&m);
    return 1;
bad:
    wzmp3_ppm_cleanup(&m);
    return 0;
}
static int padding_decode(wzmp3_range *ar,const wzmp3_header *h,
                          unsigned char *pads)
{
    wzmp3_ppm_model m;
    unsigned int run=0,bit=0,i;
    memset(&m,0,sizeof(m));
    if(!h->has_padding){
        memset(pads,0,(size_t)h->frame_count);
        return 1;
    }
    if(!wzmp3_ppm_init(&m,256,256,1,511,4096,ar->source->memory)||
       !wzmp3_ppm_decode(&m,ar,&run)||!wzmp3_ppm_shift(&m,run))goto bad;
    for(i=0;i<h->frame_count;i++){
        while(run==0){
            bit^=1U;
            if(!wzmp3_ppm_decode(&m,ar,&run)||
               !wzmp3_ppm_shift(&m,run))goto bad;
        }
        --run;
        pads[i]=(unsigned char)bit;
    }
    wzmp3_ppm_cleanup(&m);
    return 1;
bad:
    wzmp3_ppm_cleanup(&m);
    return 0;
}
static int switches(wzmp3_range *ar,const wzmp3_header *h,
                    wzmp3_granule *g)
{
    wzmp3_ppm_model sm,tm;
    unsigned int ch,code,ctx,last,run,bit;
    unsigned long j,n=h->frame_count*2UL;
    memset(&sm,0,sizeof(sm));
    memset(&tm,0,sizeof(tm));
    if(!h->has_special_blocks)return 1;
    if(!wzmp3_ppm_init(&sm,32,32,1,511,16384,ar->source->memory)||
       !wzmp3_ppm_init(&tm,4,4,1,511,4096,ar->source->memory))goto bad;
    for(ch=0;ch<h->channels;++ch){
        if(ch && !h->has_special_differences)break;
        if(!wzmp3_ppm_shift(&sm,0U)||
           !wzmp3_ppm_decode(&sm,ar,&run)||
           !wzmp3_ppm_shift(&sm,run))goto bad;
        bit=0;
        for(j=0;j<n;++j){
            while(run==0){
                bit^=1U;
                if(!wzmp3_ppm_decode(&sm,ar,&run)||
                   !wzmp3_ppm_shift(&sm,run))goto bad;
            }
            --run;
            g[ch*n+j].sw=bit;
        }
        last=3U;
        for(j=0;j<n;++j){
            wzmp3_granule *x=&g[ch*n+j];
            if(!x->sw)continue;
            if(last==3U)ctx=1U;
            else if(j+1U<n && g[ch*n+j+1U].sw)ctx=2U;
            else ctx=3U;
            if(!wzmp3_ppm_shift(&tm,ctx)||
               !wzmp3_ppm_decode(&tm,ar,&code)||code>3U)goto bad;
            x->type=last=code;
        }
    }
    if(h->channels==2U && !h->has_special_differences){
        for(j=0;j<n;++j){
            g[n+j].sw=g[j].sw;
            g[n+j].type=g[j].type;
        }
    }
    wzmp3_ppm_cleanup(&sm);wzmp3_ppm_cleanup(&tm);
    return 1;
bad:
    wzmp3_ppm_cleanup(&sm);wzmp3_ppm_cleanup(&tm);
    return 0;
}
static int gain_decode(wzmp3_range *ar,const wzmp3_header *h,
                       wzmp3_granule *g)
{
    wzmp3_ppm_model m;
    unsigned long j,n=h->frame_count*2UL;
    unsigned int last=0,code;
    if(!wzmp3_ppm_init(&m,256,0,0,511,4096,ar->source->memory))return 0;
    for(j=0;j<n;++j){
        if(!wzmp3_ppm_decode(&m,ar,&code))goto bad;
        last=(last+code)&255U;
        g[j].gain=last;
    }
    if(h->channels==2U){
        for(j=0;j<n;++j){
            if(!wzmp3_ppm_decode(&m,ar,&code))goto bad;
            g[n+j].gain=(code+g[j].gain)&255U;
        }
    }
    wzmp3_ppm_cleanup(&m);
    return 1;
bad:
    wzmp3_ppm_cleanup(&m);return 0;
}
static int slength_decode(wzmp3_range *ar,const wzmp3_header *h,
                          wzmp3_granule *g)
{
    wzmp3_ppm_model m;
    unsigned long j,n=h->frame_count*2UL;
    unsigned int histogram[256],ch,i,previous,code,v,low;
    unsigned long best,window;
    if(!wzmp3_ppm_init(&m,16,16,2,511,100000,ar->source->memory))return 0;
    for(ch=0;ch<h->channels;++ch){
        memset(histogram,0,sizeof(histogram));
        for(j=0;j<n;++j)++histogram[g[ch*n+j].gain];
        for(i=1;i<256U;++i)histogram[i]+=histogram[i-1U];
        best=0;low=0;
        for(i=0;i<256U-16U;++i){
            window=(unsigned long)histogram[i+16U]-(unsigned long)histogram[i];
            if(window>=best){best=window;low=i;}
        }
        if(!wzmp3_ppm_flush(&m,1))goto bad;
        previous=0;
        for(j=0;j<n;++j){
            v=g[ch*n+j].gain;
            if(v>=low)v-=low;
            else v=0;
            if(v>15U)v=15U;
            if(!wzmp3_ppm_shift(&m,v)||
               !wzmp3_ppm_shift(&m,previous)||
               !wzmp3_ppm_decode(&m,ar,&code)||code>=16U)goto bad;
            previous=code;
            g[ch*n+j].slength=code;
        }
    }
    wzmp3_ppm_cleanup(&m);return 1;
bad:
    wzmp3_ppm_cleanup(&m);return 0;
}
static int write_bits(wzmp3_bitwriter *w,const unsigned char *src,size_t nbits)
{
    size_t i;
    for(i=0;i<nbits;i++){
        if(!wzmp3_bits_put(w,(src[i/8U]>>(7U-(i&7U)))&1U,1U))return 0;
    }
    return 1;
}
int wzmp3_decode(wzmp3_input *input,const wzmp3_codebook books[34],
                 const wzmp3_decode_options *opt,
                 wzmp3_write_cb output,void *output_context)
{
    wzmp3_header h;
    wzmp3_range ar;
    wzmp3_granule *g=0;
    wzmp3_buf prefix,suffix;
    wzmp3_join join;
    wzmp3_tail tail;
    wzmp3_granule_state gs;
    wzmp3_spectral sp;
    wzmp3_spectrum *values=0;
    unsigned char *pads=0,*ms=0,*repair=0;
    unsigned int repair_len=0;
    size_t max_output,nbits,prefix_sum;
    unsigned long fr,n,ng;
    int success=0;
    wzmp3_memory memory;
    unsigned int granul,ch,bound;
    wzmp3_memory_init(&memory,1000000000U - 34U*sizeof(*books));
    memset(&prefix,0,sizeof(prefix));memset(&suffix,0,sizeof(suffix));
    memset(&join,0,sizeof(join));memset(&tail,0,sizeof(tail));
    memset(&gs,0,sizeof(gs));memset(&sp,0,sizeof(sp));
    if(input)input->memory=&memory;
    prefix.memory=suffix.memory=&memory;
    if(!input || !opt || !output || !books || !opt->maximum_output ||
       !opt->maximum_frames || !wzmp3_parse_header(input,&h) ||
       h.frame_count>opt->maximum_frames ||
       h.frame_count>(unsigned long)((size_t)-1)/
                     (2U*h.channels*sizeof(wzmp3_granule)))goto cleanup;
    if(!wzmp3_read_repairs(input,&h,&repair,&repair_len)||
       !wzmp3_range_init(&ar,input))goto cleanup;
    if(!metadata(&ar,&h,&prefix,&suffix))goto cleanup;
    if(prefix.len>opt->maximum_output ||
       suffix.len>opt->maximum_output-prefix.len)goto cleanup;
    max_output=opt->maximum_output-prefix.len-suffix.len;
    n=h.frame_count*2UL;
    ng=n*h.channels;
    g=(wzmp3_granule *)wzmp3_memory_calloc(&memory,(size_t)ng,sizeof(*g));
    pads=(unsigned char *)wzmp3_memory_calloc(&memory,(size_t)h.frame_count,1U);
    ms=(unsigned char *)wzmp3_memory_calloc(&memory,(size_t)h.frame_count,1U);
    if(!g || !pads || !ms || !padding_decode(&ar,&h,pads) ||
       !switches(&ar,&h,g)||!gain_decode(&ar,&h,g)||
       !slength_decode(&ar,&h,g)||!wzmp3_regions_decode(&ar,&h,g)||
       !wzmp3_scalefactor_controls_decode(&ar,&h,g)||
       !wzmp3_ms_stereo_decode(&ar,&h,ms))goto cleanup;
    if(!wzmp3_granule_init(&gs,&h,&memory)||!wzmp3_spectral_init(&sp,&h,&memory)||
       !wzmp3_tail_init(&tail,&h,&memory))goto cleanup;
    if(!wzmp3_join_init(&join,max_output,(size_t)h.frame_count,&memory))goto cleanup;
    values=(wzmp3_spectrum *)wzmp3_memory_alloc(&memory,sizeof(*values));
    if(!values)goto cleanup;
    for(fr=0;fr<h.frame_count;fr++){
        wzmp3_bitwriter whole;
        wzmp3_tail_result tr;
        wzmp3_mpeg_frame mf;
        wzmp3_granule ordered[4];
        unsigned char frame_data[8192],part[4096],side[40],scfs[36];
        size_t total_side;
        wzmp3_bits_start(&whole,frame_data,sizeof(frame_data));
        for(granul=0;granul<2U;granul++)for(ch=0;ch<h.channels;ch++){
            wzmp3_bitwriter per;
            wzmp3_granule *x=&g[ch*n+fr*2UL+granul];
            const wzmp3_granule *x0=&g[fr*2UL+granul];
            const wzmp3_granule *x1=h.channels==2U?
                         &g[n+fr*2UL+granul]:x0;
            if(!wzmp3_granule_scalefactors(&gs,&ar,x,ch,granul,scfs)||
               !wzmp3_granule_small_bound(&gs,&ar,x,ch,&bound)||
               !wzmp3_spectral_read(&sp,&ar,x,bound,ch,x0->type,x1->type,
                                    ms[fr],values))goto cleanup;
            wzmp3_bits_start(&per,part,sizeof(part));
            if(!wzmp3_mpeg_scalefactors(&per,x,scfs,granul,
                             g[ch*n+fr*2UL].share)||
               !wzmp3_huffman_spectrum(&per,books,x,values))goto cleanup;
            if(values->stuffing_count){
                unsigned int i;
                for(i=0;i<values->stuffing_count;++i)
                    if(!wzmp3_bits_put(&per,values->stuffing_bits[i],1U))goto cleanup;
            }
            x->part_length=(unsigned int)per.bits;
            if(per.bits>4095U || !write_bits(&whole,part,per.bits))goto cleanup;
            ordered[granul*2U+ch]=*x;
        }
        if(!wzmp3_tail_read(&tail,&ar,(unsigned int)whole.bits,pads[fr],
               fr+1UL==h.frame_count,&tr))goto cleanup;
        /* Choose a header solely from Method 94 global and reconstructed
         * granule/frame fields. MPEG's CRC-protected variant requires a
         * separate implementation and is currently rejected. */
        if(!wzmp3_make_frame(&h,ordered,tr.bitrate_index,pads[fr],ms[fr],
                            tr.main_data_begin,fr,repair,repair_len,&mf)||
           !wzmp3_mpeg_write_header(&mf,side,sizeof(side),&total_side)||
           !wzmp3_join_frame_add(&join,side,total_side,mf.frame_bytes,
                     mf.main_data_begin,frame_data,whole.bits,
                     tr.payload,tr.payload_bits))goto cleanup;
    }
    prefix_sum=prefix.len+suffix.len;
    if(prefix_sum>opt->maximum_output ||
       join.physical_bytes>opt->maximum_output-prefix_sum)goto cleanup;
    /* Total size also includes each MPEG header separately. */
    nbits=prefix_sum+join.physical_bytes;
    if(join.frame_count>((size_t)-1)/40U ||
       nbits>opt->maximum_output)goto cleanup;
    for(fr=0;fr<join.frame_count;fr++){
        if(join.frames[fr].header_bytes>opt->maximum_output-nbits)goto cleanup;
        nbits+=join.frames[fr].header_bytes;
    }
    if(nbits!=opt->maximum_output ||
       !wzmp3_join_emit(&join,prefix.ptr,prefix.len,suffix.ptr,suffix.len,
                        output,output_context))goto cleanup;
    success=1;
cleanup:
    wzmp3_granule_destroy(&gs);
    wzmp3_spectral_free(&sp);
    wzmp3_tail_free(&tail);
    wzmp3_join_free(&join);
    wzmp3_memory_free(&memory,g);wzmp3_memory_free(&memory,pads);
    wzmp3_memory_free(&memory,ms);wzmp3_memory_free(&memory,repair);
    wzmp3_memory_free(&memory,values);
    wzmp3_memory_free(&memory,prefix.ptr);
    wzmp3_memory_free(&memory,suffix.ptr);
    if(input)input->memory=NULL;
    return success ? 1 : (memory.exhausted ? -1 : 0);
}
