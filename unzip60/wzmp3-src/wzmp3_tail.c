/* SPDX-License-Identifier: MIT-0 */
#include "wzmp3_tail.h"
#include <string.h>
#ifdef WZMP3_TAIL_TRACE
#include <stdio.h>
#endif

static const unsigned int br_kbps[16]={
    0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0
};
static unsigned int mp3_frame_bytes(unsigned int kbps,unsigned int hz)
{
    return (144000U*kbps)/hz;
}
static unsigned int expected_bitrate(unsigned int main_size,unsigned int hz)
{
    unsigned int i;
    if(main_size==0)return 0U;
    for(i=1;i<=14U;i++)if(main_size<mp3_frame_bytes(br_kbps[i],hz))return i;
    return 15U;
}
int wzmp3_tail_init(wzmp3_tail *t,const wzmp3_header *h,wzmp3_memory *memory)
{
    if(!t || !h || h->channels<1U || h->channels>2U ||
       (h->samplerate!=44100U && h->samplerate!=48000U &&
        h->samplerate!=32000U))return 0;
    memset(t,0,sizeof(*t));
    t->rate=h->samplerate;t->channels=h->channels;
    t->bitrate_kbps=h->bitrate_kbps;
    t->has_reservoir=h->has_bit_reservoir;
    /* In the PMP header this flag indicates the presence of an MPEG CRC
     * field, not the inverted MPEG protection bit.  The four authentic
     * WinZip samples set it to zero (no CRC bytes). */
    t->crc_present=h->protection_bit;
    t->predictor_length=4U;
    memcpy(t->predictor_text,"LAME",4);
    wzmp3_binary_init(&t->control_model);
    {
        unsigned int k;
        for(k=0;k<256U;k++)t->raw_freq[k][0]=t->raw_freq[k][1]=1;
    }
    if(!wzmp3_ppm_init(&t->aux_model,256U,256U,1U,511U,150000UL,memory) ||
       !wzmp3_ppm_init(&t->bitrate_model,16U,16U,1U,511U,40000UL,memory)){
        wzmp3_tail_free(t);return 0;
    }
    t->initialized=1;
    return 1;
}
void wzmp3_tail_free(wzmp3_tail *t)
{
    if(!t)return;
    wzmp3_ppm_cleanup(&t->aux_model);
    wzmp3_ppm_cleanup(&t->bitrate_model);
    memset(t,0,sizeof(*t));
}
/* Construct the predictors' next candidate ancillary bit sequence.  Stored
 * bytes are MSB-first and final unused bits are zero. */
static void ancillary_predict(wzmp3_tail *t,unsigned int n,unsigned char *buf)
{
    unsigned int i,full=n/8U,remain=n%8U,limit=(n+7U)/8U;
    memset(buf,0,2048);
    for(i=0;i<limit;i++){
        unsigned int v;
        if(t->predictor_constant==1U)v=0U;
        else if(t->predictor_constant==2U)v=255U;
        else if(full>=1U && i<4U)v=(unsigned char)"LAME"[i];
        else if(full>=8U && i<t->predictor_length)v=t->predictor_text[i];
        else v=t->predictor_phase?0xaaU:0x55U;
        buf[i]=(unsigned char)v;
    }
    if(remain && limit)
        buf[limit-1U]=(unsigned char)(buf[limit-1U]&
                                       (0xffU << (8U-remain)));
    t->predictor_phase ^= (remain&1U);
}
static void ancillary_learn(wzmp3_tail *t,const unsigned char *actual,
                            unsigned int n)
{
    unsigned int full=n/8U,rem=n%8U,i;
    if(full>=8U && memcmp(actual,"LAME",4)==0){
        t->predictor_constant=0;
        for(i=4;i<full && i<20U;i++){
            if(actual[i]==0x55U){t->predictor_phase=0;break;}
            if(actual[i]==0xaaU){t->predictor_phase=1;break;}
            t->predictor_text[i]=actual[i];
        }
        t->predictor_length=i;
    }else if(full && (actual[0]==0U || actual[0]==255U)){
        t->predictor_constant=actual[0]?2U:1U;
    }else if(!full && rem>1U){
        unsigned int mask=(0xffU<<(8U-rem))&255U;
        if((actual[0]&mask)==0)t->predictor_constant=1;
        else if((actual[0]&mask)==mask)t->predictor_constant=2;
        else t->predictor_constant=0;
    }else t->predictor_constant=0;
}
int wzmp3_tail_read(wzmp3_tail *t,wzmp3_range *ar,
                    unsigned int main_bits,unsigned int padding,
                    int last_frame,wzmp3_tail_result *o)
{
    unsigned int index=0,kbps,n,chunk,flag,b,ctx,i;
    unsigned int fixed,main_bytes,frame_capacity;
    unsigned char guess[2048];
    wzmp3_bitwriter wr;
    int preliminary,remaining;
    if(!t || !t->initialized || !ar || !o || padding>1U ||
       main_bits>4U*4095U || (last_frame!=0 && last_frame!=1))return 0;
    memset(o,0,sizeof(*o));
    main_bytes=(main_bits+7U)/8U;
    if(main_bytes>2048U)return 0;
    if(t->bitrate_kbps){
        kbps=t->bitrate_kbps;
        for(index=1;index<=14U;index++)if(br_kbps[index]==kbps)break;
        if(index==15U)return 0;
    }else{
        ctx=expected_bitrate(main_bytes,t->rate);
        if(!wzmp3_ppm_shift(&t->bitrate_model,ctx) ||
           !wzmp3_ppm_decode(&t->bitrate_model,ar,&index) ||
           index<1U || index>14U)return 0;
        kbps=br_kbps[index];
    }
    fixed=4U+(t->crc_present?2U:0U)+(t->channels==1U?17U:32U);
    o->frame_bytes=mp3_frame_bytes(kbps,t->rate)+padding;
    if(o->frame_bytes<=fixed || o->frame_bytes>WZMP3_FRAME_LIMIT)return 0;
    frame_capacity=o->frame_bytes-fixed;
    o->main_data_begin=(unsigned int)t->reservoir;
    preliminary=(int)frame_capacity+t->reservoir-(int)main_bytes;
    if(preliminary<0 || preliminary>2048)return 0;
    if(t->has_reservoir){
        if(last_frame)n=(unsigned int)preliminary;
        else {
            n=0;do {
                if(!wzmp3_ppm_shift(&t->aux_model,t->last_aux_context) ||
                   !wzmp3_ppm_decode(&t->aux_model,ar,&chunk) ||
                   chunk>255U || n>2048U-chunk)return 0;
                t->last_aux_context=chunk;
                n+=chunk;
            }while(chunk==255U);
        }
#ifdef WZMP3_TAIL_TRACE
        fprintf(stderr,"tail: bitrate=%u preliminary=%d aux=%u\n", index,preliminary,n);
#endif
        if(n>(unsigned int)preliminary)return 0;
        remaining=preliminary-(int)n;
        if(remaining>511)return 0;
        t->reservoir=remaining;
    }else {
        n=(unsigned int)preliminary;
        t->reservoir=0;
    }
    o->aux_bytes=n;
    o->main_size=main_bytes;
    o->bitrate_index=index;
    o->following_reservoir=(unsigned int)t->reservoir;
    if(n>2048U || n> (2048U - main_bytes))return 0;
    o->payload_bits=(main_bytes+n)*8U-main_bits;
    if(o->payload_bits>sizeof(o->payload)*8U)return 0;
    wzmp3_bits_start(&wr,o->payload,sizeof(o->payload));
    if(!wzmp3_binary_shift(&t->control_model,0) ||
       !wzmp3_binary_decode(&t->control_model,ar,&flag))return 0;
#ifdef WZMP3_TAIL_TRACE
    fprintf(stderr,"tail: bits=%u flag=%u reservoir=%d\n",o->payload_bits,flag,t->reservoir);
#endif
    ancillary_predict(t,o->payload_bits,guess);
    if(flag){
        for(i=0;i<o->payload_bits;i++){
            b=(guess[i>>3]>>(7U-(i&7U)))&1U;
            if(!wzmp3_bits_put(&wr,b,1U))return 0;
        }
    }else {
        ctx=255U;
        for(i=0;i<o->payload_bits;i++){
            unsigned short *freq=t->raw_freq[ctx];
            unsigned long total=(unsigned long)freq[0]+freq[1],count;
            unsigned long low,high;
            if(!wzmp3_range_count(ar,total,&count))return 0;
            b=count<(unsigned long)freq[0]?0U:1U;
            low=b?freq[0]:0U;
            high=b?total:freq[0];
            if(!wzmp3_range_remove(ar,total,low,high) ||
               !wzmp3_bits_put(&wr,b,1U))return 0;
            freq[b]++;
            if(freq[b]>=511U){
                freq[0]=(unsigned short)(freq[0]>>1);
                freq[1]=(unsigned short)(freq[1]>>1);
                if(!freq[0])freq[0]=1;
                if(!freq[1])freq[1]=1;
            }
            ctx=((ctx<<1U)|b)&255U;
        }
        ancillary_learn(t,o->payload,o->payload_bits);
    }
    return wr.bits==o->payload_bits;
}
