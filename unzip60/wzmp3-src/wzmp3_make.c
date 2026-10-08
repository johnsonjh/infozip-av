/* SPDX-License-Identifier: MIT-0 */
#include "wzmp3_make.h"
#include <string.h>
static const unsigned int rate_khz[3]={44100U,48000U,32000U};
static const unsigned int kbps_index[16]={0,32,40,48,56,64,80,96,112,
                                          128,160,192,224,256,320,0};
int wzmp3_make_frame(const wzmp3_header *h,
                     const wzmp3_granule *gs,
                     unsigned int bitrate_index,unsigned int padding,
                     unsigned int middle_stereo,unsigned int reservoir,
                     unsigned long frame_index,
                     const unsigned char *repairs,unsigned int repair_len,
                     wzmp3_mpeg_frame *out)
{
    unsigned int sr,version2,i,ch,gr,priv,original,copyright_bit;
    unsigned int extension,channels,mode;
    const unsigned char *p=0;
    if(!h || !gs || !out || h->frame_count==0UL ||
       frame_index>=h->frame_count || h->channels<1U || h->channels>2U ||
       h->protection_bit != 0U || h->private_bit>1U ||
       h->original_bit>1U || h->copyright_bit>1U ||
       h->emphasis>3U || h->channel_mode>3U || padding>1U ||
       middle_stereo>1U || reservoir>511U ||
       bitrate_index<1U || bitrate_index>14U ||
       (repairs && repair_len<1U) || (!repairs && repair_len))return 0;
    sr=3U;
    for(i=0;i<3U;++i)if(h->samplerate==rate_khz[i])sr=i;
    if(sr==3U || !kbps_index[bitrate_index] ||
       (h->bitrate_kbps && h->bitrate_kbps!=kbps_index[bitrate_index]))return 0;
    channels=h->channels;mode=h->channel_mode;
    if((channels==1U)!=(mode==3U))return 0;
    if(middle_stereo && (mode!=1U || !h->has_ms_stereo))return 0;
    if(repairs){
        unsigned int count=repairs[0],record=2U+channels*8U;
        if(repair_len!=1U+count*record)return 0;
        if(frame_index<(unsigned long)count)
            p=repairs+1U+(unsigned int)frame_index*record;
    }
    memset(out,0,sizeof(*out));
    out->channels=channels;
    out->crc_present=0U;
    out->rate_index=sr;
    out->bitrate_index=bitrate_index;
    out->padding=padding;
    out->frame_bytes=(144000U*kbps_index[bitrate_index])/h->samplerate+padding;
    out->side_bytes=(channels==1U)?17U:32U;
    if(out->frame_bytes<4U+out->side_bytes ||
       out->frame_bytes>WZMP3_FRAME_LIMIT)return 0;
    out->main_data_begin=reservoir;
    original=h->original_bit;
    priv=h->private_bit;
    copyright_bit=h->copyright_bit;
    if(p){
        priv=(p[0]>>7)&1U;
        original=(p[0]>>6)&1U;
        copyright_bit=(p[0]>>5)&1U;
        out->main_data_begin=((unsigned int)(p[0]&1U)<<8)|(unsigned int)p[1];
        if(out->main_data_begin>511U)return 0;
    }
    out->header[0]=255U;
    out->header[1]=251U;
    out->header[2]=(unsigned char)((bitrate_index<<4)|(sr<<2)|(padding<<1)|priv);
    version2=(!h->has_intensity_stereo?0U:1U)| (middle_stereo<<1);
    extension=(mode==1U)?version2:0U;
    out->header[3]=(unsigned char)((mode<<6)|(extension<<4)|
                        (copyright_bit<<3)|(original<<2)|h->emphasis);
    for(ch=0;ch<channels;ch++)out->scfsi[ch]=gs[ch].share;
    for(gr=0;gr<2U;gr++)for(ch=0;ch<channels;ch++){
        out->granules[gr][ch]=gs[gr*2U+ch];
        if(p){
            const unsigned char *q=p+2U+(ch*2U+gr)*4U;
            out->granules[gr][ch].part_length=((unsigned int)q[0]<<4)|
                                             ((unsigned int)q[1]>>4);
            out->granules[gr][ch].slength=(unsigned int)q[1]&15U;
            out->granules[gr][ch].big_values=((unsigned int)q[2]<<1)|
                                               ((unsigned int)q[3]>>7);
        }
    }
    return 1;
}
