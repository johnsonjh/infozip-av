/* SPDX-License-Identifier: MIT-0 */
#include "wzmp3_join.h"
#include <stdlib.h>
#include <string.h>

static int copy_bits(wzmp3_join *j,const unsigned char *src,size_t bits)
{
    size_t i,pos;
    if(!j || (!src && bits) || j->main_capacity>((size_t)-1)/8U ||
       j->main_bits>j->main_capacity*8U ||
       bits>j->main_capacity*8U-j->main_bits)return 0;
    pos=j->main_bits;
    for(i=0;i<bits;i++){
        unsigned int bit=(src[i/8U]>>(7U-(i%8U)))&1U;
        if(bit)j->main_data[(pos+i)/8U]|=
            (unsigned char)(1U<<(7U-((pos+i)%8U)));
    }
    j->main_bits+=bits;
    return 1;
}
int wzmp3_join_init(wzmp3_join *j,size_t main_capacity,size_t frame_count,
                    wzmp3_memory *memory)
{
    if(!j)return 0;
    memset(j,0,sizeof(*j));
    j->memory=memory;
    if(!frame_count || !main_capacity ||
       frame_count>((size_t)-1)/sizeof(wzmp3_join_frame) ||
       main_capacity>((size_t)-1)/8U)return 0;
    j->frames=(wzmp3_join_frame*)wzmp3_memory_calloc(memory,frame_count,sizeof(*j->frames));
    j->main_data=(unsigned char*)wzmp3_memory_calloc(memory,main_capacity,1U);
    if(!j->frames || !j->main_data){wzmp3_join_free(j);return 0;}
    j->frame_count=frame_count;
    j->main_capacity=main_capacity;
    return 1;
}
void wzmp3_join_free(wzmp3_join *j)
{
    if(!j)return;
    wzmp3_memory_free(j->memory,j->frames);
    wzmp3_memory_free(j->memory,j->main_data);
    memset(j,0,sizeof(*j));
}
int wzmp3_join_frame_add(wzmp3_join *j,const unsigned char *header,
                         size_t header_bytes,size_t frame_bytes,
                         unsigned int main_data_begin,
                         const unsigned char *audio,size_t audio_bits,
                         const unsigned char *tail,size_t tail_bits)
{
    size_t body,expected_start,expected_end;
    wzmp3_join_frame *r;
    if(!j || j->error || !j->frames || !header || j->frames_used>=j->frame_count ||
       header_bytes<21U || header_bytes>40U || frame_bytes<header_bytes ||
       main_data_begin>511U || (!audio && audio_bits) || (!tail && tail_bits))goto bad;
    body=frame_bytes-header_bytes;
    if(body>j->main_capacity-j->physical_bytes ||
       main_data_begin>j->physical_bytes)goto bad;
    expected_start=j->physical_bytes-main_data_begin;
    if(expected_start>((size_t)-1)/8U ||
       j->main_bits!=expected_start*8U)goto bad;
    expected_end=j->physical_bytes+body;
    if(audio_bits>(((size_t)-1)-tail_bits) ||
       audio_bits+tail_bits>expected_end*8U-j->main_bits ||
       ((audio_bits+tail_bits)&7U)!=0U)goto bad;
    r=&j->frames[j->frames_used];
    memcpy(r->header,header,header_bytes);
    r->header_bytes=header_bytes;
    r->body_bytes=body;
    if(!copy_bits(j,audio,audio_bits) || !copy_bits(j,tail,tail_bits))goto bad;
    j->physical_bytes=expected_end;
    j->frames_used++;
    return 1;
bad:
    if(j)j->error=1;
    return 0;
}
int wzmp3_join_emit(const wzmp3_join *j,
                    const unsigned char *prefix,size_t prefix_bytes,
                    const unsigned char *suffix,size_t suffix_bytes,
                    wzmp3_write_cb write,void *opaque)
{
    size_t i,off=0;
    if(!j || !write || j->error || j->frames_used!=j->frame_count ||
       !j->main_data || j->physical_bytes>j->main_capacity ||
       j->physical_bytes>((size_t)-1)/8U ||
       j->main_bits!=j->physical_bytes*8U ||
       (prefix_bytes&&!prefix) || (suffix_bytes&&!suffix))return 0;
    if(prefix_bytes && !write(opaque,prefix,prefix_bytes))return 0;
    for(i=0;i<j->frames_used;i++){
        const wzmp3_join_frame *r=&j->frames[i];
        if(!write(opaque,r->header,r->header_bytes) ||
           r->body_bytes>j->physical_bytes-off ||
           (r->body_bytes &&
           !write(opaque,j->main_data+off,r->body_bytes)))return 0;
        off+=r->body_bytes;
    }
    if(off!=j->physical_bytes)return 0;
    if(suffix_bytes && !write(opaque,suffix,suffix_bytes))return 0;
    return 1;
}
