/* SPDX-License-Identifier: MIT-0; repair-record indexing boundary checks. */
#include "wzmp3_make.h"
#include <stdio.h>
#include <string.h>
int main(void)
{
    wzmp3_header h;
    wzmp3_granule g[4];
    wzmp3_mpeg_frame f;
    unsigned char r[37];
    memset(&h,0,sizeof(h));memset(g,0,sizeof(g));memset(r,0,sizeof(r));
    h.frame_count=3UL;h.channels=1U;h.channel_mode=3U;
    h.samplerate=44100U;h.bitrate_kbps=128U;
    /* One mono repair record has 2 + 1*8 = 10 bytes. */
    r[0]=1U;
    if(!wzmp3_make_frame(&h,g,9U,0U,0U,0U,0UL,r,11U,&f))return 1;
    if(!wzmp3_make_frame(&h,g,9U,0U,0U,0U,1UL,r,11U,&f))return 2;
    if(wzmp3_make_frame(&h,g,9U,0U,0U,0U,0UL,r,10U,&f))return 3;
    if(wzmp3_make_frame(&h,g,9U,0U,0U,0U,0UL,r,12U,&f))return 4;
    r[0]=2U;
    if(!wzmp3_make_frame(&h,g,9U,0U,0U,0U,1UL,r,21U,&f))return 5;
    if(wzmp3_make_frame(&h,g,9U,0U,0U,0U,2UL,r,20U,&f))return 6;
    if(wzmp3_make_frame(&h,g,9U,0U,0U,0U,3UL,r,21U,&f))return 7;
    r[0]=255U;
    if(wzmp3_make_frame(&h,g,9U,0U,0U,0U,0UL,r,21U,&f))return 8;
    puts("PASS: repair-record boundary and truncated length checks");
    return 0;
}
