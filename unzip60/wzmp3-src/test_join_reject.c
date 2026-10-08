/* SPDX-License-Identifier: MIT-0
 * Synthetic boundary/error checks for the standalone MPEG frame assembler.
 */
#include "wzmp3_join.h"
#include <stdio.h>
#include <string.h>

typedef struct sink_s {
    unsigned char bytes[64];
    size_t used;
    size_t limit;
} sink;
static int collect(void *opaque,const unsigned char *bytes,size_t n)
{
    sink *s=(sink*)opaque;
    if(n>s->limit-s->used)return 0;
    memcpy(s->bytes+s->used,bytes,n);
    s->used+=n;
    return 1;
}
static int run(void)
{
    unsigned char head[21],audio[2]={0x5aU,0xa5U};
    unsigned char tail[2]={0x33U,0xccU};
    wzmp3_join join;
    sink out;
    unsigned int i;
    memset(head,0,sizeof(head));
    for(i=0;i<21U;i++)head[i]=(unsigned char)i;
    memset(&join,0,sizeof(join));
    memset(&out,0,sizeof(out));
    out.limit=sizeof(out.bytes);
    if(!wzmp3_join_init(&join,4U,2U,NULL))return 0;
    if(wzmp3_join_emit(&join,0,0,0,0,collect,&out))return 0;
    if(!wzmp3_join_frame_add(&join,head,21U,23U,0U,audio,8U,tail,8U))return 0;
    if(wzmp3_join_emit(&join,0,0,0,0,collect,&out))return 0;
    if(!wzmp3_join_frame_add(&join,head,21U,23U,0U,audio+1,8U,tail+1,8U))return 0;
    if(!wzmp3_join_emit(&join,0,0,0,0,collect,&out))return 0;
    if(out.used!=46U || out.bytes[21]!=audio[0] || out.bytes[22]!=tail[0] ||
       out.bytes[44]!=audio[1] || out.bytes[45]!=tail[1])return 0;
    out.used=0;out.limit=22U;
    if(wzmp3_join_emit(&join,0,0,0,0,collect,&out))return 0;
    wzmp3_join_free(&join);
    if(!wzmp3_join_init(&join,2U,1U,NULL))return 0;
    if(wzmp3_join_frame_add(&join,head,21U,23U,0U,audio,8U,tail,7U))return 0;
    if(wzmp3_join_emit(&join,0,0,0,0,collect,&out))return 0;
    wzmp3_join_free(&join);
    if(!wzmp3_join_init(&join,2U,1U,NULL))return 0;
    if(wzmp3_join_frame_add(&join,head,21U,23U,1U,audio,8U,tail,8U))return 0;
    wzmp3_join_free(&join);
    if(!wzmp3_join_init(&join,2U,1U,NULL))return 0;
    if(wzmp3_join_frame_add(&join,head,21U,23U,512U,audio,8U,tail,8U))return 0;
    wzmp3_join_free(&join);
    return 1;
}
int main(void)
{
    int ok=run();
    puts(ok?"PASS: assembly bounds, reservoir, alignment and output failure":"FAIL: assembly validation");
    return ok?0:1;
}
