/* SPDX-License-Identifier: MIT-0
 * Each context begins with the uniform binary prior {1,1}. The model
 * tracks both outcomes, halves counts on saturation, and never lets a
 * symbol probability vanish. This has no PPM escape stage.
 */
#include "wzmp3_binary.h"
#include <string.h>
void wzmp3_binary_init(wzmp3_binary *m)
{
    unsigned int i;
    memset(m,0,sizeof(*m));
    for(i=0;i<16;++i)m->freq[i][0]=m->freq[i][1]=1;
}
int wzmp3_binary_shift(wzmp3_binary *m,unsigned int c)
{
    if(!m || c>15)return 0;
    m->current=c;
    return 1;
}
static void binary_halve(unsigned short *f,unsigned int shift)
{
    unsigned int i;
    for(i=0;i<2;++i){
        f[i] >>= shift;
        if(!f[i])f[i]=1;
    }
}
int wzmp3_binary_decode(wzmp3_binary *m,wzmp3_range *r,unsigned int *out)
{
    unsigned short *f;
    unsigned long total,count,lo,hi;
    unsigned int s;
    if(!m || !r || !out)return 0;
    f=m->freq[m->current];
    total=(unsigned long)f[0]+f[1];
    if(!wzmp3_range_count(r,total,&count))return 0;
    s=count<f[0]?0U:1U;
    lo=s ? f[0]:0U;
    hi=s ? total:f[0];
    if(!wzmp3_range_remove(r,total,lo,hi))return 0;
    ++f[s];
    if(f[s]>=511U)binary_halve(f,1);
    *out=s;
    return 1;
}
void wzmp3_binary_flush(wzmp3_binary *m,unsigned int shift)
{
    unsigned int i;
    if(!m || shift>15U)return;
    for(i=0;i<16;++i)binary_halve(m->freq[i],shift);
}
