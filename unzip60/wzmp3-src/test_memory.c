/* SPDX-License-Identifier: MIT-0; small-budget and accounting regressions. */
#include "wzmp3_memory.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>
int main(void)
{
    wzmp3_memory a,b;
    unsigned char *p, *q;
    size_t cost;
    wzmp3_memory_init(&a,128U);
    wzmp3_memory_init(&b,64U);
    p=(unsigned char *)wzmp3_memory_alloc(&a,16U);
    if(!p || !a.current || a.current>128U) return 1;
    cost=a.current;
    memset(p,0xa5,16U);
    if(wzmp3_memory_alloc(&a,128U)!=NULL || !a.exhausted ||
       a.current!=cost) return 2;
    q=(unsigned char *)wzmp3_memory_realloc(&a,p,20U);
    if(!q || q[0]!=0xa5U || q[15]!=0xa5U) return 3;
    p=q;
    cost=a.current;
    if(wzmp3_memory_realloc(&a,p,128U)!=NULL || a.current!=cost ||
       p[15]!=0xa5U) return 4;
    if(wzmp3_memory_calloc(&a,(size_t)-1,2U)!=NULL || a.current!=cost)
       return 5;
    q=(unsigned char *)wzmp3_memory_calloc(&b,4U,4U);
    if(!q || q[0] || q[15] || b.exhausted || b.current==0U) return 6;
    wzmp3_memory_free(&b,q);
    wzmp3_memory_free(&a,p);
    if(a.current || b.current || !a.peak || !b.peak) return 7;
    puts("PASS: isolated allocation budgets, overflow, realloc and cleanup");
    return 0;
}
