/* Independent primitive tests; not for the UnZip distribution. */
#include "wzmp3_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define N 6000
#define HALF 0x40000000UL
#define ONEQUART 0x20000000UL
#define THREEQUART 0x60000000UL

typedef struct { unsigned char p[131072]; unsigned long n, pos; } buffer;
typedef struct { buffer *dst;unsigned int bits,byte;unsigned long lo,hi,pending; } enc;
static unsigned long state=12UL;
static unsigned long pseudo(void) { state=(1664525UL*state+1013904223UL)&0xffffffffUL; return state; }
static int read_mem(void *vp,unsigned char *b) {
    buffer *x=(buffer*)vp;
    if (x->pos>=x->n)return 0;
    *b=x->p[x->pos++];return 1;
}
static int putbit(enc *e,int b) {
    if(e->dst->n >= sizeof(e->dst->p))return 0;
    e->byte=(e->byte<<1)|(unsigned int)b;
    if(++e->bits==8){e->dst->p[e->dst->n++]=(unsigned char)e->byte; e->bits=e->byte=0;}
    return 1;
}
static int emit(enc *e,int b){
    if(!putbit(e,b))return 0;
    while(e->pending){if(!putbit(e,!b))return 0;--e->pending;}
    return 1;
}
static int encode(enc *e,unsigned long scale,unsigned long start,unsigned long end){
    unsigned long q=(e->hi-e->lo+1)/scale;
    if(!q)return 0;
    e->hi=e->lo+q*end-1;
    e->lo+=q*start;
    for(;;){
        if(e->hi<HALF){if(!emit(e,0))return 0;}
        else if(e->lo>=HALF){if(!emit(e,1))return 0;e->lo-=HALF;e->hi-=HALF;}
        else if(e->lo>=ONEQUART && e->hi<THREEQUART){++e->pending;e->lo-=ONEQUART;e->hi-=ONEQUART;}
        else break;
        e->lo<<=1;e->hi=(e->hi<<1)|1;
    }
    return 1;
}
static int finish(enc *e){
    ++e->pending;
    if(!emit(e,e->lo>=ONEQUART))return 0;
    if(e->bits){e->dst->p[e->dst->n++]=(unsigned char)(e->byte<<(8-e->bits));}
    return 1;
}
int main(void){
    unsigned int sym[N];unsigned long scale[N],start[N],end[N],c;
    unsigned int i, errors=0;
    buffer b;enc e;wzmp3_input in;wzmp3_range d;
    memset(&b,0,sizeof(b));memset(&e,0,sizeof(e));e.dst=&b;e.hi=0x7fffffffUL;
    for(i=0;i<N;++i){
        scale[i]=2+(pseudo()%199);
        sym[i]=(unsigned int)(pseudo()%scale[i]);
        start[i]=sym[i];end[i]=sym[i]+1;
        if(!encode(&e,scale[i],start[i],end[i])) {puts("encoder failed");return 1;}
    }
    if(!finish(&e)){puts("finish failed");return 1;}
    wzmp3_input_init(&in,read_mem,&b,0,b.n);
    if(!wzmp3_range_init(&d,&in)){puts("decoder init failed");return 1;}
    for(i=0;i<N;++i){
        if(!wzmp3_range_count(&d,scale[i],&c)){
            printf("get count failed at %u\n",i);return 1;
        }
        if(c!=(unsigned long)sym[i]){
            printf("wrong symbol %u: got %lu, expected %u\n",i,c,sym[i]);return 1;
        }
        if(!wzmp3_range_remove(&d,scale[i],c,c+1)){
            printf("remove failed at %u\n",i);return 1;
        }
    }
    printf("31-bit arithmetic primitive: %u/%u round-trips pass, %lu encoded bytes, errors=%u\n",N,N,b.n,errors);
    return 0;
}
