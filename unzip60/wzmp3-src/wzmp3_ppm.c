/* SPDX-License-Identifier: MIT-0
 * Independent sparse-context PPM-style adaptive arithmetic model.
 * Uses descending symbol order, escape intervals and escape-time exclusion.
 * Intended for Method 94 v1.0 only; not a generic MP3 decoder.
 */
#include "wzmp3_ppm.h"
#include <stdlib.h>
#include <string.h>

struct wzmp3_ppm_node_s {
    struct wzmp3_ppm_node_s *allocation_next;
    struct wzmp3_ppm_node_s *children;
    struct wzmp3_ppm_node_s *sibling;
    unsigned int child_key;
    unsigned short *frequency;
    unsigned int largest;
};

static wzmp3_ppm_node *ppm_new(wzmp3_ppm_model *m)
{
    wzmp3_ppm_node *n;
    if (m->allocated >= m->node_limit) return 0;
    n=(wzmp3_ppm_node*)wzmp3_memory_calloc(m->memory,1U,sizeof(*n));
    if(!n)return 0;
    n->allocation_next=m->all_nodes;
    m->all_nodes=n;
    ++m->allocated;
    return n;
}

void wzmp3_ppm_cleanup(wzmp3_ppm_model *m)
{
    wzmp3_ppm_node *n, *next;
    if (!m)return;
    n=m->all_nodes;
    while(n){next=n->allocation_next;
        wzmp3_memory_free(m->memory,n->frequency);
        wzmp3_memory_free(m->memory,n);n=next;}
    memset(m,0,sizeof(*m));
}

int wzmp3_ppm_init(wzmp3_ppm_model *m,unsigned int alphabet,
                   unsigned int context_alphabet,unsigned int order,
                   unsigned int threshold,unsigned long node_limit,
                   wzmp3_memory *memory)
{
    if(!m || alphabet<2 || alphabet>1024 || order>4 ||
       (order && (!context_alphabet || context_alphabet>1024)) ||
       threshold<2 || threshold>65535U || node_limit<1)
        return 0;
    memset(m,0,sizeof(*m));
    m->memory=memory;
    m->alphabet=alphabet;
    m->context_alphabet=context_alphabet;
    m->order=order;
    m->threshold=threshold;
    m->node_limit=node_limit;
    m->root=ppm_new(m);
    if(!m->root){wzmp3_ppm_cleanup(m);return 0;}
    m->active[0]=m->root;
    if(order) {
        unsigned int j;
        for(j=1;j<=order;++j){
            wzmp3_ppm_node *node=ppm_new(m);
            if(!node){wzmp3_ppm_cleanup(m);return 0;}
            node->child_key=0;
            m->active[j-1]->children=node;
            m->active[j]=node;
        }
    }
    return 1;
}

int wzmp3_ppm_shift(wzmp3_ppm_model *m,unsigned int context)
{
    wzmp3_ppm_node *fresh[5];
    wzmp3_ppm_node *parent,*n;
    unsigned int k;
    if(!m)return 0;
    if(m->order==0)return 1;
    if(context>=m->context_alphabet)return 0;
    fresh[0]=m->root;
    for(k=1;k<=m->order;++k){
        parent=m->active[k-1];
        if(!parent)return 0;
        for(n=parent->children;n;n=n->sibling)
            if(n->child_key==context)break;
        if(!n){
            n=ppm_new(m);
            if(!n)return 0;
            n->child_key=context;
            n->sibling=parent->children;
            parent->children=n;
        }
        fresh[k]=n;
    }
    for(k=1;k<=m->order;++k)m->active[k]=fresh[k];
    return 1;
}

int wzmp3_ppm_flush(wzmp3_ppm_model *m,unsigned int shift)
{
    wzmp3_ppm_node *node;
    unsigned int j;
    if(!m || shift>15U)return 0;
    for(node=m->all_nodes;node;node=node->allocation_next){
        if(!node->frequency)continue;
        node->largest=0;
        for(j=0;j<m->alphabet;++j){
            node->frequency[j]>>=shift;
            if(node->frequency[j]>node->largest)
                node->largest=node->frequency[j];
        }
    }
    return 1;
}

static int ppm_prepare(wzmp3_ppm_model *m,wzmp3_ppm_node *n)
{
    if(!n->frequency){
        n->frequency=(unsigned short*)wzmp3_memory_calloc(m->memory,
                          m->alphabet,sizeof(unsigned short));
        if(!n->frequency)return 0;
    }
    return 1;
}

int wzmp3_ppm_decode(wzmp3_ppm_model *m,wzmp3_range *r,
                     unsigned int *symbol)
{
    unsigned char excluded[1024];
    unsigned char before[1024];
    int ord, chosen_order = -1;
    wzmp3_ppm_node *n;
    unsigned long scale, count, total, escape, available, unseen;
    unsigned long cursor, lo, hi;
    unsigned int i, sym=0, previous;
    int found = 0;
    if(!m || !r || !symbol)return 0;
    memset(excluded,0,sizeof(excluded));
    available=m->alphabet;
    for(ord=(int)m->order;ord>=0;--ord){
        n=m->active[ord];
        if(!n || !ppm_prepare(m,n))return 0;
        memcpy(before,excluded,m->alphabet);
        previous=(unsigned int)available;
        total=0;
        for(i=0;i<m->alphabet;++i){
            if(n->frequency[i] && !excluded[i]){
                total+=n->frequency[i];
                excluded[i]=1;
                --available;
            }
        }
        unseen=available;
        if(previous==unseen)escape=1;
        else if(unseen==0)escape=0;
        else {
            if(n->largest==0)return 0;
            escape=unseen*(previous-unseen)/(previous*n->largest)+1;
        }
        scale=total+escape;
        if(!scale || !wzmp3_range_count(r,scale,&count))return 0;
        if(count>=total){
            if(!escape || !wzmp3_range_remove(r,scale,total,scale))return 0;
            continue;
        }
        cursor=0;
        found=0;
        for(i=m->alphabet;i-- > 0;){
            if(n->frequency[i] && !before[i]){
                lo=cursor;
                cursor+=n->frequency[i];
                hi=cursor;
                if(count>=lo && count<hi){
                    if(!wzmp3_range_remove(r,scale,lo,hi))return 0;
                    sym=i;
                    found=1;
                    break;
                }
            }
        }
        if(!found)return 0;
        chosen_order=ord;
        break;
    }
    if(!found){
        /* Every order escaped; the terminal model is uniform over symbols
         * not accounted for in higher contexts. */
        if(!available || !wzmp3_range_count(r,available,&count))return 0;
        cursor=0;
        for(i=m->alphabet;i-- > 0;){
            if(!excluded[i]){
                if(cursor==count){sym=i;found=1;break;}
                ++cursor;
            }
        }
        if(!found || !wzmp3_range_remove(r,available,count,count+1))return 0;
    }
    for(ord=chosen_order<0?0:chosen_order;ord<=(int)m->order;++ord){
        n=m->active[ord];
        if(!n || !ppm_prepare(m,n))return 0;
        ++n->frequency[sym];
        if(n->frequency[sym]>=m->threshold){
            n->largest=0;
            for(i=0;i<m->alphabet;++i){
                if(n->frequency[i])n->frequency[i]>>=1;
                if(n->frequency[i]>n->largest)n->largest=n->frequency[i];
            }
        } else if(n->frequency[sym]>n->largest)n->largest=n->frequency[sym];
    }
    *symbol=sym;
    return 1;
}
