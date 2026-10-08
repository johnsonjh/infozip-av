/* SPDX-License-Identifier: MIT-0 */
#include "wzmp3_mpeg.h"
#include <limits.h>
#include <string.h>

static const unsigned int mp3_bitrates[16] = {
    0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0
};
static const unsigned int mp3_rates[4] = {44100,48000,32000,0};

typedef struct wzmp3_br_s {
    const unsigned char *src;
    size_t bits,cap;
} wzmp3_br;
static int getbits(wzmp3_br *r,unsigned int n,unsigned int *value)
{
    unsigned int v=0,i;
    if(n>16U || r->bits>r->cap || n>r->cap-r->bits)return 0;
    for(i=0;i<n;i++){
        unsigned int b=(r->src[r->bits>>3]>>(7U-(r->bits&7U)))&1U;
        v=(v<<1)|b;
        r->bits++;
    }
    *value=v;return 1;
}
void wzmp3_bits_start(wzmp3_bitwriter *w,unsigned char *dst,size_t cap)
{
    w->bytes=dst;w->capacity=cap;w->bits=0;w->failed=(dst==0);
    if(dst && cap)memset(dst,0,cap);
}
int wzmp3_bits_put(wzmp3_bitwriter *w,unsigned int value,unsigned int nbits)
{
    unsigned int i;
    if(!w || w->failed || nbits>16U || (nbits<16U && (value >> nbits)!=0U) ||
       (nbits==16U && (unsigned long)value>65535UL) ||
       w->capacity>((size_t)-1)/8U ||
       w->bits>w->capacity*8U ||
       (size_t)nbits>w->capacity*8U-w->bits){if(w)w->failed=1;return 0;}
    for(i=nbits;i>0;i--){
        unsigned int bit=(value>>(i-1U))&1U;
        size_t p=w->bits++;
        w->bytes[p>>3]=(unsigned char)(w->bytes[p>>3] |
                              (unsigned char)(bit<<(7U-(p&7U))));
    }
    return 1;
}
int wzmp3_bits_put_long(wzmp3_bitwriter *w,unsigned long v,unsigned int nbits)
{
    unsigned int i;
    if(!w || w->failed || nbits>32U ||
       w->capacity>((size_t)-1)/8U ||
       w->bits>w->capacity*8U ||
       (size_t)nbits>w->capacity*8U-w->bits ||
       (nbits<32U && (v>>nbits)!=0UL) ||
       (nbits==32U && (v>>31)>1UL)){
        if(w)w->failed=1;
        return 0;
    }
    for(i=nbits;i>0;i--){
        unsigned int bit=(unsigned int)((v>>(i-1U))&1UL);
        size_t p=w->bits++;
        w->bytes[p>>3]=(unsigned char)(w->bytes[p>>3] |
                           (unsigned char)(bit<<(7U-(p&7U))));
    }
    return 1;
}
int wzmp3_bits_align(wzmp3_bitwriter *w)
{
    unsigned int extra;
    if(!w || w->failed)return 0;
    extra=(unsigned int)((8U-(w->bits&7U))&7U);
    return wzmp3_bits_put(w,0,extra);
}
int wzmp3_bits_size(const wzmp3_bitwriter *w,size_t *size)
{
    if(!w || !size || w->failed)return 0;
    *size=w->bits/8U+(w->bits%8U!=0U);return 1;
}

/* MPEG side information is serialized in frame/granule/channel order. */
static int side_granule_read(wzmp3_br *r,wzmp3_granule *g)
{
    unsigned int i;
    if(!getbits(r,12,&g->part_length)||!getbits(r,9,&g->big_values)||
       !getbits(r,8,&g->gain)||!getbits(r,4,&g->slength)||
       !getbits(r,1,&g->sw))return 0;
    if(g->big_values>288U)return 0;
    if(g->sw){
        if(!getbits(r,2,&g->type)||!getbits(r,1,&g->mixed)||
           !getbits(r,5,&g->table[0])||!getbits(r,5,&g->table[1]))return 0;
        for(i=0;i<3;i++)if(!getbits(r,3,&g->subgain[i]))return 0;
        g->r0=g->type==2U?9U:8U;g->r1=0;
    }else {
        for(i=0;i<3;i++)if(!getbits(r,5,&g->table[i]))return 0;
        if(!getbits(r,4,&g->r0)||!getbits(r,3,&g->r1))return 0;
    }
    if(!getbits(r,1,&g->preflag)||!getbits(r,1,&g->coarse)||
       !getbits(r,1,&g->small_table))return 0;
    return 1;
}
static int side_granule_write(wzmp3_bitwriter *w,const wzmp3_granule *g)
{
    unsigned int i;
    if(g->big_values>288U || !wzmp3_bits_put(w,g->part_length,12)||
       !wzmp3_bits_put(w,g->big_values,9)||
       !wzmp3_bits_put(w,g->gain,8)||
       !wzmp3_bits_put(w,g->slength,4)||
       !wzmp3_bits_put(w,g->sw,1))return 0;
    if(g->sw){
        if(!wzmp3_bits_put(w,g->type,2)||!wzmp3_bits_put(w,g->mixed,1)||
           !wzmp3_bits_put(w,g->table[0],5)||
           !wzmp3_bits_put(w,g->table[1],5))return 0;
        for(i=0;i<3;i++)if(!wzmp3_bits_put(w,g->subgain[i],3))return 0;
    }else {
        for(i=0;i<3;i++)if(!wzmp3_bits_put(w,g->table[i],5))return 0;
        if(!wzmp3_bits_put(w,g->r0,4)||
           !wzmp3_bits_put(w,g->r1,3))return 0;
    }
    return wzmp3_bits_put(w,g->preflag,1)&&
           wzmp3_bits_put(w,g->coarse,1)&&
           wzmp3_bits_put(w,g->small_table,1);
}
int wzmp3_mpeg_parse(const unsigned char *data,size_t available,
                     wzmp3_mpeg_frame *f)
{
    wzmp3_br r;
    unsigned int ch,gr,idx,sr,kbps,crc_bytes;
    if(!data || !f || available<4)return 0;
    memset(f,0,sizeof(*f));
    if(data[0]!=0xffU || (data[1]&0xfeU)!=0xfaU)return 0;
    idx=(data[2]>>4)&15U;
    sr=(data[2]>>2)&3U;
    kbps=mp3_bitrates[idx];
    if(!kbps || !mp3_rates[sr])return 0;
    f->rate_index=sr;f->bitrate_index=idx;
    f->padding=(data[2]>>1)&1U;
    f->channels=(data[3]&0xc0U)==0xc0U?1U:2U;
    f->crc_present=(data[1]&1U)==0U;
    f->side_bytes=f->channels==1U?17U:32U;
    f->frame_bytes=144000U*kbps/mp3_rates[sr]+f->padding;
    crc_bytes=f->crc_present?2U:0U;
    if(f->frame_bytes<4U+crc_bytes+f->side_bytes ||
       (size_t)f->frame_bytes>available)return 0;
    memcpy(f->header,data,4);
    if(crc_bytes)memcpy(f->crc,data+4,2);
    r.src=data+4U+crc_bytes;r.bits=0;
    r.cap=(size_t)f->side_bytes*8U;
    if(!getbits(&r,9,&f->main_data_begin)||
       !getbits(&r,f->channels==1U?5U:3U,&f->side_private))return 0;
    for(ch=0;ch<f->channels;ch++)if(!getbits(&r,4,&f->scfsi[ch]))return 0;
    for(gr=0;gr<2;gr++)for(ch=0;ch<f->channels;ch++)
        if(!side_granule_read(&r,&f->granules[gr][ch]))return 0;
    return r.bits==r.cap;
}
int wzmp3_mpeg_write_header(const wzmp3_mpeg_frame *f,
                            unsigned char *out,size_t capacity,
                            size_t *length)
{
    wzmp3_bitwriter w;
    unsigned int gr,ch,cbytes;
    size_t side,bytes;
    if(!f || !out || !length || f->channels<1U || f->channels>2U ||
       f->crc_present>1U || f->side_bytes!=(f->channels==1U?17U:32U))return 0;
    cbytes=f->crc_present?2U:0U;
    side=4U+cbytes;
    if(capacity<side+(size_t)f->side_bytes)return 0;
    memcpy(out,f->header,4);
    if(cbytes)memcpy(out+4,f->crc,2);
    wzmp3_bits_start(&w,out+side,(size_t)f->side_bytes);
    if(!wzmp3_bits_put(&w,f->main_data_begin,9)||
       !wzmp3_bits_put(&w,f->side_private,f->channels==1U?5U:3U))return 0;
    for(ch=0;ch<f->channels;ch++)if(!wzmp3_bits_put(&w,f->scfsi[ch],4))return 0;
    for(gr=0;gr<2;gr++)for(ch=0;ch<f->channels;ch++)
        if(!side_granule_write(&w,&f->granules[gr][ch]))return 0;
    if(!wzmp3_bits_size(&w,&bytes)||bytes!=(size_t)f->side_bytes ||
       w.bits!=(size_t)f->side_bytes*8U)return 0;
    *length=side+bytes;return 1;
}

/* The caller supplies MPEG-codebook codewords from an independently sourced
 * ISO codebook. The implementation never substitutes a different codeword.
 */
int wzmp3_huffman_pair(wzmp3_bitwriter *w,const wzmp3_codebook *book,
                       unsigned int x,unsigned int y,
                       unsigned int xneg,unsigned int yneg)
{
    unsigned int ax,ay,c,base,extra,n;
    wzmp3_codeword cw;
    if(!w || !book || book->quad || book->maxvalue>15U ||
       book->linbits>13U || xneg>1U || yneg>1U)return 0;
    base=book->maxvalue;
    if(x>base || y>base){
        if(base!=15U || book->linbits==0U)return 0;
        if(x>15U+((1U<<book->linbits)-1U) ||
           y>15U+((1U<<book->linbits)-1U))return 0;
    }
    if(base==0U && book->linbits==0U && x==0U && y==0U)return 1;
    ax=x>base?base:x;ay=y>base?base:y;
    c=ax*16U+ay;
    cw=book->symbols[c];
    if(!cw.length || cw.length>32U)return 0;
    if(!wzmp3_bits_put_long(w,cw.code,cw.length))return 0;
    for(n=0;n<2;n++){
        unsigned int v=n?y:x;
        if(base==15U && book->linbits && v>=15U){
            extra=v-15U;
            if(!wzmp3_bits_put(w,extra,book->linbits))return 0;
        }
        if(v && !wzmp3_bits_put(w,n?yneg:xneg,1U))return 0;
    }
    return 1;
}
int wzmp3_huffman_quad(wzmp3_bitwriter *w,const wzmp3_codebook *book,
                       const unsigned char a[4],const unsigned char neg[4])
{
    wzmp3_codeword cw;
    unsigned int k,sym=0;
    if(!w || !book || !book->quad || !a || !neg)return 0;
    for(k=0;k<4;k++){
        if(a[k]>1U || neg[k]>1U)return 0;
        sym=(sym<<1)|a[k];
    }
    cw=book->symbols[sym];
    if(!cw.length || cw.length>32U || !wzmp3_bits_put_long(w,cw.code,cw.length))return 0;
    for(k=0;k<4;k++)if(a[k] && !wzmp3_bits_put(w,neg[k],1U))return 0;
    return 1;
}

int wzmp3_huffman_spectrum(wzmp3_bitwriter *w,
                           const wzmp3_codebook books[34],
                           const wzmp3_granule *g,const wzmp3_spectrum *s)
{
    unsigned int p,region,table,x,y,k,mag;
    unsigned char a[4],neg[4];
    if(!w || !books || !g || !s || !w->bytes || w->failed ||
       g->big_values>288U || g->bound[0]>g->bound[1] ||
       g->bound[1]>g->bound[2] || g->bound[2]!=2U*g->big_values ||
       s->small_boundary<g->bound[2] || s->small_boundary>576U ||
       (s->small_boundary-g->bound[2])%4U != 0U ||
       (g->bound[0]&1U) || (g->bound[1]&1U) ||
       s->stuffing_count>4096U)return 0;
    for(p=0;p<g->bound[2];p+=2U){
        region=p<g->bound[0]?0U:p<g->bound[1]?1U:2U;
        table=g->table[region];
        if(table>=32U || table==4U || table==14U)return 0;
        mag=s->magnitude[p];
        if(mag==15U){
            if(s->extra_width[p]>13U ||
               s->extra_bits[p]>=(1U<<13U))return 0;
            mag+=s->extra_bits[p];
        }else if(s->extra_width[p] || s->extra_bits[p])return 0;
        x=mag;
        mag=s->magnitude[p+1U];
        if(mag==15U){
            if(s->extra_width[p+1U]>13U ||
               s->extra_bits[p+1U]>=(1U<<13U))return 0;
            mag+=s->extra_bits[p+1U];
        }else if(s->extra_width[p+1U] || s->extra_bits[p+1U])return 0;
        y=mag;
        if(!wzmp3_huffman_pair(w,&books[table],x,y,
                              s->negative[p],s->negative[p+1U]))return 0;
    }
    if(g->small_table>1U)return 0;
    for(p=g->bound[2];p<s->small_boundary;p+=4U){
        for(k=0;k<4U;k++){
            if(s->magnitude[p+k]>1U || s->extra_width[p+k] ||
               s->extra_bits[p+k])return 0;
            a[k]=s->magnitude[p+k];
            neg[k]=s->negative[p+k];
        }
        if(!wzmp3_huffman_quad(w,&books[32U+g->small_table],a,neg))return 0;
    }
    for(k=0;k<s->stuffing_count;k++){
        if(s->stuffing_bits[k]>1U ||
           !wzmp3_bits_put(w,s->stuffing_bits[k],1U))return 0;
    }
    return 1;
}

int wzmp3_mpeg_main_position(const wzmp3_mpeg_frame *f,
                             size_t main_bytes_before_frame,
                             size_t *bit_position)
{
    size_t offset;
    if(!f || !bit_position || f->main_data_begin>main_bytes_before_frame)
        return 0;
    offset=main_bytes_before_frame-(size_t)f->main_data_begin;
    if(offset>((size_t)-1)/8U)return 0;
    *bit_position=offset*8U;
    return 1;
}

int wzmp3_mpeg_scalefactors(wzmp3_bitwriter *w,
                            const wzmp3_granule *g,
                            const unsigned char values[36],
                            unsigned int granule_index,
                            unsigned int share_flags)
{
    static const unsigned char widths[16][2]={
        {0,0},{0,1},{0,2},{0,3},{3,0},{1,1},{1,2},{1,3},
        {2,1},{2,2},{2,3},{3,1},{3,2},{3,3},{4,2},{4,3}
    };
    static const unsigned int ends[4]={6,11,16,21};
    unsigned int group,band,win,start=0,width;
    if(!w || !g || !values || granule_index>1U ||
       share_flags>15U || g->slength>15U || g->type>3U ||
       (g->type==2U && g->mixed))return 0;
    if(g->type==2U){
        for(win=0;win<3U;win++){
            for(band=0;band<12U;band++){
                width=widths[g->slength][band<6U?0U:1U];
                if(!wzmp3_bits_put(w,values[win*12U+band],width))return 0;
            }
        }
    }else {
        for(group=0;group<4U;group++){
            width=widths[g->slength][group<2U?0U:1U];
            if(granule_index==1U && ((share_flags>>(3U-group))&1U)){
                start=ends[group];continue;
            }
            for(band=start;band<ends[group];band++)
                if(!wzmp3_bits_put(w,values[band],width))return 0;
            start=ends[group];
        }
    }
    return 1;
}
