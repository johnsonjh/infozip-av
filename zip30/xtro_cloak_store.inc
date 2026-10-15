/* SPDX-License-Identifier: MIT-0 */
/* Linux/Unix opt-in: ZipCloak conversion of public Xtro metadata into
 * ZipCrypto-protected companions. Included only by ZipCloak, never Zip.
 * Existing STORE/Deflate companions retain their method; small inline
 * metadata is validated and staged as a new STORE companion. */
#undef local
#include "../xtrmeta/xtrv1.h"
#define local static

typedef struct xtro_cloak_stage {
    struct zlist far *owner;
    struct zlist far *side;
    FILE *content;
    xtr_extra encrypted_owner; /* replacement owner envelope (either direction) */
    unsigned char public_sha[32];
    int reverse;
    ulg crc;
    ulg len;  /* staged compressed size (excludes ZipCrypto header) */
    ulg unpacked; /* staged uncompressed size */
    int generated; /* companion synthesized from validated inline metadata */
    struct xtro_cloak_stage *next;
} xtro_cloak_stage;
static xtro_cloak_stage *xtro_cloak_stages;
static int xtro_cloak_transition_requested;

typedef struct xtro_cloak_input {
    FILE *stream;
    zoff_t at;
} xtro_cloak_input;
static size_t xtro_cloak_read(void *v,unsigned char *p,size_t n){
    xtro_cloak_input *s=(xtro_cloak_input *)v;
    return fread(p,1,n,s->stream);
}
static int xtro_cloak_reset(void *v){
    xtro_cloak_input *s=(xtro_cloak_input *)v;
    return zfseeko(s->stream,s->at,SEEK_SET)!=0;
}
static int xtro_cloak_write(void *v,const unsigned char *p,size_t n){
    return fwrite(p,1,n,(FILE *)v)!=n;
}
/* The central inline payload is a verified byte stream, not a source
 * pathname.  Replay it exactly for the two-pass metadata conversion. */
typedef struct xtro_cloak_memory {
    const unsigned char *bytes;
    size_t length, pos;
} xtro_cloak_memory;
static size_t xtro_cloak_mem_read(void *v,unsigned char *out,size_t n){
    xtro_cloak_memory *m=(xtro_cloak_memory *)v;
    if(n>m->length-m->pos)n=m->length-m->pos;
    if(n)memcpy(out,m->bytes+m->pos,n);
    m->pos+=n;
    return n;
}
static int xtro_cloak_mem_reset(void *v){
    ((xtro_cloak_memory *)v)->pos=0;
    return 0;
}
#ifdef XTRO_CLOAK_DEFLATE
/* zip.h has already selected the project's compression backend.
 * Native zlib-ng and the zlib-compat API MUST NOT be included together.
 * In the internal-Deflate build only, include the independent zlib API. */
# if !defined(USE_ZLIB)
#  define crc32 xtro_cloak_zlib_crc32_unused
#  define get_crc_table xtro_cloak_zlib_get_crc_table_unused
#  include <zlib.h>
#  undef get_crc_table
#  undef crc32
# endif
/* ZIP method 8 has a raw RFC 1951 stream, not a zlib/gzip wrapper.
 * Consume exactly the advertised compressed size and reject any trailing
 * bytes, truncated stream, excessive expansion or inconsistent CRC. */
static int xtro_cloak_inflate(FILE *src, ulg packed, ulg expected,
                               FILE *dst, ulg *computed){
    z_stream zs;
    unsigned char in[4096],out[4096];
    ulg remaining=packed, produced=0, crc=0;
    int rc=ZE_OK, state=Z_OK;
    memset(&zs,0,sizeof(zs));
    if(inflateInit2(&zs,-15)!=Z_OK)return ZE_MEM;
    while(state!=Z_STREAM_END){
        unsigned outsize;
        if(zs.avail_in==0 && remaining){
            size_t want=remaining>sizeof(in)?sizeof(in):(size_t)remaining;
            if(fread(in,1,want,src)!=want){rc=ZE_READ;break;}
            remaining-=(ulg)want;
            zs.next_in=in;zs.avail_in=(uInt)want;
        }
        zs.next_out=out;zs.avail_out=(uInt)sizeof(out);
        state=inflate(&zs,Z_NO_FLUSH);
        outsize=(unsigned)(sizeof(out)-zs.avail_out);
        if(outsize){
            if(produced>expected || (ulg)outsize>expected-produced){rc=ZE_FORM;break;}
            if(fwrite(out,1,outsize,dst)!=outsize){rc=ZE_TEMP;break;}
            crc=xtr_crc32_update(crc,out,outsize);
            produced+=(ulg)outsize;
        }
        if(state==Z_STREAM_END)break;
        if(state!=Z_OK || (zs.avail_in==0 && remaining==0 &&
                            outsize==0)){rc=ZE_FORM;break;}
    }
    if(rc==ZE_OK && (remaining || zs.avail_in || produced!=expected ||
                      state!=Z_STREAM_END))rc=ZE_FORM;
    inflateEnd(&zs);
    if(rc==ZE_OK)*computed=crc;
    return rc;
}
/* Recompress the rewritten decoded manifest with the ZIP raw Deflate
 * codec, in bounded memory and without ever emitting archive headers. */
static int xtro_cloak_deflate(FILE *src,FILE *dst,ulg maximum,
                              ulg *packed,ulg *unpacked,ulg *computed){
    z_stream zs;
    unsigned char in[4096],out[4096];
    ulg crc=0,nsrc=0,ndst=0;
    int rc=ZE_OK,state=Z_OK,flush;
    memset(&zs,0,sizeof(zs));
    if(deflateInit2(&zs,Z_DEFAULT_COMPRESSION,Z_DEFLATED,-15,
                    8,Z_DEFAULT_STRATEGY)!=Z_OK)return ZE_MEM;
    do{
        size_t got=fread(in,1,sizeof(in),src);
        if(ferror(src)){rc=ZE_READ;break;}
        if((ulg)got>maximum-nsrc){rc=ZE_BIG;break;}
        nsrc+=(ulg)got;
        crc=xtr_crc32_update(crc,in,got);
        flush=feof(src)?Z_FINISH:Z_NO_FLUSH;
        zs.next_in=in;zs.avail_in=(uInt)got;
        do{
            unsigned made;
            zs.next_out=out;zs.avail_out=(uInt)sizeof(out);
            state=deflate(&zs,flush);
            if(state!=Z_OK && state!=Z_STREAM_END){rc=ZE_FORM;break;}
            made=(unsigned)(sizeof(out)-zs.avail_out);
            if(ndst>maximum+65536UL ||
               (ulg)made>maximum+65536UL-ndst){rc=ZE_BIG;break;}
            if(made && fwrite(out,1,made,dst)!=made){rc=ZE_TEMP;break;}
            ndst+=(ulg)made;
        }while(zs.avail_in || (flush==Z_FINISH && state!=Z_STREAM_END));
        if(rc!=ZE_OK)break;
    }while(flush!=Z_FINISH);
    deflateEnd(&zs);
    if(rc==ZE_OK){*packed=ndst;*unpacked=nsrc;*computed=crc;}
    return rc;
}
#endif

static void xtro_cloak_free_local(struct zlist far *l){
    if(!l)return;
    free(l->extra);free(l->iname);free(l->name);
#ifdef UNICODE_SUPPORT
    free(l->uname);
#endif
    free(l);
}
/* ZIP's generic readlocal() tolerates several local/central discrepancies.
 * Metadata-bearing transitions must not: these bytes define the source
 * object whose attributes are being carried into the new archive. */
/* Inspect the fixed local header BEFORE calling the legacy readlocal()
 * routine, which otherwise allocates from the local name length but writes
 * a NUL at the central name length. A mismatch must not reach that routine. */
static int xtro_cloak_peek_local(struct zlist far *z){
    unsigned char b[30];
    unsigned n,flags,method;
    if(!z || !in_file || zfseeko(in_file,z->off,SEEK_SET)!=0 ||
       fread(b,1,sizeof(b),in_file)!=sizeof(b))return 0;
    if(memcmp(b,"PK\003\004",4U))return 0;
    flags=(unsigned)b[6U]|((unsigned)b[7U]<<8);
    method=(unsigned)b[8U]|((unsigned)b[9U]<<8);
    n=(unsigned)b[26U]|((unsigned)b[27U]<<8);
    if(n!=z->nam || flags!=z->flg || method!=z->how)return 0;
    return 1;
}
static int xtro_cloak_local_match(const struct zlist far *l,
                                   const struct zlist far *z){
    if(!l||!z||!l->iname||!z->iname ||l->nam!=z->nam ||
       memcmp(l->iname,z->iname,z->nam) || l->how!=z->how ||
       l->lflg!=z->flg)return 0;
    if((z->flg&8U)==0U && (l->crc!=z->crc ||
                           l->siz!=z->siz ||l->len!=z->len))return 0;
    return 1;
}
static int xtro_cloak_field(const unsigned char *s,size_t len,
                            const unsigned char **found,size_t *n){
    size_t at=0;
    *found=NULL;*n=0;
    while(at<len){
        unsigned tag,v;
        if(len-at<4U)return 0;
        tag=(unsigned)s[at]|((unsigned)s[at+1U]<<8);
        v=(unsigned)s[at+2U]|((unsigned)s[at+3U]<<8);
        if(v>len-at-4U)return 0;
        if(tag==XTR_V1_EXTRA_ID){
            if(*found)return 0;
            *found=s+at+4U;*n=v;
        }
        at+=v+4U;
    }
    return *found!=NULL;
}
static xtro_cloak_stage *xtro_cloak_find(struct zlist far *z){
    xtro_cloak_stage *p;
    for(p=xtro_cloak_stages;p;p=p->next)
        if(p->owner==z||p->side==z)return p;
    return NULL;
}
static void xtro_cloak_discard(void){
    xtro_cloak_stage *p=xtro_cloak_stages,*q;
    while(p){q=p->next;if(p->content)fclose(p->content);free(p);p=q;}
    xtro_cloak_stages=NULL;
}
/* Stage an inline owner as a new STORE companion.  In particular, never
 * copy the inline values into an encrypted owner's central extra field. */
static int xtro_cloak_inline(struct zlist far *z){
    struct zlist far *l=NULL;
    xtro_cloak_stage *p;
    xtro_cloak_memory mem;
    xtr_reader reader;
    xtr1_sink sink;
    xtr1_policy limits;
    xtr1_digest digest;
    xtr_u64 n;
    xtr_extra original;
    unsigned char sha[32],id[16],mode;
    unsigned char buf[4096];
    const unsigned char *lf,*cf;
    size_t ln,cn;
    int rc;
    unsigned long crc=0,len=0;
    if(xtro_central_owner(z,id,&mode)!=1 || mode!=XTR_V1_INLINE ||
       (z->flg&1U) || !z->iname || !*z->iname ||
       z->iname[strlen(z->iname)-1U]=='/' ||
       !xtro_cloak_peek_local(z))return ZE_FORM;
    rc=readlocal(&l,z);
    if(rc!=ZE_OK)return rc;
    if(!xtro_cloak_local_match(l,z) ||
       !xtro_cloak_field((const unsigned char *)l->extra,l->ext,&lf,&ln) ||
       !xtro_cloak_field((const unsigned char *)z->cextra,z->cext,&cf,&cn) ||
       xtr1_check_headers(lf,ln,cf,cn,&original,sha)!=XTR_OK ||
       original.mode!=XTR_V1_INLINE || original.flags ||
       memcmp(id,original.owner,16U) || cn<40U ||
       original.manifest_len.hi || original.manifest_len.lo!=cn-40U ||
       cn-40U>32UL*1024UL*1024UL){
        xtro_cloak_free_local(l);return ZE_FORM;
    }
    xtro_cloak_free_local(l);
    p=(xtro_cloak_stage *)calloc(1,sizeof(*p));
    if(!p)return ZE_MEM;
    p->content=tmpfile();
    if(!p->content){free(p);return ZE_TEMP;}
    p->owner=z;p->generated=1;
    p->next=xtro_cloak_stages;xtro_cloak_stages=p;
    mem.bytes=cf+40U;mem.length=cn-40U;mem.pos=0;
    memset(&limits,0,sizeof(limits));
    limits.max_records=65536UL;
    limits.max_field=1024UL*1024UL;
    limits.max_manifest.lo=32UL*1024UL*1024UL;
    memset(&reader,0,sizeof(reader));
    reader.context=&mem;reader.read=xtro_cloak_mem_read;
    sink.context=p->content;sink.write=xtro_cloak_write;
    n.lo=(unsigned long)mem.length;n.hi=0;
    rc=xtr1_reframe_companion(&reader,n,&original,NULL,&limits,
                              xtro_cloak_mem_reset,&mem,&sink,1,
                              &p->encrypted_owner,&digest);
    if(rc!=XTR_OK || digest.manifest_length.hi ||
       digest.manifest_length.lo!=(unsigned long)mem.length)return ZE_FORM;
    if(fflush(p->content)!=0 || fseek(p->content,0,SEEK_SET)!=0)return ZE_TEMP;
    for(;;){
        size_t got=fread(buf,1,sizeof(buf),p->content);
        if(got){
            if(len>32UL*1024UL*1024UL+36UL-(ulg)got)return ZE_BIG;
            len+=(ulg)got;crc=xtr_crc32_update(crc,buf,got);
        }
        if(got<sizeof(buf)){
            if(ferror(p->content))return ZE_READ;
            break;
        }
    }
    if(len!=mem.length+36U || fseek(p->content,0,SEEK_SET)!=0)return ZE_FORM;
    p->len=p->unpacked=len;p->crc=crc;
    return ZE_OK;
}
/* Synthetic ZIP entries are only linked after all source metadata has
 * passed preflight; an aborted operation leaves the input archive intact. */
static char *xtro_cloak_dup(const char *s){
    size_t n=strlen(s)+1U;
    char *p=(char *)malloc(n);
    if(p)memcpy(p,s,n);
    return p;
}
static int xtro_cloak_append_inline(void){
    xtro_cloak_stage *p;
    struct zlist far *tail=zfiles;
    size_t extra_count=0;
    if(!tail)return ZE_FORM;
    while(tail->nxt)tail=tail->nxt;
    for(p=xtro_cloak_stages;p;p=p->next)if(p->generated)extra_count++;
    if(extra_count>(size_t)((extent)-1)-(size_t)zcount)return ZE_BIG;
    /* Allocate all entries before linking one into the archive graph. */
    for(p=xtro_cloak_stages;p;p=p->next){
        struct zlist far *s;
        char name[52];
        if(!p->generated)continue;
        if(xtr1_companion_name(p->encrypted_owner.owner,name)!=XTR_OK)
            return ZE_FORM;
        s=(struct zlist far *)calloc(1,sizeof(*s));
        if(!s)return ZE_MEM;
        s->name=xtro_cloak_dup(name);
        s->iname=xtro_cloak_dup(name);
        s->zname=xtro_cloak_dup(name);
        s->oname=xtro_cloak_dup(name);
        if(!s->name||!s->iname||!s->zname||!s->oname){
            free(s->name);free(s->iname);free(s->zname);free(s->oname);
            free(s);return ZE_MEM;
        }
        s->nam=51U;s->how=0U;
        s->vem=p->owner->vem;
        s->ver=20U;
        s->tim=p->owner->tim;
        s->atx=p->owner->atx;
        s->att=p->owner->att;
        s->len=p->unpacked;
        s->siz=p->len;
        s->crc=p->crc;
        s->dsk=0;
        p->side=s;
    }
    for(p=xtro_cloak_stages;p;p=p->next){
        if(!p->generated)continue;
        tail->nxt=p->side;tail=p->side;zcount++;
    }
    return ZE_OK;
}
/* Validate existing public companion pairs and inline owners before
 * emitting output bytes.  CRC, SHA and member identities are checked
 * independently.  No owner extra is changed during preflight. */
static int xtro_cloak_stage_all(void){
    struct zlist far *z,*side,*l=NULL;
    xtro_cloak_stage *p;
    unsigned char id[16],sideid[16],mode,sha[32],buf[4096];
    unsigned long crc;
    xtr_extra original;
    xtr1_digest digest;
    xtr1_policy limits;
    xtr_reader reader;
    xtr1_sink sink;
    xtro_cloak_input input;
    xtr_u64 n;
    FILE *plain=NULL,*framed=NULL;
    const unsigned char *lf,*cf;
    size_t ln,cn;
    int rc;
    for(z=zfiles;z;z=z->nxt){
        if(xtro_central_owner(z,id,&mode)!=1)continue;
        if(mode==XTR_V1_INLINE){
            rc=xtro_cloak_inline(z);
            if(rc!=ZE_OK)return rc;
            continue;
        }
        if(mode!=XTR_V1_COMPANION || xtro_field_flags(z)!=0 ||
           (z->flg&1U) || !z->iname || !*z->iname ||
           z->iname[strlen(z->iname)-1U]=='/')return ZE_PARMS;
        side=NULL;
        for(side=zfiles;side;side=side->nxt)
            if(side->iname && xtro_sidecar_id(side->iname,sideid) &&
               !memcmp(id,sideid,16U))break;
        if(!side || (side->how!=0U && side->how!=8U) ||
           (side->flg & (1U|8U)) || side->len>32UL*1024UL*1024UL ||
           side->siz>33UL*1024UL*1024UL ||
           (side->how==0U && side->len!=side->siz))
            return ZE_PARMS;
#ifndef XTRO_CLOAK_DEFLATE
        if(side->how==8U)return ZE_PARMS;
#endif
        p=(xtro_cloak_stage *)calloc(1,sizeof(*p));
        if(!p)return ZE_MEM;
        p->owner=z;p->side=side;
        p->content=tmpfile();
        if(!p->content){free(p);return ZE_TEMP;}
        p->next=xtro_cloak_stages;xtro_cloak_stages=p;
        if(!xtro_cloak_peek_local(z))return ZE_FORM;
        rc=readlocal(&l,z);
        if(rc!=ZE_OK)return rc;
        if(!xtro_cloak_local_match(l,z) ||
           !xtro_cloak_field((const unsigned char *)l->extra,l->ext,&lf,&ln)||
           !xtro_cloak_field((const unsigned char *)z->cextra,z->cext,&cf,&cn)||
           xtr1_check_headers(lf,ln,cf,cn,&original,sha)!=XTR_OK ||
           original.mode!=XTR_V1_COMPANION || original.flags ||
           memcmp(id,original.owner,16U)){
            xtro_cloak_free_local(l);l=NULL;return ZE_FORM;
        }
        xtro_cloak_free_local(l);l=NULL;
        if(!xtro_cloak_peek_local(side))return ZE_FORM;
        rc=readlocal(&l,side);
        if(rc!=ZE_OK)return rc;
        if(!xtro_cloak_local_match(l,side) ||
           l->how!=side->how || (l->lflg&(1U|8U))){
            xtro_cloak_free_local(l);l=NULL;return ZE_FORM;
        }
        xtro_cloak_free_local(l);l=NULL;
        input.stream=in_file;input.at=zftello(in_file);
        if(input.at<0)return ZE_READ;
        /* A compressed companion is never passed directly to the manifest
         * parser. Decode and validate the RFC 1951 stream in private storage. */
        if(side->how==8U){
#ifdef XTRO_CLOAK_DEFLATE
            ulg original_crc=0;
            plain=tmpfile();
            if(!plain)return ZE_TEMP;
            rc=xtro_cloak_inflate(in_file,(ulg)side->siz,(ulg)side->len,
                                  plain,&original_crc);
            if(rc!=ZE_OK){fclose(plain);return rc;}
            if(original_crc!=(ulg)side->crc ||
               fseek(plain,0,SEEK_SET)!=0){fclose(plain);return ZE_FORM;}
            input.stream=plain;input.at=0;
#else
            return ZE_PARMS;
#endif
        }
        memset(&limits,0,sizeof(limits));
        limits.max_records=65536UL;limits.max_field=1024UL*1024UL;
        limits.max_manifest.lo=32UL*1024UL*1024UL;
        memset(&reader,0,sizeof(reader));reader.context=&input;
        reader.read=xtro_cloak_read;
        /* For Deflate, frame first and then recompress with method 8. */
        framed=side->how==8U?tmpfile():p->content;
        if(!framed){if(plain)fclose(plain);return ZE_TEMP;}
        sink.context=framed;sink.write=xtro_cloak_write;
        n.lo=(unsigned long)side->len;n.hi=0;
        rc=xtr1_reframe_companion(&reader,n,&original,sha,&limits,
                                  xtro_cloak_reset,&input,&sink,1,
                                  &p->encrypted_owner,&digest);
        if(plain){fclose(plain);plain=NULL;}
        if(rc!=XTR_OK){if(framed!=p->content)fclose(framed);return ZE_FORM;}
        if(digest.manifest_length.hi ||
           digest.manifest_length.lo!=(unsigned long)side->len ||
           digest.crc32!=(unsigned long)side->crc){
            if(framed!=p->content)fclose(framed);
            return ZE_FORM;
        }
        if(fflush(framed)!=0||fseek(framed,0,SEEK_SET)!=0){
            if(framed!=p->content)fclose(framed);
            return ZE_TEMP;
        }
        if(side->how==8U){
#ifdef XTRO_CLOAK_DEFLATE
            rc=xtro_cloak_deflate(framed,p->content,
                    32UL*1024UL*1024UL+36UL,&p->len,&p->unpacked,&p->crc);
            fclose(framed);framed=NULL;
            if(rc!=ZE_OK)return rc;
#else
            return ZE_PARMS;
#endif
        }else{
            crc=0UL;p->len=0UL;
            for(;;){
                size_t r=fread(buf,1,sizeof(buf),p->content);
                if(r){
                    crc=xtr_crc32_update(crc,buf,r);
                    if(p->len>32UL*1024UL*1024UL+36UL-(ulg)r)return ZE_BIG;
                    p->len+=(ulg)r;
                }
                if(r<sizeof(buf)){
                    if(ferror(p->content))return ZE_READ;
                    break;
                }
            }
            p->unpacked=p->len;p->crc=(ulg)crc;
        }
        if(p->unpacked!=(ulg)side->len+36UL ||
           fflush(p->content)!=0 || fseek(p->content,0,SEEK_SET)!=0)
            return ZE_FORM;
    }
    return xtro_cloak_append_inline();
}
static int xtro_cloak_replace_extra(struct zlist far *l,struct zlist far *z,
                                    const xtr_extra *replacement,
                                    const unsigned char *sha);
static int xtro_cloak_replace_side_extra(struct zlist far *l,
                                          struct zlist far *z,int encrypted_target);
/* M6E2F: decode and verify complete ZipCrypto member data before changing
 * any Xtro owner/companion headers.  A one-byte password-header match alone
 * is not sufficient: check the complete decoded CRC and declared length.
 * The optional destination receives the raw compressed plaintext, never the
 * uncompressed contents.  All reads are bounded; no source filename is used.
 */
static int xtro_cloak_check_crypto(struct zlist far *z,const char *password,
                                   FILE *raw){
    struct zlist far *l=NULL;
    unsigned char in[4096];
#ifdef XTRO_CLOAK_DEFLATE
    unsigned char out[4096];
#endif
    uzoff_t left,produced=0;
    ulg crc=0;
    unsigned i;
    int c,rc=ZE_OK;
#ifdef XTRO_CLOAK_DEFLATE
    z_stream zs;
    int state=Z_OK;
    int active=0;
#endif
    if(!z || !(z->flg&1U) || (z->flg&8U) || z->siz<RAND_HEAD_LEN ||
       (z->how!=0U && z->how!=8U) || !xtro_cloak_peek_local(z))
        return ZE_PARMS;
#ifndef XTRO_CLOAK_DEFLATE
    if(z->how==8U)return ZE_PARMS;
#endif
    rc=readlocal(&l,z);
    if(rc!=ZE_OK)return rc;
    if(!xtro_cloak_local_match(l,z)){xtro_cloak_free_local(l);return ZE_FORM;}
    xtro_cloak_free_local(l);
    init_keys(password);
    for(i=0;i<RAND_HEAD_LEN;i++){
        c=getc(in_file);
        if(c==EOF)return ferror(in_file)?ZE_READ:ZE_EOF;
        zdecode(c);
    }
    if((unsigned)c != (unsigned)((z->crc>>24)&255UL))return ZE_MISS;
#ifdef XTRO_CLOAK_DEFLATE
    memset(&zs,0,sizeof(zs));
    if(z->how==8U){
        if(inflateInit2(&zs,-15)!=Z_OK)return ZE_MEM;
        active=1;
    }
#endif
    left=z->siz-RAND_HEAD_LEN;
    while(left){
        size_t n=(left>sizeof(in))?sizeof(in):(size_t)left,j;
        if(fread(in,1,n,in_file)!=n){rc=ZE_READ;break;}
        for(j=0;j<n;j++){
            c=(int)in[j];zdecode(c);in[j]=(unsigned char)c;
        }
        if(raw && fwrite(in,1,n,raw)!=n){rc=ZE_TEMP;break;}
        left-=(uzoff_t)n;
        if(z->how==0U){
            if((uzoff_t)n>z->len-produced){rc=ZE_FORM;break;}
            crc=xtr_crc32_update(crc,in,n);
            produced+=(uzoff_t)n;
        }
#ifdef XTRO_CLOAK_DEFLATE
        else{
            zs.next_in=in;zs.avail_in=(uInt)n;
            while(zs.avail_in){
                size_t made;
                uInt before=zs.avail_in;
                zs.next_out=out;zs.avail_out=(uInt)sizeof(out);
                state=inflate(&zs,Z_NO_FLUSH);
                made=sizeof(out)-zs.avail_out;
                if((uzoff_t)made>z->len-produced){rc=ZE_FORM;break;}
                crc=xtr_crc32_update(crc,out,made);
                produced+=(uzoff_t)made;
                if(state==Z_STREAM_END){
                    if(zs.avail_in || left){rc=ZE_FORM;}
                    break;
                }
                if(state!=Z_OK || (!made && before==zs.avail_in)){
                    rc=ZE_FORM;
                    break;
                }
            }
            if(rc!=ZE_OK || state==Z_STREAM_END)break;
        }
#endif
    }
#ifdef XTRO_CLOAK_DEFLATE
    if(z->how==8U){
        if(state!=Z_STREAM_END)rc=ZE_FORM;
        if(active)inflateEnd(&zs);
    }
#endif
    if(rc==ZE_OK && (left || produced!=z->len || crc!=z->crc))rc=ZE_FORM;
    if(rc==ZE_OK && raw && (fflush(raw)!=0 || fseek(raw,0,SEEK_SET)!=0))
        rc=ZE_TEMP;
    return rc;
}

/* Verify and prepare only complete encrypted Xtro pairs.  The owner payload
 * is independently CRC-checked with the same password.  An encrypted
 * companion is decoded, verified against its own CRC and XTCS/SHA, and
 * converted into a public XTMD payload before writing output headers. */
static int xtro_cloak_stage_decrypt(const char *password){
    struct zlist far *z,*side,*l=NULL;
    xtro_cloak_stage *p;
    unsigned char id[16],sid[16],mode,sha[32];
    const unsigned char *lf,*cf;
    size_t ln,cn;
    xtr_extra prior;
    xtr1_digest digest;
    xtr1_policy limits;
    xtr_reader reader;
    xtr1_sink sink;
    xtro_cloak_input input;
    xtr_u64 n;
    FILE *compressed=NULL,*decoded=NULL,*manifest=NULL;
    int rc;
    for(z=zfiles;z;z=z->nxt){
        if(xtro_central_owner(z,id,&mode)!=1 || !(z->flg&1U))continue;
        if(mode!=XTR_V1_COMPANION || xtro_field_flags(z)!=1)return ZE_FORM;
        for(side=zfiles;side;side=side->nxt)
            if(side->iname && xtro_sidecar_id(side->iname,sid) &&
               !memcmp(id,sid,16U))break;
        if(!side || !(side->flg&1U) || (side->flg&8U) ||
           (side->how!=0U && side->how!=8U) ||
           side->len>32UL*1024UL*1024UL+36UL ||
           side->siz>33UL*1024UL*1024UL+RAND_HEAD_LEN)
            return ZE_PARMS;
        if(!xtro_cloak_peek_local(z))return ZE_FORM;
        rc=readlocal(&l,z);
        if(rc!=ZE_OK)return rc;
        if(!xtro_cloak_local_match(l,z) ||
           !xtro_cloak_field((const unsigned char *)l->extra,l->ext,&lf,&ln)||
           !xtro_cloak_field((const unsigned char *)z->cextra,z->cext,&cf,&cn)||
           xtr1_check_headers(lf,ln,cf,cn,&prior,sha)!=XTR_OK ||
           prior.mode!=XTR_V1_COMPANION ||
           !(prior.flags&XTR_V1_ENCRYPTED) ||
           memcmp(prior.owner,id,16U)){
            xtro_cloak_free_local(l);return ZE_FORM;
        }
        xtro_cloak_free_local(l);l=NULL;
        rc=xtro_cloak_check_crypto(z,password,NULL);
        if(rc!=ZE_OK)return rc;
        compressed=tmpfile();
        if(!compressed)return ZE_TEMP;
        rc=xtro_cloak_check_crypto(side,password,compressed);
        if(rc!=ZE_OK){fclose(compressed);return rc;}
        if(side->how==8U){
#ifdef XTRO_CLOAK_DEFLATE
            ulg checksum;
            decoded=tmpfile();
            if(!decoded){fclose(compressed);return ZE_TEMP;}
            rc=xtro_cloak_inflate(compressed,(ulg)(side->siz-RAND_HEAD_LEN),
                                  (ulg)side->len,decoded,&checksum);
            fclose(compressed);compressed=NULL;
            if(rc!=ZE_OK || checksum!=side->crc ||
               fseek(decoded,0,SEEK_SET)!=0){fclose(decoded);return ZE_FORM;}
#else
            fclose(compressed);return ZE_PARMS;
#endif
        }else{
            decoded=compressed;compressed=NULL;
        }
        p=(xtro_cloak_stage *)calloc(1,sizeof(*p));
        if(!p){fclose(decoded);return ZE_MEM;}
        p->content=tmpfile();
        if(!p->content){free(p);fclose(decoded);return ZE_TEMP;}
        p->owner=z;p->side=side;p->reverse=1;
        p->next=xtro_cloak_stages;xtro_cloak_stages=p;
        memset(&limits,0,sizeof(limits));
        limits.max_records=65536UL;limits.max_field=1024UL*1024UL;
        limits.max_manifest.lo=32UL*1024UL*1024UL;
        memset(&reader,0,sizeof(reader));
        input.stream=decoded;input.at=0;
        reader.context=&input;reader.read=xtro_cloak_read;
        manifest=side->how==8U?tmpfile():p->content;
        if(!manifest){fclose(decoded);return ZE_TEMP;}
        sink.context=manifest;sink.write=xtro_cloak_write;
        n.lo=(unsigned long)side->len;n.hi=0;
        rc=xtr1_reframe_companion(&reader,n,&prior,NULL,&limits,
                     xtro_cloak_reset,&input,&sink,0,
                     &p->encrypted_owner,&digest);
        fclose(decoded);decoded=NULL;
        if(rc!=XTR_OK || digest.manifest_length.hi ||
           digest.manifest_length.lo+36UL!=(unsigned long)side->len){
            if(manifest!=p->content)fclose(manifest);
            return ZE_FORM;
        }
        memcpy(p->public_sha,digest.sha256,32U);
        if(fflush(manifest)!=0 || fseek(manifest,0,SEEK_SET)!=0){
            if(manifest!=p->content)fclose(manifest);
            return ZE_TEMP;
        }
        if(side->how==8U){
#ifdef XTRO_CLOAK_DEFLATE
            rc=xtro_cloak_deflate(manifest,p->content,32UL*1024UL*1024UL,
                                  &p->len,&p->unpacked,&p->crc);
            fclose(manifest);manifest=NULL;
            if(rc!=ZE_OK)return rc;
#else
            return ZE_PARMS;
#endif
        }else{
            p->len=p->unpacked=(ulg)digest.manifest_length.lo;
            p->crc=(ulg)digest.crc32;
        }
        if(p->unpacked!=(ulg)side->len-36UL ||
           fflush(p->content)!=0 || fseek(p->content,0,SEEK_SET)!=0)
            return ZE_FORM;
    }
    return ZE_OK;
}

/* Reverse transitions use the verified password and staged new metadata,
 * not the weak, header-only check in the legacy generic zipbare() path. */
static int xtro_cloak_decrypt_owner(xtro_cloak_stage *p,const char *password){
    struct zlist far *z=p->owner,*l=NULL;
    uch buf[4096];unsigned used=0;
    uzoff_t left;
    zoff_t n=(zoff_t)zftello(y);
    int rc,c;
    unsigned i;
    if(n<0 || !xtro_cloak_peek_local(z))return ZE_FORM;
    rc=readlocal(&l,z);
    if(rc!=ZE_OK)return rc;
    if(!xtro_cloak_local_match(l,z)){xtro_cloak_free_local(l);return ZE_FORM;}
    rc=xtro_cloak_replace_extra(l,z,&p->encrypted_owner,p->public_sha);
    if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    z->dsk=0;z->off=n;
    z->flg=(ush)(z->flg&~9U);l->lflg=(ush)(l->lflg&~9U);
    z->siz-=RAND_HEAD_LEN;l->siz=z->siz;
    rc=putlocal(l,PUTLOCAL_WRITE);
    if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    init_keys(password);
    for(i=0;i<RAND_HEAD_LEN;i++){
        c=getc(in_file);
        if(c==EOF){xtro_cloak_free_local(l);return ZE_READ;}
        zdecode(c);
    }
    left=z->siz;
    while(left--){
        c=getc(in_file);
        if(c==EOF){xtro_cloak_free_local(l);return ZE_READ;}
        zdecode(c);buf[used++]=(uch)c;
        if(used==sizeof(buf)){
            if(bfwrite(buf,1,used,BFWRITE_DATA)!=used){xtro_cloak_free_local(l);return ZE_TEMP;}
            used=0;
        }
    }
    if(used && bfwrite(buf,1,used,BFWRITE_DATA)!=used){xtro_cloak_free_local(l);return ZE_TEMP;}
    tempzn+=(4+LOCHEAD)+l->nam+l->ext+l->siz;
    xtro_cloak_free_local(l);
    return ZE_OK;
}
static int xtro_cloak_decrypt_side(xtro_cloak_stage *p){
    struct zlist far *z=p->side,*l=NULL;
    uch buf[4096];size_t got;
    zoff_t n=(zoff_t)zftello(y);
    int rc;
    if(n<0 || !xtro_cloak_peek_local(z))return ZE_FORM;
    rc=readlocal(&l,z);
    if(rc!=ZE_OK)return rc;
    if(!xtro_cloak_local_match(l,z)){xtro_cloak_free_local(l);return ZE_FORM;}
    rc=xtro_cloak_replace_side_extra(l,z,0);
    if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    z->dsk=0;z->off=n;
    z->crc=l->crc=p->crc;
    z->len=l->len=p->unpacked;
    z->siz=l->siz=p->len;
    z->flg=(ush)(z->flg&~9U);l->lflg=(ush)(l->lflg&~9U);
    rc=putlocal(l,PUTLOCAL_WRITE);
    if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    if(fseek(p->content,0,SEEK_SET)!=0){xtro_cloak_free_local(l);return ZE_TEMP;}
    while((got=fread(buf,1,sizeof(buf),p->content))!=0){
        if(bfwrite(buf,1,got,BFWRITE_DATA)!=got){xtro_cloak_free_local(l);return ZE_TEMP;}
    }
    if(ferror(p->content)){xtro_cloak_free_local(l);return ZE_READ;}
    tempzn+=(4+LOCHEAD)+l->nam+l->ext+l->siz;
    xtro_cloak_free_local(l);
    return ZE_OK;
}

/* Consume existing local and central lists; do not publish either rewritten
 * field unless both buffers validate. The original lists are heap-owned. */
static int xtro_cloak_replace_extra(struct zlist far *l,struct zlist far *z,
                                    const xtr_extra *replacement,
                                    const unsigned char *sha){
    unsigned char *bl,*bc;
    size_t nl=0,nc=0;
    int rc;
    bl=(unsigned char *)malloc(65535U);
    bc=(unsigned char *)malloc(65535U);
    if(!bl||!bc){free(bl);free(bc);return ZE_MEM;}
    rc=xtr1_rewrite_owner_extras((const unsigned char *)l->extra,l->ext,
                        (const unsigned char *)z->cextra,z->cext,
                        replacement,NULL,0,sha,bl,65535U,&nl,
                        bc,65535U,&nc);
    if(rc!=XTR_OK){free(bl);free(bc);return ZE_FORM;}
    free(l->extra);l->extra=(char *)bl;l->ext=(ush)nl;
    if(z->cextra!=z->extra)free(z->cextra);
    z->cextra=(char *)bc;z->cext=(ush)nc;
    return ZE_OK;
}
static int xtro_cloak_replace_side_extra(struct zlist far *l,
                                          struct zlist far *z,int encrypted_target){
    unsigned char *bl,*bc;
    size_t nl=0,nc=0;
    int rc;
    bl=(unsigned char *)malloc(65535U);
    bc=(unsigned char *)malloc(65535U);
    if(!bl||!bc){free(bl);free(bc);return ZE_MEM;}
    rc=xtr1_rewrite_companion_extras((const unsigned char *)l->extra,l->ext,
                         (const unsigned char *)z->cextra,z->cext,
                         encrypted_target,0,NULL,bl,65535U,&nl,bc,65535U,&nc);
    if(rc!=XTR_OK){free(bl);free(bc);return ZE_FORM;}
    free(l->extra);l->extra=(char *)bl;l->ext=(ush)nl;
    if(z->cextra!=z->extra)free(z->cextra);
    z->cextra=(char *)bc;z->cext=(ush)nc;
    return ZE_OK;
}
/* Like the legacy zipcloak() transport, but install the checked Xtro local
 * and central extra lists before encrypting. No compression format changes. */
static int xtro_cloak_encrypt_owner(xtro_cloak_stage *p,const char *password){
    struct zlist far *z=p->owner,*l=NULL;
    uch b[4096];
    zoff_t oldn,n;
    int rc,c,t;
    unsigned used=0;
    n=(zoff_t)zftello(y);
    if(n<0)return ZE_TEMP;
    if(!xtro_cloak_peek_local(z))return ZE_FORM;
    rc=readlocal(&l,z);
    if(rc!=ZE_OK)return rc;
    if(!xtro_cloak_local_match(l,z)){xtro_cloak_free_local(l);return ZE_FORM;}
    rc=xtro_cloak_replace_extra(l,z,&p->encrypted_owner,NULL);
    if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    oldn=(zoff_t)z->siz;
    z->dsk=0;z->off=n;
    z->flg=(ush)((z->flg|1U)&~8U);
    l->lflg=(ush)((l->lflg|1U)&~8U);
    z->siz+=RAND_HEAD_LEN;l->siz=z->siz;
    rc=putlocal(l,PUTLOCAL_WRITE);
    if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    crypthead(password,l->crc);
    while(oldn--){
        c=getc(in_file);
        if(c==EOF){xtro_cloak_free_local(l);return ferror(in_file)?ZE_READ:ZE_EOF;}
        b[used++]=(uch)zencode(c,t);
        if(used==sizeof(b)){
            if(bfwrite(b,1,used,BFWRITE_DATA)!=used){xtro_cloak_free_local(l);return ZE_TEMP;}
            used=0;
        }
    }
    if(used && bfwrite(b,1,used,BFWRITE_DATA)!=used){xtro_cloak_free_local(l);return ZE_TEMP;}
    tempzn+=(4+LOCHEAD)+l->nam+l->ext+l->siz;
    xtro_cloak_free_local(l);
    return ZE_OK;
}
/* Existing companion or new STORE companion: staged decoded bytes gained
 * a protected SHA trailer, so CRC and uncompressed size must be rewritten. */
static int xtro_cloak_encrypt_side(xtro_cloak_stage *p,const char *password){
    struct zlist far *z=p->side,*l=NULL;
    uch b[4096];
    unsigned used=0;
    ulg remaining=p->len;
    zoff_t n=(zoff_t)zftello(y);
    int rc,c,t;
    if(n<0)return ZE_TEMP;
    if(p->generated){
        l=z;
    }else{
        if(!xtro_cloak_peek_local(z))return ZE_FORM;
        rc=readlocal(&l,z);
        if(rc!=ZE_OK)return rc;
        if(!xtro_cloak_local_match(l,z)){
            xtro_cloak_free_local(l);return ZE_FORM;
        }
        rc=xtro_cloak_replace_side_extra(l,z,1);
        if(rc!=ZE_OK){xtro_cloak_free_local(l);return rc;}
    }
    z->dsk=0;z->off=n;
    z->crc=l->crc=p->crc;
    z->len=l->len=p->unpacked;
    z->siz=l->siz=(uzoff_t)p->len+RAND_HEAD_LEN;
    z->flg=(ush)((z->flg|1U)&~8U);
    l->lflg=(ush)((l->lflg|1U)&~8U);
    rc=putlocal(l,PUTLOCAL_WRITE);
    if(rc!=ZE_OK){if(!p->generated)xtro_cloak_free_local(l);return rc;}
    crypthead(password,z->crc);
    if(fseek(p->content,0,SEEK_SET)!=0){if(!p->generated)xtro_cloak_free_local(l);return ZE_TEMP;}
    while(remaining--){
        c=getc(p->content);
        if(c==EOF){if(!p->generated)xtro_cloak_free_local(l);return ZE_TEMP;}
        b[used++]=(uch)zencode(c,t);
        if(used==sizeof(b)){
            if(bfwrite(b,1,used,BFWRITE_DATA)!=used){if(!p->generated)xtro_cloak_free_local(l);return ZE_TEMP;}
            used=0;
        }
    }
    if(used && bfwrite(b,1,used,BFWRITE_DATA)!=used){if(!p->generated)xtro_cloak_free_local(l);return ZE_TEMP;}
    tempzn+=(4+LOCHEAD)+l->nam+l->ext+l->siz;
    if(!p->generated)xtro_cloak_free_local(l);
    return ZE_OK;
}
