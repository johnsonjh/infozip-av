/* SPDX-License-Identifier: MIT-0 */
/* FreeBSD/NetBSD UnZip traditional-extattr restoration. Native writes
   follow complete ZIP member integrity checks, SHA, structural and inode
   association validation. Companion data never becomes an output pathname. */
#if (defined(__FreeBSD__) || defined(__NetBSD__) || defined(XTR_BSD_TEST)) && !defined(SFX) && !defined(DLL)
#include "../xtrmeta/xtrbsd.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static int xtr_restore_rejected;
static int xtr_exit_hook;
static size_t xtr_stage_read(void *,unsigned char *,size_t);
static void xtr_bsd_policy(xtr1_policy *);
/* Archive-wide registry: entries in the central directory can be processed
   in separate DIR_BLKSIZ blocks, and the companion normally follows owner.
   Never apply attributes until the entire selected set has been checked. */
typedef struct xtr_pending_restore {
    struct xtr_pending_restore *next;
    unsigned char id[16],sha[32];
    xtr_extra outer;
    int has_owner,has_companion,owner_verified,companion_verified;
    unsigned owner_crypto,companion_crypto,owner_strength,companion_strength;
    unsigned owner_iterations,companion_iterations;
    int companion_fwkcs;
    int is_dir;
    int fd;
    FILE *stage;
    char *output_name;
} xtr_pending_restore;
static xtr_pending_restore *xtr_pending_head;
static unsigned long long xtr_stage_reserved;
static unsigned long long xtr_stage_advertised;
static unsigned long xtr_registry_count;
/* The Linux adapter currently caps a logical manifest at 32 MiB, with
   another 36 bytes for the encrypted SHA footer. Reject a larger advertised
   companion BEFORE decompressing it into private temporary storage.
   Archive-wide reservation stops many individually bounded companions from
   exhausting scratch storage. These are explicit implementation limits, not
   restrictions imposed by the Xtro on-disk format. */
#define XTR_STAGE_MAX (32UL*1024UL*1024UL+36UL)
#define XTR_STAGE_AGGREGATE (128ULL*1024ULL*1024ULL)
#define XTR_OWNER_MAX 65536UL

static unsigned xtr_transport(const min_info *in){
#ifndef NO_AES
    if(in->aes_strength){
        if(in->aes_version==1U)return 2U;
        if(in->aes_version==2U)return 3U;
        if(in->aes_version==3U)return 4U;
        return 5U;
    }
#endif
    return in->encrypted ? 1U : 0U;
}
static xtr_pending_restore *xtr_lookup(const unsigned char id[16],int create){
    xtr_pending_restore *p;
    for(p=xtr_pending_head;p;p=p->next)
        if(memcmp(p->id,id,16)==0)return p;
    if(!create || xtr_registry_count>=XTR_OWNER_MAX)return NULL;
    p=(xtr_pending_restore *)calloc(1,sizeof(*p));
    if(!p)return NULL;
    memcpy(p->id,id,16);p->fd=-1;
    p->next=xtr_pending_head;xtr_pending_head=p;
    xtr_registry_count++;
    return p;
}
static int xtr_id_from_name(const char *name,unsigned char id[16]){
    static const char prefix[]="__XTRO_ZIP__/x/";
    unsigned i;
    if(!name || strlen(name)!=51U || strncmp(name,prefix,15) ||
       strcmp(name+47,".xtm"))return 1;
    for(i=0;i<16U;i++){
        unsigned n,j,k;
        char a=name[15U+2U*i],b=name[16U+2U*i];
        j=(a>='0'&&a<='9')?(unsigned)(a-'0'):
          (a>='a'&&a<='f')?(unsigned)(a-'a'+10):16U;
        k=(b>='0'&&b<='9')?(unsigned)(b-'0'):
          (b>='a'&&b<='f')?(unsigned)(b-'a'+10):16U;
        if(j>15U||k>15U)return 1;
        n=(j<<4)|k;id[i]=(unsigned char)n;
    }
    return xtr1_companion_matches(id,name,strlen(name))!=XTR_OK;
}
static int xtr_register_owner(min_info *info,const xtr_extra *e,
                              const unsigned char sha[32]){
    xtr_pending_restore *p=xtr_lookup(e->owner,1);
    if(!p||p->has_owner)return 1;
    p->has_owner=1;p->outer=*e;
    if(sha)memcpy(p->sha,sha,32);
    p->owner_crypto=xtr_transport(info);
#ifndef NO_AES
    p->owner_strength=info->aes_strength;
    p->owner_iterations=info->aes_iterations;
#endif
    return 0;
}
static int xtr_register_companion(min_info *info,const unsigned char id[16]){
    xtr_pending_restore *p=xtr_lookup(id,1);
    if(!p||p->has_companion)return 1;
    p->has_companion=1;p->companion_crypto=xtr_transport(info);
    p->companion_fwkcs=info->fwkcs_md5;
#ifndef NO_AES
    p->companion_strength=info->aes_strength;
    p->companion_iterations=info->aes_iterations;
#endif
    return 0;
}
static void xtr_release_registry(void){
    xtr_pending_restore *p=xtr_pending_head,*next;
    while(p){
        next=p->next;
        if(p->fd>=0)close(p->fd);
        if(p->stage)fclose(p->stage);
        free(p->output_name);free(p);p=next;
    }
    xtr_pending_head=NULL;
    xtr_registry_count=0;
    xtr_stage_reserved=0;
    xtr_stage_advertised=0;
}



/* Locate exactly one Xtro field.  A malformed or duplicated field is fatal
   if the caller enabled metadata restoration. */
static int xtr_locate(const unsigned char *p,size_t n,
                      const unsigned char **value,size_t *len){
    size_t at=0;
    *value=NULL;*len=0;
    while(at<n){
        unsigned id,sz;
        if(n-at<4 || !p)return XTR_CORRUPT;
        id=(unsigned)p[at]|((unsigned)p[at+1]<<8);
        sz=(unsigned)p[at+2]|((unsigned)p[at+3]<<8);
        at+=4;
        if(sz>n-at)return XTR_CORRUPT;
        if(id==XTR_V1_EXTRA_ID){
            if(*value)return XTR_CORRUPT;
            *value=p+at;*len=sz;
        }
        at+=sz;
    }
    return XTR_OK;
}

static int xtr_note_central(min_info *info,const uch *ef,unsigned len,
                            const char *name){
    const unsigned char *v;
    size_t n;
    unsigned char id[16],sha[32];
    xtr_extra e;
    int rc;
    info->xtr_central=NULL;
    info->xtr_central_len=0;
    info->xtr_source_name=NULL;
    info->xtr_restore_fd=-1;
    info->xtr_companion=0;
    rc=xtr_locate(ef,len,&v,&n);
    if(rc){fprintf(stderr,"unzip: malformed Xtro extra field: %s\n",name);goto fail;}
    if(strncmp(name,"__XTRO_ZIP__/",13)==0){
        /* These entries are never mapped to filesystem paths. */
        if(v||xtr_id_from_name(name,id)){
            fprintf(stderr,"unzip: invalid reserved Xtro member: %s\n",name);
            goto fail;
        }
        info->xtr_companion=1;
        /* Central-directory preflight: refuse impossible staging budgets
           before ordinary owner extraction has started. */
        {
            unsigned long long bytes=(unsigned long long)info->uncompr_size;
            if(bytes>XTR_STAGE_MAX ||
               bytes>XTR_STAGE_AGGREGATE-xtr_stage_advertised){
                fprintf(stderr,"unzip: Xtro metadata staging quota exceeded: %s\n",name);
                goto fail;
            }
            xtr_stage_advertised+=bytes;
        }
        if(xtr_register_companion(info,id)){
            fprintf(stderr,"unzip: duplicate Xtro companion: %s\n",name);
            goto fail;
        }
        return 0;
    }
    if(!v)return 0;
    memset(sha,0,sizeof(sha));
    rc=xtr1_extra_decode(v,n,1,&e,sha);
    if(rc){fprintf(stderr,"unzip: invalid Xtro central metadata: %s\n",name);goto fail;}
    if(name[0] && name[strlen(name)-1]=='/'){
        info->xtr_source_name=(char *)malloc(strlen(name)+1U);
        if(!info->xtr_source_name)goto fail;
        strcpy(info->xtr_source_name,name);
    }
    if(e.mode==XTR_V1_COMPANION && xtr_register_owner(info,&e,sha)){
        fprintf(stderr,"unzip: duplicate Xtro owner identity: %s\n",name);
        goto fail;
    }
    info->xtr_central=(unsigned char *)malloc(n);
    if(!info->xtr_central){fprintf(stderr,"unzip: no memory for Xtro metadata\n");goto fail;}
    memcpy(info->xtr_central,v,n);
    info->xtr_central_len=(unsigned)n;
    return 0;
fail:
    free(info->xtr_source_name);
    info->xtr_source_name=NULL;
    free(info->xtr_central);
    info->xtr_central=NULL;
    xtr_restore_rejected=1;
    return 1;
}

static void xtr_cleanup_block(min_info *entries,unsigned n){
    unsigned i;
    for(i=0;i<n;i++){
        if(entries[i].xtr_restore_fd>=0)close(entries[i].xtr_restore_fd);
        entries[i].xtr_restore_fd=-1;
        free(entries[i].xtr_central);
        free(entries[i].xtr_source_name);
        entries[i].xtr_source_name=NULL;
        entries[i].xtr_central=NULL;
        entries[i].xtr_central_len=0;
    }
}

/* Record the actual inode from the descriptor before close_outfile() closes
   it.  Later name-based lookup MUST still identify that same object. */
static int xtr_pin_output(min_info *info,FILE *output){
    struct stat st;
    int fd;
    if(!info->xtr_central)return 0;
    info->xtr_restore_fd=-1;
    if(!output)return 1;
    fd=dup(fileno(output));
    if(fd<0)return 1;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode)){
        close(fd);return 1;
    }
    info->xtr_restore_fd=fd;
    return 0;
}

/* Resolve output paths one component at a time without following symlinks.
   This protects against a renamed intermediate directory becoming a symlink
   between ordinary extraction and the xattr application. */
static int xtr_open_output_kind(const char *name,int directory){
    char *copy,*p,*q;
    int dirfd=-1,fd=-1,owned=0;
    struct stat st;
    size_t n;
    if(!name || !*name)return -1;
    n=strlen(name);
    if(n>65535U)return -1;
    copy=(char *)malloc(n+1);
    if(!copy)return -1;
    memcpy(copy,name,n+1);
    /* ZIP directory names have a trailing slash, which is not itself a
       filesystem component. Do not permit doubled or empty components. */
    if(directory && n>1U && copy[n-1U]=='/')copy[n-1U]='\0';
    p=copy;
    if(*p=='/'){
        /* UnZip -d may make G.filename absolute.  Traverse from a pinned
           root descriptor; no component may resolve through a symlink. */
        dirfd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if(dirfd<0){free(copy);return -1;}
        owned=1;
        p++;
        if(!*p || *p=='/'){close(dirfd);free(copy);return -1;}
    }
    while(p && *p){
        q=strchr(p,'/');
        if(!*p || !strcmp(p,"..") || !strcmp(p,"."))break;
        if(q){
            *q='\0';
            if(!*p || !strcmp(p,"..") || !strcmp(p,"."))break;
            fd=openat(owned?dirfd:AT_FDCWD,p,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(fd<0)break;
            if(owned)close(dirfd);
            dirfd=fd;owned=1;fd=-1;
            p=q+1;
        }else{
            fd=openat(owned?dirfd:AT_FDCWD,p,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|
                      (directory?O_DIRECTORY:0));
            if(fd>=0 && (fstat(fd,&st)!=0 ||
               (directory?!S_ISDIR(st.st_mode):!S_ISREG(st.st_mode)))){
                close(fd);fd=-1;
            }
            break;
        }
    }
    if(owned)close(dirfd);
    free(copy);
    return fd;
}

static int xtr_open_output(const char *name){
    return xtr_open_output_kind(name,0);
}

/* Validate a directory local header without changing UnZip's buffered
   central-directory read state. Directory entries take the mapname fast
   path and otherwise never reach extract_or_test_member(). Only ordinary
   seekable single-volume, unencrypted, empty STORE directories are eligible.
   All other layouts fail closed rather than skipping local-header checks. */
static int xtr_directory_preflight(min_info *info,int zipfd,zoff_t extra){
    unsigned char h[30],name[65535],ef[65535];
    const unsigned char *loc;
    size_t ln;
    unsigned fn,sz;
    unsigned long long pos;
    off_t base;
    xtr_extra e;
    if(!info || !info->xtr_central || !info->xtr_source_name ||
       info->diskstart || info->encrypted || info->compression_method!=0 ||
       info->uncompr_size || info->compr_size || info->crc ||
       info->offset<0 || extra<0)return 1;
    pos=(unsigned long long)info->offset+(unsigned long long)extra;
    base=(off_t)pos;
    if((unsigned long long)base!=pos || base<0 ||
       pread(zipfd,h,sizeof(h),base)!=(ssize_t)sizeof(h))return 1;
    if(memcmp(h,"PK\003\004",4)!=0 ||
       (h[6]&9U) || h[8] || h[9] ||
       memcmp(h+14,"\0\0\0\0\0\0\0\0\0\0\0\0",12)!=0)
        return 1;
    fn=(unsigned)h[26]|((unsigned)h[27]<<8);
    sz=(unsigned)h[28]|((unsigned)h[29]<<8);
    if(!fn || strlen(info->xtr_source_name)!=fn ||
       pos>~0ULL-30ULL-(unsigned long long)fn-(unsigned long long)sz)return 1;
    if(pread(zipfd,name,fn,base+30)!=(ssize_t)fn ||
       memcmp(name,info->xtr_source_name,fn)!=0 ||
       pread(zipfd,ef,sz,base+30+(off_t)fn)!=(ssize_t)sz ||
       xtr_locate(ef,sz,&loc,&ln)!=XTR_OK || !loc ||
       xtr1_check_headers(loc,ln,info->xtr_central,
                          info->xtr_central_len,&e,NULL)!=XTR_OK)return 1;
    return 0;
}

/* Only call after mapname reports MPN_CREATED_DIR. Existing directories
   are intentionally excluded: the normal extractor skipped those entries. */
static int xtr_directory_created(min_info *info,const char *name){
    xtr_extra e;
    xtr_pending_restore *p;
    int fd;
    if(!info || !info->xtr_central)return 0;
    if(xtr1_extra_decode(info->xtr_central,info->xtr_central_len,
                         1,&e,NULL)!=XTR_OK)return 1;
    fd=xtr_open_output_kind(name,1);
    if(fd<0)return 1;
    p=xtr_lookup(e.owner,1);
    if(!p || p->owner_verified || (p->has_owner && e.mode==XTR_V1_INLINE)){
        close(fd);return 1;
    }
    if(e.mode==XTR_V1_INLINE){
        if(e.manifest_len.hi ||
           e.manifest_len.lo > XTR_STAGE_AGGREGATE-xtr_stage_advertised){
            close(fd);return 1;
        }
        if(e.flags || e.manifest_len.hi ||
           e.manifest_len.lo!=info->xtr_central_len-40U){close(fd);return 1;}
        p->stage=tmpfile();
        if(!p->stage || fwrite(info->xtr_central+40,1,
                   (size_t)e.manifest_len.lo,p->stage)!=(size_t)e.manifest_len.lo ||
           fflush(p->stage)!=0){
            close(fd);return 1;
        }
        xtr_stage_reserved+=(unsigned long long)e.manifest_len.lo;
        xtr_stage_advertised+=(unsigned long long)e.manifest_len.lo;
        p->has_owner=p->has_companion=p->companion_verified=1;
        p->outer=e;
    }else if(!p->has_owner){close(fd);return 1;}
    p->output_name=(char *)malloc(strlen(name)+1U);
    if(!p->output_name){close(fd);return 1;}
    strcpy(p->output_name,name);
    p->fd=fd;p->owner_verified=1;p->is_dir=1;
    return 0;
}

static int xtr_restore_verified(min_info *info,const uch *local,unsigned local_len,
                                const char *name){
    const unsigned char *loc;
    size_t ln;
    xtr_extra outer;
    xtr_u64 encoded;
    FILE *stage;
    int fd=-1,probe=-1,rc;
    if(!info->xtr_central)return 0;
    if(xtr_locate(local,local_len,&loc,&ln)!=XTR_OK || !loc ||
       xtr1_check_headers(loc,ln,info->xtr_central,
                          info->xtr_central_len,&outer,NULL)!=XTR_OK ||
       outer.mode!=XTR_V1_INLINE){
        fprintf(stderr,"unzip: inconsistent Xtro local/central metadata: %s\n",name);
        return 1;
    }
    encoded=outer.manifest_len;
    if(encoded.hi || encoded.lo != info->xtr_central_len-40U)return 1;
    stage=tmpfile();
    if(!stage)return 1;
    if(fwrite(info->xtr_central+40,1,(size_t)encoded.lo,stage)!=(size_t)encoded.lo){
        fclose(stage);return 1;
    }
    fd=info->xtr_restore_fd;
    info->xtr_restore_fd=-1;
    if(fd<0){fclose(stage);return 1;}
    /* Never follow a symlink in any path component.  The descriptor we
       actually restore to remains the one UnZip wrote, NOT this lookup. */
    probe=xtr_open_output(name);
    if(probe<0){
        fprintf(stderr,"unzip: cannot safely open extracted Xtro owner: %s\n",name);
        close(fd);fclose(stage);return 1;
    }
    {
        struct stat st,check;
        if(fstat(fd,&st)!=0 || fstat(probe,&check)!=0 ||
           st.st_dev!=check.st_dev || st.st_ino!=check.st_ino){
            fprintf(stderr,"unzip: extracted Xtro owner was replaced: %s\n",name);
            close(probe);close(fd);fclose(stage);return 1;
        }
    }
    close(probe);
    rc=xtr_bsd_restore_fd(fd,stage,encoded,&outer,NULL);
    close(fd);fclose(stage);
    if(rc!=XTR_OK){
        fprintf(stderr,"unzip: Xtro metadata verification/restoration failed (%d): %s\n",rc,name);
        return 1;
    }
    return 0;
}

/* The caller bypasses mapname/overwrite prompts for internal companions.
   Every byte still passes through UnZip's ordinary codec, CRC, password and
   AES authentication paths. This temporary FILE is never given a path. */
static int xtr_stage_begin(min_info *info,const char *name){
    unsigned char id[16];
    xtr_pending_restore *p;
    unsigned long long bytes=(unsigned long long)info->uncompr_size;
    if(!info->xtr_companion || xtr_id_from_name(name,id) ||
       bytes>XTR_STAGE_MAX ||
       bytes>XTR_STAGE_AGGREGATE-xtr_stage_reserved)return 1;
    p=xtr_lookup(id,0);
    if(!p || !p->has_companion || p->stage)return 1;
    p->stage=tmpfile();
    if(!p->stage)return 1;
    xtr_stage_reserved+=bytes;
    return 0;
}
static FILE *xtr_stage_file(const char *name){
    unsigned char id[16];
    xtr_pending_restore *p;
    if(xtr_id_from_name(name,id))return NULL;
    p=xtr_lookup(id,0);
    return p?p->stage:NULL;
}
static int xtr_stage_end(min_info *info,const char *name){
    FILE *f;
    (void)info;
    f=xtr_stage_file(name);
    struct stat st;
    if(!f || fflush(f)!=0 || fstat(fileno(f),&st)!=0 ||
       st.st_size<0 || (unsigned long long)st.st_size > XTR_STAGE_MAX ||
       (unsigned long long)st.st_size!=(unsigned long long)info->uncompr_size ||
       fseek(f,0,SEEK_SET)!=0)return 1;
    return 0;
}
static void xtr_stage_verified(const char *name){
    unsigned char id[16];
    xtr_pending_restore *p;
    if(xtr_id_from_name(name,id))return;
    p=xtr_lookup(id,0);
    if(p && p->stage)p->companion_verified=1;
}
/* Capture the successfully extracted inode. The owner must pass all normal
   ZIP integrity checks before this is called. Native writes occur later. */
static int xtr_defer_owner(min_info *info,const uch *local,unsigned local_len,
                           const char *name){
    const unsigned char *loc;
    size_t ln;
    xtr_extra outer;
    unsigned char sha[32];
    xtr_pending_restore *p;
    int fd=info->xtr_restore_fd;
    info->xtr_restore_fd=-1;
    if(fd<0)return 1;
    if(xtr_locate(local,local_len,&loc,&ln)!=XTR_OK || !loc ||
       xtr1_check_headers(loc,ln,info->xtr_central,
                          info->xtr_central_len,&outer,sha)!=XTR_OK ||
       outer.mode!=XTR_V1_COMPANION){close(fd);return 1;}
    p=xtr_lookup(outer.owner,0);
    if(!p||!p->has_owner||p->fd>=0||p->owner_verified){close(fd);return 1;}
    p->output_name=(char *)malloc(strlen(name)+1U);
    if(!p->output_name){close(fd);return 1;}
    strcpy(p->output_name,name);
    p->fd=fd;p->owner_verified=1;
    return 0;
}
/* off_t is at least 64-bit with normal BSD large-file builds. The conversion to
   the portable hi/lo pair does not use C99 types in the portable core. */
static int xtr_stage_length(FILE *f,xtr_u64 *out){
    struct stat st;
    unsigned long long n;
    if(!f||!out||fstat(fileno(f),&st)!=0||st.st_size<0)return 1;
    n=(unsigned long long)st.st_size;
    if(n>XTR_STAGE_MAX)return 1;
    out->lo=(unsigned long)(n & 0xffffffffULL);
    out->hi=(unsigned long)(n >> 32);
    return fseek(f,0,SEEK_SET)!=0;
}
static int xtr_apply_pending(int selective){
    xtr_pending_restore *p;
    int probe=-1,rc;
    xtr_u64 length;
    struct stat st,check;
    /* First verify the entire selected graph and every payload, before
       applying any native metadata. Skipped owners are not altered. */
    for(p=xtr_pending_head;p;p=p->next){
        xtr_reader rd;
        xtr1_digest dig;
        xtr1_policy pol;
        /* Explicit member selections may leave intentionally unselected
           owners. Those unrelated companions are not an extraction error. */
        if(selective && !p->has_owner)continue;
        if(!p->has_owner||!p->has_companion||!p->companion_verified){
            fprintf(stderr,"unzip: incomplete Xtro owner/companion association\n");return 1;
        }
        if(p->owner_crypto>4U || p->owner_crypto!=p->companion_crypto ||
           p->owner_strength!=p->companion_strength ||
           p->owner_iterations!=p->companion_iterations ||
           ((p->outer.flags&XTR_V1_ENCRYPTED)!=0)!=(p->owner_crypto!=0) ||
           (p->companion_crypto!=0 && p->companion_fwkcs)){
            fprintf(stderr,"unzip: Xtro encryption/FWKCS mismatch\n");return 1;
        }
        if(!p->owner_verified)continue; /* normal extraction skipped owner */
        if(xtr_stage_length(p->stage,&length))return 1;
        memset(&rd,0,sizeof(rd));rd.context=p->stage;rd.read=xtr_stage_read;
        xtr_bsd_policy(&pol);
        rc=xtr1_check_manifest(&rd,length,&p->outer,
            ((p->outer.flags&XTR_V1_ENCRYPTED) ||
              p->outer.mode==XTR_V1_INLINE)?NULL:p->sha,&pol,&dig);
        if(rc||!dig.schema_supported){
            fprintf(stderr,"unzip: Xtro companion SHA/schema verification failed\n");return 1;
        }
        probe=xtr_open_output_kind(p->output_name,p->is_dir);
        if(probe<0 || fstat(probe,&check)!=0 || fstat(p->fd,&st)!=0 ||
           st.st_dev!=check.st_dev || st.st_ino!=check.st_ino){
            if(probe>=0)close(probe);
            fprintf(stderr,"unzip: Xtro output inode changed\n");return 1;
        }
        close(probe);probe=-1;
    }
    for(p=xtr_pending_head;p;p=p->next){
        if(!p->owner_verified || p->is_dir)continue;
        if(xtr_stage_length(p->stage,&length))return 1;
        rc=xtr_bsd_restore_fd(p->fd,p->stage,length,&p->outer,
              (p->outer.flags&XTR_V1_ENCRYPTED)?NULL:p->sha);
        if(rc){
            fprintf(stderr,"unzip: Xtro companion native restore failed (%d)\n",rc);
            return 1;
        }
    }
    return 0;
}
/* Called after verified member/companion extraction and before deferred
   directory chmod/timestamp restoration, while directories are writable. */
static int xtr_apply_directories(void){
    xtr_pending_restore *p;
    xtr_u64 length;
    for(p=xtr_pending_head;p;p=p->next){
        int probe,rc;
        struct stat oldst,newst;
        if(!p->is_dir || !p->owner_verified)continue;
        probe=xtr_open_output_kind(p->output_name,1);
        if(probe<0 || fstat(probe,&newst)!=0 || fstat(p->fd,&oldst)!=0 ||
           newst.st_dev!=oldst.st_dev || newst.st_ino!=oldst.st_ino){
            if(probe>=0)close(probe);
            fprintf(stderr,"unzip: Xtro directory output inode changed\n");return 1;
        }
        close(probe);
        if(xtr_stage_length(p->stage,&length))return 1;
        rc=xtr_bsd_restore_fd(p->fd,p->stage,length,&p->outer,
                  p->outer.mode==XTR_V1_INLINE ||
                  (p->outer.flags&XTR_V1_ENCRYPTED)?NULL:p->sha);
        if(rc){fprintf(stderr,"unzip: Xtro directory metadata restore failed (%d)\n",rc);
               return 1;}
    }
    return 0;
}
static size_t xtr_stage_read(void *opaque,unsigned char *dst,size_t size){
    return fread(dst,1,size,(FILE *)opaque);
}
static void xtr_bsd_policy(xtr1_policy *p){
    memset(p,0,sizeof(*p));p->max_records=1024UL;
    p->max_field=1024UL*1024UL;
    p->max_manifest.lo=32UL*1024UL*1024UL;p->max_manifest.hi=0;
}
#endif
