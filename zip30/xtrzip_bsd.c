/* SPDX-License-Identifier: MIT-0 */
/* FreeBSD/NetBSD extattr/named-attribute staging for Zip. The temporary
 * companion is created in a private 0700 directory and removed after use.
 * It is not an archive member pathname until the ZIP writer consumes it. */
#define _GNU_SOURCE 1
#include "zip.h"
#undef local
#include "../xtrmeta/xtrbsd.h"
#define local static
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>


extern int xtr_zip_xattrs;
extern int fwkcs_md5;

typedef struct xtr_pending {
    FILE *stage;
    unsigned aes_version;
    char member[52];
    char source[64];
    char private_dir[64];
    struct xtr_pending *next;
} xtr_pending;
static xtr_pending *pending_first=NULL,*pending_last=NULL;

static int xtr_random_id(unsigned char id[16]){
    FILE *f=fopen("/dev/urandom","rb");
    size_t n;int nz=0;unsigned i;
    if(!f)return 0;
    n=fread(id,1,16,f);fclose(f);
    if(n!=16)return 0;
    for(i=0;i<16;i++)nz|=id[i];
    return nz!=0;
}
static int xtr_id_exists(const unsigned char id[16]){
    struct zlist far *z;
    xtr_pending *p;
    for(p=pending_first;p;p=p->next){
        char name[52];
        if(!xtr1_companion_name(id,name) && !strcmp(name,p->member))return 1;
    }
    for(z=zfiles;z;z=z->nxt){
        unsigned at=0;
        const unsigned char *e=(const unsigned char *)z->cextra;
        while(e && at+4U<=z->cext){
            unsigned n=(unsigned)e[at+2U]|((unsigned)e[at+3U]<<8);
            if(n>z->cext-at-4U)break;
            if(e[at]==0x54 && e[at+1]==0x58 && n>=40U &&
               !memcmp(e+at+4U,"XTRO",4) && !memcmp(e+at+12U,id,16))return 1;
            at+=4U+n;
        }
    }
    return 0;
}
static int xtr_extend_extras(struct zlist far *z,
                              const unsigned char *p,size_t sz,int central){
    unsigned old=central?z->cext:z->ext;
    char *data=central?z->cextra:z->extra;
    char *next;
    unsigned at=0;
    while(at<old){
        unsigned tag,n;
        if(old-at<4U)return ZE_FORM;
        tag=(unsigned)(unsigned char)data[at]|
            ((unsigned)(unsigned char)data[at+1U]<<8);
        n=(unsigned)(unsigned char)data[at+2U]|
          ((unsigned)(unsigned char)data[at+3U]<<8);
        if(n>old-at-4U)return ZE_FORM;
        if(tag==XTR_V1_EXTRA_ID)return ZE_FORM;
        at+=n+4U;
    }
    if(old>65531U || sz>65535U-old-4U)return ZE_BIG;
    next=(char *)malloc(old+sz+4U);
    if(!next)return ZE_MEM;
    if(old)memcpy(next,data,old);
    next[old]=0x54;next[old+1]=0x58;
    next[old+2]=(char)(sz&255U);next[old+3]=(char)((sz>>8)&255U);
    memcpy(next+old+4U,p,sz);
    if(central){
        if(z->cextra!=z->extra)free(z->cextra);
        z->cextra=next;z->cext=(ush)(old+sz+4U);
    }else{
        free(z->extra);z->extra=next;z->ext=(ush)(old+sz+4U);
    }
    return ZE_OK;
}
int xtr_zip_is_stage(const char *path,const char *member){
    xtr_pending *p;
    for(p=pending_first;p;p=p->next)
        if(path&&member&&!strcmp(path,p->source)&&!strcmp(member,p->member))
            return 1;
    return 0;
}
/* Descriptor capture for symbolic links is not implemented by the M7A
 * adapter. Fail closed: never silently claim native EA preservation. */
static int xtr_symlink_capture_check(const char *path){
    (void)path;
    return ZE_PARMS;
}
/* A pathname is needed by the legacy Zip source and stat readers.
 * Make one only inside a per-companion private directory, owned by us,
 * with a mode-0600 file. Do not use /proc/self/fd or assume fdescfs mounts.
 * Pending scratch paths are removed both on success and on process exit. */
static int xtr_stage_create(xtr_pending *p){
    const char *base=getenv("TMPDIR");
    int fd;
    size_t n;
    if(!base || !*base)base="/tmp";
    n=strlen(base);
    if(n>47U || n==0U)return ZE_TEMP;
    if(n>1U && base[n-1]=='/')n--;
    memcpy(p->private_dir,base,n);
    memcpy(p->private_dir+n,"/xtro-XXXXXX",13U);
    if(!mkdtemp(p->private_dir))return ZE_TEMP;
    strcpy(p->source,p->private_dir);
    strcat(p->source,"/m");
    fd=open(p->source,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0)return ZE_TEMP;
    p->stage=fdopen(fd,"w+b");
    if(!p->stage){close(fd);return ZE_TEMP;}
    return ZE_OK;
}
static void xtr_stage_destroy(xtr_pending *p){
    if(p->stage)fclose(p->stage);
    if(p->source[0])unlink(p->source);
    if(p->private_dir[0])rmdir(p->private_dir);
    p->stage=NULL;
}
static int xtr_cleanup_registered;
static void xtr_cleanup_pending(void){
    xtr_pending *p=pending_first,*next;
    while(p){
        next=p->next;
        xtr_stage_destroy(p);
        free(p);
        p=next;
    }
    pending_first=pending_last=NULL;
}
int xtr_zip_capture(struct zlist far *z,int isdir,int issym,int encrypted,int original_fd){
    unsigned char id[16],loc[128],cen[65535];
    xtr_extra outer;
    xtr1_digest dig;
    FILE *stage=NULL;
    xtr_pending *newp=NULL;
    size_t nl=0,nc=0;
    int fd=-1,r=ZE_PARMS,i;
    unsigned long n;
    if(!xtr_zip_xattrs || xtr_zip_is_stage(z->name,z->iname))return ZE_OK;
    if(!z->name || !strcmp(z->name,"-"))return ZE_PARMS;
    if(issym)return xtr_symlink_capture_check(z->name);
    if(encrypted && fwkcs_md5)return ZE_PARMS;
    /* For ordinary files, use the very same descriptor from which Zip
       reads file contents. Reopening a mutable pathname could capture EAs
       belonging to a different inode after a rename/replacement race. */
    if(!isdir){
        fd=original_fd;
        if(fd<0)return ZE_OPEN;
    }else{
        fd=open(z->name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY);
        if(fd<0)return ZE_OPEN;
    }
    newp=(xtr_pending *)calloc(1,sizeof(*newp));
    if(!newp){r=ZE_MEM;goto done;}
    r=xtr_stage_create(newp);
    if(r!=ZE_OK)goto done;
    stage=newp->stage;
    if(!xtr_cleanup_registered){
        if(atexit(xtr_cleanup_pending)!=0){r=ZE_TEMP;goto done;}
        xtr_cleanup_registered=1;
    }
    for(i=0;i<16;i++)id[i]=0;
    for(i=0;i<12;i++)if(xtr_random_id(id)&&!xtr_id_exists(id))break;
    if(i==12){r=ZE_TEMP;goto done;}
    r=xtr_bsd_capture_fd(fd,id,stage,encrypted,&dig);
    if(r!=XTR_OK){r=ZE_TEMP;goto done;}
    if(dig.count==0){r=ZE_OK;goto done;}
    /* V1 directory metadata is encrypted only in its companion. The ZIP
       directory owner itself stays cleartext; its outer record advertises
       encrypted companion metadata without exposing the EA values. */
    memset(&outer,0,sizeof(outer));
    memcpy(outer.owner,id,16);
    outer.mode=XTR_V1_COMPANION;
    outer.flags=encrypted?XTR_V1_ENCRYPTED:0;
    if(!encrypted){
        outer.count=dig.count;outer.manifest_len=dig.manifest_length;
        outer.crc32=dig.crc32;
    }
    /* Inline only when unencrypted and the exact central field fits while
       retaining room for local format fields already constructed by Zip. */
    if(!encrypted && dig.manifest_length.hi==0 &&
       dig.manifest_length.lo<=60000UL &&
       dig.manifest_length.lo+44UL<=65535UL-z->cext){
        unsigned char *manifest;
        n=dig.manifest_length.lo;
        manifest=(unsigned char *)malloc((size_t)n);
        if(!manifest){r=ZE_MEM;goto done;}
        if(fseek(stage,0,SEEK_SET)!=0||fread(manifest,1,(size_t)n,stage)!=(size_t)n){
            free(manifest);r=ZE_TEMP;goto done;
        }
        outer.mode=XTR_V1_INLINE;
        r=xtr1_extra_encode(loc,sizeof(loc),&outer,0,NULL,0,NULL,&nl);
        if(r==XTR_OK)r=xtr1_extra_encode(cen,sizeof(cen),&outer,1,
                                          manifest,(size_t)n,NULL,&nc);
        free(manifest);
        if(r!=XTR_OK){r=ZE_TEMP;goto done;}
    }else{
        r=xtr1_extra_encode(loc,sizeof(loc),&outer,0,NULL,0,NULL,&nl);
        if(r==XTR_OK)r=xtr1_extra_encode(cen,sizeof(cen),&outer,1,
                                       NULL,0,encrypted?NULL:dig.sha256,&nc);
        if(r!=XTR_OK){r=ZE_TEMP;goto done;}
        if(xtr1_companion_name(id,newp->member)!=XTR_OK){r=ZE_TEMP;goto done;}
        {struct stat a,b;
         if(fstat(fileno(stage),&a)!=0||stat(newp->source,&b)!=0||
            a.st_dev!=b.st_dev||a.st_ino!=b.st_ino ||
            !S_ISREG(b.st_mode) || (b.st_mode&077)!=0){r=ZE_TEMP;goto done;}}
    }
    if(xtr_extend_extras(z,loc,nl,0)!=ZE_OK){r=ZE_BIG;goto done;}
    if(xtr_extend_extras(z,cen,nc,1)!=ZE_OK){r=ZE_BIG;goto done;}
    /* Inline manifests have no companion and must not be queued. */
    if(outer.mode==XTR_V1_INLINE){
        xtr_stage_destroy(newp);free(newp);newp=NULL;stage=NULL;
    }
    if(newp){
        if(pending_last)pending_last->next=newp;else pending_first=newp;
        pending_last=newp;newp=NULL;stage=NULL;
    }
    r=ZE_OK;
done:
    if(isdir && fd>=0)close(fd);
    if(newp){xtr_stage_destroy(newp);free(newp);}
    else if(stage)fclose(stage);
    return r;
}
void xtr_zip_owner_complete(const struct zlist far *z){
    xtr_pending *p;
    unsigned at;
    const unsigned char *e=(const unsigned char *)z->cextra;
    unsigned char id[16];
    int found=0;
    if(!z->cextra)return;
    for(at=0;at+4U<=z->cext;){
        unsigned n=(unsigned)(unsigned char)e[at+2U]|
                   ((unsigned)(unsigned char)e[at+3U]<<8);
        if(n>z->cext-at-4U)break;
        if(e[at]==0x54 && e[at+1]==0x58 && n>=40U &&
           !memcmp(e+at+4U,"XTRO",4)){
            memcpy(id,e+at+12U,16);found=1;break;
        }
        at+=n+4U;
    }
    if(!found)return;
    for(p=pending_first;p;p=p->next){
        if(xtr1_companion_matches(id,p->member,strlen(p->member))!=XTR_OK)
            continue;
        p->aes_version=0;
        for(at=0;at+4U<=z->cext;){
            unsigned n=(unsigned)(unsigned char)e[at+2U]|
                       ((unsigned)(unsigned char)e[at+3U]<<8);
            if(n>z->cext-at-4U)break;
            if(e[at]==1 && e[at+1]==(unsigned char)0x99 && n>=7U){
                p->aes_version=(unsigned)(unsigned char)e[at+4U];
                break;
            }
            at+=n+4U;
        }
        return;
    }
}
unsigned xtr_zip_stage_aes_version(void){
    return pending_first?pending_first->aes_version:0U;
}
int xtr_zip_next_companion(char source[64],char member[52]){
    xtr_pending *p=pending_first;
    if(!p)return 0;
    strcpy(source,p->source);strcpy(member,p->member);
    return 1;
}
void xtr_zip_companion_done(void){
    xtr_pending *p=pending_first;
    if(!p)return;
    pending_first=p->next;
    if(!pending_first)pending_last=NULL;
    xtr_stage_destroy(p);free(p);
}
