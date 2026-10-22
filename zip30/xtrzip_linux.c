/* SPDX-License-Identifier: MIT-0 */
/* Linux-only Xtro metadata staging for Zip. No native filesystem metadata
 * is written here. Every pending companion owns an unlinked temporary file;
 * the ZIP writer consumes it before publishing the central directory. */
#define _GNU_SOURCE 1
#include "zip.h"
#undef local
#include "../xtrmeta/xtrlinux.h"
#define local static
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/xattr.h>

extern int xtr_zip_xattrs;
extern int fwkcs_md5;

typedef struct xtr_pending {
    FILE *stage;
    unsigned aes_version;
    char member[52];
    char source[64];
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
/* Linux generally does not support user.* EAs on symbolic links.  A
   metadata-free link still needs to be archived when -y and --xattrs are
   used together. Check the link itself, never its referent; an actual
   eligible link EA must produce an error instead of being silently lost. */
static int xtr_symlink_capture_check(const char *path){
    struct stat before,after;
    ssize_t size,got;
    char *names;
    size_t at;
    int eligible=0;
    if(!path || lstat(path,&before)!=0 || !S_ISLNK(before.st_mode))
        return ZE_OPEN;
    size=llistxattr(path,NULL,0);
    if(size<0 || (unsigned long)size>1024UL*1024UL)return ZE_OPEN;
    names=(char *)malloc(size?(size_t)size:1U);
    if(!names)return ZE_MEM;
    got=llistxattr(path,names,(size_t)size);
    if(got<0 || got>size){free(names);return ZE_OPEN;}
    for(at=0;at<(size_t)got;){
        size_t end=at;
        while(end<(size_t)got && names[end])end++;
        if(end==(size_t)got || end==at){free(names);return ZE_FORM;}
        if(end-at>5U && !memcmp(names+at,"user.",5U))eligible=1;
        at=end+1U;
    }
    free(names);
    if(lstat(path,&after)!=0 || !S_ISLNK(after.st_mode) ||
       before.st_dev!=after.st_dev || before.st_ino!=after.st_ino)
        return ZE_OPEN;
    return eligible?ZE_PARMS:ZE_OK;
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
    stage=tmpfile();
    if(!stage){r=ZE_TEMP;goto done;}
    for(i=0;i<16;i++)id[i]=0;
    for(i=0;i<12;i++){
        int generated;
        if(iz_sde_active){
            iz_sde_random(id,16U,"XtroOwner",z->iname);
            generated=1;
        }else generated=xtr_random_id(id);
        if(generated&&!xtr_id_exists(id))break;
    }
    if(i==12){r=ZE_TEMP;goto done;}
    r=xtr_linux_capture_fd(fd,id,stage,encrypted,&dig);
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
        newp=(xtr_pending *)calloc(1,sizeof(*newp));
        if(!newp){r=ZE_MEM;goto done;}
        newp->stage=stage;
        if(xtr1_companion_name(id,newp->member)!=XTR_OK){r=ZE_TEMP;goto done;}
        /* Linux fd numbers fit well within this fixed 64-byte buffer. */
        sprintf(newp->source,"/proc/self/fd/%d",fileno(stage));
        /* Reopening through /proc/self/fd must address this unlinked file. */
        {struct stat a,b;
         if(fstat(fileno(stage),&a)!=0||stat(newp->source,&b)!=0||
            a.st_dev!=b.st_dev||a.st_ino!=b.st_ino){r=ZE_TEMP;goto done;}}
    }
    if(xtr_extend_extras(z,loc,nl,0)!=ZE_OK){r=ZE_BIG;goto done;}
    if(xtr_extend_extras(z,cen,nc,1)!=ZE_OK){r=ZE_BIG;goto done;}
    if(newp){
        if(pending_last)pending_last->next=newp;else pending_first=newp;
        pending_last=newp;newp=NULL;stage=NULL;
    }
    r=ZE_OK;
done:
    if(isdir && fd>=0)close(fd);
    if(stage)fclose(stage);
    if(newp)free(newp);
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
    fclose(p->stage);free(p);
}
