/* SPDX-License-Identifier: MIT-0 */
/* Windows NT EA staging for Zip. The temporary
 * companion is created in a current-user-DACL directory and removed after use.
 * It is not an archive member pathname until the ZIP writer consumes it. */
#include "zip.h"
#undef local
#include "../xtrmeta/xtrwin_nt.h"
#include "../xtrmeta/xtrwin_mixed.h"
#define local static
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

extern int xtr_zip_xattrs;
extern int xtr_zip_streams;
extern int fwkcs_md5;

typedef struct xtr_pending {
    FILE *stage;
    unsigned aes_version;
    char member[52];
    char source[512];
    char private_dir[512];
    struct xtr_pending *next;
} xtr_pending;
static xtr_pending *pending_first=NULL,*pending_last=NULL;

/* Match Win32's Unicode file-open behavior when Zip uses native wide
 * names. Final reparse points are opened as objects, never followed. */
static HANDLE xtr_open_source(const struct zlist far *z,int isdir,DWORD rights){
    DWORD flags=FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS;
    HANDLE result=INVALID_HANDLE_VALUE;
#if defined(UNICODE_SUPPORT) && defined(WIN32)
    if(z->namew && !no_win32_wide){
        const wchar_t *name=z->namew;
        wchar_t *copy;
        size_t len=0;
        while(name[len])len++;
        if(!len || len>32766U)return INVALID_HANDLE_VALUE;
        copy=(wchar_t *)malloc((len+1U)*sizeof(*copy));
        if(!copy)return INVALID_HANDLE_VALUE;
        memcpy(copy,name,(len+1U)*sizeof(*copy));
        if(isdir && len>1U && (copy[len-1U]==L'/' || copy[len-1U]==L'\\')){
            if(len==3U && copy[1]==L':'){
                free(copy);return INVALID_HANDLE_VALUE;
            }
            copy[len-1U]=0;
        }
        result=CreateFileW(copy,rights,FILE_SHARE_READ|FILE_SHARE_WRITE|
                  FILE_SHARE_DELETE,NULL,OPEN_EXISTING,flags,NULL);
        free(copy);
        return result;
    }
#endif
    {
        char *copy;
        size_t len=strlen(z->name);
        if(!len)return INVALID_HANDLE_VALUE;
        copy=(char *)malloc(len+1U);
        if(!copy)return INVALID_HANDLE_VALUE;
        memcpy(copy,z->name,len+1U);
        if(isdir && len>1U && (copy[len-1U]=='/' || copy[len-1U]=='\\')){
            if(len==3U && copy[1]==':'){
                free(copy);return INVALID_HANDLE_VALUE;
            }
            copy[len-1U]=0;
        }
        result=CreateFileA(copy,rights,FILE_SHARE_READ|FILE_SHARE_WRITE|
                  FILE_SHARE_DELETE,NULL,OPEN_EXISTING,flags,NULL);
        free(copy);
    }
    return result;
}

/* Windows cryptographic RNG; never use a timestamp or process ID for an
 * Xtro owner identity or a private temporary directory pathname. */
static int xtr_random_id(unsigned char id[16]){
    HCRYPTPROV provider=0;
    unsigned i;int nz=0,ok;
    if(!CryptAcquireContextA(&provider,NULL,NULL,PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))return 0;
    ok=CryptGenRandom(provider,16,(BYTE *)id)!=0;
    CryptReleaseContext(provider,0);
    if(!ok)return 0;
    for(i=0;i<16;i++)nz|=id[i];
    return nz!=0;
}
static int xtr_same_handle(HANDLE a,HANDLE b){
    BY_HANDLE_FILE_INFORMATION x,y;
    if(a==INVALID_HANDLE_VALUE || b==INVALID_HANDLE_VALUE ||
       !GetFileInformationByHandle(a,&x) || !GetFileInformationByHandle(b,&y))
        return 0;
    return x.dwVolumeSerialNumber==y.dwVolumeSerialNumber &&
        x.nFileIndexHigh==y.nFileIndexHigh &&
        x.nFileIndexLow==y.nFileIndexLow &&
        !(x.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) &&
        !(y.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT);
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
/* Windows reparse-point capture is intentionally unsupported; fail closed
 * rather than attributing a reparse target's metadata to its link. */
static int xtr_symlink_capture_check(const char *path){
    (void)path;
    return ZE_PARMS;
}
/* Legacy Zip needs a companion source pathname. Create a random private
 * directory before opening its file with CREATE_NEW; never reuse a caller
 * supplied temporary pathname or create attributes in an archive namespace. */
/* A metadata companion, including an encrypted owner's plaintext metadata,
 * resides briefly on disk. Create the scratch directory with an explicit
 * current-user-only DACL; inheriting a permissive TMPDIR DACL is unsafe. */
static int xtr_private_directory(const char *path){
    HANDLE token=NULL;
    TOKEN_USER *user=NULL;
    ACL *acl=NULL;
    DWORD needed=0,bytes;
    SECURITY_DESCRIPTOR desc;
    SECURITY_ATTRIBUTES attr;
    int good=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 0;
    GetTokenInformation(token,TokenUser,NULL,0,&needed);
    if(!needed || needed>65536UL)goto finish;
    user=(TOKEN_USER *)malloc((size_t)needed);
    if(!user || !GetTokenInformation(token,TokenUser,user,needed,&needed))
        goto finish;
    bytes=(DWORD)(sizeof(ACL)+sizeof(ACCESS_ALLOWED_ACE)+
                  GetLengthSid(user->User.Sid)-sizeof(DWORD));
    acl=(ACL *)malloc(bytes);
    if(!acl || !InitializeAcl(acl,bytes,ACL_REVISION) ||
       !AddAccessAllowedAce(acl,ACL_REVISION,GENERIC_ALL,user->User.Sid) ||
       !InitializeSecurityDescriptor(&desc,SECURITY_DESCRIPTOR_REVISION) ||
       !SetSecurityDescriptorDacl(&desc,TRUE,acl,FALSE))goto finish;
    memset(&attr,0,sizeof(attr));
    attr.nLength=sizeof(attr);
    attr.lpSecurityDescriptor=&desc;
    good=CreateDirectoryA(path,&attr)!=0;
finish:
    free(acl);free(user);
    CloseHandle(token);
    return good;
}
static int xtr_stage_create(xtr_pending *p){
    static const char hex[]="0123456789abcdef";
    char tmp[512],volume[MAX_PATH+1];
    unsigned char nonce[16];
    DWORD n,fsflags=0;
    unsigned k,i;
    HANDLE h;
    int fd;
    n=GetTempPathA((DWORD)sizeof(tmp),tmp);
    if(!n || n>=sizeof(tmp) || n+42U>=sizeof(p->private_dir))return ZE_TEMP;
    /* Do not stage plaintext metadata on FAT/exFAT or a volume which cannot
     * enforce our restrictive temporary-directory DACL. */
    if(!GetVolumePathNameA(tmp,volume,MAX_PATH+1U) ||
       !GetVolumeInformationA(volume,NULL,0,NULL,NULL,&fsflags,NULL,0) ||
       !(fsflags&FILE_PERSISTENT_ACLS))return ZE_TEMP;
    for(k=0;k<16U;k++){
        size_t len;
        if(!xtr_random_id(nonce))return ZE_TEMP;
        strcpy(p->private_dir,tmp);
        len=strlen(p->private_dir);
        if(len && p->private_dir[len-1]!='\\')strcat(p->private_dir,"\\");
        strcat(p->private_dir,"xtro-");
        len=strlen(p->private_dir);
        for(i=0;i<16U;i++){
            p->private_dir[len+i*2]=hex[nonce[i]>>4];
            p->private_dir[len+i*2+1]=hex[nonce[i]&15U];
        }
        p->private_dir[len+32U]=0;
        if(xtr_private_directory(p->private_dir))break;
        p->private_dir[0]=0;
    }
    if(k==16U)return ZE_TEMP;
    strcpy(p->source,p->private_dir);
    strcat(p->source,"\\m");
    h=CreateFileA(p->source,GENERIC_READ|GENERIC_WRITE,
                  FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return ZE_TEMP;
    fd=_open_osfhandle((intptr_t)h,_O_RDWR|_O_BINARY);
    if(fd<0){CloseHandle(h);return ZE_TEMP;}
    p->stage=_fdopen(fd,"w+b");
    if(!p->stage){_close(fd);return ZE_TEMP;}
    return ZE_OK;
}
/* The additional ADS spool inherits the same private-directory DACL as
 * the metadata companion, and is never named in the resulting ZIP. */
static FILE *xtr_spool_open(const xtr_pending *p,char pathname[512]){
    HANDLE h;
    int fd;
    FILE *file;
    size_t n=strlen(p->private_dir);
    if(n>sizeof(p->private_dir)-4U)return NULL;
    memcpy(pathname,p->private_dir,n);
    strcpy(pathname+n,"\\s");
    h=CreateFileA(pathname,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return NULL;
    fd=_open_osfhandle((intptr_t)h,_O_RDWR|_O_BINARY);
    if(fd<0){CloseHandle(h);DeleteFileA(pathname);return NULL;}
    file=_fdopen(fd,"w+b");
    if(!file){_close(fd);DeleteFileA(pathname);return NULL;}
    return file;
}
static void xtr_stage_destroy(xtr_pending *p){
    if(p->stage)fclose(p->stage);
    if(p->source[0])DeleteFileA(p->source);
    if(p->private_dir[0])RemoveDirectoryA(p->private_dir);
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
    FILE *stage=NULL,*spool=NULL;
    char spool_path[512];
    xtr_pending *newp=NULL;
    size_t nl=0,nc=0;
    HANDLE h=INVALID_HANDLE_VALUE;
    int r=ZE_PARMS,i;
    unsigned long n;
    spool_path[0]=0;
    if(!(xtr_zip_xattrs||xtr_zip_streams) ||
       xtr_zip_is_stage(z->name,z->iname))return ZE_OK;
    if(!z->name || !strcmp(z->name,"-"))return ZE_PARMS;
    if(issym)return xtr_symlink_capture_check(z->name);
    if(encrypted && fwkcs_md5)return ZE_PARMS;
    /* For ordinary files, use the very same descriptor from which Zip
       reads file contents. Reopening a mutable pathname could capture EAs
       belonging to a different inode after a rename/replacement race. */
    if(!isdir){
        if(original_fd<0)return ZE_OPEN;
        h=(HANDLE)_get_osfhandle(original_fd);
        if(h==INVALID_HANDLE_VALUE)return ZE_OPEN;
    }else{
        h=xtr_open_source(z,1,FILE_READ_EA|FILE_READ_ATTRIBUTES);
        if(h==INVALID_HANDLE_VALUE)return ZE_OPEN;
    }
    if(!isdir){
        HANDLE probe=xtr_open_source(z,0,FILE_READ_ATTRIBUTES);
        int same=xtr_same_handle(h,probe);
        if(probe!=INVALID_HANDLE_VALUE)CloseHandle(probe);
        if(!same)return ZE_OPEN;
    }
    {
        BY_HANDLE_FILE_INFORMATION info;
        if(!GetFileInformationByHandle(h,&info) ||
           (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) ||
           ((info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)!=!!isdir){
            if(isdir)CloseHandle(h);
            return ZE_OPEN;
        }
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
    for(i=0;i<12;i++){
        int generated;
        if(iz_sde_active){
            iz_sde_random(id,16U,"XtroOwner",z->iname);
            generated=1;
        }else generated=xtr_random_id(id);
        if(generated&&!xtr_id_exists(id))break;
    }
    if(i==12){r=ZE_TEMP;goto done;}
    if(xtr_zip_streams){
        spool=xtr_spool_open(newp,spool_path);
        if(!spool){r=ZE_TEMP;goto done;}
        r=xtr_win_mixed_capture((void *)h,id,stage,spool,
                                xtr_zip_xattrs,encrypted,&dig);
        if(fclose(spool)!=0 && r==XTR_OK)r=XTR_IO;
        spool=NULL;
        /* Never publish a ZIP after failing to remove plaintext ADS spool
         * bytes. Preserve the pathname so the error cleanup can retry. */
        if(DeleteFileA(spool_path))spool_path[0]=0;
        else if(r==XTR_OK)r=XTR_IO;
    }else{
        r=xtr_win_nt_capture_handle((void *)h,id,stage,encrypted,&dig);
    }
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
        {HANDLE verify=CreateFileA(newp->source,FILE_READ_ATTRIBUTES,
                   FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,
                   OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
         HANDLE original=(HANDLE)_get_osfhandle(_fileno(stage));
         int same=xtr_same_handle(original,verify);
         if(verify!=INVALID_HANDLE_VALUE)CloseHandle(verify);
         if(!same){r=ZE_TEMP;goto done;}}
    }
    if(xtr_extend_extras(z,loc,nl,0)!=ZE_OK){r=ZE_BIG;goto done;}
    if(xtr_extend_extras(z,cen,nc,1)!=ZE_OK){r=ZE_BIG;goto done;}
    /* Inline manifests have no companion and must not be queued. */
    if(outer.mode==XTR_V1_INLINE){
        xtr_stage_destroy(newp);free(newp);newp=NULL;stage=NULL;
    }
    if(newp){
        /* On Windows, Zip reopens companion source by pathname. Closing the
         * writable staging HANDLE prevents CRT sharing-mode conflicts. */
        if(fflush(newp->stage)!=0){r=ZE_TEMP;goto done;}
        if(fclose(newp->stage)!=0){
            newp->stage=NULL;r=ZE_TEMP;goto done;
        }
        newp->stage=NULL;
        if(pending_last)pending_last->next=newp;else pending_first=newp;
        pending_last=newp;newp=NULL;stage=NULL;
    }
    r=ZE_OK;
done:
    if(spool)fclose(spool);
    if(spool_path[0])DeleteFileA(spool_path);
    if(isdir && h!=INVALID_HANDLE_VALUE)CloseHandle(h);
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
int xtr_zip_next_companion(char source[512],char member[52]){
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
