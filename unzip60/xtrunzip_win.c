/* SPDX-License-Identifier: MIT-0 */
/* Windows W2B2B: opt-in verified NT EA restoration for regular files.
 * Inline and companion-backed members, including encrypted companions.
 * Directory metadata remains explicitly unsupported.
 * Included by extract.c, not separately compiled. */
#if defined(XTR_WIN_NATIVE) && defined(WIN32) && !defined(SFX) && !defined(DLL)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
#if defined(XTR_WIN_UTF8_ACTIVE)
#include "../xtrmeta/xtrwin_utf8path.h"
#endif
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#ifndef XTR_WIN_TEST_STAGE
#include <wincrypt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../xtrmeta/xtrwin_nt.h"
#include "../xtrmeta/xtrwin_restore_plan.h"
#include "../xtrmeta/xtrwin_ads_restore.h"

extern int xtr_unzip_xattrs;
extern int xtr_unzip_streams;
static int xtr_restore_rejected;
static int xtr_exit_hook;
/* Owner/companion identities survive central-directory processing blocks.
 * No EA is applied from a companion until ALL associations are verified. */
#define XTR_WIN_STAGE_MAX (32UL*1024UL*1024UL+36UL)
#define XTR_WIN_AGGREGATE (128UL*1024UL*1024UL)
#define XTR_WIN_OWNER_LIMIT 65536UL
typedef struct xtr_win_pending {
    struct xtr_win_pending *next;
    unsigned char id[16],sha[32];
    xtr_extra outer;
    unsigned owner_crypto,companion_crypto,owner_strength,companion_strength;
    unsigned owner_iterations,companion_iterations;
    int has_owner,has_companion,owner_verified,companion_verified;
    int companion_fwkcs;
    int is_dir;
    HANDLE pinned;
    FILE *stage;
    char stage_path[512],stage_dir[512];
    char *output_name;
} xtr_win_pending;
static xtr_win_pending *xtr_win_head;
static unsigned long xtr_win_count,xtr_win_reserved,xtr_win_advertised;
static unsigned xtr_transport(const min_info *i){
#ifndef NO_AES
    if(i->aes_strength){
        if(i->aes_version==1U)return 2U;
        if(i->aes_version==2U)return 3U;
        if(i->aes_version==3U)return 4U;
        return 5U;
    }
#endif
    return i->encrypted?1U:0U;
}
static xtr_win_pending *xtr_lookup(const unsigned char id[16],int create){
    xtr_win_pending *p;
    for(p=xtr_win_head;p;p=p->next)if(!memcmp(p->id,id,16))return p;
    if(!create || xtr_win_count>=XTR_WIN_OWNER_LIMIT)return NULL;
    p=(xtr_win_pending *)calloc(1,sizeof(*p));
    if(!p)return NULL;
    memcpy(p->id,id,16);
    p->next=xtr_win_head;xtr_win_head=p;xtr_win_count++;
    return p;
}
static int xtr_id_from_name(const char *name,unsigned char id[16]){
    static const char prefix[]="__XTRO_ZIP__/x/";
    unsigned i;
    if(!name || strlen(name)!=51U || strncmp(name,prefix,15) ||
       strcmp(name+47,".xtm"))return 1;
    for(i=0;i<16U;i++){
        char a=name[15U+2U*i],b=name[16U+2U*i];
        unsigned j=(a>='0'&&a<='9')?(unsigned)(a-'0'):
                   (a>='a'&&a<='f')?(unsigned)(a-'a'+10):16U;
        unsigned k=(b>='0'&&b<='9')?(unsigned)(b-'0'):
                   (b>='a'&&b<='f')?(unsigned)(b-'a'+10):16U;
        if(j>15U||k>15U)return 1;
        id[i]=(unsigned char)((j<<4)|k);
    }
    return xtr1_companion_matches(id,name,strlen(name))!=XTR_OK;
}
static int xtr_register_owner(min_info *i,const xtr_extra *e,
                               const unsigned char sha[32]){
    xtr_win_pending *p=xtr_lookup(e->owner,1);
    if(!p || p->has_owner)return 1;
    p->has_owner=1;p->outer=*e;
    if(sha)memcpy(p->sha,sha,32);
    p->owner_crypto=xtr_transport(i);
#ifndef NO_AES
    p->owner_strength=i->aes_strength;p->owner_iterations=i->aes_iterations;
#endif
    return 0;
}
static int xtr_register_companion(min_info *i,const unsigned char id[16]){
    xtr_win_pending *p=xtr_lookup(id,1);
    if(!p || p->has_companion)return 1;
    p->has_companion=1;p->companion_crypto=xtr_transport(i);
    p->companion_fwkcs=i->fwkcs_md5;
#ifndef NO_AES
    p->companion_strength=i->aes_strength;p->companion_iterations=i->aes_iterations;
#endif
    return 0;
}
static void xtr_stage_destroy(xtr_win_pending *p){
    if(p->stage)fclose(p->stage);
    p->stage=NULL;
    if(p->stage_path[0])DeleteFileA(p->stage_path);
    if(p->stage_dir[0])RemoveDirectoryA(p->stage_dir);
    p->stage_path[0]=p->stage_dir[0]=0;
}
static void xtr_release_registry(void){
    xtr_win_pending *p=xtr_win_head,*next;
    while(p){
        next=p->next;
        if(p->pinned && p->pinned!=INVALID_HANDLE_VALUE)CloseHandle(p->pinned);
        xtr_stage_destroy(p);
        free(p->output_name);free(p);p=next;
    }
    xtr_win_head=NULL;xtr_win_count=0;
    xtr_win_reserved=xtr_win_advertised=0;
}
/* Native descriptor security is as important as ZIP encryption: decrypted
 * EA metadata must never be staged under a globally readable temp directory. */
#ifndef XTR_WIN_TEST_STAGE
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
    user=(TOKEN_USER *)malloc(needed);
    if(!user || !GetTokenInformation(token,TokenUser,user,needed,&needed))goto finish;
    bytes=(DWORD)(sizeof(ACL)+sizeof(ACCESS_ALLOWED_ACE)+
                  GetLengthSid(user->User.Sid)-sizeof(DWORD));
    acl=(ACL *)malloc(bytes);
    if(!acl || !InitializeAcl(acl,bytes,ACL_REVISION) ||
       !AddAccessAllowedAce(acl,ACL_REVISION,GENERIC_ALL,user->User.Sid) ||
       !InitializeSecurityDescriptor(&desc,SECURITY_DESCRIPTOR_REVISION) ||
       !SetSecurityDescriptorDacl(&desc,TRUE,acl,FALSE))goto finish;
    memset(&attr,0,sizeof(attr));attr.nLength=sizeof(attr);
    attr.lpSecurityDescriptor=&desc;
    good=CreateDirectoryA(path,&attr)!=0;
finish:
    free(acl);free(user);if(token)CloseHandle(token);
    return good;
}
static int xtr_secure_stage(xtr_win_pending *p){
    static const char hex[]="0123456789abcdef";
    char tmp[512],volume[MAX_PATH+1];
    unsigned char nonce[16];
    DWORD n,fsflags=0;
    HCRYPTPROV provider=0;
    unsigned k,i;
    HANDLE h=INVALID_HANDLE_VALUE;
    int fd;
    n=GetTempPathA((DWORD)sizeof(tmp),tmp);
    if(!n || n>=sizeof(tmp) || n+47U>sizeof(p->stage_dir))return 1;
    if(!GetVolumePathNameA(tmp,volume,MAX_PATH+1) ||
       !GetVolumeInformationA(volume,NULL,0,NULL,NULL,&fsflags,NULL,0) ||
       !(fsflags&FILE_PERSISTENT_ACLS))return 1;
    if(!CryptAcquireContextA(&provider,NULL,NULL,PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))return 1;
    for(k=0;k<16U;k++){
        size_t len;
        if(!CryptGenRandom(provider,16U,nonce))break;
        strcpy(p->stage_dir,tmp);
        len=strlen(p->stage_dir);
        if(len && p->stage_dir[len-1]!='\\')strcat(p->stage_dir,"\\");
        strcat(p->stage_dir,"xtro-unzip-");
        len=strlen(p->stage_dir);
        for(i=0;i<16U;i++){
            p->stage_dir[len+2U*i]=hex[nonce[i]>>4];
            p->stage_dir[len+2U*i+1U]=hex[nonce[i]&15U];
        }
        p->stage_dir[len+32U]=0;
        if(xtr_private_directory(p->stage_dir))break;
        p->stage_dir[0]=0;
    }
    CryptReleaseContext(provider,0);
    if(k==16U || !p->stage_dir[0])return 1;
    strcpy(p->stage_path,p->stage_dir);strcat(p->stage_path,"\\m");
    h=CreateFileA(p->stage_path,GENERIC_READ|GENERIC_WRITE,
                  FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return 1;
    fd=_open_osfhandle((intptr_t)h,_O_RDWR|_O_BINARY);
    if(fd<0){CloseHandle(h);return 1;}
    p->stage=_fdopen(fd,"w+b");
    if(!p->stage){_close(fd);return 1;}
    return 0;
}


#else
static int xtr_secure_stage(xtr_win_pending *p){
    p->stage=tmpfile();return p->stage?0:1;
}
#endif /* XTR_WIN_TEST_STAGE */

static int xtr_locate(const unsigned char *p,size_t n,
                      const unsigned char **value,size_t *len){
    size_t at=0;
    *value=NULL;*len=0;
    while(at<n){
        unsigned id,sz;
        if(n-at<4U || !p)return XTR_CORRUPT;
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
    const unsigned char *v=NULL;
    size_t n=0;
    unsigned char id[16],sha[32];
    xtr_extra e;
    int rc;
    info->xtr_central=NULL;info->xtr_central_len=0;
    info->xtr_source_name=NULL;info->xtr_restore_handle=NULL;
    info->xtr_companion=0;
    rc=xtr_locate(ef,len,&v,&n);
    if(rc!=XTR_OK)goto reject;
    if(name && strncmp(name,"__XTRO_ZIP__/",13)==0){
        unsigned long bytes;
        if(v || xtr_id_from_name(name,id))goto reject;
        bytes=(unsigned long)info->uncompr_size;
        if(info->uncompr_size>XTR_WIN_STAGE_MAX ||
           bytes>XTR_WIN_AGGREGATE-xtr_win_advertised)goto reject;
        if(xtr_register_companion(info,id))goto reject;
        xtr_win_advertised+=bytes;
        info->xtr_companion=1;
        return 0;
    }
    if(!v)return 0;
    if(!name || !*name)goto reject;
    if(name[strlen(name)-1]=='/' || name[strlen(name)-1]=='\\'){
        /* Preserve the *central-directory* name for independent local-header
         * verification before UnZip's directory mapname fast path. */
        info->xtr_source_name=(char *)malloc(strlen(name)+1U);
        if(!info->xtr_source_name)goto reject;
        strcpy(info->xtr_source_name,name);
    }
    rc=xtr1_extra_decode(v,n,1,&e,sha);
    if(rc!=XTR_OK || (e.mode!=XTR_V1_INLINE && e.mode!=XTR_V1_COMPANION))goto reject;
    if(e.mode==XTR_V1_INLINE){
        if(e.flags || e.manifest_len.hi || n<40U ||
           e.manifest_len.lo!=(unsigned long)(n-40U))goto reject;
    }else if(xtr_register_owner(info,&e,sha))goto reject;
    info->xtr_central=(unsigned char *)malloc(n);
    if(!info->xtr_central)goto reject;
    memcpy(info->xtr_central,v,n);
    info->xtr_central_len=(unsigned)n;
    return 0;
reject:
    free(info->xtr_source_name);info->xtr_source_name=NULL;
    free(info->xtr_central);info->xtr_central=NULL;
    info->xtr_central_len=0;
    fprintf(stderr,"unzip: invalid or unsupported Windows Xtro metadata: %s\n",
            name?name:"(unknown)");
    xtr_restore_rejected=1;
    return 1;
}

static void xtr_cleanup_block(min_info *entries,unsigned n){
    unsigned i;
    for(i=0;i<n;i++){
        if(entries[i].xtr_restore_handle){
            CloseHandle((HANDLE)entries[i].xtr_restore_handle);
            entries[i].xtr_restore_handle=NULL;
        }
        free(entries[i].xtr_central);
        entries[i].xtr_central=NULL;
        entries[i].xtr_central_len=0;
        free(entries[i].xtr_source_name);
        entries[i].xtr_source_name=NULL;
    }
}

static int xtr_same_handle_kind(HANDLE x,HANDLE y,int directory){
    BY_HANDLE_FILE_INFORMATION a,b;
    if(x==NULL || y==NULL || x==INVALID_HANDLE_VALUE ||
       y==INVALID_HANDLE_VALUE ||
       !GetFileInformationByHandle(x,&a) ||
       !GetFileInformationByHandle(y,&b))return 0;
    return a.dwVolumeSerialNumber==b.dwVolumeSerialNumber &&
           a.nFileIndexHigh==b.nFileIndexHigh &&
           a.nFileIndexLow==b.nFileIndexLow &&
           !!(a.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==!!directory &&
           !!(b.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==!!directory &&
           !(a.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) &&
           !(b.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT);
}
static int xtr_same_handle(HANDLE x,HANDLE y){
    return xtr_same_handle_kind(x,y,0);
}

/* Strict ACP-to-UTF-16 conversion of an existing narrow extraction path.
 * UnZip has already mapped/created this pathname through its narrow CRT.
 * We therefore MUST NOT interpret it as UTF-8 or accept Windows best-fit
 * substitutions; these could restore metadata to a different object.
 * A future wide-path extraction implementation must supply UTF-16 directly. */
static wchar_t *xtr_widen_exact_acp(const char *name){
#if defined(XTR_WIN_UTF8_ACTIVE)
    /* The UTF-8 extraction mode uses the same mapped pathname bytes for
     * file creation and EA/ADS reopen. No ACP reinterpretation is allowed. */
    return xtr_win_u8_wide(name);
#else
    int needed,used,roundtrip,substituted=0;
    unsigned cp=GetACP();
    DWORD flags=(cp==CP_UTF8)?0U:WC_NO_BEST_FIT_CHARS;
    size_t n;
    wchar_t *wide=NULL;
    char *check=NULL;
    if(!name || !*name)return NULL;
    n=strlen(name);
    if(n>32760U)return NULL;
    needed=MultiByteToWideChar(cp,cp==CP_UTF8?MB_ERR_INVALID_CHARS:0U,
                              name,-1,NULL,0);
    if(needed<=0 || needed>32768)return NULL;
    wide=(wchar_t *)malloc((size_t)needed*sizeof(*wide));
    if(!wide)return NULL;
    if(MultiByteToWideChar(cp,cp==CP_UTF8?MB_ERR_INVALID_CHARS:0U,
                           name,-1,wide,needed)!=needed)
        goto fail;
    roundtrip=WideCharToMultiByte(cp,flags,wide,-1,NULL,0,NULL,NULL);
    if(roundtrip<=0 || (size_t)roundtrip!=n+1U)goto fail;
    check=(char *)malloc((size_t)roundtrip);
    if(!check)goto fail;
    used=WideCharToMultiByte(cp,flags,wide,-1,check,roundtrip,
                             NULL,cp==CP_UTF8?NULL:&substituted);
    if(used!=roundtrip || substituted || memcmp(check,name,n+1U))goto fail;
    free(check);return wide;
fail:
    free(check);free(wide);return NULL;
#endif /* XTR_WIN_UTF8_ACTIVE */
}

/* Verify each path component using UTF-16 opens; never rely on a best-fit
 * CreateFileA conversion for metadata restoration. The final handle must
 * still match the pinned output object before ANY native EA writes.
 * Only drive-rooted paths are supported here; UNC/device paths fail closed.
 */
static HANDLE xtr_open_verified_path_kind_rights(const char *name,
                                                 int directory,DWORD additional){
    wchar_t *input,*path;
    DWORD n;
    size_t i;
    HANDLE final=INVALID_HANDLE_VALUE;
    input=xtr_widen_exact_acp(name);
    if(!input)return INVALID_HANDLE_VALUE;
    path=(wchar_t *)malloc(32768U*sizeof(*path));
    if(!path){free(input);return INVALID_HANDLE_VALUE;}
    n=GetFullPathNameW(input,32768U,path,NULL);
    free(input);
    if(directory && n>3U && n<32768U &&
       (path[n-1U]==L'/' || path[n-1U]==L'\\'))path[--n]=0;
    if(n<4U || n>=32768U || path[1]!=L':' ||
       (path[2]!=L'\\' && path[2]!=L'/'))goto finish;
    for(i=3U;i<=(size_t)n;i++){
        wchar_t sep;
        HANDLE h;
        BY_HANDLE_FILE_INFORMATION info;
        int last;
        DWORD rights;
        if(path[i]!=L'\\' && path[i]!=L'/' && path[i]!=0)continue;
        sep=path[i];last=(i==(size_t)n);
        if(i==3U || (i>3U && (path[i-1U]==L'\\' || path[i-1U]==L'/')))
            goto finish;
        path[i]=0;
        rights=last?(FILE_READ_ATTRIBUTES|
            (xtr_unzip_xattrs?(FILE_READ_EA|FILE_WRITE_EA):0U)|additional):
            FILE_READ_ATTRIBUTES;
        h=CreateFileW(path,rights,FILE_SHARE_READ|FILE_SHARE_WRITE|
             FILE_SHARE_DELETE,NULL,OPEN_EXISTING,
             FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        path[i]=sep;
        if(h==INVALID_HANDLE_VALUE)goto finish;
        if(!GetFileInformationByHandle(h,&info) ||
           (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) ||
           (!last && !(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)) ||
           (last &&
             !!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=!!directory)){
            CloseHandle(h);goto finish;
        }
        if(last){final=h;break;}
        CloseHandle(h);
    }
finish:
    free(path);
    return final;
}
static HANDLE xtr_open_verified_path_kind(const char *name,int directory){
    return xtr_open_verified_path_kind_rights(name,directory,0U);
}
static HANDLE xtr_open_verified_path(const char *name){
    return xtr_open_verified_path_kind(name,0);
}
/* Windows extraction of an existing file must truncate only the unnamed
 * data stream. Deleting/recreating the owner silently destroys NT EAs and
 * named $DATA streams which --no-xattrs/--no-streams must preserve.
 * Open and check every path component BEFORE changing any file contents;
 * retain the checked final handle as the CRT output descriptor.
 *
 * Used only by the explicit native Xtro restoration build and only after
 * normal overwrite/skip decisions. Unmodified Win32 builds keep their
 * historical open_outfile() behavior. */
FILE *xtr_win_open_existing_output(const char *name,int readable){
    DWORD access=FILE_WRITE_DATA | (readable?FILE_READ_DATA:0U);
    HANDLE h=xtr_open_verified_path_kind_rights(name,0,access);
    LARGE_INTEGER start;
    BY_HANDLE_FILE_INFORMATION identity;
    int fd,flags;
    FILE *out;
    if(h==INVALID_HANDLE_VALUE)return NULL;
    /* In-place truncation of a hard-linked owner would alter OTHER names,
     * unlike the former unlink/recreate path. Fail closed in this case. */
    if(!GetFileInformationByHandle(h,&identity) ||
       identity.nNumberOfLinks!=1U){
        CloseHandle(h);return NULL;
    }
    start.QuadPart=0;
    if(!SetFilePointerEx(h,start,NULL,FILE_BEGIN) || !SetEndOfFile(h)){
        CloseHandle(h);return NULL;
    }
    flags=_O_BINARY|(readable?_O_RDWR:_O_WRONLY);
    fd=_open_osfhandle((intptr_t)h,flags);
    if(fd<0){CloseHandle(h);return NULL;}
    out=_fdopen(fd,readable?"w+b":"wb");
    if(!out){_close(fd);return NULL;}
    return out;
}

/* Keep the handle of the actual file written by UnZip, even after fclose().
 * _get_osfhandle cannot be closed by this code; DuplicateHandle owns its copy. */
static int xtr_pin_output(min_info *info,FILE *output){
    INT_PTR raw;
    HANDLE pin=NULL;
    BY_HANDLE_FILE_INFORMATION st;
    if(!info->xtr_central)return 0;
    if(!output)return 1;
    raw=_get_osfhandle(_fileno(output));
    if(raw==-1)return 1;
    if(!DuplicateHandle(GetCurrentProcess(),(HANDLE)raw,GetCurrentProcess(),
                        &pin,0,FALSE,DUPLICATE_SAME_ACCESS))return 1;
    if(!GetFileInformationByHandle(pin,&st) ||
       (st.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))){
        CloseHandle(pin);return 1;
    }
    info->xtr_restore_handle=pin;
    return 0;
}

/* ReOpenFile provides an independent seek pointer to the already opened ZIP
 * object. DuplicateHandle alone would share its pointer and corrupt UnZip's
 * buffered central-directory reader. Reject split, encrypted, nonempty and
 * unsupported directory layouts before mapname creates the directory. */
static int xtr_win_read_at(HANDLE h,LARGE_INTEGER at,void *buf,DWORD size){
    DWORD got=0;
    return SetFilePointerEx(h,at,NULL,FILE_BEGIN) &&
           ReadFile(h,buf,size,&got,NULL) && got==size;
}
static int xtr_directory_preflight(min_info *info,int zipfd,zoff_t extra){
    HANDLE original,independent=INVALID_HANDLE_VALUE;
    LARGE_INTEGER total,pos,where;
    unsigned char hdr[30],*name=NULL,*ef=NULL;
    unsigned fn,sz;
    const unsigned char *field=NULL;
    size_t length=0;
    xtr_extra decoded;
    int bad=1;
    if(!info || !info->xtr_central || !info->xtr_source_name ||
       info->diskstart || info->encrypted || info->compression_method ||
       info->uncompr_size || info->compr_size || info->crc ||
       info->offset<0 || extra<0)return 1;
    original=(HANDLE)_get_osfhandle(zipfd);
    if(original==INVALID_HANDLE_VALUE)return 1;
    /* ReOpenFile accepts FILE_FLAG_* flags, not FILE_ATTRIBUTE_* values.
     * FILE_ATTRIBUTE_NORMAL is invalid under the documented API contract.
     * No special flags are needed for a regular ZIP archive file. */
    independent=ReOpenFile(original,GENERIC_READ,
               FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0);
    if(independent==INVALID_HANDLE_VALUE ||
       !xtr_same_handle(original,independent) ||
       !GetFileSizeEx(independent,&total) || total.QuadPart<30 ||
       info->offset>total.QuadPart ||
       extra>total.QuadPart-info->offset)goto done;
    pos.QuadPart=info->offset+extra;
    if(pos.QuadPart>total.QuadPart-30 ||
       !xtr_win_read_at(independent,pos,hdr,30U) ||
       memcmp(hdr,"PK\003\004",4)!=0 ||
       (hdr[6]&9U) || hdr[8] || hdr[9] ||
       memcmp(hdr+14,"\0\0\0\0\0\0\0\0\0\0\0\0",12))
        goto done;
    fn=(unsigned)hdr[26]|((unsigned)hdr[27]<<8);
    sz=(unsigned)hdr[28]|((unsigned)hdr[29]<<8);
    if(!fn || strlen(info->xtr_source_name)!=(size_t)fn ||
       (LONGLONG)fn+(LONGLONG)sz>total.QuadPart-pos.QuadPart-30)
        goto done;
    name=(unsigned char *)malloc(fn);
    ef=(unsigned char *)malloc(sz?sz:1U);
    if(!name || !ef)goto done;
    where.QuadPart=pos.QuadPart+30;
    if(!xtr_win_read_at(independent,where,name,(DWORD)fn) ||
       memcmp(name,info->xtr_source_name,fn)!=0)goto done;
    where.QuadPart+=fn;
    if(sz && !xtr_win_read_at(independent,where,ef,(DWORD)sz))goto done;
    if(xtr_locate(ef,sz,&field,&length)!=XTR_OK || !field ||
       xtr1_check_headers(field,length,info->xtr_central,
                     info->xtr_central_len,&decoded,NULL)!=XTR_OK)goto done;
    bad=0;
done:
    free(name);free(ef);
    if(independent!=INVALID_HANDLE_VALUE)CloseHandle(independent);
    return bad;
}
/* Only newly created directories receive EAs. Existing and skipped
 * directories retain their current metadata, matching BSD semantics. */
static int xtr_directory_created(min_info *info,const char *name){
    xtr_extra e;
    xtr_win_pending *p;
    HANDLE pin=INVALID_HANDLE_VALUE;
    if(!info || !info->xtr_central)return 0;
    if(xtr1_extra_decode(info->xtr_central,info->xtr_central_len,
                          1,&e,NULL)!=XTR_OK)return 1;
    pin=xtr_open_verified_path_kind(name,1);
    if(pin==INVALID_HANDLE_VALUE)return 1;
    p=xtr_lookup(e.owner,1);
    if(!p || p->owner_verified || p->pinned ||
       (e.mode==XTR_V1_INLINE && p->has_owner))goto fail;
    if(e.mode==XTR_V1_INLINE){
        if(e.flags || e.manifest_len.hi ||
           info->xtr_central_len<40U ||
           e.manifest_len.lo!=info->xtr_central_len-40U ||
           e.manifest_len.lo>XTR_WIN_AGGREGATE-xtr_win_reserved ||
           xtr_secure_stage(p))goto fail;
        if(fwrite(info->xtr_central+40U,1,(size_t)e.manifest_len.lo,p->stage)
                 !=(size_t)e.manifest_len.lo ||
           fflush(p->stage)!=0 || fseek(p->stage,0,SEEK_SET)!=0)goto fail;
        xtr_win_reserved+=e.manifest_len.lo;
        p->outer=e;
        p->has_owner=p->has_companion=p->companion_verified=1;
        p->owner_crypto=p->companion_crypto=0;
    }else if(e.mode!=XTR_V1_COMPANION || !p->has_owner)goto fail;
    p->output_name=(char *)malloc(strlen(name)+1U);
    if(!p->output_name)goto fail;
    strcpy(p->output_name,name);
    p->pinned=pin;p->owner_verified=1;p->is_dir=1;
    return 0;
fail:
    if(pin!=INVALID_HANDLE_VALUE)CloseHandle(pin);
    return 1;
}

/* The two optional classes are independently selected. Verify the complete
 * mixed manifest before any native write, then apply EAs and ADS with
 * compensating rollback if ADS restoration fails after EA restoration.
 * This is best-effort per owner, not archive-wide filesystem atomicity. */
static int xtr_apply_win_metadata(HANDLE native,FILE *stage,xtr_u64 length,
                                  const xtr_extra *outer,
                                  const unsigned char *sha,int directory){
    xtr_win_restore_plan plan;
    xtr_win_ea_list original_eas;
    xtr_win_pending backup;
    unsigned select=0;
    size_t i;
    int rc,ea_applied=0,rollback_failed=0,rr=0,failed=1;
    if(xtr_unzip_xattrs)select|=XTR_WIN_SELECT_EA;
    if(xtr_unzip_streams)select|=XTR_WIN_SELECT_ADS;
    if(!select)return 0;
    memset(&plan,0,sizeof(plan));memset(&original_eas,0,sizeof(original_eas));
    memset(&backup,0,sizeof(backup));
    rc=xtr_win_restore_plan_load(stage,length,outer,sha,select,&plan);
    if(rc!=XTR_OK)goto done;
    if(xtr_unzip_streams && directory && plan.ads_count){
        /* W3C2 currently supports named data streams on files, not on
         * directory handles; never silently discard selected streams. */
        rc=XTR_UNSUPPORTED;goto done;
    }
    /* A manifest without records of a class does not establish that class
     * was captured. Never clear unrelated destination metadata. */
    if(xtr_unzip_xattrs && plan.eas.count){
        /* NT zero-length EA writes DELETE the attribute, so even rollback
         * would be impossible when the original snapshot contains one. */
        for(i=0;i<plan.eas.count;i++)if(!plan.eas.items[i].value_len){
            rc=XTR_UNSUPPORTED;goto done;
        }
        if(xtr_unzip_streams && plan.ads_count){
            rc=xtr_win_nt_snapshot_handle(native,&original_eas);
            if(rc!=XTR_OK)goto done;
            for(i=0;i<original_eas.count;i++)
                if(!original_eas.items[i].value_len){
                    rc=XTR_UNSUPPORTED;goto done;
                }
        }
        rc=xtr_win_nt_apply_list(native,&plan.eas,&rollback_failed);
        if(rc!=XTR_OK)goto done;
        ea_applied=1;
    }
    if(xtr_unzip_streams && plan.ads_count){
        rc=xtr_secure_stage(&backup)?XTR_IO:XTR_OK;
        if(rc==XTR_OK)
            rc=xtr_win_ads_restore_exact(native,plan.ads,plan.ads_count,
                                          stage,backup.stage,&rollback_failed);
        if(rc!=XTR_OK){
            if(ea_applied){
                int ea_rollback_failed=0;
                rr=xtr_win_nt_apply_list(native,&original_eas,&ea_rollback_failed);
                if(rr!=XTR_OK || ea_rollback_failed)rollback_failed=1;
            }
            goto done;
        }
    }
    failed=0;
done:
    if(failed){
        fprintf(stderr,"unzip: Windows Xtro EA/ADS restoration failed (%d)%s\n",
                rc,rollback_failed?" (rollback incomplete)":"");
    }
    xtr_stage_destroy(&backup);
    xtr_win_ea_free(&original_eas);
    xtr_win_restore_plan_free(&plan);
    return failed;
}

static int xtr_restore_verified(min_info *info,const uch *local,
                                unsigned local_len,const char *name){
    const unsigned char *field=NULL;
    size_t length=0;
    xtr_extra outer;
    xtr_u64 encoded;
    HANDLE pin=(HANDLE)info->xtr_restore_handle;
    HANDLE native=INVALID_HANDLE_VALUE;
    xtr_win_pending inline_stage;
    FILE *stage=NULL;
    int failed=1;
    memset(&inline_stage,0,sizeof(inline_stage));
    info->xtr_restore_handle=NULL;
    if(!pin || pin==INVALID_HANDLE_VALUE || !info->xtr_central)goto done;
    if(xtr_locate(local,local_len,&field,&length)!=XTR_OK || !field ||
       xtr1_check_headers(field,length,info->xtr_central,
                         info->xtr_central_len,&outer,NULL)!=XTR_OK ||
       outer.mode!=XTR_V1_INLINE || outer.flags || outer.manifest_len.hi ||
       info->xtr_central_len<40U ||
       outer.manifest_len.lo!=info->xtr_central_len-40U)
        goto done;
    encoded=outer.manifest_len;
    /* Even public inline manifests can contain independently selectable
     * ADS data. Do not use the process-default, potentially shared temp
     * directory for metadata payloads. */
    if(xtr_secure_stage(&inline_stage))goto done;
    stage=inline_stage.stage;
    if(fwrite(info->xtr_central+40,1,(size_t)encoded.lo,stage)!=(size_t)encoded.lo ||
       fflush(stage)!=0 || fseek(stage,0,SEEK_SET)!=0)goto done;
    native=xtr_open_verified_path(name);
    if(native==INVALID_HANDLE_VALUE || !xtr_same_handle(pin,native))goto done;
    if(xtr_apply_win_metadata(native,stage,encoded,&outer,NULL,0)==0 &&
       xtr_same_handle(pin,native))failed=0;
done:
    if(failed)fprintf(stderr,"unzip: Windows inline Xtro metadata rejected: %s\n",name);
    if(native!=INVALID_HANDLE_VALUE)CloseHandle(native);
    if(pin && pin!=INVALID_HANDLE_VALUE)CloseHandle(pin);
    xtr_stage_destroy(&inline_stage);
    if(failed)xtr_restore_rejected=1;
    return failed;
}

/* Companion decoding flows through the normal UnZip decompressor, CRC,
 * password and AES authentication path, never mapname(). Only the private
 * FILE* receives plaintext. */
static int xtr_stage_begin(min_info *info,const char *name){
    unsigned char id[16];
    xtr_win_pending *p;
    unsigned long bytes;
    if(!info->xtr_companion || xtr_id_from_name(name,id) ||
       info->uncompr_size>XTR_WIN_STAGE_MAX)return 1;
    bytes=(unsigned long)info->uncompr_size;
    if(bytes>XTR_WIN_AGGREGATE-xtr_win_reserved)return 1;
    p=xtr_lookup(id,0);
    if(!p || !p->has_companion || p->stage || xtr_secure_stage(p))return 1;
    xtr_win_reserved+=bytes;
    return 0;
}
static FILE *xtr_stage_file(const char *name){
    unsigned char id[16];
    xtr_win_pending *p;
    if(xtr_id_from_name(name,id))return NULL;
    p=xtr_lookup(id,0);
    return p?p->stage:NULL;
}
static int xtr_stage_length(FILE *stage,xtr_u64 *length){
    long size;
    if(!stage || fflush(stage)!=0 || fseek(stage,0,SEEK_END)!=0)return 1;
    size=ftell(stage);
    if(size<0 || (unsigned long)size>XTR_WIN_STAGE_MAX ||
       fseek(stage,0,SEEK_SET)!=0)return 1;
    length->hi=0;length->lo=(unsigned long)size;
    return 0;
}
static int xtr_stage_end(min_info *info,const char *name){
    FILE *stage=xtr_stage_file(name);
    xtr_u64 length;
    if(!stage || xtr_stage_length(stage,&length) ||
       info->uncompr_size!=length.lo)return 1;
    return 0;
}
static void xtr_stage_verified(const char *name){
    unsigned char id[16];
    xtr_win_pending *p;
    if(xtr_id_from_name(name,id))return;
    p=xtr_lookup(id,0);
    if(p && p->stage)p->companion_verified=1;
}
static int xtr_defer_owner(min_info *info,const uch *local,
                           unsigned len,const char *name){
    const unsigned char *field=NULL;
    size_t length=0;
    unsigned char sha[32];
    xtr_extra outer;
    xtr_win_pending *p;
    HANDLE pin=(HANDLE)info->xtr_restore_handle;
    info->xtr_restore_handle=NULL;
    if(!pin || pin==INVALID_HANDLE_VALUE)return 1;
    if(xtr_locate(local,len,&field,&length)!=XTR_OK || !field ||
       xtr1_check_headers(field,length,info->xtr_central,
                 info->xtr_central_len,&outer,sha)!=XTR_OK ||
       outer.mode!=XTR_V1_COMPANION){CloseHandle(pin);return 1;}
    p=xtr_lookup(outer.owner,0);
    if(!p || !p->has_owner || p->owner_verified || p->pinned){
        CloseHandle(pin);return 1;
    }
    p->output_name=(char *)malloc(strlen(name)+1U);
    if(!p->output_name){CloseHandle(pin);return 1;}
    strcpy(p->output_name,name);
    p->pinned=pin;p->owner_verified=1;
    return 0;
}
static size_t xtr_win_stage_read(void *,unsigned char *,size_t);
static int xtr_apply_pending(int selective){
    xtr_win_pending *p;
    xtr_u64 length;
    HANDLE native;
    xtr_reader rd;
    xtr1_policy policy;
    xtr1_digest digest;
    int rc,rollback_failed;
    /* Graph, cryptographic transport, payload and destination verification
     * all precede native EA writes. Absent members are not assumed valid. */
    for(p=xtr_win_head;p;p=p->next){
        if(selective && !p->has_owner)continue;
        if(!p->has_owner || !p->has_companion || !p->companion_verified ||
           p->owner_crypto>4U ||
           p->owner_crypto!=p->companion_crypto ||
           p->owner_strength!=p->companion_strength ||
           p->owner_iterations!=p->companion_iterations ||
           (((p->outer.flags&XTR_V1_ENCRYPTED)!=0)!=(p->owner_crypto!=0)) ||
           (p->owner_crypto && p->companion_fwkcs)){
            fprintf(stderr,"unzip: Windows Xtro owner/companion association rejected\n");
            return 1;
        }
        if(!p->owner_verified)continue; /* extraction skipped or not selected */
        if(xtr_stage_length(p->stage,&length))return 1;
        memset(&policy,0,sizeof(policy));
        policy.max_records=1024U;policy.max_field=1024UL*1024UL;
        policy.max_manifest.lo=32UL*1024UL*1024UL;
        memset(&rd,0,sizeof(rd));
        rd.context=p->stage;rd.read=xtr_win_stage_read;
        rc=xtr1_check_manifest(&rd,length,&p->outer,
              (p->outer.flags&XTR_V1_ENCRYPTED)?NULL:p->sha,
              &policy,&digest);
        if(rc!=XTR_OK || !digest.schema_supported){
            fprintf(stderr,"unzip: Windows Xtro companion SHA/schema rejected\n");
            return 1;
        }
        {
            xtr_win_mixed_summary verified;
            if(xtr_win_mixed_verify(p->stage,length,&p->outer,
                 (p->outer.flags&XTR_V1_ENCRYPTED)?NULL:p->sha,
                 &verified)!=XTR_OK){
                fprintf(stderr,"unzip: Windows mixed Xtro manifest rejected\n");
                return 1;
            }
        }
        native=xtr_open_verified_path_kind(p->output_name,p->is_dir);
        if(native==INVALID_HANDLE_VALUE ||
           !xtr_same_handle_kind(p->pinned,native,p->is_dir)){
            if(native!=INVALID_HANDLE_VALUE)CloseHandle(native);
            fprintf(stderr,"unzip: Windows Xtro owner identity changed\n");
            return 1;
        }
        CloseHandle(native);
    }
    for(p=xtr_win_head;p;p=p->next){
        if(!p->owner_verified || p->is_dir)continue;
        if(xtr_stage_length(p->stage,&length))return 1;
        native=xtr_open_verified_path(p->output_name);
        if(native==INVALID_HANDLE_VALUE || !xtr_same_handle(p->pinned,native)){
            if(native!=INVALID_HANDLE_VALUE)CloseHandle(native);
            return 1;
        }
        rollback_failed=0;
        rc=xtr_apply_win_metadata(native,p->stage,length,&p->outer,
             (p->outer.flags&XTR_V1_ENCRYPTED)?NULL:p->sha,0)?XTR_IO:XTR_OK;
        if(rc==XTR_OK && !xtr_same_handle(p->pinned,native))rc=XTR_CORRUPT;
        CloseHandle(native);
        if(rc!=XTR_OK){
            fprintf(stderr,"unzip: Windows Xtro companion restoration failed (%d)%s\n",
                    rc,rollback_failed?" (rollback incomplete)":"");
            return 1;
        }
    }
    return 0;
}
static size_t xtr_win_stage_read(void *opaque,unsigned char *buf,size_t n){
    return fread(buf,1,n,(FILE *)opaque);
}
/* Run only after complete archive-level verification, and before UnZip's
 * deferred directory timestamps and permissions. The original directory
 * handle remains pinned across extraction and is matched before each write. */
static int xtr_apply_directories(void){
    xtr_win_pending *p;
    xtr_u64 length;
    HANDLE native;
    int rc,rollback_failed;
    for(p=xtr_win_head;p;p=p->next){
        if(!p->is_dir || !p->owner_verified)continue;
        if(xtr_stage_length(p->stage,&length))return 1;
        native=xtr_open_verified_path_kind(p->output_name,1);
        if(native==INVALID_HANDLE_VALUE ||
           !xtr_same_handle_kind(p->pinned,native,1)){
            if(native!=INVALID_HANDLE_VALUE)CloseHandle(native);
            fprintf(stderr,"unzip: Windows Xtro directory identity changed\n");
            return 1;
        }
        rollback_failed=0;
        rc=xtr_apply_win_metadata(native,p->stage,length,&p->outer,
             (p->outer.flags&XTR_V1_ENCRYPTED)?NULL:p->sha,1)?XTR_IO:XTR_OK;
        if(rc==XTR_OK && !xtr_same_handle_kind(p->pinned,native,1))rc=XTR_CORRUPT;
        CloseHandle(native);
        if(rc!=XTR_OK){
            fprintf(stderr,"unzip: Windows Xtro directory restoration failed (%d)%s\n",
                    rc,rollback_failed?" (rollback incomplete)":"");
            return 1;
        }
    }
    return 0;
}
#endif
