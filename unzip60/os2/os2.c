/*
  Copyright (c) 1990-2007 Info-ZIP.  All rights reserved.

  See the accompanying file LICENSE, version 2000-Apr-09 or later
  (the contents of which are also included in zip.h) for terms of use.
  If, for some reason, both of these files are missing, the Info-ZIP license
  also may be found at:  ftp://ftp.info-zip.org/pub/infozip/license.html
*/
/*---------------------------------------------------------------------------

  os2.c

  OS/2-specific routines for use with Info-ZIP's UnZip 5.1 and later.

  This file contains the OS/2 versions of the file name/attribute/time/etc
  code.  Most or all of the routines which make direct use of OS/2 system
  calls (i.e., the non-lowercase routines) are Kai Uwe Rommel's.  The read-
  dir() suite was written by Michael Rendell and ported to OS/2 by Kai Uwe;
  it is in the public domain.

  Contains:  GetCountryInfo()
             SetFileSize()
             GetFileTime()
             SetFileTime()              (TIMESTAMP only)
             stamp_file()               (TIMESTAMP only)
             Utime2DosDateTime()
             SetPathAttrTimes()
             SetEAs()
             GetLoadPath()
             opendir()
             closedir()
             readdir()
             [ seekdir() ]             not used
             [ telldir() ]             not used
             free_dircontents()
             getdirent()
             IsFileSystemFAT()
             do_wild()
             mapattr()
             mapname()
             checkdir()
             isfloppy()
             IsFileNameValid()
             map2fat()
             SetLongNameEA()
             close_outfile()
             check_for_newer()
             dateformat()
             version()
             zcalloc()                      (16-bit, only)
             zcfree()                       (16-bit, only)
             InitNLS()
             IsUpperNLS()
             ToLowerNLS()
             StringLower()
             screensize()
             DebugMalloc()

  ---------------------------------------------------------------------------*/


#define UNZIP_INTERNAL
#include "unzip.h"

/* fUnZip does not need anything from here except the zcalloc() & zcfree()
 * function pair (when Deflate64 support is enabled in 16-bit environment).
 */
#ifndef FUNZIP

#include "os2acl.h"

extern ZCONST char Far TruncEAs[];

/* The native OW2 runtime does not interpret kLIBC link EAs. The queue
 * deliberately writes them only after all selected archive contents and
 * ordinary EAs have been checked. Ordinary EAs are written first. */
#if defined(__32BIT__) && !defined(DLL)
#include "../../xtrmeta/xtros2_ea.h"
#include "../../xtrmeta/xtros2_nls.h"
#include "../../zip30/os2/os2link.h"

typedef struct iz_os2_link_pending {
    struct iz_os2_link_pending *next;
    char *path;
    unsigned char *ea;
    size_t length;
} iz_os2_link_pending;
static iz_os2_link_pending *iz_os2_links_first;
static iz_os2_link_pending *iz_os2_links_last;
static size_t iz_os2_links_count;
static int iz_os2_links_exit_registered;

static void iz_os2_links_clear(void) {
    iz_os2_link_pending *p=iz_os2_links_first,*next;
    while(p){next=p->next;free(p->path);free(p->ea);free(p);p=next;}
    iz_os2_links_first=iz_os2_links_last=NULL;
    iz_os2_links_count=0U;
}
static int iz_os2_links_enqueue(const char *name,unsigned char **bytes,
                                size_t length) {
    iz_os2_link_pending *p,*cur;
    size_t n,i;
    char native_path[CCHMAXPATH];
    xtr_os2_ea_item marker;
    size_t count=0U,link_bytes;
    const unsigned char *value;
    if(!name || !*name || !bytes || !*bytes || !length ||
       iz_os2_links_count>=65536U)return PK_ERR;
    /* Reject malformed kLIBC link metadata before it can be activated.
     * A complete FEA2LIST is not sufficient: the value must also have
     * a typed EAT_ASCII length and an embedded-NUL-free target. */
    if(xtr_os2_ea_parse_ex(*bytes,length,&marker,1,&count,
                     xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK ||
       count!=1U || marker.name_len!=7U ||
       xtr_os2_ea_native_equal(marker.name,marker.name_len,
            (const unsigned char *)"SYMLINK",7U,NULL)!=1 ||
       marker.value_len<5U || marker.value_len>1028U)return PK_ERR;
    value=marker.value;
    link_bytes=(size_t)value[2]+((size_t)value[3]<<8);
    if(value[0]!=0xfdU || value[1]!=0xffU || !link_bytes ||
       link_bytes!=marker.value_len-4U ||
       memchr(value+4U,0,link_bytes)!=NULL)return PK_ERR;
    n=strlen(name);
    if(n>=CCHMAXPATH)return PK_ERR;
    for(i=0;i<n;i++)native_path[i]=name[i]=='/'?'\\':name[i];
    native_path[n]=0;
    for(cur=iz_os2_links_first;cur;cur=cur->next){
        int equal=xtr_os2_ea_native_equal((const unsigned char *)native_path,n,
                              (const unsigned char *)cur->path,
                              strlen(cur->path),NULL);
        if(equal!=0)return PK_ERR; /* error or same path: fail closed */
    }
    p=(iz_os2_link_pending *)calloc(1,sizeof(*p));
    if(!p)return PK_MEM4;
    p->path=(char *)malloc(n+1U);
    if(!p->path){free(p);return PK_MEM4;}
    memcpy(p->path,native_path,n+1U);
    p->ea=*bytes;p->length=length;*bytes=NULL;
    if(!iz_os2_links_exit_registered){
        if(atexit(iz_os2_links_clear)!=0){
            free(p->ea);free(p->path);free(p);return PK_ERR;
        }
        iz_os2_links_exit_registered=1;
    }
    if(iz_os2_links_last)iz_os2_links_last->next=p;
    else iz_os2_links_first=p;
    iz_os2_links_last=p;
    iz_os2_links_count++;
    return PK_OK;
}
int iz_os2_link_safe_path(const char *name) {
    char prefix[CCHMAXPATH],target[1024],normalized[CCHMAXPATH];
    size_t i,n;
    int rc;
    if(!name || !*name)return 0;
    n=strlen(name);
    if(n>=sizeof(prefix))return 0;
    /* Native DosQueryPathInfo requires ordinary directory paths without
     * trailing separators. Preserve a drive root such as C:\. */
    memcpy(normalized,name,n+1U);
    while(n>1U && (normalized[n-1U]=='/' || normalized[n-1U]=='\\') &&
          !(n==3U && normalized[1U]==':'))
        normalized[--n]='\0';
    name=normalized;
    /* Drive-relative paths can depend on a mutable process drive CWD. */
    if(n>=2U && name[1]==':' &&
       (n==2U || (name[2]!='\\' && name[2]!='/')))return 0;
    for(i=0;i<=n;i++){
        int separator=(i==n || name[i]=='\\' || name[i]=='/');
        if(!separator)continue;
        /* The complete pathname must not contain a dot-dot component. */
        {size_t j=i;
         while(j>0 && name[j-1]!='\\' && name[j-1]!='/')j--;
         if(i-j==2 && name[j]=='.' && name[j+1]=='.')return 0;}
        if(i==0 || (i==2 && name[1]==':'))continue;
        if(i==n){
            rc=iz_os2_link_target(name,target,sizeof(target));
            if(rc!=0){
                if(rc>0)fprintf(stderr,
                    "unzip: OS/2 destination is a symlink: %s\n",name);
                return 0; /* preexisting symlink or query failure */
            }
        }else{
            memcpy(prefix,name,i);prefix[i]=0;
            /* Drive roots are structural, not traversable components. */
            if(i==3 && prefix[1]==':' && (prefix[2]=='\\'||prefix[2]=='/'))continue;
            rc=iz_os2_link_target(prefix,target,sizeof(target));
            if(rc!=0){
                if(rc>0)fprintf(stderr,
                    "unzip: OS/2 parent is a symlink: %s\n",prefix);
                return 0;
            }
        }
    }
    return 1;
}

/* Native Xtro restoration transaction plan. Both legacy 0x0009 lists and
 * XTRO interface-10 lists are staged and reconciled BEFORE any native EA
 * mutator runs. Native writes are only performed after archive completion.
 * This is not an archive-wide filesystem rollback transaction. */
typedef struct iz_os2_ea_pending {
    struct iz_os2_ea_pending *next;
    char *path;
    unsigned char *legacy,*xtro;
    size_t legacy_size,xtro_size;
} iz_os2_ea_pending;
static iz_os2_ea_pending *iz_os2_ea_head,*iz_os2_ea_tail;
static int iz_os2_ea_exit_registered;
static void iz_os2_ea_clear(void){
    iz_os2_ea_pending *p=iz_os2_ea_head,*next;
    while(p){
        next=p->next;
        free(p->path);
        if(p->legacy){
            xtr_os2_memory_wipe(p->legacy,p->legacy_size);free(p->legacy);
        }
        if(p->xtro){
            xtr_os2_memory_wipe(p->xtro,p->xtro_size);free(p->xtro);
        }
        free(p);p=next;
    }
    iz_os2_ea_head=iz_os2_ea_tail=NULL;
}
static iz_os2_ea_pending *iz_os2_ea_lookup(const char *path){
    iz_os2_ea_pending *p;
    size_t n,i;
    char native_path[CCHMAXPATH];
    if(!path || !*path)return NULL;
    n=strlen(path);
    if(n>=CCHMAXPATH)return NULL;
    /* ZIP directory paths may have a trailing slash; native legacy EA
     * restoration strips it. Their identities must compare identically. */
    while(n>1U && (path[n-1U]=='/' || path[n-1U]=='\\') &&
          !(n==3U && path[1]==':'))n--;
    if(!n)return NULL;
    /* Treat slash variants as the same pending destination, and pass a
     * native path to DosQueryPathInfo/DosSetPathInfo/DosOpen on commit. */
    for(i=0;i<n;i++)
        native_path[i]=path[i]=='/'?'\\':path[i];
    native_path[n]=0;
    for(p=iz_os2_ea_head;p;p=p->next){
        int eq=xtr_os2_ea_native_equal((const unsigned char *)native_path,n,
            (const unsigned char *)p->path,strlen(p->path),NULL);
        if(eq<0)return NULL;
        if(eq)return p;
    }
    p=(iz_os2_ea_pending *)calloc(1,sizeof(*p));
    if(!p)return NULL;
    p->path=(char *)malloc(n+1U);
    if(!p->path){free(p);return NULL;}
    memcpy(p->path,native_path,n+1U);
    if(!iz_os2_ea_exit_registered){
        if(atexit(iz_os2_ea_clear)!=0){free(p->path);free(p);return NULL;}
        iz_os2_ea_exit_registered=1;
    }
    if(iz_os2_ea_tail)iz_os2_ea_tail->next=p;
    else iz_os2_ea_head=p;
    iz_os2_ea_tail=p;
    return p;
}
static int iz_os2_stage_ea(const char *path,const unsigned char *raw,
                           size_t length,int legacy){
    iz_os2_ea_pending *p;
    unsigned char *copy;
    size_t n=0;
    if(!raw || length<4U || length>16UL*1024UL*1024UL ||
       xtr_os2_ea_parse_ex(raw,length,NULL,0,&n,
                xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK){
        fprintf(stderr,"unzip: OS/2 invalid %s EA data for %s\n",
            legacy?"legacy":"Xtro",path?path:"(null)");
        return PK_ERR;
    }
    p=iz_os2_ea_lookup(path);
    if(!p){
        fprintf(stderr,"unzip: OS/2 cannot register %s EA destination: %s\n",
            legacy?"legacy":"Xtro",path?path:"(null)");
        return PK_ERR;
    }
    if(legacy?p->legacy:p->xtro){
        fprintf(stderr,"unzip: OS/2 duplicate %s EA stage: %s\n",
            legacy?"legacy":"Xtro",path);
        return PK_ERR;
    }
    copy=(unsigned char *)malloc(length);
    if(!copy){
        fprintf(stderr,"unzip: OS/2 cannot allocate %s EA stage: %s\n",
            legacy?"legacy":"Xtro",path);
        return PK_MEM4;
    }
    memcpy(copy,raw,length);
    if(legacy){p->legacy=copy;p->legacy_size=length;}
    else{p->xtro=copy;p->xtro_size=length;}
    return PK_OK;
}
int iz_os2_xtr_stage_legacy(const char *path,const unsigned char *raw,
                            size_t length){
    return iz_os2_stage_ea(path,raw,length,1);
}
int iz_os2_xtr_stage_native(const char *path,const unsigned char *raw,
                            size_t length){
    return iz_os2_stage_ea(path,raw,length,0);
}
static int iz_os2_ea_merge(iz_os2_ea_pending *p,
                           unsigned char **output,size_t *length){
    xtr_os2_ea_item *a=NULL,*b=NULL,*joined=NULL;
    size_t na=0,nb=0,ka=0,kb=0,i,j,n=0;
    int rc=PK_ERR;
    *output=NULL;*length=0U;
    if(p->legacy && xtr_os2_ea_parse_ex(p->legacy,p->legacy_size,NULL,0,&na,
                   xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK)goto finish;
    if(p->xtro && xtr_os2_ea_parse_ex(p->xtro,p->xtro_size,NULL,0,&nb,
                   xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK)goto finish;
    if(na>(size_t)-1/sizeof(*a) || nb>(size_t)-1/sizeof(*b) ||
       na>(size_t)-1-nb)goto finish;
    if(na){
        a=(xtr_os2_ea_item *)malloc(na*sizeof(*a));if(!a)goto finish;
        if(xtr_os2_ea_parse_ex(p->legacy,p->legacy_size,a,na,&ka,
                    xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK || ka!=na)
            goto finish;
    }
    if(nb){
        b=(xtr_os2_ea_item *)malloc(nb*sizeof(*b));if(!b)goto finish;
        if(xtr_os2_ea_parse_ex(p->xtro,p->xtro_size,b,nb,&kb,
                    xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK || kb!=nb)
            goto finish;
    }
    if(xtr_os2_ea_reconcile_ex(a,na,b,nb,xtr_os2_ea_native_equal,NULL)
                                      !=XTR_OS2_EA_OK)goto finish;
    joined=(xtr_os2_ea_item *)malloc((na+nb?na+nb:1U)*sizeof(*joined));
    if(!joined)goto finish;
    if(na)memcpy(joined,a,na*sizeof(*a));n=na;
    for(j=0;j<nb;j++){
        for(i=0;i<na;i++){
            int equal=xtr_os2_ea_native_equal(a[i].name,a[i].name_len,
                                             b[j].name,b[j].name_len,NULL);
            if(equal<0)goto finish;
            if(equal)break;
        }
        if(i==na)joined[n++]=b[j];
    }
    if(xtr_os2_ea_pack_list(joined,n,output,length,
                     xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK)goto finish;
    rc=PK_OK;
finish:
    free(a);free(b);free(joined);
    if(rc!=PK_OK){free(*output);*output=NULL;*length=0;}
    return rc;
}
/* OS/2 does not provide openat2-style descendant locking. For ordinary
 * files use a pinned HFILE; for directories, native DosSetPathInfo is
 * preceded by parent-component checks immediately before mutation. */
static int iz_os2_ea_apply(const char *path,unsigned char *list,size_t len){
    xtr_os2_ea_partition parts;
    int err=PK_OK;
    APIRET rc;
    FILESTATUS3 st;
    EAOP2 ea;
    if(!list || !len)return PK_OK;
    if(!iz_os2_link_safe_path(path)){
        fprintf(stderr,"unzip: OS/2 unsafe or unqueryable EA destination: %s\n",path);
        return PK_ERR;
    }
    if(xtr_os2_ea_partition_list(list,len,&parts,
        xtr_os2_ea_native_equal,NULL)!=XTR_OS2_EA_OK){
        fprintf(stderr,"unzip: OS/2 cannot partition native EAs: %s\n",path);
        return PK_ERR;
    }
    rc=DosQueryPathInfo((PSZ)path,FIL_STANDARD,&st,sizeof(st));
    if(rc!=NO_ERROR){
        fprintf(stderr,"unzip: OS/2 EA DosQueryPathInfo rc=%lu: %s\n",
            (unsigned long)rc,path);
        err=PK_ERR;goto cleanup;
    }
    if(parts.ordinary){
        ea.fpGEA2List=NULL;ea.fpFEA2List=(PFEA2LIST)parts.ordinary;
        ea.oError=0;
        if(st.attrFile&FILE_DIRECTORY){
            if(!iz_os2_link_safe_path(path)){
                fprintf(stderr,"unzip: OS/2 EA destination became unsafe: %s\n",path);
                err=PK_ERR;
            }else{
                rc=DosSetPathInfo((PSZ)path,FIL_QUERYEASIZE,
                             &ea,sizeof(ea),0);
                if(rc!=NO_ERROR){
                    fprintf(stderr,"unzip: OS/2 EA DosSetPathInfo rc=%lu: %s\n",
                        (unsigned long)rc,path);
                    err=PK_ERR;
                }
            }
        }else{
            HFILE h;
            ULONG action=0;
            rc=DosOpen((PSZ)path,&h,&action,0,FILE_NORMAL,
                OPEN_ACTION_OPEN_IF_EXISTS|OPEN_ACTION_FAIL_IF_NEW,
                OPEN_ACCESS_READWRITE|OPEN_SHARE_DENYWRITE,NULL);
            if(rc!=NO_ERROR){
                fprintf(stderr,"unzip: OS/2 EA DosOpen rc=%lu: %s\n",
                    (unsigned long)rc,path);
                err=PK_ERR;
            }
            else{
                rc=DosSetFileInfo(h,FIL_QUERYEASIZE,&ea,sizeof(ea));
                if(rc!=NO_ERROR){
                    fprintf(stderr,"unzip: OS/2 EA DosSetFileInfo rc=%lu: %s\n",
                        (unsigned long)rc,path);
                    err=PK_ERR;
                }
                rc=DosClose(h);
                if(rc!=NO_ERROR){
                    fprintf(stderr,"unzip: OS/2 EA DosClose rc=%lu: %s\n",
                        (unsigned long)rc,path);
                    err=PK_ERR;
                }
            }
        }
    }
    if(err==PK_OK && parts.symlink){
        err=iz_os2_links_enqueue(path,&parts.symlink,parts.symlink_len);
    }
cleanup:
    xtr_os2_ea_partition_free(&parts);
    return err;
}
int iz_os2_xtr_ea_complete(int success){
    iz_os2_ea_pending *p;
    int rc=PK_OK;
    if(!success){iz_os2_ea_clear();return PK_OK;}
    /* Pass 1: validate full source union, conflicts, and destination paths
     * before changing even one native attribute. */
    for(p=iz_os2_ea_head;p;p=p->next){
        unsigned char *list=NULL;size_t length=0;
        if(iz_os2_ea_merge(p,&list,&length)!=PK_OK){
            fprintf(stderr,"unzip: OS/2 legacy/Xtro EA conflict or invalid data: %s\n",
                p->path);
            rc=PK_ERR;
        }else if(!iz_os2_link_safe_path(p->path)){
            fprintf(stderr,"unzip: OS/2 unsafe or unqueryable EA destination: %s\n",
                p->path);
            rc=PK_ERR;
        }
        if(list){xtr_os2_memory_wipe(list,length);free(list);}
        if(rc!=PK_OK)break;
    }
    if(rc==PK_OK){
        for(p=iz_os2_ea_head;p;p=p->next){
            unsigned char *list=NULL;size_t length=0;
            if(iz_os2_ea_merge(p,&list,&length)!=PK_OK){
                fprintf(stderr,"unzip: OS/2 EA merge failed during commit: %s\n",
                    p->path);
                rc=PK_ERR;break;
            }
            rc=iz_os2_ea_apply(p->path,list,length);
            if(list){xtr_os2_memory_wipe(list,length);free(list);}
            if(rc!=PK_OK)break;
        }
    }
    if(rc!=PK_OK)fprintf(stderr,
       "unzip: OS/2 Xtro native EA restoration incomplete; no filesystem rollback\n");
    iz_os2_ea_clear();
    return rc;
}

int iz_os2_deferred_links_complete(int success) {
    iz_os2_link_pending *p;
    int result=PK_OK;
    if(!success){iz_os2_links_clear();return PK_OK;}
    /* Preflight the entire destination list before activating any links. */
    for(p=iz_os2_links_first;p;p=p->next)
        if(!iz_os2_link_safe_path(p->path)){
            fprintf(stderr,"unzip: unsafe deferred OS/2 symlink destination: %s\n",p->path);
            iz_os2_links_clear();return PK_ERR;
        }
    for(p=iz_os2_links_first;p;p=p->next){
        HFILE h;
        ULONG action=0;
        APIRET rc;
        EAOP2 op;
        if(!iz_os2_link_safe_path(p->path)){result=PK_ERR;break;}
        rc=DosOpen((PSZ)p->path,&h,&action,0,FILE_NORMAL,
                   OPEN_ACTION_OPEN_IF_EXISTS|OPEN_ACTION_FAIL_IF_NEW,
                   OPEN_ACCESS_READWRITE|OPEN_SHARE_DENYWRITE,NULL);
        if(rc!=NO_ERROR){result=PK_ERR;break;}
        op.fpGEA2List=NULL;op.fpFEA2List=(PFEA2LIST)p->ea;op.oError=0;
        rc=DosSetFileInfo(h,FIL_QUERYEASIZE,&op,sizeof(op));
        if(DosClose(h)!=NO_ERROR)result=PK_ERR;
        if(rc!=NO_ERROR){
            fprintf(stderr,"unzip: DosSetFileInfo failed for %s (rc=%lu)\n",
                    p->path,(unsigned long)rc);
            result=PK_ERR;break;
        }
    }
    if(result!=PK_OK)fprintf(stderr,
       "unzip: deferred OS/2 SYMLINK EA restoration incomplete (no archive-wide rollback)\n");
    iz_os2_links_clear();
    return result;
}
#endif /* __32BIT__ && !DLL */


/* local prototypes */

#ifdef TIMESTAMP
  static int SetFileTime(ZCONST char *name, ulg stamp);
#endif
#if defined(USE_EF_UT_TIME) || defined(TIMESTAMP)
  static ulg Utime2DosDateTime  OF((time_t uxtime));
#endif
static int   getOS2filetimes    OF((__GPRO__
                                    ulg *pM_dt, ulg *pA_dt, ulg *pC_dt));
static void  SetPathAttrTimes   OF((__GPRO__ int flags, int dir));
static int   SetEAs             OF((__GPRO__ const char *path,
                                    void *ef_block));
static int   SetACL             OF((__GPRO__ const char *path,
                                    void *ef_block));
static int   EvalExtraFields    OF((__GPRO__ const char *path,
                                    void *extra_field, unsigned ef_len));
static int   isfloppy           OF((int nDrive));
static int   IsFileNameValid    OF((const char *name));
static void  map2fat            OF((char *pathcomp, char **pEndFAT));
static int   SetLongNameEA      OF((char *name, char *longname));
static void  InitNLS            OF((void));


#ifdef ACORN_FTYPE_NFS
/* Acorn bits for NFS filetyping */
typedef struct {
  uch ID[2];
  uch size[2];
  uch ID_2[4];
  uch loadaddr[4];
  uch execaddr[4];
  uch attr[4];
} RO_extra_block;

#endif /* ACORN_FTYPE_NFS */


/*****************************/
/*  Strings used in os2.c  */
/*****************************/

#ifndef SFX
  static ZCONST char Far CantAllocateWildcard[] =
    "warning:  cannot allocate wildcard buffers\n";
#endif
static ZCONST char Far WarnDirTraversSkip[] =
  "warning:  skipped \"../\" path component(s) in %s\n";
static ZCONST char Far Creating[] = "   creating: %-22s ";
static ZCONST char Far ConversionFailed[] =
  "mapname:  conversion of %s failed\n";
static ZCONST char Far Labelling[] = "labelling %c: %-22s\n";
static ZCONST char Far ErrSetVolLabel[] =
  "mapname:  error setting volume label\n";
static ZCONST char Far PathTooLong[] = "checkdir error:  path too long: %s\n";
static ZCONST char Far CantCreateDir[] = "checkdir error:  cannot create %s\n\
                 unable to process %s.\n";
static ZCONST char Far DirIsntDirectory[] =
  "checkdir error:  %s exists but is not directory\n\
                 unable to process %s.\n";
static ZCONST char Far PathTooLongTrunc[] =
  "checkdir warning:  path too long; truncating\n                   %s\n\
                -> %s\n";
#if (!defined(SFX) || defined(SFX_EXDIR))
   static ZCONST char Far CantCreateExtractDir[] =
     "checkdir:  cannot create extraction directory: %s\n";
#endif

#ifndef __GNUC__
   /* all supported non-gcc compilers provide MSC/DOS style mkdir() */
#  if (_MSC_VER >= 600) || defined(__IBMC__)
#    include <direct.h>          /* have special MSC/IBM C mkdir prototype */
#  else                          /* own prototype because dir.h conflicts? */
     int mkdir(const char *path);
#  endif
#  define MKDIR(path,mode)   mkdir(path)
#else
    /* EMX and hopefully all other gcc ports support POSIX style mkdir() */
#  define MKDIR(path,mode)   mkdir(path,mode)
#endif


#ifdef __32BIT__

USHORT DosDevIOCtl32(PVOID pData, USHORT cbData, PVOID pParms, USHORT cbParms,
                     USHORT usFunction, USHORT usCategory, HFILE hDevice)
{
  ULONG ulParmLengthInOut = cbParms, ulDataLengthInOut = cbData;
  return (USHORT) DosDevIOCtl(hDevice, usCategory, usFunction,
                              pParms, cbParms, &ulParmLengthInOut,
                              pData, cbData, &ulDataLengthInOut);
}

#  define DosDevIOCtl DosDevIOCtl32
#else
#  define DosDevIOCtl DosDevIOCtl2
#endif


typedef struct
{
  ush nID;
  ush nSize;
  ulg lSize;
}
EFHEADER, *PEFHEADER;


#ifdef __32BIT__

#define DosFindFirst(p1, p2, p3, p4, p5, p6) \
        DosFindFirst(p1, p2, p3, p4, p5, p6, 1)

#else

typedef struct
{
  ULONG oNextEntryOffset;
  BYTE fEA;
  BYTE cbName;
  USHORT cbValue;
  CHAR szName[1];
}
FEA2, *PFEA2;

typedef struct
{
  ULONG cbList;
  FEA2 list[1];
}
FEA2LIST, *PFEA2LIST;

#define DosQueryCurrentDisk DosQCurDisk
#define DosQueryFSAttach(p1, p2, p3, p4, p5) \
        DosQFSAttach(p1, p2, p3, p4, p5, 0)
#define DosEnumAttribute(p1, p2, p3, p4, p5, p6, p7) \
        DosEnumAttribute(p1, p2, p3, p4, p5, p6, p7, 0)
#define DosFindFirst(p1, p2, p3, p4, p5, p6) \
        DosFindFirst(p1, p2, p3, p4, p5, p6, 0)
#define DosMapCase DosCaseMap
#define DosSetPathInfo(p1, p2, p3, p4, p5) \
        DosSetPathInfo(p1, p2, p3, p4, p5, 0)
#define DosQueryPathInfo(p1, p2, p3, p4) \
        DosQPathInfo(p1, p2, p3, p4, 0)
#define DosQueryFileInfo DosQFileInfo
#define DosMapCase DosCaseMap
#define DosQueryCtryInfo DosGetCtryInfo

#endif /* !__32BIT__ */





/*
 * @(#) dir.h 1.4 87/11/06   Public Domain.
 */

#define A_RONLY    0x01
#define A_HIDDEN   0x02
#define A_SYSTEM   0x04
#define A_LABEL    0x08
#define A_DIR      0x10
#define A_ARCHIVE  0x20


const int attributes = A_DIR | A_HIDDEN | A_SYSTEM;


extern DIR *opendir(__GPRO__ ZCONST char *);
extern struct direct *readdir(__GPRO__ DIR *);
extern void seekdir(DIR *, long);
extern long telldir(DIR *);
extern void closedir(DIR *);
#define rewinddir(dirp) seekdir(dirp, 0L)

int IsFileSystemFAT(__GPRO__ ZCONST char *dir);
char *StringLower(char *szArg);




/*
 * @(#)dir.c 1.4 87/11/06 Public Domain.
 */


#ifndef S_IFMT
#  define S_IFMT 0xF000
#endif


#ifndef SFX
   static char *getdirent(__GPRO__ ZCONST char *);
   static void free_dircontents(struct _dircontents *);
#endif /* !SFX */




int GetCountryInfo(void)
{
    COUNTRYINFO ctryi;
    COUNTRYCODE ctryc;
#ifdef __32BIT__
    ULONG cbInfo;
#else
    USHORT cbInfo;
#endif

  ctryc.country = ctryc.codepage = 0;

  if ( DosQueryCtryInfo(sizeof(ctryi), &ctryc, &ctryi, &cbInfo) != NO_ERROR )
    return 0;

  return ctryi.fsDateFmt;
}


int SetFileSize(FILE *file, ulg filesize)
{
#ifdef __32BIT__
  return DosSetFileSize(fileno(file), (size_t)filesize) ? -1 : 0;
#else
  return 0;
#endif
}


long GetFileTime(ZCONST char *name)
{
#ifdef __32BIT__
  FILESTATUS3 fs;
#else
  FILESTATUS fs;
#endif
  USHORT nDate, nTime;

  if ( DosQueryPathInfo((PSZ) name, 1, (PBYTE) &fs, sizeof(fs)) )
    return -1;

  nDate = * (USHORT *) &fs.fdateLastWrite;
  nTime = * (USHORT *) &fs.ftimeLastWrite;

  return ((ULONG) nDate) << 16 | nTime;
}


#ifdef TIMESTAMP

static int SetFileTime(ZCONST char *name, ulg stamp)   /* swiped from Zip */
{
#ifdef __32BIT__
  FILESTATUS3 fs;
#else
  FILESTATUS fs;
#endif
  USHORT fd, ft;

  if (DosQueryPathInfo((PSZ) name, FIL_STANDARD, (PBYTE) &fs, sizeof(fs)))
    return -1;

  fd = (USHORT) (stamp >> 16);
  ft = (USHORT) stamp;
  fs.fdateLastWrite = fs.fdateCreation = * (FDATE *) &fd;
  fs.ftimeLastWrite = fs.ftimeCreation = * (FTIME *) &ft;

  if (DosSetPathInfo((PSZ) name, FIL_STANDARD, (PBYTE) &fs, sizeof(fs), 0))
    return -1;

  return 0;
}


int stamp_file(ZCONST char *fname, time_t modtime)
{
    return SetFileTime(fname, Utime2DosDateTime(modtime));
}

#endif /* TIMESTAMP */


/* The following DOS date/time structures are machine-dependent as they
 * assume "little-endian" byte order.  For OS/2-specific code, which
 * is run on x86 CPUs (or emulators?), this assumption is valid; but
 * care should be taken when using this code as template for other ports.
 */
typedef union {
  ULONG timevalue;          /* combined value, useful for comparisons */
  struct {
    FTIME ft;               /* system file time record:
                             *    USHORT twosecs : 5
                             *    USHORT minutes : 6;
                             *    USHORT hours   : 5;   */
    FDATE fd;               /* system file date record:
                             *    USHORT day     : 5
                             *    USHORT month   : 4;
                             *    USHORT year    : 7;   */
  } _fdt;
} F_DATE_TIME, *PF_DATE_TIME;


#if defined(USE_EF_UT_TIME) || defined(TIMESTAMP)

static ulg Utime2DosDateTime(uxtime)
    time_t uxtime;
{
    F_DATE_TIME dosfiletime;
    struct tm *t;

    /* round up to even seconds */
    /* round up (down if "up" overflows) to even seconds */
    if (((ulg)uxtime) & 1)
        uxtime = (uxtime + 1 > uxtime) ? uxtime + 1 : uxtime - 1;

    t = localtime(&(uxtime));
    if (t == (struct tm *)NULL) {
        /* time conversion error; use current time instead, hoping
           that localtime() does not reject it as well! */
        time_t now = time(NULL);
        t = localtime(&now);
    }
    if (t->tm_year < 80) {
        dosfiletime._fdt.ft.twosecs = 0;
        dosfiletime._fdt.ft.minutes = 0;
        dosfiletime._fdt.ft.hours   = 0;
        dosfiletime._fdt.fd.day     = 1;
        dosfiletime._fdt.fd.month   = 1;
        dosfiletime._fdt.fd.year    = 0;
    } else {
        dosfiletime._fdt.ft.twosecs = t->tm_sec >> 1;
        dosfiletime._fdt.ft.minutes = t->tm_min;
        dosfiletime._fdt.ft.hours   = t->tm_hour;
        dosfiletime._fdt.fd.day     = t->tm_mday;
        dosfiletime._fdt.fd.month   = t->tm_mon + 1;
        dosfiletime._fdt.fd.year    = t->tm_year - 80;
    }
    return dosfiletime.timevalue;

} /* end function Utime2DosDateTime() */

#endif /* USE_EF_UT_TIME || TIMESTAMP */


static int getOS2filetimes(__GPRO__ ulg *pM_dt, ulg *pA_dt, ulg *pC_dt)
{
#ifdef USE_EF_UT_TIME
    unsigned eb_izux_flg;
    iztimes z_utime;
#endif

    /* Copy and/or convert time and date variables, if necessary;   */
    /* return a flag indicating which time stamps are available.    */
#ifdef USE_EF_UT_TIME
    if (G.extra_field &&
#ifdef IZ_CHECK_TZ
        G.tz_is_valid &&
#endif
        ((eb_izux_flg = ef_scan_for_izux(G.extra_field,
          G.lrec.extra_field_length, 0, G.lrec.last_mod_dos_datetime,
          &z_utime, NULL)) & EB_UT_FL_MTIME))
    {
        TTrace((stderr, "getOS2filetimes: UT e.f. modif. time = %lu\n",
                z_utime.mtime));
        *pM_dt = Utime2DosDateTime(z_utime.mtime);
        if (eb_izux_flg & EB_UT_FL_ATIME) {
            TTrace((stderr, "getOS2filetimes: UT e.f. access time = %lu\n",
                    z_utime.atime));
            *pA_dt = Utime2DosDateTime(z_utime.atime);
        }
        if (eb_izux_flg & EB_UT_FL_CTIME) {
            TTrace((stderr, "getOS2filetimes: UT e.f. creation time = %lu\n",
                    z_utime.ctime));
            *pC_dt = Utime2DosDateTime(z_utime.ctime);
        } else {
            /* no creation time value supplied, set it to modification time */
            *pC_dt = *pM_dt;
            eb_izux_flg |= EB_UT_FL_CTIME;
        }
        return (int)eb_izux_flg;
    }
#endif /* USE_EF_UT_TIME */
    *pC_dt = *pM_dt = G.lrec.last_mod_dos_datetime;
    TTrace((stderr, "\ngetOS2filetimes: DOS dir modific./creation time = %lu\n",
            *pM_dt));
    return (EB_UT_FL_MTIME | EB_UT_FL_CTIME);
}


static void SetPathAttrTimes(__GPRO__ int flags, int dir)
{
  HFILE hFile;
#ifdef __32BIT__
  ULONG nAction;
#else
  USHORT nAction;
#endif
#ifdef __32BIT__
  FILESTATUS3 fs;
#else
  FILESTATUS fs;
#endif
  USHORT nLength;
  char szName[CCHMAXPATH];
  ulg Mod_dt, Acc_dt, Cre_dt;
  int gotTimes;

  strcpy(szName, G.filename);
  nLength = strlen(szName);
  if (szName[nLength - 1] == '/')
    szName[nLength - 1] = 0;

  if (dir)
  {
    if ( DosQueryPathInfo(szName, FIL_STANDARD, (PBYTE) &fs, sizeof(fs)) )
      return;
  }
  else
  {
    /* for regular files, open them and operate on the file handle, to
       work around certain network operating system bugs ... */

    if ( DosOpen(szName, &hFile, &nAction, 0, 0,
                 OPEN_ACTION_OPEN_IF_EXISTS | OPEN_ACTION_FAIL_IF_NEW,
                 OPEN_SHARE_DENYREADWRITE | OPEN_ACCESS_READWRITE, 0) )
      return;

    if ( DosQueryFileInfo(hFile, FIL_STANDARD, (PBYTE) &fs, sizeof(fs)) )
      return;
  }

  if (uO.D_flag <= (dir ? 1 : 0)) {
    /* set date/time stamps */
    gotTimes = getOS2filetimes(__G__ &Mod_dt, &Acc_dt, &Cre_dt);
    if (gotTimes & EB_UT_FL_MTIME) {
      fs.fdateLastWrite = ((F_DATE_TIME *)&Mod_dt)->_fdt.fd;
      fs.ftimeLastWrite = ((F_DATE_TIME *)&Mod_dt)->_fdt.ft;
    }
    if (gotTimes & EB_UT_FL_ATIME) {
      fs.fdateLastAccess = ((F_DATE_TIME *)&Acc_dt)->_fdt.fd;
      fs.ftimeLastAccess = ((F_DATE_TIME *)&Acc_dt)->_fdt.ft;
    }
    if (gotTimes & EB_UT_FL_CTIME) {
      fs.fdateCreation = ((F_DATE_TIME *)&Cre_dt)->_fdt.fd;
      fs.ftimeCreation = ((F_DATE_TIME *)&Cre_dt)->_fdt.ft;
    }
  }

  if ( flags != -1 )
    fs.attrFile = flags; /* hidden, system, archive, read-only */

  if (dir)
  {
    DosSetPathInfo(szName, FIL_STANDARD, (PBYTE) &fs, sizeof(fs), 0);
  }
  else
  {
    DosSetFileInfo(hFile, FIL_STANDARD, (PBYTE) &fs, sizeof(fs));
    DosClose(hFile);
  }
}


typedef struct
{
  ULONG cbList;               /* length of value + 22 */
#ifdef __32BIT__
  ULONG oNext;
#endif
  BYTE fEA;                   /* 0 */
  BYTE cbName;                /* length of ".LONGNAME" = 9 */
  USHORT cbValue;             /* length of value + 4 */
  BYTE szName[10];            /* ".LONGNAME" */
  USHORT eaType;              /* 0xFFFD for length-preceded ASCII */
  USHORT eaSize;              /* length of value */
  BYTE szValue[CCHMAXPATH];
}
FEALST;


/* Validate the entire untrusted FEA2LIST before calling DosSetPathInfo.
 * Native OS/2 writes may otherwise accept a partial or malformed set.
 * In particular, a malformed SYMLINK value must never activate a link. */
#ifdef __32BIT__
static int iz_os2_ea_nameeq(const unsigned char *p,const char *s,unsigned n)
{
  unsigned i;
  for(i=0;i<n;i++)
    if(toupper((unsigned char)p[i])!=toupper((unsigned char)s[i]))return 0;
  return s[n]=='\0';
}
static int iz_os2_validate_eas(const unsigned char *bytes,unsigned long length)
{
  unsigned long at=4,prev,offset,need,j,next;
  unsigned name_len,value_len;
  const unsigned char *name,*value;
  if(length<4 || length>1024UL*1024UL ||
     (unsigned long)bytes[0]+((unsigned long)bytes[1]<<8)+
     ((unsigned long)bytes[2]<<16)+((unsigned long)bytes[3]<<24)!=length)
    return 0;
  while(at<length){
    if(length-at<9)return 0;
    offset=(unsigned long)bytes[at] |
           ((unsigned long)bytes[at+1]<<8) |
           ((unsigned long)bytes[at+2]<<16) |
           ((unsigned long)bytes[at+3]<<24);
    name_len=(unsigned)bytes[at+5];
    value_len=(unsigned)bytes[at+6] | ((unsigned)bytes[at+7]<<8);
    need=8UL+(unsigned long)name_len+1UL+(unsigned long)value_len;
    if(!name_len || need>length-at || bytes[at+8+name_len]!=0 ||
       memchr(bytes+at+8,0,name_len)!=NULL ||
       (bytes[at+4] & ~0x80U))return 0;
    name=bytes+at+8;
    value=name+name_len+1;
    /* OS/2 EA names are case insensitive. Reject ambiguous duplicates. */
    for(prev=4;prev<at;){
      unsigned pn=(unsigned)bytes[prev+5];
      unsigned k;
      if(pn==name_len){
        for(k=0;k<name_len;k++)
          if(toupper((unsigned char)bytes[prev+8+k])!=
             toupper((unsigned char)name[k]))break;
        if(k==name_len)return 0;
      }
      next=(unsigned long)bytes[prev] |
           ((unsigned long)bytes[prev+1]<<8) |
           ((unsigned long)bytes[prev+2]<<16) |
           ((unsigned long)bytes[prev+3]<<24);
      if(next==0 || next>at-prev)return 0;
      prev+=next;
    }
    if(name_len==7 && iz_os2_ea_nameeq(name,"SYMLINK",7)){
      if(value_len<5 || value[0]!=0xfdU || value[1]!=0xffU)return 0;
      j=(unsigned)value[2]+((unsigned)value[3]<<8);
      if(j==0 || j!=value_len-4U || !value[4] ||
         memchr(value+4,0,(size_t)j)!=NULL)return 0;
    }
    if(offset==0){
      /* Last FEA2 record may end before up to 3 padding bytes. */
      if(length-at-need>3U)return 0;
      for(j=(unsigned)(at+need);j<length;j++)if(bytes[j]!=0)return 0;
      return 1;
    }
    if(offset<need || (offset&3U) || offset>length-at)return 0;
    at+=offset;
  }
  return 0;
}
#endif

static int SetEAs(__GPRO__ const char *path, void *ef_block)
{                                               /* returns almost-PK errors */
  EFHEADER *pEAblock = (PEFHEADER) ef_block;
#ifdef __32BIT__
  EAOP2 eaop;
  PFEA2LIST pFEA2list;
#ifndef DLL
  xtr_os2_ea_partition parts;
  int parts_rc;
#endif
#else
  EAOP eaop;
  PFEALIST pFEAlist;
  PFEA pFEA;
  PFEA2LIST pFEA2list;
  PFEA2 pFEA2;
  ULONG nLength2;
#endif
  USHORT nLength;
  char szName[CCHMAXPATH];
  int error;

  if ( ef_block == NULL || pEAblock -> nID != EF_OS2 )
    return PK_OK;  /* not an OS/2 extra field:  assume OK */

  if ( pEAblock->nSize < 4 || (pEAblock->lSize > 0L && pEAblock->nSize <= 10) )
    return IZ_EF_TRUNC;  /* no compressed data! */

  if (!path || strlen(path)>=sizeof(szName) || !*path)return PK_ERR;
  strcpy(szName, path);
  nLength = strlen(szName);
  if (szName[nLength - 1] == '/')
    szName[nLength - 1] = 0;

  if (pEAblock->lSize < 4UL || pEAblock->lSize > 1024UL*1024UL)
    return PK_ERR;
  if ( (pFEA2list = (PFEA2LIST) malloc((size_t) pEAblock -> lSize)) == NULL )
    return PK_MEM4;

  if ( (error = memextract(__G__ (uch *)pFEA2list, pEAblock->lSize,
       (uch *)(pEAblock+1), (ulg)(pEAblock->nSize - 4))) != PK_OK )
  {
    free(pFEA2list);
    return error;
  }

#ifdef __32BIT__
  if(!iz_os2_validate_eas((const unsigned char *)pFEA2list,
                           pEAblock->lSize)){
    free(pFEA2list);
    return PK_ERR;
  }
#ifndef DLL
#ifdef XTR_OS2_NATIVE
  /* Under --xattrs the legacy OS/2 EA data must not be applied before
   * the archive-wide Xtro graph, digests and conflict checks finish. */
  {
    extern int xtr_unzip_xattrs;
    if(xtr_unzip_xattrs){
      int deferred=iz_os2_xtr_stage_legacy(szName,
                   (const unsigned char *)pFEA2list,
                   (size_t)pEAblock->lSize);
      free(pFEA2list);
      return deferred;
    }
  }
#endif
  /* Validate/split before mutation; malformed link metadata fails closed.
   * Only the SYMLINK marker is deferred. Ordinary EAs apply now. */
  parts_rc=xtr_os2_ea_partition_list((const unsigned char *)pFEA2list,
                 (size_t)pEAblock->lSize,&parts,
                 xtr_os2_ea_native_equal,NULL);
  if(parts_rc!=XTR_OS2_EA_OK){free(pFEA2list);return PK_ERR;}
  if(parts.ordinary){
    eaop.fpGEA2List=NULL;eaop.fpFEA2List=(PFEA2LIST)parts.ordinary;
    eaop.oError=0;
    if(DosSetPathInfo(szName,FIL_QUERYEASIZE,(PBYTE)&eaop,sizeof(eaop),0)!=NO_ERROR){
      xtr_os2_ea_partition_free(&parts);free(pFEA2list);return PK_ERR;
    }
  }
  if(parts.symlink){
    int q=iz_os2_links_enqueue(szName,&parts.symlink,parts.symlink_len);
    if(q!=PK_OK){xtr_os2_ea_partition_free(&parts);free(pFEA2list);return q;}
  }
  xtr_os2_ea_partition_free(&parts);
  if(!uO.tflag && QCOND2)
    Info(slide,0,((char *)slide," (%ld bytes EAs)",pFEA2list->cbList));
  free(pFEA2list);
  return PK_COOL;
#else
  eaop.fpGEA2List = NULL;
  eaop.fpFEA2List = pFEA2list;
#endif
#else
  pFEAlist  = (PVOID) pFEA2list;
  pFEA2 = pFEA2list -> list;
  pFEA  = pFEAlist  -> list;

  do
  {
    nLength2 = pFEA2 -> oNextEntryOffset;
    nLength = sizeof(FEA) + pFEA2 -> cbName + 1 + pFEA2 -> cbValue;

    memcpy(pFEA, (PCH) pFEA2 + sizeof(pFEA2 -> oNextEntryOffset), nLength);

    pFEA2 = (PFEA2) ((PCH) pFEA2 + nLength2);
    pFEA = (PFEA) ((PCH) pFEA + nLength);
  }
  while ( nLength2 != 0 );

  pFEAlist -> cbList = (PCH) pFEA - (PCH) pFEAlist;

  eaop.fpGEAList = NULL;
  eaop.fpFEAList = pFEAlist;
#endif

  eaop.oError = 0;
  {
    APIRET api_rc=DosSetPathInfo(szName,FIL_QUERYEASIZE,
                                 (PBYTE)&eaop,sizeof(eaop),0);
    if(api_rc!=NO_ERROR){
      fprintf(stderr,"unzip: OS/2 EA restore failed for %s (DosSetPathInfo rc=%lu)\n",
              szName,(unsigned long)api_rc);
      free(pFEA2list);
      return PK_ERR;
    }
  }

  if (!uO.tflag && QCOND2)
    Info(slide, 0, ((char *)slide, " (%ld bytes EAs)", pFEA2list -> cbList));

  free(pFEA2list);
  return PK_COOL;
}


static int SetACL(__GPRO__ const char *path, void *ef_block)
{                                               /* returns almost-PK errors */
  EFHEADER *pACLblock = (PEFHEADER) ef_block;
  char *szACL;
  int error;

  if ( ef_block == NULL || pACLblock -> nID != EF_ACL )
    return PK_OK;  /* not an OS/2 extra field:  assume OK */

  if (pACLblock->nSize < 4 || (pACLblock->lSize > 0L && pACLblock->nSize <= 10))
    return IZ_EF_TRUNC;  /* no compressed data! */

  /* An untrusted archive must not request an unbounded ACL allocation. */
  if(pACLblock->lSize == 0 || pACLblock->lSize > 1024UL*1024UL)
    return PK_ERR;
  if ( (szACL = malloc((size_t) pACLblock -> lSize)) == NULL )
    return PK_MEM4;

  if ( (error = memextract(__G__ (uch *)szACL, pACLblock->lSize,
       (uch *)(pACLblock+1), (ulg)(pACLblock->nSize - 4))) != PK_OK )
  {
    free(szACL);
    return error;
  }

  if(pACLblock->lSize==0 ||
     memchr(szACL,0,(size_t)pACLblock->lSize)==NULL){
    free(szACL);return PK_ERR;
  }
  if (acl_set(NULL, path, szACL) != 0) {
    fprintf(stderr, "unzip: cannot restore OS/2 LAN ACL for %s\n", path);
    free(szACL);
    return PK_ERR;
  }
  if (!uO.tflag && QCOND2)
    Info(slide, 0, ((char *)slide, " (%ld bytes ACL)", strlen(szACL)));

  free(szACL);
  return PK_COOL;
}


#ifdef SFX

char *GetLoadPath(__GPRO)
{
#ifdef __32BIT__ /* generic for 32-bit API */
  PTIB pptib;
  PPIB pppib;
  char *szPath;

  DosGetInfoBlocks(&pptib, &pppib);
  szPath = pppib -> pib_pchenv;
#else /* 16-bit, note: requires large data model */
  SEL selEnv;
  USHORT offCmd;
  char *szPath;

  DosGetEnv(&selEnv, &offCmd);
  szPath = MAKEP(selEnv, 0);
#endif

  while (*szPath) /* find end of process environment */
    szPath = strchr(szPath, 0) + 1;

  return szPath + 1; /* .exe file name follows environment */

} /* end function GetLoadPath() */





#else /* !SFX */

DIR *opendir(__GPRO__ const char *name)
{
  struct stat statb;
  DIR *dirp;
  char c;
  char *s;
  struct _dircontents *dp;
  char nbuf[MAXPATHLEN + 1];
  int len;

  strcpy(nbuf, name);
  if ((len = strlen(nbuf)) == 0)
    return NULL;

  if ( ((c = nbuf[len - 1]) == '\\' || c == '/') && (len > 1) )
  {
    nbuf[len - 1] = 0;
    --len;

    if ( nbuf[len - 1] == ':' )
    {
      strcpy(nbuf+len, "\\.");
      len += 2;
    }
  }
  else
    if ( nbuf[len - 1] == ':' )
    {
      strcpy(nbuf+len, ".");
      ++len;
    }

  /* GRR:  Borland and Watcom C return non-zero on wildcards... < 0 ? */
  if (stat(nbuf, &statb) < 0 || (statb.st_mode & S_IFMT) != S_IFDIR)
  {
    Trace((stderr, "opendir:  stat(%s) returns negative or not directory\n",
      FnFilter1(nbuf)));
    return NULL;
  }

  if ( (dirp = malloc(sizeof(DIR))) == NULL )
    return NULL;

  if ( nbuf[len - 1] == '.' && (len == 1 || nbuf[len - 2] != '.') )
    strcpy(nbuf+len-1, "*");
  else
    if ( ((c = nbuf[len - 1]) == '\\' || c == '/') && (len == 1) )
      strcpy(nbuf+len, "*");
    else
      strcpy(nbuf+len, "\\*");

  /* len is no longer correct (but no longer needed) */
  Trace((stderr, "opendir:  nbuf = [%s]\n", FnFilter1(nbuf)));

  dirp -> dd_loc = 0;
  dirp -> dd_contents = dirp -> dd_cp = NULL;

  if ((s = getdirent(__G__ nbuf)) == NULL)
    return dirp;

  do
  {
    if (((dp = malloc(sizeof(struct _dircontents))) == NULL) ||
        ((dp -> _d_entry = malloc(strlen(s) + 1)) == NULL)      )
    {
      if (dp)
        free(dp);
      free_dircontents(dirp -> dd_contents);

      return NULL;
    }

    if (dirp -> dd_contents)
    {
      dirp -> dd_cp -> _d_next = dp;
      dirp -> dd_cp = dirp -> dd_cp -> _d_next;
    }
    else
      dirp -> dd_contents = dirp -> dd_cp = dp;

    strcpy(dp -> _d_entry, s);
    dp -> _d_next = NULL;

    dp -> _d_size = G.os2.find.cbFile;
    dp -> _d_mode = G.os2.find.attrFile;
    dp -> _d_time = *(unsigned *) &(G.os2.find.ftimeLastWrite);
    dp -> _d_date = *(unsigned *) &(G.os2.find.fdateLastWrite);
  }
  while ((s = getdirent(__G__ NULL)) != NULL);

  dirp -> dd_cp = dirp -> dd_contents;

  return dirp;
}


void closedir(DIR * dirp)
{
  free_dircontents(dirp -> dd_contents);
  free(dirp);
}


struct direct *readdir(__GPRO__ DIR * dirp)
{
  /* moved to os2data.h so it can be global */
  /* static struct direct dp; */

  if (dirp -> dd_cp == NULL)
    return NULL;

  G.os2.dp.d_namlen = G.os2.dp.d_reclen =
    strlen(strcpy(G.os2.dp.d_name, dirp -> dd_cp -> _d_entry));

  G.os2.dp.d_ino = 0;

  G.os2.dp.d_size = dirp -> dd_cp -> _d_size;
  G.os2.dp.d_mode = dirp -> dd_cp -> _d_mode;
  G.os2.dp.d_time = dirp -> dd_cp -> _d_time;
  G.os2.dp.d_date = dirp -> dd_cp -> _d_date;

  dirp -> dd_cp = dirp -> dd_cp -> _d_next;
  dirp -> dd_loc++;

  return &G.os2.dp;
}



#if 0  /* not used in unzip; retained for possibly future use */

void seekdir(DIR * dirp, long off)
{
  long i = off;
  struct _dircontents *dp;

  if (off >= 0)
  {
    for (dp = dirp -> dd_contents; --i >= 0 && dp; dp = dp -> _d_next);

    dirp -> dd_loc = off - (i + 1);
    dirp -> dd_cp = dp;
  }
}


long telldir(DIR * dirp)
{
  return dirp -> dd_loc;
}

#endif /* 0 */



static void free_dircontents(struct _dircontents * dp)
{
  struct _dircontents *odp;

  while (dp)
  {
    if (dp -> _d_entry)
      free(dp -> _d_entry);

    dp = (odp = dp) -> _d_next;
    free(odp);
  }
}


static char *getdirent(__GPRO__ ZCONST char *dir)
{
  int done;
  /* moved to os2data.h so it can be global */
  /* static int lower; */

  if (dir != NULL)
  {                                    /* get first entry */
    G.os2.hdir = HDIR_SYSTEM;
    G.os2.count = 1;
    done = DosFindFirst((PSZ) dir, &G.os2.hdir, attributes,
                        &G.os2.find, sizeof(G.os2.find), &G.os2.count);
    G.os2.lower = IsFileSystemFAT(__G__ dir);
  }
  else                                 /* get next entry */
    done = DosFindNext(G.os2.hdir,
                       &G.os2.find, sizeof(G.os2.find), &G.os2.count);

  if (done == 0)
  {
    if ( G.os2.lower )
      StringLower(G.os2.find.achName);
    return G.os2.find.achName;
  }
  else
  {
    DosFindClose(G.os2.hdir);
    return NULL;
  }
}



int IsFileSystemFAT(__GPRO__ ZCONST char *dir)  /* FAT / HPFS detection */
{
  /* moved to os2data.h so they can be global */
  /* static USHORT nLastDrive=(USHORT)(-1), nResult; */
  ULONG lMap;
  BYTE bData[64];
  char bName[3];
#ifdef __32BIT__
  ULONG nDrive, cbData;
  PFSQBUFFER2 pData = (PFSQBUFFER2) bData;
#else
  USHORT nDrive, cbData;
  PFSQBUFFER pData = (PFSQBUFFER) bData;
#endif

    /* We separate FAT and HPFS+other file systems here.
       at the moment I consider other systems to be similar to HPFS,
       i.e. support long file names and case sensitive */

    if ( isalpha((uch)dir[0]) && (dir[1] == ':') )
      nDrive = toupper(dir[0]) - '@';
    else
      DosQueryCurrentDisk(&nDrive, &lMap);

    if ( nDrive == G.os2.nLastDrive )
      return G.os2.nResult;

    bName[0] = (char) (nDrive + '@');
    bName[1] = ':';
    bName[2] = 0;

    G.os2.nLastDrive = nDrive;
    cbData = sizeof(bData);

    if ( !DosQueryFSAttach(bName, 0, FSAIL_QUERYNAME, (PVOID) pData, &cbData) )
      G.os2.nResult = !strcmp((char *) (pData -> szFSDName) + pData -> cbName,
                              "FAT");
    else
      G.os2.nResult = FALSE;

    /* End of this ugly code */
    return G.os2.nResult;
} /* end function IsFileSystemFAT() */





/************************/
/*  Function do_wild()  */
/************************/

char *do_wild(__G__ wildspec)
    __GDEF
    ZCONST char *wildspec;  /* only used first time on a given dir */
{
  /* moved to os2data.h so they can be global */
#if 0
  static DIR *wild_dir = NULL;
  static ZCONST char *wildname;
  static char *dirname, matchname[FILNAMSIZ];
  static int notfirstcall=FALSE, have_dirname, dirnamelen;
#endif
    char *fnamestart;
    struct direct *file;

    /* Even when we're just returning wildspec, we *always* do so in
     * matchname[]--calling routine is allowed to append four characters
     * to the returned string, and wildspec may be a pointer to argv[].
     */
    if (!G.os2.notfirstcall) {  /* first call:  must initialize everything */
        G.os2.notfirstcall = TRUE;

        if (!iswild(wildspec)) {
            strncpy(G.os2.matchname, wildspec, FILNAMSIZ);
            G.os2.matchname[FILNAMSIZ-1] = '\0';
            G.os2.have_dirname = FALSE;
            G.os2.wild_dir = NULL;
            return G.os2.matchname;
        }

        /* break the wildspec into a directory part and a wildcard filename */
        if ((G.os2.wildname = (ZCONST char *)strrchr(wildspec, '/')) == NULL &&
            (G.os2.wildname = (ZCONST char *)strrchr(wildspec, ':')) == NULL) {
            G.os2.dirname = ".";
            G.os2.dirnamelen = 1;
            G.os2.have_dirname = FALSE;
            G.os2.wildname = wildspec;
        } else {
            ++G.os2.wildname;     /* point at character after '/' or ':' */
            G.os2.dirnamelen = G.os2.wildname - wildspec;
            if ((G.os2.dirname = (char *)malloc(G.os2.dirnamelen+1)) == NULL) {
                Info(slide, 1, ((char *)slide,
                  LoadFarString(CantAllocateWildcard)));
                strncpy(G.os2.matchname, wildspec, FILNAMSIZ);
                G.os2.matchname[FILNAMSIZ-1] = '\0';
                return G.os2.matchname;   /* but maybe filespec was not a wildcard */
            }
            strncpy(G.os2.dirname, wildspec, G.os2.dirnamelen);
            G.os2.dirname[G.os2.dirnamelen] = '\0';   /* terminate for strcpy below */
            G.os2.have_dirname = TRUE;
        }
        Trace((stderr, "do_wild:  dirname = [%s]\n",
          FnFilter1(G.os2.dirname)));

        if ((G.os2.wild_dir = opendir(__G__ G.os2.dirname)) != NULL) {
            if (G.os2.have_dirname) {
                strcpy(G.os2.matchname, G.os2.dirname);
                fnamestart = G.os2.matchname + G.os2.dirnamelen;
            } else
                fnamestart = G.os2.matchname;
            while ((file = readdir(__G__ G.os2.wild_dir)) != NULL) {
                Trace((stderr, "do_wild:  readdir returns %s\n",
                  FnFilter1(file->d_name)));
                strcpy(fnamestart, file->d_name);
                if (strrchr(fnamestart, '.') == (char *)NULL)
                    strcat(fnamestart, ".");
                if (match(fnamestart, G.os2.wildname, 1 WISEP) &&
                                                      /* 1 == ignore case */
                    /* skip "." and ".." directory entries */
                    strcmp(fnamestart, ".") && strcmp(fnamestart, "..")) {
                    Trace((stderr, "do_wild:  match() succeeds\n"));
                    /* remove trailing dot */
                    fnamestart += strlen(fnamestart) - 1;
                    if (*fnamestart == '.')
                        *fnamestart = '\0';
                    return G.os2.matchname;
                }
            }
            /* if we get to here directory is exhausted, so close it */
            closedir(G.os2.wild_dir);
            G.os2.wild_dir = NULL;
        }
#ifdef DEBUG
        else {
            Trace((stderr, "do_wild:  opendir(%s) returns NULL\n",
              FnFilter1(G.os2.dirname)));
        }
#endif /* DEBUG */

        /* return the raw wildspec in case that works (e.g., directory not
         * searchable, but filespec was not wild and file is readable) */
        strncpy(G.os2.matchname, wildspec, FILNAMSIZ);
        G.os2.matchname[FILNAMSIZ-1] = '\0';
        return G.os2.matchname;
    }

    /* last time through, might have failed opendir but returned raw wildspec */
    if (G.os2.wild_dir == NULL) {
        G.os2.notfirstcall = FALSE;  /* nothing left to try--reset */
        if (G.os2.have_dirname)
            free(G.os2.dirname);
        return (char *)NULL;
    }

    /* If we've gotten this far, we've read and matched at least one entry
     * successfully (in a previous call), so dirname has been copied into
     * matchname already.
     */
    if (G.os2.have_dirname) {
        /* strcpy(G.os2.matchname, G.os2.dirname); */
        fnamestart = G.os2.matchname + G.os2.dirnamelen;
    } else
        fnamestart = G.os2.matchname;
    while ((file = readdir(__G__ G.os2.wild_dir)) != NULL) {
        Trace((stderr, "do_wild:  readdir returns %s\n",
          FnFilter1(file->d_name)));
        strcpy(fnamestart, file->d_name);
        if (strrchr(fnamestart, '.') == (char *)NULL)
            strcat(fnamestart, ".");
        if (match(fnamestart, G.os2.wildname, 1 WISEP)) { /* 1==ignore case */
            Trace((stderr, "do_wild:  match() succeeds\n"));
            /* remove trailing dot */
            fnamestart += strlen(fnamestart) - 1;
            if (*fnamestart == '.')
                *fnamestart = '\0';
            return G.os2.matchname;
        }
    }

    closedir(G.os2.wild_dir);   /* have read at least one entry; nothing left */
    G.os2.wild_dir = NULL;
    G.os2.notfirstcall = FALSE; /* reset for new wildspec */
    if (G.os2.have_dirname)
        free(G.os2.dirname);
    return (char *)NULL;

} /* end function do_wild() */

#endif /* !SFX */


/* scan extra fields for something we happen to know */

static int EvalExtraFields(__GPRO__ const char *path,
                           void *extra_field, unsigned ef_len)
{
  char *ef_ptr = extra_field;
  PEFHEADER pEFblock;
  int rc = PK_OK;

  while (ef_len >= sizeof(EFHEADER))
  {
    pEFblock = (PEFHEADER) ef_ptr;

    if (pEFblock -> nSize > (ef_len - EB_HEADSIZE))
      return PK_ERR;            /* claimed EFblock length exceeds EF size! */

    switch (pEFblock -> nID)
    {
    case EF_OS2:
      rc = SetEAs(__G__ path, ef_ptr);
      break;
    case EF_ACL:
      rc = (uO.X_flag) ? SetACL(__G__ path, ef_ptr) : PK_OK;
      break;
#if 0
    case EF_IZUNIX:
    case EF_PKUNIX:
      /* handled elsewhere */
      break;
#endif
    default:
      TTrace((stderr,"EvalExtraFields: unknown extra field block, ID=%d\n",
              pEFblock -> nID));
      break;
    }

    ef_ptr += (pEFblock -> nSize + EB_HEADSIZE);
    ef_len -= (pEFblock -> nSize + EB_HEADSIZE);

    if (rc != PK_OK)
      break;
  }

  return rc;
}



/************************/
/*  Function mapattr()  */
/************************/

int mapattr(__G)
    __GDEF
{
    /* set archive bit (file is not backed up): */
    G.pInfo->file_attr = (unsigned)(G.crec.external_file_attributes | 32) & 0xff;
    return 0;
}





/************************/
/*  Function mapname()  */
/************************/

/*
 * There are presently two possibilities in OS/2:  the output filesystem is
 * FAT, or it is HPFS.  If the former, we need to map to FAT, obviously, but
 * we *also* must map to HPFS and store that version of the name in extended
 * attributes.  Either way, we need to map to HPFS, so the main mapname
 * routine does that.  In the case that the output file system is FAT, an
 * extra filename-mapping routine is called in checkdir().  While it should
 * be possible to determine the filesystem immediately upon entry to mapname(),
 * it is conceivable that the DOS APPEND utility could be added to OS/2 some-
 * day, allowing a FAT directory to be APPENDed to an HPFS drive/path.  There-
 * fore we simply check the filesystem at each path component.
 *
 * Note that when alternative IFSes become available/popular, everything will
 * become immensely more complicated.  For example, a Minix filesystem would
 * have limited filename lengths like FAT but no extended attributes in which
 * to store the longer versions of the names.  A BSD Unix filesystem would
 * support paths of length 1024 bytes or more, but it is not clear that FAT
 * EAs would allow such long .LONGNAME fields or that OS/2 would properly
 * restore such fields when moving files from FAT to the new filesystem.
 *
 * GRR:  some or all of the following chars should be checked in either
 *       mapname (HPFS) or map2fat (FAT), depending:  ,=^+'"[]<>|\t&
 */
int mapname(__G__ renamed)
    __GDEF
    int renamed;
/*
 * returns:
 *  MPN_OK          - no problem detected
 *  MPN_INF_TRUNC   - caution (truncated filename)
 *  MPN_INF_SKIP    - info "skip entry" (dir doesn't exist)
 *  MPN_ERR_SKIP    - error -> skip entry
 *  MPN_ERR_TOOLONG - error -> path is too long
 *  MPN_NOMEM       - error (memory allocation failed) -> skip entry
 *  [also MPN_VOL_LABEL, MPN_CREATED_DIR]
 */
{
    char pathcomp[FILNAMSIZ];      /* path-component buffer */
    char *pp, *cp=(char *)NULL;    /* character pointers */
    char *lastsemi=(char *)NULL;   /* pointer to last semi-colon in pathcomp */
#ifdef ACORN_FTYPE_NFS
    char *lastcomma=(char *)NULL;  /* pointer to last comma in pathcomp */
    RO_extra_block *ef_spark;      /* pointer Acorn FTYPE ef block */
#endif
    int killed_ddot = FALSE;       /* is set when skipping "../" pathcomp */
    int error = MPN_OK;
    register unsigned workch;      /* hold the character being tested */


/*---------------------------------------------------------------------------
    Initialize various pointers and counters and stuff.
  ---------------------------------------------------------------------------*/

    /* can create path as long as not just freshening, or if user told us */
    G.create_dirs = (!uO.fflag || renamed);

    G.os2.created_dir = FALSE;  /* not yet */
    G.os2.renamed_fullpath = FALSE;
    G.os2.fnlen = strlen(G.filename);

/* GRR:  for VMS, convert to internal format now or later? or never? */
    if (renamed) {
        cp = G.filename - 1;    /* point to beginning of renamed name... */
        while (*++cp)
            if (*cp == '\\')    /* convert backslashes to forward */
                *cp = '/';
        cp = G.filename;
        /* use temporary rootpath if user gave full pathname */
        if (G.filename[0] == '/') {
            G.os2.renamed_fullpath = TRUE;
            pathcomp[0] = '/';  /* copy the '/' and terminate */
            pathcomp[1] = '\0';
            ++cp;
        } else if (isalpha((uch)G.filename[0]) && G.filename[1] == ':') {
            G.os2.renamed_fullpath = TRUE;
            pp = pathcomp;
            *pp++ = *cp++;      /* copy the "d:" (+ '/', possibly) */
            *pp++ = *cp++;
            if (*cp == '/')
                *pp++ = *cp++;  /* otherwise add "./"? */
            *pp = '\0';
        }
    }

    /* pathcomp is ignored unless renamed_fullpath is TRUE: */
    if ((error = checkdir(__G__ pathcomp, INIT)) != 0)    /* init path buffer */
        return error;           /* ...unless no mem or vol label on hard disk */

    *pathcomp = '\0';           /* initialize translation buffer */
    pp = pathcomp;              /* point to translation buffer */
    if (!renamed) {             /* cp already set if renamed */
        if (uO.jflag)           /* junking directories */
/* GRR:  watch out for VMS version... */
            cp = (char *)strrchr(G.filename, '/');
        if (cp == (char *)NULL) /* no '/' or not junking dirs */
            cp = G.filename;    /* point to internal zipfile-member pathname */
        else
            ++cp;               /* point to start of last component of path */
    }

/*---------------------------------------------------------------------------
    Begin main loop through characters in filename.
  ---------------------------------------------------------------------------*/

    while ((workch = (uch)*cp++) != 0) {

        switch (workch) {
            case '/':             /* can assume -j flag not given */
                *pp = '\0';
                if (strcmp(pathcomp, ".") == 0) {
                    /* don't bother appending "./" to the path */
                    *pathcomp = '\0';
                } else if (!uO.ddotflag && strcmp(pathcomp, "..") == 0) {
                    /* "../" dir traversal detected, skip over it */
                    *pathcomp = '\0';
                    killed_ddot = TRUE;     /* set "show message" flag */
                }
                /* when path component is not empty, append it now */
                if (*pathcomp != '\0' &&
                    ((error = checkdir(__G__ pathcomp, APPEND_DIR))
                     & MPN_MASK) > MPN_INF_TRUNC)
                    return error;
                pp = pathcomp;    /* reset conversion buffer for next piece */
                lastsemi = (char *)NULL; /* leave direct. semi-colons alone */
                break;

            case ':':             /* drive never stored, so no colon allowed */
            case '\\':            /* "non-dos" FSs may  allow '\\' as normal */
                *pp++ = '_';      /*  character in filenames */
                break;            /* -> map invalid chars to underscore */

            case ';':             /* start of VMS version? */
                lastsemi = pp;    /* remove VMS version later... */
                *pp++ = ';';      /*  but keep semicolon for now */
                break;

#ifdef ACORN_FTYPE_NFS
            case ',':             /* NFS filetype extension */
                lastcomma = pp;
                *pp++ = ',';      /* keep for now; may need to remove */
                break;            /*  later, if requested */
#endif

            case ' ':             /* keep spaces unless specifically */
                if (uO.sflag)     /*  requested to change to underscore */
                    *pp++ = '_';
                else
                    *pp++ = ' ';
                break;

            default:
                /* allow ASCII 255 and European characters in filenames: */
                if (isprint(workch) || workch >= 127)
                    *pp++ = (char)workch;
        } /* end switch */

    } /* end while loop */

    /* Show warning when stripping insecure "parent dir" path components */
    if (killed_ddot && QCOND2) {
        Info(slide, 0, ((char *)slide, LoadFarString(WarnDirTraversSkip),
          FnFilter1(G.filename)));
        if (!(error & ~MPN_MASK))
            error = (error & MPN_MASK) | PK_WARN;
    }

/*---------------------------------------------------------------------------
    Report if directory was created (and no file to create:  filename ended
    in '/'), check name to be sure it exists, and combine path and name be-
    fore exiting.
  ---------------------------------------------------------------------------*/

    if (G.filename[G.os2.fnlen-1] == '/') {
        checkdir(__G__ G.filename, GETPATH);
        if (G.os2.created_dir) {
            if (QCOND2)
                Info(slide, 0, ((char *)slide, LoadFarString(Creating),
                  FnFilter1(G.filename)));
            if (G.extra_field) { /* zipfile extra field has extended attribs */
                int err = EvalExtraFields(__G__ G.filename, G.extra_field,
                                          G.lrec.extra_field_length);

                if (err == IZ_EF_TRUNC) {
                    if (uO.qflag)
                        Info(slide, 1, ((char *)slide, "%-22s ",
                          FnFilter1(G.filename)));
                    Info(slide, 1, ((char *)slide, LoadFarString(TruncEAs),
                      makeword(G.extra_field+2)-10, "\n"));
                } else if (!uO.qflag)
                    (*G.message)((zvoid *)&G, (uch *)"\n", 1L, 0);
            } else if (!uO.qflag)
                (*G.message)((zvoid *)&G, (uch *)"\n", 1L, 0);

            /* set date/time stamps */
            SetPathAttrTimes(__G__ G.pInfo->file_attr & ~A_ARCHIVE, 1);

            /* dir time already set */
            return (error & ~MPN_MASK) | MPN_CREATED_DIR;

        } else if (G.extra_field && IS_OVERWRT_ALL) {
            /* overwrite EAs of existing directory since user requested it */
            int err = EvalExtraFields(__G__ G.filename, G.extra_field,
                                      G.lrec.extra_field_length);

            if (err == IZ_EF_TRUNC) {
                Info(slide, 0x421, ((char *)slide, "%-22s ",
                  FnFilter1(G.filename)));
                Info(slide, 0x401, ((char *)slide, LoadFarString(TruncEAs),
                  makeword(G.extra_field+2)-10, "\n"));
            }

            /* set date/time stamps (dirs only have creation times) */
            SetPathAttrTimes(__G__ G.pInfo->file_attr & ~A_ARCHIVE, 1);
        }
        /* dir existed already; don't look for data to extract */
        return (error & ~MPN_MASK) | MPN_INF_SKIP;
    }

    *pp = '\0';                   /* done with pathcomp:  terminate it */

    /* if not saving them, remove VMS version numbers (appended "###") */
    if (!uO.V_flag && lastsemi) {
        pp = lastsemi + 1;        /* semi-colon was kept:  expect #s after */
        while (isdigit((uch)(*pp)))
            ++pp;
        if (*pp == '\0')          /* only digits between ';' and end:  nuke */
            *lastsemi = '\0';
    }

#ifdef ACORN_FTYPE_NFS
    /* translate Acorn filetype information if asked to do so */
    if (uO.acorn_nfs_ext &&
        (ef_spark = (RO_extra_block *)
                    getRISCOSexfield(G.extra_field, G.lrec.extra_field_length))
        != (RO_extra_block *)NULL)
    {
        /* file *must* have a RISC OS extra field */
        long ft = (long)makelong(ef_spark->loadaddr);
        /*32-bit*/
        if (lastcomma) {
            pp = lastcomma + 1;
            while (isxdigit((uch)(*pp))) ++pp;
            if (pp == lastcomma+4 && *pp == '\0') *lastcomma='\0'; /* nuke */
        }
        if ((ft & 1<<31)==0) ft=0x000FFD00;
        sprintf(pathcomp+strlen(pathcomp), ",%03x", (int)(ft>>8) & 0xFFF);
    }
#endif /* ACORN_FTYPE_NFS */

    if (*pathcomp == '\0') {
        Info(slide, 1, ((char *)slide, LoadFarString(ConversionFailed),
          FnFilter1(G.filename)));
        return (error & ~MPN_MASK) | MPN_ERR_SKIP;
    }

    checkdir(__G__ pathcomp, APPEND_NAME);  /* returns 1 if truncated: care? */
    checkdir(__G__ G.filename, GETPATH);
    Trace((stderr, "mapname returns with filename = [%s] (error = %d)\n\n",
      FnFilter1(G.filename), error));

    if (G.pInfo->vollabel) {    /* set the volume label now */
        VOLUMELABEL FSInfoBuf;
/* GRR:  "VOLUMELABEL" defined for IBM C and emx, but haven't checked MSC... */

        strcpy(FSInfoBuf.szVolLabel, G.filename);
        FSInfoBuf.cch = (BYTE)strlen(FSInfoBuf.szVolLabel);

        if (!uO.qflag)
            Info(slide, 0, ((char *)slide, LoadFarString(Labelling),
              (char)(G.os2.nLabelDrive + 'a' - 1), FnFilter1(G.filename)));
        if (DosSetFSInfo(G.os2.nLabelDrive, FSIL_VOLSER, (PBYTE)&FSInfoBuf,
                         sizeof(VOLUMELABEL)))
        {
            Info(slide, 1, ((char *)slide, LoadFarString(ErrSetVolLabel)));
            return (error & ~MPN_MASK) | MPN_ERR_SKIP;
        }
        /* success:  skip the "extraction" quietly */
        return (error & ~MPN_MASK) | MPN_INF_SKIP;
    }

    return error;

} /* end function mapname() */





/***********************/
/* Function checkdir() */
/***********************/

int checkdir(__G__ pathcomp, flag)
    __GDEF
    char *pathcomp;
    int flag;
/*
 * returns:
 *  MPN_OK          - no problem detected
 *  MPN_INF_TRUNC   - (on APPEND_NAME) truncated filename
 *  MPN_INF_SKIP    - path doesn't exist, not allowed to create
 *  MPN_ERR_SKIP    - path doesn't exist, tried to create and failed; or path
 *                    exists and is not a directory, but is supposed to be
 *  MPN_ERR_TOOLONG - path is too long
 *  MPN_NOMEM       - can't allocate memory for filename buffers
 */
{
  /* moved to os2data.h so they can be global */
#if 0
    static int rootlen = 0;      /* length of rootpath */
    static char *rootpath;       /* user's "extract-to" directory */
    static char *buildpathHPFS;  /* full path (so far) to extracted file, */
    static char *buildpathFAT;   /*  both HPFS/EA (main) and FAT versions */
    static char *endHPFS;        /* corresponding pointers to end of */
    static char *endFAT;         /*  buildpath ('\0') */
#endif

#   define FN_MASK   7
#   define FUNCTION  (flag & FN_MASK)



/*---------------------------------------------------------------------------
    APPEND_DIR:  append the path component to the path being built and check
    for its existence.  If doesn't exist and we are creating directories, do
    so for this one; else signal success or error as appropriate.
  ---------------------------------------------------------------------------*/

    if (FUNCTION == APPEND_DIR) {
        char *p = pathcomp;
        int longdirEA, too_long=FALSE;

        Trace((stderr, "appending dir segment [%s]\n", FnFilter1(pathcomp)));
        while ((*G.os2.endHPFS = *p++) != '\0')     /* copy to HPFS filename */
            ++G.os2.endHPFS;
        if (IsFileNameValid(G.os2.buildpathHPFS)) {
            longdirEA = FALSE;
            p = pathcomp;
            while ((*G.os2.endFAT = *p++) != '\0')  /* copy to FAT filename, too */
                ++G.os2.endFAT;
        } else {
            longdirEA = TRUE;
/* GRR:  check error return? */
            map2fat(pathcomp, &G.os2.endFAT);  /* map, put in FAT fn, update endFAT */
        }

        /* GRR:  could do better check, see if overrunning buffer as we go:
         * check endHPFS-G.os2.buildpathHPFS after each append, set warning variable
         * if within 20 of FILNAMSIZ; then if var set, do careful check when
         * appending.  Clear variable when begin new path. */

        /* next check:  need to append '/', at least one-char name, '\0' */
        if ((G.os2.endHPFS-G.os2.buildpathHPFS) > FILNAMSIZ-3)
            too_long = TRUE;                 /* check if extracting dir? */
#ifdef MSC /* MSC 6.00 bug:  stat(non-existent-dir) == 0 [exists!] */
        if (GetFileTime(G.os2.buildpathFAT) == -1 || stat(G.os2.buildpathFAT, &G.statbuf))
#else
        if (stat(G.os2.buildpathFAT, &G.statbuf))    /* path doesn't exist */
#endif
        {
            if (!G.create_dirs) { /* told not to create (freshening) */
                free(G.os2.buildpathHPFS);
                free(G.os2.buildpathFAT);
                /* path doesn't exist:  nothing to do */
                return MPN_INF_SKIP;
            }
            if (too_long) {   /* GRR:  should allow FAT extraction w/o EAs */
                Info(slide, 1, ((char *)slide, LoadFarString(PathTooLong),
                  FnFilter1(G.os2.buildpathHPFS)));
                free(G.os2.buildpathHPFS);
                free(G.os2.buildpathFAT);
                /* no room for filenames:  fatal */
                return MPN_ERR_TOOLONG;
            }
            if (MKDIR(G.os2.buildpathFAT, 0777) == -1) {   /* create the directory */
                Info(slide, 1, ((char *)slide, LoadFarString(CantCreateDir),
                  FnFilter2(G.os2.buildpathFAT), FnFilter1(G.filename)));
                free(G.os2.buildpathHPFS);
                free(G.os2.buildpathFAT);
                /* path didn't exist, tried to create, failed */
                return MPN_ERR_SKIP;
            }
            G.os2.created_dir = TRUE;
            /* only set EA if creating directory */
/* GRR:  need trailing '/' before function call? */
            if (longdirEA) {
#ifdef DEBUG
                int e =
#endif
                  SetLongNameEA(G.os2.buildpathFAT, pathcomp);
                Trace((stderr, "APPEND_DIR:  SetLongNameEA() returns %d\n", e));
            }
        } else if (!S_ISDIR(G.statbuf.st_mode)) {
            Info(slide, 1, ((char *)slide, LoadFarString(DirIsntDirectory),
              FnFilter2(G.os2.buildpathFAT), FnFilter1(G.filename)));
            free(G.os2.buildpathHPFS);
            free(G.os2.buildpathFAT);
            /* path existed but wasn't dir */
            return MPN_ERR_SKIP;
        }
        if (too_long) {
            Info(slide, 1, ((char *)slide, LoadFarString(PathTooLong),
              FnFilter1(G.os2.buildpathHPFS)));
            free(G.os2.buildpathHPFS);
            free(G.os2.buildpathFAT);
            /* no room for filenames:  fatal */
            return MPN_ERR_TOOLONG;
        }
        *G.os2.endHPFS++ = '/';
        *G.os2.endFAT++ = '/';
        *G.os2.endHPFS = *G.os2.endFAT = '\0';
        Trace((stderr, "buildpathHPFS now = [%s]\n",
          FnFilter1(G.os2.buildpathHPFS)));
        Trace((stderr, "buildpathFAT now =  [%s]\n",
          FnFilter1(G.os2.buildpathFAT)));
        return MPN_OK;

    } /* end if (FUNCTION == APPEND_DIR) */

/*---------------------------------------------------------------------------
    GETPATH:  copy full FAT path to the string pointed at by pathcomp (want
    filename to reflect name used on disk, not EAs; if full path is HPFS,
    buildpathFAT and buildpathHPFS will be identical).  Also free both paths.
  ---------------------------------------------------------------------------*/

    if (FUNCTION == GETPATH) {
        Trace((stderr, "getting and freeing FAT path [%s]\n",
          FnFilter1(G.os2.buildpathFAT)));
        Trace((stderr, "freeing HPFS path [%s]\n",
          FnFilter1(G.os2.buildpathHPFS)));
        strcpy(pathcomp, G.os2.buildpathFAT);
        free(G.os2.buildpathFAT);
        free(G.os2.buildpathHPFS);
        G.os2.buildpathHPFS = G.os2.buildpathFAT = G.os2.endHPFS = G.os2.endFAT = (char *)NULL;
        return MPN_OK;
    }

/*---------------------------------------------------------------------------
    APPEND_NAME:  assume the path component is the filename; append it and
    return without checking for existence.
  ---------------------------------------------------------------------------*/

    if (FUNCTION == APPEND_NAME) {
        char *p = pathcomp;
        int error = MPN_OK;

        Trace((stderr, "appending filename [%s]\n", FnFilter1(pathcomp)));
        /* The buildpathHPFS buffer has been allocated large enough to
         * hold the complete combined name, so there is no need to check
         * for OS filename size limit overflow within the copy loop.
         */
        while ((*G.os2.endHPFS = *p++) != '\0') {   /* copy to HPFS filename */
            ++G.os2.endHPFS;
        }
        /* Now, check for OS filename size overflow.  When detected, the
         * mapped HPFS name is truncated and a warning message is shown.
         */
        if ((G.os2.endHPFS-G.os2.buildpathHPFS) >= FILNAMSIZ) {
            G.os2.buildpathHPFS[FILNAMSIZ-1] = '\0';
            Info(slide, 1, ((char *)slide, LoadFarString(PathTooLongTrunc),
              FnFilter1(G.filename), FnFilter2(G.os2.buildpathHPFS)));
            error = MPN_INF_TRUNC;  /* filename truncated */
        }

/* GRR:  how can longnameEA ever be set before this point???  we don't want
 * to save the original name to EAs if user renamed it, do we?
 *
 * if (!G.os2.longnameEA && ((G.os2.longnameEA = !IsFileNameValid(name)) != 0))
 */
        /* The buildpathFAT buffer has the same allocated size as the
         * buildpathHPFS buffer, so there is no need for an overflow check
         * within the following copy loop, either.
         */
        if (G.pInfo->vollabel || IsFileNameValid(G.os2.buildpathHPFS)) {
            G.os2.longnameEA = FALSE;
            /* copy to FAT filename, too */
            p = pathcomp;
            while ((*G.os2.endFAT = *p++) != '\0')
                ++G.os2.endFAT;
        } else {
            G.os2.longnameEA = TRUE;
            if ((G.os2.lastpathcomp = (char *)malloc(strlen(pathcomp)+1)) ==
                (char *)NULL)
            {
                Info(slide, 1, ((char *)slide,
                 "checkdir warning:  cannot save longname EA: out of memory\n"));
                G.os2.longnameEA = FALSE;
                /* can't set .LONGNAME extended attribute */
                error = MPN_INF_TRUNC;
            } else           /* used and freed in close_outfile() */
                strcpy(G.os2.lastpathcomp, pathcomp);
            /* map, put in FAT fn, update endFAT */
            map2fat(pathcomp, &G.os2.endFAT);
        }

        /* Check that the FAT path does not exceed the FILNAMSIZ limit, and
         * truncate when neccessary.
         * Note that truncation can only happen when the HPFS path (which is
         * never shorter than the FAT path) has been already truncated.
         * So, emission of the warning message and setting the error code
         * has already happened.
         */
        if ((G.os2.endFAT-G.os2.buildpathFAT) >= FILNAMSIZ)
            G.os2.buildpathFAT[FILNAMSIZ-1] = '\0';
        Trace((stderr, "buildpathHPFS: %s\nbuildpathFAT:  %s\n",
          FnFilter1(G.os2.buildpathHPFS), FnFilter2(G.os2.buildpathFAT)));

        return error;  /* could check for existence, prompt for new name... */

    } /* end if (FUNCTION == APPEND_NAME) */

/*---------------------------------------------------------------------------
    INIT:  allocate and initialize buffer space for the file currently being
    extracted.  If file was renamed with an absolute path, don't prepend the
    extract-to path.
  ---------------------------------------------------------------------------*/

    if (FUNCTION == INIT) {
        Trace((stderr, "initializing buildpathHPFS and buildpathFAT to "));
#ifdef ACORN_FTYPE_NFS
        if ((G.os2.buildpathHPFS = (char *)malloc(G.os2.fnlen+G.os2.rootlen+
                                                  (uO.acorn_nfs_ext ? 5 : 1)))
#else
        if ((G.os2.buildpathHPFS = (char *)malloc(G.os2.fnlen+G.os2.rootlen+1))
#endif
            == (char *)NULL)
            return MPN_NOMEM;
#ifdef ACORN_FTYPE_NFS
        if ((G.os2.buildpathFAT = (char *)malloc(G.os2.fnlen+G.os2.rootlen+
                                                 (uO.acorn_nfs_ext ? 5 : 1)))
#else
        if ((G.os2.buildpathFAT = (char *)malloc(G.os2.fnlen+G.os2.rootlen+1))
#endif
            == (char *)NULL) {
            free(G.os2.buildpathHPFS);
            return MPN_NOMEM;
        }
        if (G.pInfo->vollabel) {  /* use root or renamed path, but don't store */
/* GRR:  for network drives, do strchr() and return IZ_VOL_LABEL if not [1] */
            if (G.os2.renamed_fullpath && pathcomp[1] == ':')
                *G.os2.buildpathHPFS = (char)ToLower(*pathcomp);
            else if (!G.os2.renamed_fullpath && G.os2.rootlen > 1 && G.os2.rootpath[1] == ':')
                *G.os2.buildpathHPFS = (char)ToLower(*G.os2.rootpath);
            else {
                ULONG lMap;
                DosQueryCurrentDisk(&G.os2.nLabelDrive, &lMap);
                *G.os2.buildpathHPFS = (char)(G.os2.nLabelDrive - 1 + 'a');
            }
            G.os2.nLabelDrive = *G.os2.buildpathHPFS - 'a' + 1; /* save for mapname() */
            if (uO.volflag == 0 || *G.os2.buildpathHPFS < 'a' ||  /* no labels/bogus? */
                (uO.volflag == 1 && !isfloppy(G.os2.nLabelDrive))) { /* -$:  no fixed */
                free(G.os2.buildpathHPFS);
                free(G.os2.buildpathFAT);
                return MPN_VOL_LABEL;   /* skipping with message */
            }
            *G.os2.buildpathHPFS = '\0';
        } else if (G.os2.renamed_fullpath)   /* pathcomp = valid data */
            strcpy(G.os2.buildpathHPFS, pathcomp);
        else if (G.os2.rootlen > 0)
            strcpy(G.os2.buildpathHPFS, G.os2.rootpath);
        else
            *G.os2.buildpathHPFS = '\0';
        G.os2.endHPFS = G.os2.buildpathHPFS;
        G.os2.endFAT = G.os2.buildpathFAT;
        while ((*G.os2.endFAT = *G.os2.endHPFS) != '\0') {
            ++G.os2.endFAT;
            ++G.os2.endHPFS;
        }
        Trace((stderr, "[%s]\n", FnFilter1(G.os2.buildpathHPFS)));
        return MPN_OK;
    }

/*---------------------------------------------------------------------------
    ROOT:  if appropriate, store the path in rootpath and create it if neces-
    sary; else assume it's a zipfile member and return.  This path segment
    gets used in extracting all members from every zipfile specified on the
    command line.  Note that under OS/2 and MS-DOS, if a candidate extract-to
    directory specification includes a drive letter (leading "x:"), it is
    treated just as if it had a trailing '/'--that is, one directory level
    will be created if the path doesn't exist, unless this is otherwise pro-
    hibited (e.g., freshening).
  ---------------------------------------------------------------------------*/

#if (!defined(SFX) || defined(SFX_EXDIR))
    if (FUNCTION == ROOT) {
        Trace((stderr, "initializing root path to [%s]\n",
          FnFilter1(pathcomp)));
        if (pathcomp == (char *)NULL) {
            G.os2.rootlen = 0;
            return MPN_OK;
        }
        if (G.os2.rootlen > 0)  /* rootpath was already set, nothing to do */
            return MPN_OK;
        if ((G.os2.rootlen = strlen(pathcomp)) > 0) {
            int had_trailing_pathsep=FALSE, has_drive=FALSE, add_dot=FALSE;
            char *tmproot;

            if ((tmproot = (char *)malloc(G.os2.rootlen+3)) == (char *)NULL) {
                G.os2.rootlen = 0;
                return MPN_NOMEM;
            }
            strcpy(tmproot, pathcomp);
            if (isalpha((uch)tmproot[0]) && tmproot[1] == ':')
                has_drive = TRUE;   /* drive designator */
            if (tmproot[G.os2.rootlen-1] == '/') {
                tmproot[--G.os2.rootlen] = '\0';
                had_trailing_pathsep = TRUE;
            }
            if (has_drive && (G.os2.rootlen == 2)) {
                if (!had_trailing_pathsep)   /* i.e., original wasn't "x:/" */
                    add_dot = TRUE;    /* relative path: add '.' before '/' */
            } else if (G.os2.rootlen > 0) {   /* need not check "x:." and "x:/" */
#ifdef MSC      /* MSC 6.00 bug:  stat(non-existent-dir) == 0 [exists!] */
                if (GetFileTime(tmproot) == -1 ||
                    SSTAT(tmproot, &G.statbuf) || !S_ISDIR(G.statbuf.st_mode))
#else
                if (SSTAT(tmproot, &G.statbuf) || !S_ISDIR(G.statbuf.st_mode))
#endif
                {   /* path does not exist */
                    if (!G.create_dirs                 /* || iswild(tmproot) */
                                       ) {
                        free(tmproot);
                        G.os2.rootlen = 0;
                        return MPN_INF_SKIP;    /* treat as stored file */
                    }
                    /* create directory (could add loop here scanning tmproot
                     * to create more than one level, but really necessary?) */
                    if (MKDIR(tmproot, 0777) == -1) {
                        Info(slide, 1, ((char *)slide,
                          LoadFarString(CantCreateExtractDir),
                          FnFilter1(tmproot)));
                        free(tmproot);
                        G.os2.rootlen = 0;
                        /* path didn't exist, tried to create, failed: */
                        /* file exists, or need 2+ directory levels */
                        return MPN_ERR_SKIP;
                    }
                }
            }
            if (add_dot)                    /* had just "x:", make "x:." */
                tmproot[G.os2.rootlen++] = '.';
            tmproot[G.os2.rootlen++] = '/';
            tmproot[G.os2.rootlen] = '\0';
            if ((G.os2.rootpath = realloc(tmproot, G.os2.rootlen+1)) == NULL) {
                free(tmproot);
                G.os2.rootlen = 0;
                return MPN_NOMEM;
            }
            Trace((stderr, "rootpath now = [%s]\n", FnFilter1(G.os2.rootpath)));
        }
        return MPN_OK;
    }
#endif /* !SFX || SFX_EXDIR */

/*---------------------------------------------------------------------------
    END:  free rootpath, immediately prior to program exit.
  ---------------------------------------------------------------------------*/

    if (FUNCTION == END) {
        Trace((stderr, "freeing rootpath\n"));
        if (G.os2.rootlen > 0) {
            free(G.os2.rootpath);
            G.os2.rootlen = 0;
        }
        return MPN_OK;
    }

    return MPN_INVALID; /* should never reach */

} /* end function checkdir() */





/***********************/
/* Function isfloppy() */   /* more precisely, is it removable? */
/***********************/

static int isfloppy(nDrive)
    int nDrive;   /* 1 == A:, 2 == B:, etc. */
{
    uch ParmList[1] = {0};
    uch DataArea[1] = {0};
    char Name[3];
    HFILE handle;
#ifdef __32BIT__
    ULONG rc;
    ULONG action;
#else
    USHORT rc;
    USHORT action;
#endif


    Name[0] = (char) (nDrive + 'A' - 1);
    Name[1] = ':';
    Name[2] = 0;

    rc = DosOpen(Name, &handle, &action, 0L, FILE_NORMAL, FILE_OPEN,
                 OPEN_FLAGS_DASD | OPEN_FLAGS_FAIL_ON_ERROR |
                 OPEN_ACCESS_READONLY | OPEN_SHARE_DENYNONE, 0L);

    if (rc == ERROR_NOT_READY)   /* must be removable */
      return TRUE;
    else if (rc) {   /* other error:  do default a/b heuristic instead */
      Trace((stderr, "error in DosOpen(DASD):  guessing...\n", rc));
      return (nDrive == 1 || nDrive == 2)? TRUE : FALSE;
    }

    rc = DosDevIOCtl(DataArea, sizeof(DataArea), ParmList, sizeof(ParmList),
                     DSK_BLOCKREMOVABLE, IOCTL_DISK, handle);
    DosClose(handle);

    if (rc) {   /* again, just check for a/b */
        Trace((stderr, "error in DosDevIOCtl category IOCTL_DISK, function "
          "DSK_BLOCKREMOVABLE\n  (rc = 0x%04x):  guessing...\n", rc));
        return (nDrive == 1 || nDrive == 2)? TRUE : FALSE;
    } else {
        return DataArea[0] ? FALSE : TRUE;
    }
} /* end function isfloppy() */





static int IsFileNameValid(const char *name)
{
  HFILE hf;
#ifdef __32BIT__
  ULONG uAction;
#else
  USHORT uAction;
#endif

  switch( DosOpen((PSZ) name, &hf, &uAction, 0, 0, FILE_OPEN,
                  OPEN_ACCESS_READONLY | OPEN_SHARE_DENYNONE, 0) )
  {
  case ERROR_INVALID_NAME:
  case ERROR_FILENAME_EXCED_RANGE:
    return FALSE;
  case NO_ERROR:
    DosClose(hf);
  default:
    return TRUE;
  }
}





/**********************/
/* Function map2fat() */
/**********************/

static void map2fat(pathcomp, pEndFAT)
    char *pathcomp, **pEndFAT;
{
    char *ppc = pathcomp;          /* variable pointer to pathcomp */
    char *pEnd = *pEndFAT;         /* variable pointer to buildpathFAT */
    char *pBegin = *pEndFAT;       /* constant pointer to start of this comp. */
    char *last_dot = (char *)NULL; /* last dot not converted to underscore */
    int dotname = FALSE;           /* flag:  path component begins with dot */
                                   /*  ("." and ".." don't count) */
    register unsigned workch;      /* hold the character being tested */


    /* Only need check those characters which are legal in HPFS but not
     * in FAT:  to get here, must already have passed through mapname.
     * (GRR:  oops, small bug--if char was quoted, no longer have any
     * knowledge of that.)  Also must truncate path component to ensure
     * 8.3 compliance...
     */
    while ((workch = (uch)*ppc++) != 0) {
        switch (workch) {
            case '[':               /* add  '"'  '+'  ','  '='  ?? */
            case ']':
                *pEnd++ = '_';      /* convert brackets to underscores */
                break;

            case '.':
                if (pEnd == *pEndFAT) {   /* nothing appended yet... */
                    if (*ppc == '\0')     /* don't bother appending a */
                        break;            /*  "./" component to the path */
                    else if (*ppc == '.' && ppc[1] == '\0') {   /* "../" */
                        *pEnd++ = '.';    /* add first dot, unchanged... */
                        ++ppc;            /* skip second dot, since it will */
                    } else {              /*  be "added" at end of if-block */
                        *pEnd++ = '_';    /* FAT doesn't allow null filename */
                        dotname = TRUE;   /*  bodies, so map .exrc -> _.exrc */
                    }                     /*  (extra '_' now, "dot" below) */
                } else if (dotname) {     /* found a second dot, but still */
                    dotname = FALSE;      /*  have extra leading underscore: */
                    *pEnd = '\0';         /*  remove it by shifting chars */
                    pEnd = *pEndFAT + 1;  /*  left one space (e.g., .p1.p2: */
                    while (pEnd[1]) {     /*  __p1 -> _p1_p2 -> _p1.p2 when */
                        *pEnd = pEnd[1];  /*  finished) [opt.:  since first */
                        ++pEnd;           /*  two chars are same, can start */
                    }                     /*  shifting at second position] */
                }
                last_dot = pEnd;    /* point at last dot so far... */
                *pEnd++ = '_';      /* convert dot to underscore for now */
                break;

            default:
                *pEnd++ = (char)workch;

        } /* end switch */
    } /* end while loop */

    *pEnd = '\0';                 /* terminate buildpathFAT */

    /* NOTE:  keep in mind that pEnd points to the end of the path
     * component, and *pEndFAT still points to the *beginning* of it...
     * Also note that the algorithm does not try to get too fancy:
     * if there are no dots already, the name either gets truncated
     * at 8 characters or the last underscore is converted to a dot
     * (only if more characters are saved that way).  In no case is
     * a dot inserted between existing characters.
     */
    if (last_dot == (char *)NULL) {  /* no dots:  check for underscores... */
        char *plu = strrchr(pBegin, '_');    /* pointer to last underscore */

        if (plu == (char *)NULL) { /* no dots, no underscores:  truncate at 8 */
            *pEndFAT += 8;         /* chars (could insert '.' and keep 11...) */
            if (*pEndFAT > pEnd)
                *pEndFAT = pEnd;   /* oops...didn't have 8 chars to truncate */
            else
                **pEndFAT = '\0';
        } else if (MIN(plu - pBegin, 8) + MIN(pEnd - plu - 1, 3) > 8) {
            last_dot = plu;        /* be lazy:  drop through to next if-block */
        } else if ((pEnd - *pEndFAT) > 8) {
            *pEndFAT += 8;         /* more fits into just basename than if */
            **pEndFAT = '\0';      /*  convert last underscore to dot */
        } else
            *pEndFAT = pEnd;       /* whole thing fits into 8 chars or less */
    }

    if (last_dot != (char *)NULL) {   /* one dot (or two, in the case of */
        *last_dot = '.';              /*  "..") is OK:  put it back in */

        if ((last_dot - pBegin) > 8) {
            char *p, *q;
            int i;

            p = last_dot;
            q = last_dot = pBegin + 8;
            for (i = 0;  (i < 4) && *p;  ++i)  /* too many chars in basename: */
                *q++ = *p++;                   /*  shift ".ext" left and */
            *q = '\0';                         /*  truncate/terminate it */
            *pEndFAT = q;
        } else if ((pEnd - last_dot) > 4) {    /* too many chars in extension */
            *pEndFAT = last_dot + 4;
            **pEndFAT = '\0';
        } else
            *pEndFAT = pEnd;   /* filename is fine; point at terminating zero */

        if ((last_dot - pBegin) > 0 && last_dot[-1] == ' ')
            last_dot[-1] = '_';                /* NO blank in front of '.'! */
    }
} /* end function map2fat() */





static int SetLongNameEA(char *name, char *longname)
{
  EAOP eaop;
  FEALST fealst;

  eaop.fpFEAList = (PFEALIST) &fealst;
  eaop.fpGEAList = NULL;
  eaop.oError = 0;

  strcpy((char *) fealst.szName, ".LONGNAME");
  strcpy((char *) fealst.szValue, longname);

  fealst.cbList  = sizeof(fealst) - CCHMAXPATH + strlen((char *) fealst.szValue);
  fealst.cbName  = (BYTE) strlen((char *) fealst.szName);
  fealst.cbValue = sizeof(USHORT) * 2 + strlen((char *) fealst.szValue);

#ifdef __32BIT__
  fealst.oNext   = 0;
#endif
  fealst.fEA     = 0;
  fealst.eaType  = 0xFFFD;
  fealst.eaSize  = strlen((char *) fealst.szValue);

  return DosSetPathInfo(name, FIL_QUERYEASIZE,
                        (PBYTE) &eaop, sizeof(eaop), 0);
}





/****************************/
/* Function close_outfile() */
/****************************/

           /* GRR:  need to return error level!! */

int close_outfile(__G)   /* only for extracted files, not directories */
    __GDEF
{
    int close_status = PK_OK;
    if (fclose(G.outfile) == EOF)
        close_status = PK_WARN;

    /* set extra fields, both stored-in-zipfile and .LONGNAME flavors */
    if (G.extra_field) {    /* zipfile extra field may have extended attribs */
        int err = EvalExtraFields(__G__ G.filename, G.extra_field,
                                  G.lrec.extra_field_length);

        if (err != PK_OK && close_status == PK_OK)
            close_status = PK_ERR;
        if (err != PK_OK && err != IZ_EF_TRUNC) {
            Info(slide, 0x401, ((char *)slide,
              "error:  OS/2 extended attribute/ACL restoration failed for %s\n",
              FnFilter1(G.filename)));
        }
        if (err == IZ_EF_TRUNC) {
            if (uO.qflag)
                Info(slide, 1, ((char *)slide, "%-22s ",
                  FnFilter1(G.filename)));
            Info(slide, 1, ((char *)slide, LoadFarString(TruncEAs),
              makeword(G.extra_field+2)-10, uO.qflag? "\n" : ""));
        }
    }

    if (G.os2.longnameEA) {
#ifdef DEBUG
        int e =
#endif
          SetLongNameEA(G.filename, G.os2.lastpathcomp);
        Trace((stderr, "close_outfile:  SetLongNameEA() returns %d\n", e));
        free(G.os2.lastpathcomp);
    }

    /* set date/time and permissions */
    SetPathAttrTimes(__G__ G.pInfo->file_attr, 0);

    return close_status;
} /* end function close_outfile() */





/******************************/
/* Function check_for_newer() */
/******************************/

int check_for_newer(__G__ filename)   /* return 1 if existing file newer or equal; */
    __GDEF
    char *filename;             /*  0 if older; -1 if doesn't exist yet */
{
    ulg existing, archive;
#ifdef USE_EF_UT_TIME
    iztimes z_utime;
#endif

    if ((existing = (ulg)GetFileTime(filename)) == (ulg)-1)
        return DOES_NOT_EXIST;

#ifdef USE_EF_UT_TIME
    if (G.extra_field &&
#ifdef IZ_CHECK_TZ
        G.tz_is_valid &&
#endif
        (ef_scan_for_izux(G.extra_field, G.lrec.extra_field_length, 0,
                          G.lrec.last_mod_dos_datetime, &z_utime, NULL)
         & EB_UT_FL_MTIME))
    {
        TTrace((stderr, "check_for_newer:  using Unix extra field mtime\n"));
        archive = Utime2DosDateTime(z_utime.mtime);
    } else {
        archive = G.lrec.last_mod_dos_datetime;
    }
#else /* !USE_EF_UT_TIME */
    archive = G.lrec.last_mod_dos_datetime;
#endif /* ?USE_EF_UT_TIME */

    return (existing >= archive);
} /* end function check_for_newer() */





#ifndef SFX

/*************************/
/* Function dateformat() */
/*************************/

int dateformat()
{
/*-----------------------------------------------------------------------------
  For those operating systems which support it, this function returns a value
  which tells how national convention says that numeric dates are displayed.
  Return values are DF_YMD, DF_DMY and DF_MDY.
 -----------------------------------------------------------------------------*/

    switch (GetCountryInfo()) {
        case 0:
            return DF_MDY;
        case 1:
            return DF_DMY;
        case 2:
            return DF_YMD;
    }
    return DF_MDY;   /* default if error */

} /* end function dateformat() */





/************************/
/*  Function version()  */
/************************/

void version(__G)
    __GDEF
{
    int len;
#if defined(__IBMC__) || defined(__WATCOMC__) || defined(_MSC_VER)
    char buf[80];
#endif

    len = sprintf((char *)slide, LoadFarString(CompiledWith),

#if defined(__GNUC__)
#  ifdef __EMX__  /* __EMX__ is defined as "1" only (sigh) */
      "emx+gcc ", __VERSION__,
#  else
      "gcc ", __VERSION__,
#  endif
#elif defined(__IBMC__)
      "IBM ",
#  if (__IBMC__ < 200)
      (sprintf(buf, "C Set/2 %d.%02d", __IBMC__/100,__IBMC__%100), buf),
#  elif (__IBMC__ < 300)
      (sprintf(buf, "C Set++ %d.%02d", __IBMC__/100,__IBMC__%100), buf),
#  else
      (sprintf(buf, "Visual Age C++ %d.%02d", __IBMC__/100,__IBMC__%100), buf),
#  endif
#elif defined(__WATCOMC__)
      "Watcom C", (sprintf(buf, " (__WATCOMC__ = %d)", __WATCOMC__), buf),
#elif defined(__TURBOC__)
#  ifdef __BORLANDC__
      "Borland C++",
#    if (__BORLANDC__ < 0x0460)
        " 1.0",
#    elif (__BORLANDC__ == 0x0460)
        " 1.5",                     /* from Kai Uwe:  three less than DOS */
#    else
        " 2.0",                     /* (__BORLANDC__ == 0x0500)? */
#    endif
#  else
      "Turbo C",                    /* these are probably irrelevant */
#    if (__TURBOC__ >= 661)
       "++ 1.0 or later",
#    elif (__TURBOC__ == 661)
       " 3.0?",
#    elif (__TURBOC__ == 397)
       " 2.0",
#    else
       " 1.0 or 1.5?",
#    endif
#  endif
#elif defined(MSC)
      "Microsoft C ",
#  ifdef _MSC_VER
      (sprintf(buf, "%d.%02d", _MSC_VER/100, _MSC_VER%100), buf),
#  else
      "5.1 or earlier",
#  endif
#else
      "unknown compiler", "",
#endif /* ?compilers */

      "OS/2",

/* GRR:  does IBM C/2 identify itself as IBM rather than Microsoft? */
#if (defined(MSC) || (defined(__WATCOMC__) && !defined(__386__)))
#  if defined(M_I86HM) || defined(__HUGE__)
      " (16-bit, huge)",
#  elif defined(M_I86LM) || defined(__LARGE__)
      " (16-bit, large)",
#  elif defined(M_I86MM) || defined(__MEDIUM__)
      " (16-bit, medium)",
#  elif defined(M_I86CM) || defined(__COMPACT__)
      " (16-bit, compact)",
#  elif defined(M_I86SM) || defined(__SMALL__)
      " (16-bit, small)",
#  elif defined(M_I86TM) || defined(__TINY__)
      " (16-bit, tiny)",
#  else
      " (16-bit)",
#  endif
#else
      " (32-bit)",
#endif

#ifdef __DATE__
      " on ", IZ_BUILD_DATE
#else
      "", ""
#endif
    );

    (*G.message)((zvoid *)&G, slide, (ulg)len, 0);
                                /* MSC can't handle huge macro expansions */

    /* temporary debugging code for Borland compilers only */
    /* __TCPLUSPLUS__, __BCPLUSPLUS__ not defined for v1.5 */
#if (defined(__TURBOC__) && defined(DEBUG))
    Info(slide, 0, ((char *)slide, "\t(__TURBOC__ = 0x%04x = %d)\n", __TURBOC__,
      __TURBOC__));
#ifdef __BORLANDC__
    Info(slide, 0, ((char *)slide, "\t(__BORLANDC__ = 0x%04x)\n",__BORLANDC__));
#else
    Info(slide, 0, ((char *)slide, "\tdebug(__BORLANDC__ not defined)\n"));
#endif
#endif /* __TURBOC__ && DEBUG */

} /* end function version() */

#endif /* !SFX */


#if defined(SET_DIR_ATTRIB) && defined(__32BIT__)
/* Restore directory write times after extracting children.  The old OS/2
 * mapname sets them too early, and later file creations modify them again.
 * Capture the native DOS time rather than relying on kLIBC/utime. */
typedef struct iz_os2_dirattr {
    struct iz_os2_dirattr *next;
    char *fn;
    ulg modify;
    ulg access;
    ulg create;
    unsigned mask;
    char name[1];
} iz_os2_dirattr;

int defer_dir_attribs(__G__ pd)
    __GDEF
    direntry **pd;
{
    size_t n;
    iz_os2_dirattr *p;
    unsigned flags;
    ulg mod=0,acc=0,cre=0;
    *pd=NULL;
    n=strlen(G.filename);
    if(n>=CCHMAXPATH)return PK_ERR;
    p=(iz_os2_dirattr *)malloc(sizeof(*p)+n);
    if(!p)return PK_MEM;
    memset(p,0,sizeof(*p)+n);
    p->fn=p->name;
    memcpy(p->fn,G.filename,n+1);
    flags=(unsigned)getOS2filetimes(__G__ &mod,&acc,&cre);
    p->modify=mod;
    p->access=acc;
    p->create=cre;
    p->mask=flags;
    if(!(flags&EB_UT_FL_MTIME))p->modify=G.lrec.last_mod_dos_datetime;
    *pd=(direntry *)p;
    return PK_OK;
}

int set_direc_attribs(__G__ d)
    __GDEF
    direntry *d;
{
    iz_os2_dirattr *p=(iz_os2_dirattr *)d;
    FILESTATUS3 fs;
    char name[CCHMAXPATH];
    size_t n;
    ULONG rc;
    if(uO.D_flag>0)return PK_OK;
    n=strlen(p->fn);
    if(n==0 || n>=sizeof(name))return PK_WARN;
    memcpy(name,p->fn,n+1);
    if(name[n-1]=='/' && (n<2 || name[n-2]!=':'))name[n-1]=0;
    rc=DosQueryPathInfo(name,FIL_STANDARD,&fs,sizeof(fs));
    if(rc!=NO_ERROR)return PK_WARN;
    fs.fdateLastWrite=((F_DATE_TIME *)&p->modify)->_fdt.fd;
    fs.ftimeLastWrite=((F_DATE_TIME *)&p->modify)->_fdt.ft;
    if(p->mask&EB_UT_FL_ATIME){
        fs.fdateLastAccess=((F_DATE_TIME *)&p->access)->_fdt.fd;
        fs.ftimeLastAccess=((F_DATE_TIME *)&p->access)->_fdt.ft;
    }
    if(p->mask&EB_UT_FL_CTIME){
        fs.fdateCreation=((F_DATE_TIME *)&p->create)->_fdt.fd;
        fs.ftimeCreation=((F_DATE_TIME *)&p->create)->_fdt.ft;
    }
    rc=DosSetPathInfo(name,FIL_STANDARD,&fs,sizeof(fs),0);
    if(rc!=NO_ERROR){
        fprintf(stderr,"unzip: cannot restore OS/2 directory time for %s (rc=%lu)\n",
                name,(unsigned long)rc);
        return PK_WARN;
    }
    return PK_OK;
}
#endif /* SET_DIR_ATTRIB && __32BIT__ */

#endif /* !FUNZIP */



#ifdef MY_ZCALLOC       /* Special zcalloc function for MEMORY16 (MSDOS/OS2) */

#if defined(MSC) || defined(__WATCOMC__)
#if (!defined(_MSC_VER) || (_MSC_VER < 700))
#  define _halloc  halloc
#  define _hfree   hfree
#endif

zvoid far *zcalloc (unsigned items, unsigned size)
{
    return (zvoid far *)_halloc((long)items, size);
}

zvoid zcfree (zvoid far *ptr)
{
    _hfree((void huge *)ptr);
}
#endif /* MSC || __WATCOMC__ */

#endif /* MY_ZCALLOC */



#ifndef FUNZIP

/* This table can be static because it is pseudo-constant */
static unsigned char cUpperCase[256], cLowerCase[256];
static BOOL bInitialized=FALSE;

/* Initialize the tables of upper- and lowercase characters, including
   handling of country-dependent characters. */

static void InitNLS(void)
{
  unsigned nCnt, nU;
  COUNTRYCODE cc;

  if (bInitialized == FALSE) {
    bInitialized = TRUE;

    for ( nCnt = 0; nCnt < 256; nCnt++ )
      cUpperCase[nCnt] = cLowerCase[nCnt] = (unsigned char) nCnt;

    cc.country = cc.codepage = 0;
    DosMapCase(sizeof(cUpperCase), &cc, (PCHAR) cUpperCase);

    for ( nCnt = 0; nCnt < 256; nCnt++ ) {
      nU = cUpperCase[nCnt];
      if (nU != nCnt && cLowerCase[nU] == (unsigned char) nU)
        cLowerCase[nU] = (unsigned char) nCnt;
    }

    for ( nCnt = 'A'; nCnt <= 'Z'; nCnt++ )
      cLowerCase[nCnt] = (unsigned char) (nCnt - 'A' + 'a');
  }
}


int IsUpperNLS(int nChr)
{
  return (cUpperCase[nChr] == (unsigned char) nChr);
}


int ToLowerNLS(int nChr)
{
  return cLowerCase[nChr];
}


char *StringLower(char *szArg)
{
  unsigned char *szPtr;

  for ( szPtr = (unsigned char *) szArg; *szPtr; szPtr++ )
    *szPtr = cLowerCase[*szPtr];
  return szArg;
}


#ifdef MORE
int screensize(int *tt_rows, int *tt_cols)
{
#ifdef __EMX__
  int dst[2];
  _scrsize(dst);
  if (tt_rows != NULL) *tt_rows = dst[1];
  if (tt_cols != NULL) *tt_cols = dst[0];
#else
  VIOMODEINFO vmi;
  vmi.cb = sizeof(vmi);
  VioGetMode(&vmi, 0);
  if (tt_rows != NULL) *tt_rows = vmi.row;
  if (tt_cols != NULL) *tt_cols = vmi.col;
#endif
  return 0;
}
#endif /* MORE */


#if defined(__IBMC__) && defined(__DEBUG_ALLOC__)
void DebugMalloc(void)
{
  _dump_allocated(0); /* print out debug malloc memory statistics */
}
#endif


#if defined(REENTRANT) && defined(USETHREADID)
ulg GetThreadId(void)
{
  PTIB   pptib;       /* Address of a pointer to the
                         Thread Information Block */
  PPIB   pppib;       /* Address of a pointer to the
                         Process Information Block */

  DosGetInfoBlocks(&pptib, &pppib);
  return pptib->tib_ptib2->tib2_ultid;
}
#endif /* defined(REENTRANT) && defined(USETHREADID) */


void os2GlobalsCtor(__GPRO)
{
  G.os2.nLastDrive = (USHORT)(-1);

#ifdef OS2DLL
  G.os2.rexx_mes = "0";
#endif

  InitNLS();
}

#endif /* !FUNZIP */
