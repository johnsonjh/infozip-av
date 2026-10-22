/*
 * @(#)dir.c 1.4 87/11/06 Public Domain.
 *
 *  A public domain implementation of BSD directory routines for
 *  MS-DOS.  Written by Michael Rendell ({uunet,utai}michael@garfield),
 *  August 1987
 *
 *  Ported to OS/2 by Kai Uwe Rommel
 *  Addition of other OS/2 file system specific code
 *  Placed into the public domain
 */

/* does also contain EA access code for use in ZIP */


#ifdef OS2


#if defined(__EMX__) && !defined(__32BIT__)
#  define __32BIT__
#endif

#include "zip.h"

#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#ifndef __BORLANDC__
#include <malloc.h>
#endif

#define INCL_NOPM
#define INCL_DOSNLS
#define INCL_DOSERRORS
#include <os2.h>

#include "os2zip.h"
#include "os2acl.h"


#ifndef max
#define max(a, b) ((a) < (b) ? (b) : (a))
#endif


#ifdef __32BIT__
#define DosFindFirst(p1, p2, p3, p4, p5, p6) \
        DosFindFirst(p1, p2, p3, p4, p5, p6, 1)
#else
#define DosQueryCurrentDisk DosQCurDisk
#define DosQueryFSAttach(p1, p2, p3, p4, p5) \
        DosQFSAttach(p1, p2, p3, p4, p5, 0)
#define DosQueryFSInfo(d, l, b, s) \
        DosQFSInfo(d, l, b, s)
#define DosQueryPathInfo(p1, p2, p3, p4) \
        DosQPathInfo(p1, p2, p3, p4, 0)
#define DosSetPathInfo(p1, p2, p3, p4, p5) \
        DosSetPathInfo(p1, p2, p3, p4, p5, 0)
#define DosEnumAttribute(p1, p2, p3, p4, p5, p6, p7) \
        DosEnumAttribute(p1, p2, p3, p4, p5, p6, p7, 0)
#define DosFindFirst(p1, p2, p3, p4, p5, p6) \
        DosFindFirst(p1, p2, p3, p4, p5, p6, 0)
#define DosMapCase DosCaseMap
#endif


#ifndef UTIL

extern int noisy;

#ifndef S_IFMT
#define S_IFMT 0xF000
#endif

static int attributes = _A_DIR | _A_HIDDEN | _A_SYSTEM;

static char *getdirent(char *);
static void free_dircontents(struct _dircontents *);

#ifdef __32BIT__
static HDIR hdir;
static ULONG count;
static FILEFINDBUF3 find;
#else
static HDIR hdir;
static USHORT count;
static FILEFINDBUF find;
#endif

DIR *opendir(const char *name)
{
  struct stat statb;
  DIR *dirp;
  char c;
  char *s;
  struct _dircontents *dp;
  char nbuf[MAXPATHLEN + 1];
  int len;

  attributes = hidden_files ? (_A_DIR | _A_HIDDEN | _A_SYSTEM) : _A_DIR;

  strcpy(nbuf, name);
  if ((len = strlen(nbuf)) == 0)
    return NULL;

  if (((c = nbuf[len - 1]) == '\\' || c == '/') && (len > 1))
  {
    nbuf[len - 1] = 0;
    --len;

    if (nbuf[len - 1] == ':')
    {
      strcpy(nbuf+len, "\\.");
      len += 2;
    }
  }
  else
    if (nbuf[len - 1] == ':')
    {
      strcpy(nbuf+len, ".");
      ++len;
    }

#ifndef __BORLANDC__
  /* when will we ever see a Borland compiler that can properly stat !!! */
  if (stat(nbuf, &statb) < 0 || (statb.st_mode & S_IFMT) != S_IFDIR)
    return NULL;
#endif

  if ((dirp = malloc(sizeof(DIR))) == NULL)
    return NULL;

  if (nbuf[len - 1] == '.' && (len == 1 || nbuf[len - 2] != '.'))
    strcpy(nbuf+len-1, "*.*");
  else
    if (((c = nbuf[len - 1]) == '\\' || c == '/') && (len == 1))
      strcpy(nbuf+len, "*");
    else
      strcpy(nbuf+len, "\\*");

  /* len is no longer correct (but no longer needed) */

  dirp -> dd_loc = 0;
  dirp -> dd_contents = dirp -> dd_cp = NULL;

  if ((s = getdirent(nbuf)) == NULL)
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

    dp -> _d_size = find.cbFile;
    dp -> _d_mode = find.attrFile;
    dp -> _d_time = *(unsigned *) &(find.ftimeLastWrite);
    dp -> _d_date = *(unsigned *) &(find.fdateLastWrite);
  }
  while ((s = getdirent(NULL)) != NULL);

  dirp -> dd_cp = dirp -> dd_contents;

  return dirp;
}

void closedir(DIR * dirp)
{
  free_dircontents(dirp -> dd_contents);
  free(dirp);
}

struct dirent *readdir(DIR * dirp)
{
  static struct dirent dp;

  if (dirp -> dd_cp == NULL)
    return NULL;

  dp.d_namlen = dp.d_reclen =
    strlen(strcpy(dp.d_name, dirp -> dd_cp -> _d_entry));

  dp.d_ino = 0;

  dp.d_size = dirp -> dd_cp -> _d_size;
  dp.d_mode = dirp -> dd_cp -> _d_mode;
  dp.d_time = dirp -> dd_cp -> _d_time;
  dp.d_date = dirp -> dd_cp -> _d_date;

  dirp -> dd_cp = dirp -> dd_cp -> _d_next;
  dirp -> dd_loc++;

  return &dp;
}

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

static char *getdirent(char *dir)
{
  int done;
  static int lower;

  if (dir != NULL)
  {                                    /* get first entry */
    hdir = HDIR_SYSTEM;
    count = 1;
    done = DosFindFirst(dir, &hdir, attributes, &find, sizeof(find), &count);
    lower = IsFileSystemFAT(dir);
  }
  else                                 /* get next entry */
    done = DosFindNext(hdir, &find, sizeof(find), &count);

  if (done == 0)
  {
    if (lower)
      StringLower(find.achName);
    return find.achName;
  }
  else
  {
    DosFindClose(hdir);
    return NULL;
  }
}

/* FAT / HPFS detection */

int IsFileSystemFAT(char *dir)
{
  static USHORT nLastDrive = -1, nResult;
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
     i.e. support long file names and being case sensitive */

  if (isalpha(dir[0]) && (dir[1] == ':'))
    nDrive = to_up(dir[0]) - '@';
  else
    DosQueryCurrentDisk(&nDrive, &lMap);

  if (nDrive == nLastDrive)
    return nResult;

  bName[0] = (char) (nDrive + '@');
  bName[1] = ':';
  bName[2] = 0;

  nLastDrive = nDrive;
  cbData = sizeof(bData);

  if (!DosQueryFSAttach(bName, 0, FSAIL_QUERYNAME, (PVOID) pData, &cbData))
    nResult = !strcmp((char *) pData -> szFSDName + pData -> cbName, "FAT");
  else
    nResult = FALSE;

  /* End of this ugly code */
  return nResult;
}

/* access mode bits and time stamp */

int GetFileMode(char *name)
{
#ifdef __32BIT__
  FILESTATUS3 fs;
  return DosQueryPathInfo(name, 1, &fs, sizeof(fs)) ? -1 : fs.attrFile;
#else
  USHORT mode;
  return DosQFileMode(name, &mode, 0L) ? -1 : mode;
#endif
}

ulg GetFileTime(char *name)
{
#ifdef __32BIT__
  FILESTATUS3 fs;
#else
  FILESTATUS fs;
#endif
  USHORT nDate, nTime;
  DATETIME dtCurrent;

  if (strcmp(name, "-") == 0)
  {
    DosGetDateTime(&dtCurrent);
    fs.fdateLastWrite.day     = dtCurrent.day;
    fs.fdateLastWrite.month   = dtCurrent.month;
    fs.fdateLastWrite.year    = dtCurrent.year - 1980;
    fs.ftimeLastWrite.hours   = dtCurrent.hours;
    fs.ftimeLastWrite.minutes = dtCurrent.minutes;
    fs.ftimeLastWrite.twosecs = dtCurrent.seconds / 2;
  }
  else
    if (DosQueryPathInfo(name, 1, (PBYTE) &fs, sizeof(fs)))
      return -1;

  nDate = * (USHORT *) &fs.fdateLastWrite;
  nTime = * (USHORT *) &fs.ftimeLastWrite;

  return ((ULONG) nDate) << 16 | nTime;
}

void SetFileTime(char *path, ulg stamp)
{
#ifdef __32BIT__
  FILESTATUS3 fs;
#else
  FILESTATUS fs;
#endif
  USHORT fd, ft;

  if (DosQueryPathInfo(path, FIL_STANDARD, (PBYTE) &fs, sizeof(fs)))
    return;

  fd = (USHORT) (stamp >> 16);
  ft = (USHORT) stamp;
  fs.fdateLastWrite = fs.fdateCreation = * (FDATE *) &fd;
  fs.ftimeLastWrite = fs.ftimeCreation = * (FTIME *) &ft;

  DosSetPathInfo(path, FIL_STANDARD, (PBYTE) &fs, sizeof(fs), 0);
}

/* read volume label */

char *getVolumeLabel(int drive, unsigned long *vtime, unsigned long *vmode,
                     time_t *utim)
{
  static FSINFO fi;

  if (DosQueryFSInfo(drive ? drive - 'A' + 1 : 0,
                     FSIL_VOLSER, (PBYTE) &fi, sizeof(fi)))
    return NULL;

  time(utim);
  *vtime = unix2dostime(utim);
  *vmode = _A_VOLID | _A_ARCHIVE;

  return (fi.vol.cch > 0) ? fi.vol.szVolLabel : NULL;
}

/* FAT / HPFS name conversion stuff */

int IsFileNameValid(char *name)
{
  HFILE hf;
#ifdef __32BIT__
  ULONG uAction;
#else
  USHORT uAction;
#endif

  switch(DosOpen(name, &hf, &uAction, 0, 0, FILE_OPEN,
                 OPEN_ACCESS_READONLY | OPEN_SHARE_DENYNONE, 0))
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

void ChangeNameForFAT(char *name)
{
  char *src, *dst, *next, *ptr, *dot, *start;
  static char invalid[] = ":;,=+\"[]<>| \t";

  if (isalpha(name[0]) && (name[1] == ':'))
    start = name + 2;
  else
    start = name;

  src = dst = start;
  if ((*src == '/') || (*src == '\\'))
    src++, dst++;

  while (*src)
  {
    for (next = src; *next && (*next != '/') && (*next != '\\'); next++);

    for (ptr = src, dot = NULL; ptr < next; ptr++)
      if (*ptr == '.')
      {
        dot = ptr; /* remember last dot */
        *ptr = '_';
      }

    if (dot == NULL)
      for (ptr = src; ptr < next; ptr++)
        if (*ptr == '_')
          dot = ptr; /* remember last _ as if it were a dot */

    if (dot && (dot > src) &&
        ((next - dot <= 4) ||
         ((next - src > 8) && (dot - src > 3))))
    {
      if (dot)
        *dot = '.';

      for (ptr = src; (ptr < dot) && ((ptr - src) < 8); ptr++)
        *dst++ = *ptr;

      for (ptr = dot; (ptr < next) && ((ptr - dot) < 4); ptr++)
        *dst++ = *ptr;
    }
    else
    {
      if (dot && (next - src == 1))
        *dot = '.';           /* special case: "." as a path component */

      for (ptr = src; (ptr < next) && ((ptr - src) < 8); ptr++)
        *dst++ = *ptr;
    }

    *dst++ = *next; /* either '/' or 0 */

    if (*next)
    {
      src = next + 1;

      if (*src == 0) /* handle trailing '/' on dirs ! */
        *dst = 0;
    }
    else
      break;
  }

  for (src = start; *src != 0; ++src)
    if ((strchr(invalid, *src) != NULL) || (*src == ' '))
      *src = '_';
}

/* .LONGNAME EA code */

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

typedef struct
{
  ULONG cbList;
#ifdef __32BIT__
  ULONG oNext;
#endif
  BYTE cbName;
  BYTE szName[10];            /* ".LONGNAME" */
}
GEALST;

char *GetLongNameEA(const char *name)
{
  EAOP eaop;
  GEALST gealst;
  static FEALST fealst;
  char *ptr;

  eaop.fpGEAList = (PGEALIST) &gealst;
  eaop.fpFEAList = (PFEALIST) &fealst;
  eaop.oError = 0;

  strcpy((char *) gealst.szName, ".LONGNAME");
  gealst.cbName  = (BYTE) strlen((char *) gealst.szName);
#ifdef __32BIT__
  gealst.oNext   = 0;
#endif

  gealst.cbList  = sizeof(gealst);
  fealst.cbList  = sizeof(fealst);

  if (DosQueryPathInfo(name, FIL_QUERYEASFROMLIST,
                       (PBYTE) &eaop, sizeof(eaop)))
    return NULL;

  if (fealst.cbValue > 4 && fealst.eaType == 0xFFFD)
  {
    fealst.szValue[fealst.eaSize] = 0;

    for (ptr = fealst.szValue; *ptr; ptr++)
      if (*ptr == '/' || *ptr == '\\')
        *ptr = '!';

    return (char *) fealst.szValue;
  }

  return NULL;
}

char *GetLongPathEA(const char *name)
{
  static char nbuf[CCHMAXPATH + 1];
  char tempbuf[CCHMAXPATH + 1];
  char *comp, *next, *ea, sep;
  BOOL bFound = FALSE;

  nbuf[0] = 0;
  strncpy(tempbuf, name, CCHMAXPATH);
  tempbuf[CCHMAXPATH] = '\0';
  next = tempbuf;

  while (*next)
  {
    comp = next;

    while (*next != '\\' && *next != '/' && *next != 0)
      next++;

    sep = *next;
    *next = 0;

    ea = GetLongNameEA(tempbuf);
    strcat(nbuf, ea ? ea : comp);
    bFound = bFound || (ea != NULL);

    if (sep)
    {
      strcat(nbuf, "\\");
      *next++ = sep;
    }
  }

  return (nbuf[0] != 0) && bFound ? nbuf : NULL;
}

/* general EA code */

typedef struct
{
  USHORT nID;
  USHORT nSize;
  ULONG lSize;
}
EFHEADER, *PEFHEADER;

#ifdef __32BIT__

/* Perhaps due to bugs in the current OS/2 2.0 kernel, the success or
   failure of the DosEnumAttribute() and DosQueryPathInfo() system calls
   depends on the area where the return buffers are allocated. This
   differs for the various compilers, for some alloca() works, for some
   malloc() works, for some, both work. We'll have to live with that. */

/* The use of malloc() is not very convenient, because it requires
   backtracking (i.e. free()) at error returns. We do that for system
   calls that may fail, but not for malloc() calls, because they are VERY
   unlikely to fail. If ever, we just leave some memory allocated
   over the usually short lifetime of a zip process ... */

#ifdef __GNUC__
#define alloc(x) alloca(x)
#define unalloc(x)
#else
#define alloc(x) malloc(x)
#define unalloc(x) free(x)
#endif

int GetEAs(char *path, char **bufptr, size_t *size,
                        char **cbufptr, size_t *csize)
{
  FILESTATUS4 fs;
  PDENA2 pDENA, pFound;
  EAOP2 eaop;
  PGEA2 pGEA, pPrevious = NULL;
  PGEA2LIST pGEAlist;
  PFEA2LIST pFEAlist;
  PEFHEADER pEAblock;
  ULONG ulAttributes, ulMemoryBlock;
  ULONG nLength;
  ULONG nBlock;
  APIRET api_rc;
  PEFHEADER central_block;
  char szName[CCHMAXPATH];

  *size = *csize = 0;

  if(!path || !*path || strlen(path)>=sizeof(szName))return -1;
  strcpy(szName, path);
  nLength = strlen(szName);
  if (szName[nLength - 1] == '/')
    szName[nLength - 1] = 0;

  api_rc=DosQueryPathInfo(szName,FIL_QUERYEASIZE,(PBYTE)&fs,sizeof(fs));
  if(api_rc==ERROR_EAS_NOT_SUPPORTED)return 0;
  if(api_rc!=NO_ERROR)return -1;
  if(fs.cbList>16UL*1024UL*1024UL)return -1;
  nBlock = max(fs.cbList, 65535);
  if ((pDENA = alloc((size_t) nBlock)) == NULL)
    return -1;

  ulAttributes = -1;

  api_rc=DosEnumAttribute(ENUMEA_REFTYPE_PATH,szName,1,pDENA,nBlock,
                           &ulAttributes,ENUMEA_LEVEL_NO_VALUE);
  if(api_rc==ERROR_EAS_NOT_SUPPORTED ||
     (api_rc==NO_ERROR && ulAttributes==0)){
    unalloc(pDENA);
    return 0;
  }
  if(api_rc!=NO_ERROR){unalloc(pDENA);return -1;}
  if((pGEAlist=alloc((size_t)nBlock))==NULL){
    unalloc(pDENA);return -1;
  }

  pGEA = pGEAlist -> list;
  memset(pGEAlist, 0, nBlock);
  pFound = pDENA;

  while (ulAttributes--)
  {
    if (!(strcmp(pFound -> szName, ".LONGNAME") == 0 && use_longname_ea))
    {
      pGEA -> cbName = pFound -> cbName;
      strcpy(pGEA -> szName, pFound -> szName);

      nLength = sizeof(GEA2) + strlen(pGEA -> szName);
      nLength = ((nLength - 1) / sizeof(ULONG) + 1) * sizeof(ULONG);

      /* oNextEntryOffset must link the *included* GEA records.  When
       * .LONGNAME is intentionally omitted it may be the last enumerated
       * EA; the old ulAttributes-based test left a dangling next offset. */
      if (pPrevious != NULL)
        pPrevious -> oNextEntryOffset = (ULONG)((PCH)pGEA-(PCH)pPrevious);
      pGEA -> oNextEntryOffset = 0;
      pPrevious = pGEA;
      pGEA   = (PGEA2)  ((PCH) pGEA + nLength);
    }

    pFound = (PDENA2) ((PCH) pFound + pFound -> oNextEntryOffset);
  }

  if (pGEA == pGEAlist -> list) /* no attributes to save */
  {
    unalloc(pDENA);
    unalloc(pGEAlist);
    return 0;
  }

  pGEAlist -> cbList = (PCH) pGEA - (PCH) pGEAlist;

  pFEAlist = (PVOID) pDENA;  /* reuse buffer */
  pFEAlist -> cbList = nBlock;

  eaop.fpGEA2List = pGEAlist;
  eaop.fpFEA2List = pFEAlist;
  eaop.oError = 0;

  if (DosQueryPathInfo(szName, FIL_QUERYEASFROMLIST,
                       (PBYTE) &eaop, sizeof(eaop)))
  {
    unalloc(pDENA);
    unalloc(pGEAlist);
    return -1;
  }

  /* The maximum compressed size is (in case of STORE type) the
     uncompressed size plus the size of the compression type field
     plus the size of the CRC field + 2*5 deflate overhead bytes
     for uncompressable data.
     (5 bytes per 32Kb block, max compressed size = 2 blocks) */

  ulAttributes = pFEAlist -> cbList;
  if(ulAttributes<4U || ulAttributes>16UL*1024UL*1024UL){
    unalloc(pDENA);unalloc(pGEAlist);return -1;
  }
  ulMemoryBlock = ulAttributes +
                  sizeof(USHORT) + sizeof(ULONG) + EB_DEFLAT_EXTRA;
  pEAblock = (PEFHEADER) malloc(sizeof(EFHEADER) + ulMemoryBlock);

  if (pEAblock == NULL)
  {
    unalloc(pDENA);
    unalloc(pGEAlist);
    return -1;
  }

  *bufptr = (char *) pEAblock;
  *size = sizeof(EFHEADER);

  pEAblock -> nID = EF_OS2EA;
  pEAblock -> nSize = sizeof(pEAblock -> lSize);
  pEAblock -> lSize = ulAttributes; /* uncompressed size */

  nLength = memcompress((char *) (pEAblock + 1), ulMemoryBlock,
                        (char *) pFEAlist, ulAttributes);
  if(nLength==0 || nLength>65535UL-sizeof(ULONG)){
    free(pEAblock);*bufptr=NULL;*size=0;
    unalloc(pDENA);unalloc(pGEAlist);
    /* Distinguish format capacity from native EA read/compression errors.
     * Xtro can retain the complete set when legacy 0x0009 will not fit. */
    return nLength? -2 : -1;
  }
  *size += nLength;
  pEAblock -> nSize += nLength;

  central_block=(PEFHEADER)malloc(sizeof(EFHEADER));
  if(central_block==NULL){
    free(pEAblock);*bufptr=NULL;*size=0;
    unalloc(pDENA);unalloc(pGEAlist);return -1;
  }
  *cbufptr = (char *) central_block;
  *csize = sizeof(EFHEADER);
  central_block -> nID = EF_OS2EA;
  central_block -> nSize = sizeof(central_block -> lSize);
  central_block -> lSize = ulAttributes;

  if (noisy)
    printf(" (%ld bytes EA's)", ulAttributes);

  unalloc(pDENA);
  unalloc(pGEAlist);
  return 0;
}

#else /* !__32BIT__ */

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

void GetEAs(char *path, char **bufptr, size_t *size,
                        char **cbufptr, size_t *csize)
{
  FILESTATUS2 fs;
  PDENA1 pDENA, pFound;
  EAOP eaop;
  PGEALIST pGEAlist;
  PGEA pGEA;
  PFEALIST pFEAlist;
  PFEA pFEA;
  PFEA2LIST pFEA2list;
  PFEA2 pFEA2;
  EFHEADER *pEAblock;
  ULONG ulAttributes;
  USHORT nLength, nMaxSize;
  char szName[CCHMAXPATH];

  *size = *csize = 0;

  strcpy(szName, path);
  nLength = strlen(szName);
  if (szName[nLength - 1] == '/')
    szName[nLength - 1] = 0;

  if (DosQueryPathInfo(szName, FIL_QUERYEASIZE, (PBYTE) &fs, sizeof(fs))
      || fs.cbList <= 2 * sizeof(ULONG))
    return;

  ulAttributes = -1;
  nMaxSize = (USHORT) min(fs.cbList * 2, 65520L);

  if ((pDENA = malloc((size_t) nMaxSize)) == NULL)
    return;

  if (DosEnumAttribute(ENUMEA_REFTYPE_PATH, szName, 1, pDENA, fs.cbList,
                       &ulAttributes, ENUMEA_LEVEL_NO_VALUE)
    || ulAttributes == 0
    || (pGEAlist = malloc(nMaxSize)) == NULL)
  {
    free(pDENA);
    return;
  }

  pGEA = pGEAlist -> list;
  pFound = pDENA;

  while (ulAttributes--)
  {
    nLength = strlen(pFound -> szName);

    if (!(strcmp(pFound -> szName, ".LONGNAME") == 0 && use_longname_ea))
    {
      pGEA -> cbName = pFound -> cbName;
      strcpy(pGEA -> szName, pFound -> szName);

      pGEA++;
      pGEA = (PGEA) (((PCH) pGEA) + nLength);
    }

    pFound++;
    pFound = (PDENA1) (((PCH) pFound) + nLength);
  }

  if (pGEA == pGEAlist -> list)
  {
    free(pDENA);
    free(pGEAlist);
    return;
  }

  pGEAlist -> cbList = (PCH) pGEA - (PCH) pGEAlist;

  pFEAlist = (PFEALIST) pDENA; /* reuse buffer */
  pFEAlist -> cbList = fs.cbList;
  pFEA = pFEAlist -> list;

  eaop.fpGEAList = pGEAlist;
  eaop.fpFEAList = pFEAlist;
  eaop.oError = 0;

  if (DosQueryPathInfo(szName, FIL_QUERYEASFROMLIST,
                       (PBYTE) &eaop, sizeof(eaop)))
  {
    free(pDENA);
    free(pGEAlist);
    return;
  }

  /* now convert into new OS/2 2.0 32-bit format */

  pFEA2list = (PFEA2LIST) pGEAlist;  /* reuse buffer */
  pFEA2 = pFEA2list -> list;

  while ((PCH) pFEA - (PCH) pFEAlist < pFEAlist -> cbList)
  {
    nLength = sizeof(FEA) + pFEA -> cbName + 1 + pFEA -> cbValue;
    memcpy((PCH) pFEA2 + sizeof(pFEA2 -> oNextEntryOffset), pFEA, nLength);
    memset((PCH) pFEA2 + sizeof(pFEA2 -> oNextEntryOffset) + nLength, 0, 3);
    pFEA = (PFEA) ((PCH) pFEA + nLength);

    nLength = sizeof(FEA2) + pFEA2 -> cbName + 1 + pFEA2 -> cbValue;
    nLength = ((nLength - 1) / sizeof(ULONG) + 1) * sizeof(ULONG);
    /* rounded up to 4-byte boundary */
    pFEA2 -> oNextEntryOffset =
      ((PCH) pFEA - (PCH) pFEAlist < pFEAlist -> cbList) ? nLength : 0;
    pFEA2 = (PFEA2) ((PCH) pFEA2 + nLength);
  }

  pFEA2list -> cbList = (PCH) pFEA2 - (PCH) pFEA2list;
  ulAttributes = pFEA2list -> cbList;

  pEAblock = (PEFHEADER) pDENA; /* reuse buffer */

  *bufptr = (char *) pEAblock;
  *size = sizeof(EFHEADER);

  pEAblock -> nID = EF_OS2EA;
  pEAblock -> nSize = sizeof(pEAblock -> lSize);
  pEAblock -> lSize = ulAttributes; /* uncompressed size */

  nLength = (USHORT) memcompress((char *) (pEAblock + 1),
    nMaxSize - sizeof(EFHEADER), (char *) pFEA2list, ulAttributes);

  *size += nLength;
  pEAblock -> nSize += nLength;

  pEAblock = (PEFHEADER) pGEAlist;

  *cbufptr = (char *) pEAblock;
  *csize = sizeof(EFHEADER);

  pEAblock -> nID = EF_OS2EA;
  pEAblock -> nSize = sizeof(pEAblock -> lSize);
  pEAblock -> lSize = ulAttributes;

  if (noisy)
    printf(" (%ld bytes EA's)", ulAttributes);
}

#endif /* __32BIT__ */

/* Preserve ACLs without modifying either extra field until both new
 * buffers, the compressed payload, and the resulting ZIP lengths are valid.
 * The original void helper silently lost ACLs on allocation/size failures. */
int GetACL(char *path, char **bufptr, size_t *size,
           char **cbufptr, size_t *csize)
{
  static char *buffer;
  char *localnew, *centralnew, *nul;
  long bytes, cbytes;
  size_t capacity, local_total, central_total;
  PEFHEADER block;

  if (buffer == NULL) {
    buffer = malloc(ACL_BUFFERSIZE);
    if (buffer == NULL) return -1;
  }
  if (acl_get(NULL, path, buffer)) return 0; /* no LAN ACL available */
  nul = memchr(buffer, '\0', ACL_BUFFERSIZE);
  if (nul == NULL) return -1;
  bytes = (long)(nul - buffer);
  /* Empty ACLs carry no useful data.  Preserve nonempty ACLs completely. */
  if (bytes == 0) return 0;
  if (bytes > 65535L - (long)sizeof(EFHEADER) -
                       (long)sizeof(ULONG) - (long)EB_DEFLAT_EXTRA -
                       (long)sizeof(USHORT)) return -1;
  capacity = (size_t)bytes + sizeof(USHORT) + sizeof(ULONG) + EB_DEFLAT_EXTRA;
  if (*size > 65535U - sizeof(EFHEADER) - capacity ||
      *csize > 65535U - sizeof(EFHEADER)) return -1;
  local_total = *size + sizeof(EFHEADER) + capacity;
  central_total = *csize + sizeof(EFHEADER);
  localnew = malloc(local_total);
  if (!localnew) return -1;
  centralnew = malloc(central_total);
  if (!centralnew) { free(localnew); return -1; }
  if (*size && *bufptr) memcpy(localnew, *bufptr, *size);
  if (*csize && *cbufptr) memcpy(centralnew, *cbufptr, *csize);
  block = (PEFHEADER)(localnew + *size);
  cbytes = memcompress((char *)(block + 1), (ulg)capacity, buffer, (ulg)bytes);
  if (cbytes <= 0 || (size_t)cbytes > capacity ||
      *size + sizeof(EFHEADER) + (size_t)cbytes > 65535U ||
      sizeof(ULONG) + (size_t)cbytes > 65535U) {
    free(localnew); free(centralnew); return -1;
  }
  block->nID = EF_ACL;
  block->nSize = (USHORT)(sizeof(ULONG) + (size_t)cbytes);
  block->lSize = (ULONG)bytes;
  block = (PEFHEADER)(centralnew + *csize);
  block->nID = EF_ACL;
  block->nSize = sizeof(ULONG);
  block->lSize = (ULONG)bytes;
  free(*bufptr);
  free(*cbufptr);
  *bufptr = localnew;
  *cbufptr = centralnew;
  *size += sizeof(EFHEADER) + (size_t)cbytes;
  *csize = central_total;
  if (noisy) printf(" (%ld bytes ACL)", bytes);
  return 0;
}

#ifdef USE_EF_UT_TIME

int GetExtraTime(struct zlist far *z, iztimes *z_utim)
{
  int eb_c_size = EB_HEADSIZE + EB_UT_LEN(1);
  int eb_l_size = eb_c_size;
  char *eb_c_ptr;
  char *eb_l_ptr;
  unsigned long ultime;

#ifdef IZ_CHECK_TZ
  if (!zp_tz_is_valid) return ZE_OK;    /* skip silently no correct tz info */
#endif

  /* ZIP extra-field lengths are 16-bit even in the 32-bit OS/2 port.
   * Validate BOTH totals before modifying either buffer. */
  if (z_utim->mtime != z_utim->atime || z_utim->mtime != z_utim->ctime)
    eb_l_size = EB_HEADSIZE + EB_UT_LEN(3);
  if ((size_t)z->cext + (size_t)eb_c_size > 65535U ||
      (size_t)z->ext + (size_t)eb_l_size > 65535U)
    return ZE_BIG;

  eb_c_ptr = realloc(z->cextra, (z->cext + eb_c_size));
  if (eb_c_ptr == NULL)
    return ZE_MEM;
  z->cextra = eb_c_ptr;
  eb_c_ptr += z->cext;
  z->cext += eb_c_size;

  eb_c_ptr[0]  = 'U';
  eb_c_ptr[1]  = 'T';
  eb_c_ptr[2]  = EB_UT_LEN(1);          /* length of data part of e.f. */
  eb_c_ptr[3]  = 0;
  eb_c_ptr[4]  = EB_UT_FL_MTIME;
  ultime = (unsigned long) z_utim->mtime;
  eb_c_ptr[5]  = (char)(ultime);
  eb_c_ptr[6]  = (char)(ultime >> 8);
  eb_c_ptr[7]  = (char)(ultime >> 16);
  eb_c_ptr[8]  = (char)(ultime >> 24);

  if (z_utim->mtime != z_utim->atime || z_utim->mtime != z_utim->ctime)
  {
    eb_c_ptr[4]  = EB_UT_FL_MTIME | EB_UT_FL_ATIME | EB_UT_FL_CTIME;
    eb_l_size = EB_HEADSIZE + EB_UT_LEN(3); /* only on HPFS they can differ */
  /* so only then it makes sense to store all three time stamps */
  }

  eb_l_ptr = realloc(z->extra, (z->ext + eb_l_size));
  if (eb_l_ptr == NULL)
    return ZE_MEM;
  z->extra = eb_l_ptr;
  eb_l_ptr += z->ext;
  z->ext += eb_l_size;

  memcpy(eb_l_ptr, eb_c_ptr, eb_c_size);

  if (eb_l_size > eb_c_size)
  {
    eb_l_ptr[2]  = EB_UT_LEN(3);
    ultime = (unsigned long) z_utim->atime;
    eb_l_ptr[9]  = (char)(ultime);
    eb_l_ptr[10] = (char)(ultime >> 8);
    eb_l_ptr[11] = (char)(ultime >> 16);
    eb_l_ptr[12] = (char)(ultime >> 24);
    ultime = (unsigned long) z_utim->ctime;
    eb_l_ptr[13] = (char)(ultime);
    eb_l_ptr[14] = (char)(ultime >> 8);
    eb_l_ptr[15] = (char)(ultime >> 16);
    eb_l_ptr[16] = (char)(ultime >> 24);
  }

  return ZE_OK;
}

#endif /* USE_EF_UT_TIME */

int set_extra_field(struct zlist far *z, iztimes *z_utim)
{
  /* store EA data in local header, and size only in central headers */
  size_t ext_len = 0, cext_len = 0;
  const char *metadata_name=z->name;
#ifdef XTR_OS2_NATIVE
  extern int xtr_zip_is_stage(const char *,const char *);
  extern int xtr_zip_xattrs;
#endif
#ifdef OS2_KLIBC_SYMLINKS
  char resolved[1024];
#endif
#ifdef XTR_OS2_NATIVE
  if(xtr_zip_is_stage(z->name,z->iname))return ZE_OK;
#endif
#ifdef OS2_KLIBC_SYMLINKS
  if (!linkput) {
    if (iz_os2_link_resolve(z->name,resolved,sizeof(resolved),1))return ZE_OPEN;
    metadata_name=resolved;
  }
#endif
#ifdef XTR_OS2_NATIVE
  /* ZIP extra fields are plaintext even when the member itself is AES-
   * encrypted. Confidential Xtro metadata MUST NOT be copied into 0x0009.
   * Native capture in zipup() still collects the full EA set in memory. */
  if(!(xtr_zip_xattrs && key!=NULL))
#endif
  {
    int ea_rc=GetEAs((char *)metadata_name, &z->extra, &ext_len, &z->cextra,
                     &cext_len);
    if(ea_rc!=0){
#ifdef XTR_OS2_NATIVE
      if(ea_rc==-2 && xtr_zip_xattrs){
        fprintf(stderr,"zip warning: OS/2 legacy EA field too large; "
                       "complete EAs retained in Xtro V1 only\n");
      }else
#endif
        return ZE_OPEN;
    }
  }
#ifdef OS2_KLIBC_SYMLINKS
  if (linkput) {
    char target[1024];
    int is_link=iz_os2_link_target(z->name,target,sizeof(target));
    if(is_link<0)return ZE_OPEN;
    /* The native link cannot be reconstructed without its SYMLINK EA.
     * The EA writer is historically void-returning, so explicitly require
     * that it produced the legacy OS/2 field for a recognized link. */
    if(is_link==1
#ifdef XTR_OS2_NATIVE
       && !(xtr_zip_xattrs && key!=NULL)
#endif
       && (ext_len<8U || !z->extra ||
        (unsigned char)z->extra[0]!=0x09U ||
        (unsigned char)z->extra[1]!=0x00U))return ZE_OPEN;
  }
#endif
  if (ext_len > 65535U || cext_len > 65535U)
    return ZE_BIG;
  z->ext = (ush) ext_len;
  z->cext = (ush) cext_len;

  /* store ACL data in local header, and size only in central headers */
  if (GetACL((char *)metadata_name, &z->extra, &ext_len, &z->cextra,
             &cext_len) != 0) return ZE_OPEN;
  if (ext_len > 65535U || cext_len > 65535U)
    return ZE_BIG;
  z->ext = (ush) ext_len;
  z->cext = (ush) cext_len;

#ifdef USE_EF_UT_TIME
  /* store extended time stamps in both headers */
  return GetExtraTime(z, z_utim);
#else /* !USE_EF_UT_TIME */
  return ZE_OK;
#endif /* ?USE_EF_UT_TIME */
}

#endif /* !UTIL */

/* Initialize the table of uppercase characters including handling of
   country dependent characters. */

void init_upper()
{
  COUNTRYCODE cc;
  unsigned nCnt, nU;

  for (nCnt = 0; nCnt < sizeof(upper); nCnt++)
    upper[nCnt] = lower[nCnt] = (unsigned char) nCnt;

  cc.country = cc.codepage = 0;
  DosMapCase(sizeof(upper), &cc, (PCHAR) upper);

  for (nCnt = 0; nCnt < 256; nCnt++)
  {
    nU = upper[nCnt];
    if (nU != nCnt && lower[nU] == (unsigned char) nU)
      lower[nU] = (unsigned char) nCnt;
  }

  for (nCnt = 'A'; nCnt <= 'Z'; nCnt++)
    lower[nCnt] = (unsigned char) (nCnt - 'A' + 'a');
}

char *StringLower(char *szArg)
{
  unsigned char *szPtr;
  for (szPtr = (unsigned char *) szArg; *szPtr; szPtr++)
    *szPtr = lower[*szPtr];
  return szArg;
}

#if defined(__IBMC__) && defined(__DEBUG_ALLOC__)
void DebugMalloc(void)
{
  _dump_allocated(0); /* print out debug malloc memory statistics */
}
#endif


/******************************/
/*  Function version_local()  */
/******************************/

void version_local()
{
    static ZCONST char CompiledWith[] = "Compiled with %s%s for %s%s%s%s.\n\n";
#if defined(__IBMC__) || defined(__WATCOMC__) || defined(_MSC_VER)
    char buf[80];
#endif

    printf(CompiledWith,

#ifdef __GNUC__
#  ifdef __EMX__  /* __EMX__ is defined as "1" only (sigh) */
      "emx+gcc ", __VERSION__,
#  else
      "gcc/2 ", __VERSION__,
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
        " 1.5",
#    else
        " 2.0",
#    endif
#  else
      "Turbo C",
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
#endif /* __GNUC__ */

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
      " 2.x/3.x (32-bit)",
#endif

#ifdef __DATE__
      " on ", IZ_BUILD_DATE
#else
      "", ""
#endif
    );

    /* temporary debugging code for Borland compilers only */
#ifdef __TURBOC__
    printf("\t(__TURBOC__ = 0x%04x = %d)\n", __TURBOC__, __TURBOC__);
#ifdef __BORLANDC__
    printf("\t(__BORLANDC__ = 0x%04x)\n",__BORLANDC__);
#else
    printf("\tdebug(__BORLANDC__ not defined)\n");
#endif
#ifdef __TCPLUSPLUS__
    printf("\t(__TCPLUSPLUS__ = 0x%04x)\n", __TCPLUSPLUS__);
#else
    printf("\tdebug(__TCPLUSPLUS__ not defined)\n");
#endif
#ifdef __BCPLUSPLUS__
    printf("\t(__BCPLUSPLUS__ = 0x%04x)\n\n", __BCPLUSPLUS__);
#else
    printf("\tdebug(__BCPLUSPLUS__ not defined)\n\n");
#endif
#endif /* __TURBOC__ */

} /* end function version_local() */

#endif /* OS2 */
