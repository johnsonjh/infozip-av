/*
  Copyright (c) 1990-1999 Info-ZIP.  All rights reserved.

  See the accompanying file LICENSE, version 1999-Oct-05 or later
  (the contents of which are also included in zip.h) for terms of use.
  If, for some reason, both of these files are missing, the Info-ZIP license
  also may be found at:  ftp://ftp.cdrom.com/pub/infozip/license.html
*/
#define fhow (O_RDONLY|O_BINARY)
#define fbad (-1)
typedef int ftype;
#ifdef XTR_OS2_NATIVE
int xtr_os2_stage_open(const char *,int);
int xtr_os2_stage_read(int,void *,unsigned);
int xtr_os2_stage_close(int);
#define zopen(n,p) xtr_os2_stage_open(n,p)
#define zread(f,b,n) xtr_os2_stage_read(f,b,n)
#define zclose(f) xtr_os2_stage_close(f)
#else
#define zopen(n,p) open(n,p)
#define zread(f,b,n) read(f,b,n)
#define zclose(f) close(f)
#endif
#define zerr(f) (k == (extent)(-1L))
#define zstdin 0
