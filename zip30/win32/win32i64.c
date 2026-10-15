/*
  win32/win32i64.c - Zip 3

  Copyright (c) 1990-2007 Info-ZIP.  All rights reserved.

  See the accompanying file LICENSE, version 2005-Feb-10 or later
  (the contents of which are also included in zip.h) for terms of use.
  If, for some reason, all these files are missing, the Info-ZIP license
  also may be found at:  ftp://ftp.info-zip.org/pub/infozip/license.html
*/

#include "../zip.h"

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <windows.h>
/* for LARGE_FILE_SUPPORT but may not be needed */
#include <io.h>


/* --------------------------------------------------- */
/* Large File Support
 *
 * Initial functions by E. Gordon and R. Nausedat
 * 9/10/2003
 *
 * These implement 64-bit file support for Windows.  The
 * defines and headers are in win32/osdep.h.
 *
 * These moved from win32.c by Mike White to avoid conflicts
 * in WiZ of same name functions in UnZip and Zip libraries.
 * 9/25/04 EG
 */

#if defined(LARGE_FILE_SUPPORT) && !defined(__CYGWIN__)

/* 64-bit buffered ftello/fseeko.  Modern MinGW provides CRT functions
 * that synchronize the FILE stream and its file descriptor; other Win32
 * compilers keep the historical code below. */

/* On MinGW, use the CRT's buffered-stream-aware 64-bit interfaces.
 * Direct _lseeki64() on fileno(stream) does not clear stdio EOF state,
 * and may leave the stream's read buffer inconsistent with the descriptor.
 * In particular, scanzipf_regnew() scans through EOCD to EOF, then seeks
 * backwards and reads central-directory records.  A descriptor-only seek
 * can leave all those reads at EOF, rejecting a valid existing archive.
 * Keep the historical fallback for other Win32 compilers. */
zoff_t zftello(FILE *stream)
{
#if defined(__MINGW32__)
  return (zoff_t)_ftelli64(stream);
#else
  fpos_t fpos = 0;

  if (fgetpos(stream, &fpos) != 0) {
    return -1L;
  } else {
    return fpos;
  }
#endif
}

int zfseeko(FILE *stream, zoff_t offset, int origin)
{
#if defined(__MINGW32__)
  return _fseeki64(stream, offset, origin);
#else
  zoff_t location;

  location = zftello(stream);
  fflush(stream);
  if (origin == SEEK_CUR) {
    offset = location + offset;
    location = _lseeki64(fileno(stream), offset, SEEK_SET);
  } else {
    location = _lseeki64(fileno(stream), offset, origin);
  }
  if (location == -1L) {
    return -1L;
  } else {
    return 0;
  }
#endif
}

#endif  /* Win32 LARGE_FILE_SUPPORT */

#if 0
FILE* zfopen(filename,mode)
char *filename;
char *mode;
{
FILE* fTemp;
  
  fTemp = fopen(filename,mode);
  if( fTemp == NULL )
    return NULL;
  
  /* sorry, could not make VC60 and its rtl work properly without setting the file buffer to NULL. the  */
  /* problem seems to be _telli64 which seems to return the max stream position, comments are welcome   */
  setbuf(fTemp,NULL);

  return fTemp;
}
#endif
/* --------------------------------------------------- */
