/* Native Open Watcom OS/2 file publication support for ZIP utilities.
 * SPDX-License-Identifier: MIT-0
 * No kLIBC, EMX, or POSIX emulation library is required.
 */
#ifndef IZ_ZO_OS2_PORT_H
# define IZ_ZO_OS2_PORT_H
# if !defined(OS2) || !defined(__WATCOMC__)
#  error OS/2 Open Watcom only
# endif /* if !defined( OS2 ) || !defined( __WATCOMC__ ) */
# ifndef INCL_DOSERRORS
#  define INCL_DOSERRORS
# endif /* ifndef INCL_DOSERRORS */
# ifndef INCL_DOSFILEMGR
#  define INCL_DOSFILEMGR
# endif /* ifndef INCL_DOSFILEMGR */
# include <os2.h>
# include <errno.h>
# include <fcntl.h>
# include <io.h>
# include <process.h>
# include <string.h>
# include <sys/stat.h>
# include <time.h>

/* This is a replacement for mkstemp, not mktemp: O_EXCL prevents races on
 * temporary file creation. The caller owns the fd and modified pathname. */
static int
iz_os2_mkstemp (char *pattern)
{
  static unsigned long counter;
  static const char hex[] = "0123456789abcdef";
  unsigned long seed;
  size_t len;
  unsigned attempt, i;
  int fd;

  if (!pattern)
    {
      return -1;
    }

  len = strlen (pattern);
  if (len < 6 || strcmp (pattern + len - 6, "XXXXXX"))
    {
      return -1;
    }

  seed = (unsigned long)time (NULL) ^ (unsigned long)clock ()
         ^ ((unsigned long)getpid () << 13) ^ ++counter;
  for (attempt = 0; attempt < 1024; ++attempt)
    {
      unsigned long n = seed + (unsigned long)attempt * 2654435761UL;
      for (i = 0; i < 6; ++i)
        {
          pattern[len - 6 + i] = hex[n & 15U];
          n >>= 4;
        }

      fd = open (pattern, O_RDWR | O_CREAT | O_EXCL | O_BINARY,
                 S_IREAD | S_IWRITE);
      if (fd >= 0)
        {
          return fd;
        }

      if (errno != EEXIST)
        {
          return -1;
        }
    }

  return -1;
}

/* Native DosMove in the output directory. This deliberately does not
 * replace existing output. Recheck the OS/2 rename semantics on HPFS/JFS
 * as part of native acceptance before release. */
static int
iz_os2_publish_noreplace (const char *temp, const char *dest)
{
  FILESTATUS3 st;
  APIRET rc = DosQueryPathInfo (dest, FIL_STANDARD, &st, sizeof (st));

  if (rc != ERROR_FILE_NOT_FOUND && rc != ERROR_PATH_NOT_FOUND)
    {
      return -1;
    }

  return DosMove (temp, dest) == NO_ERROR ? 0 : -1;
}
#endif /* ifndef IZ_ZO_OS2_PORT_H */
