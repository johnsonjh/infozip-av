#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
long _get_osfhandle (int);
int _open_osfhandle (intptr_t, int);
FILE *_fdopen (int, const char *);
int _close (int);
int _fileno (FILE *);
#ifndef _O_RDWR
# define _O_RDWR 2
#endif /* ifndef _O_RDWR */
#ifndef _O_BINARY
# define _O_BINARY 0x8000
#endif /* ifndef _O_BINARY */

#ifndef _O_WRONLY
# define _O_WRONLY 1
#endif /* ifndef _O_WRONLY */
