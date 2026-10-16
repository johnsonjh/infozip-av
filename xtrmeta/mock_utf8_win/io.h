#ifndef XTR_TEST_IO_H
# define XTR_TEST_IO_H
# include <stdio.h>
# include <wchar.h>
struct _stati64
{
  unsigned short st_mode;
  unsigned long st_size;
};
int _wstati64 (const wchar_t *, struct _stati64 *);
int _waccess (const wchar_t *, int);
int _wunlink (const wchar_t *);
int _wrename (const wchar_t *, const wchar_t *);
int _wchmod (const wchar_t *, int);
FILE *_wfopen (const wchar_t *, const wchar_t *);
# ifndef _O_BINARY
#  define _O_BINARY 0x8000
# endif /* ifndef _O_BINARY */
int _wopen (const wchar_t *, int, ...);
#endif /* ifndef XTR_TEST_IO_H */
