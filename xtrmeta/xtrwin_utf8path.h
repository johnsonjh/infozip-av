/* Xtro-ZIP Windows UTF-8 filesystem pathname shim.  Experimental opt-in.
 * SPDX-License-Identifier: MIT-0
 * No exported Windows types: intended for the native MinGW UnZip build. */
#ifndef XTRWIN_UTF8PATH_H
# define XTRWIN_UTF8PATH_H
# include <io.h>
# include <stddef.h>
# include <stdio.h>
# include <sys/stat.h>
# include <wchar.h>
# include <windows.h>

/* Returned heap strings must be freed by the caller.  Strict conversions
 * never select a replacement character or silently truncate a filename. */
wchar_t *xtr_win_u8_wide (const char *path);
char *xtr_win_acp_u8 (const char *path);
int xtr_win_u8_valid (const char *path);
/* Inspect a raw ZIP member before Win32 mapname can replace characters. */
int xtr_win_u8_member_safe (const char *name);
int xtr_win_u8_stat (const char *path, struct _stati64 *st);
int xtr_win_u8_mkdir (const char *path);
int xtr_win_u8_access (const char *path, int mode);
int xtr_win_u8_unlink (const char *path);
int xtr_win_u8_rename (const char *from, const char *to);
int xtr_win_u8_chmod (const char *path, int mode);
FILE *xtr_win_u8_fopen (const char *path, const char *mode);
/* Open a ZIP archive as an fd for MinGW's !USE_STRM_INPUT build. */
int xtr_win_u8_archive_fd (const char *path);
HANDLE xtr_win_u8_open (const char *path, DWORD access, DWORD share,
                        DWORD creation, DWORD flags);
DWORD xtr_win_u8_attributes (const char *path);
int xtr_win_u8_set_attributes (const char *path, DWORD attrs);
#endif /* ifndef XTRWIN_UTF8PATH_H */
