/* SPDX-License-Identifier: MIT-0 */
#ifndef IZ_OS2LINK_H
# define IZ_OS2LINK_H
/* OS/2 native (not kLIBC) access to kLIBC's SYMLINK EA convention.
 * The application is compiled and linked with Open Watcom, not kLIBC. */
# include <stddef.h>
# include <sys/stat.h>
/* Returns 1 for a valid symlink, 0 if no SYMLINK EA, -1 for malformed EA
 * or an OS/2 API failure other than 'no attributes'. */
int iz_os2_link_target (const char *path, char *target, size_t capacity);
int iz_os2_link_target_fd (int fd, char *target, size_t capacity);
/* Resolves EAs on path components; at most 32 links; never silently
 * dereferences a malformed or cyclic link. follow_final=0 keeps last link. */
int iz_os2_link_resolve (const char *path, char *resolved, size_t capacity,
                         int follow_final);
int iz_os2_link_lstat (const char *path, struct stat *result);
int iz_os2_link_stat (const char *path, struct stat *result);
/* Obtain raw underlying OS/2 file bytes, not the SYMLINK EA target.
 * On overflow or an I/O error returns -1. */
int iz_os2_link_body (const char *path, char *buffer, size_t capacity);
#endif /* ifndef IZ_OS2LINK_H */
