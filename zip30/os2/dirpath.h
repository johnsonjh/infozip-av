/* Normalize user-supplied OS/2 Zip input paths before wildcard splitting.
 * SPDX-License-Identifier: MIT-0
 * Keep the original slash/drive-root rules shared with the host test.
 */
#ifndef IZ_OS2_ZIP_DIRPATH_H
#define IZ_OS2_ZIP_DIRPATH_H

#include <string.h>

static void
iz_os2_zip_normalize_dirpath (char *path)
{
  char *p;
  size_t n;

  for (p = path; *p; p++)
    if (*p == '\\')
      *p = '/';

  /* A trailing separator names the directory itself.  Do not leave an
   * empty filename pattern for wild() to match.  Preserve / and X:/ roots,
   * which have different filesystem semantics from X: and empty strings. */
  n = strlen(path);
  while (n > 1U && path[n - 1U] == '/'
         && !(n == 3U && path[1] == ':'))
    path[--n] = '\0';
}

#endif /* IZ_OS2_ZIP_DIRPATH_H */
