/* C89 host-side coverage of native OS/2 Zip input-directory normalization.
 * SPDX-License-Identifier: MIT-0
 * cc -std=c89 -pedantic -Wall -Wextra -Werror test_zip_dirpath.c -o test_zip_dirpath
 */
#include <stdio.h>
#include <string.h>

#include "../../zip30/os2/dirpath.h"

struct path_case { const char *input, *want; };

int main(void)
{
  static const struct path_case cases[] = {
    { "DIRSRC\\", "DIRSRC" },
    { "DIRSRC/", "DIRSRC" },
    { "DIRSRC\\\\", "DIRSRC" },
    { ".\\DIRSRC\\", "./DIRSRC" },
    { "C:\\DIRSRC\\", "C:/DIRSRC" },
    { "C:\\", "C:/" },
    { "C:/", "C:/" },
    { "\\", "/" },
    { "/", "/" },
    { "C:", "C:" },
    { "\\\\server\\share\\DIRSRC\\", "//server/share/DIRSRC" },
    { "sub\\*.txt", "sub/*.txt" },
    { "", "" }
  };
  size_t i;

  for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char path[128];
    strcpy(path, cases[i].input);
    iz_os2_zip_normalize_dirpath(path);
    if (strcmp(path, cases[i].want) != 0) {
      fprintf(stderr, "OS/2 path normalization failed: [%s] -> [%s] != [%s]\n",
              cases[i].input, path, cases[i].want);
      return 1;
    }
  }

  puts("OS/2 Zip trailing-directory-path normalization: PASS");
  return 0;
}
