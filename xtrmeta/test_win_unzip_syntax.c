/* Strict C89 compile-only check of the native, non-mocked staging branch.
 * Real MinGW and NTFS runtime acceptance remain separate release gates. */
#define XTR_WIN_NATIVE 1
#define WIN32 1
#define _WIN32 1
#include <stdio.h>
typedef unsigned char uch;
typedef long zoff_t;
typedef struct min_info
{
  zoff_t offset;
  unsigned long compr_size, crc, diskstart;
  unsigned compression_method;
  unsigned char *xtr_central;
  char *xtr_source_name;
  unsigned xtr_central_len;
  void *xtr_restore_handle;
  unsigned char xtr_companion;
  unsigned long uncompr_size;
  unsigned encrypted, fwkcs_md5;
  unsigned aes_strength, aes_version, aes_iterations;
} min_info;
#include "../unzip60/xtrunzip_win.c"
