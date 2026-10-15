/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef ZO_ARCHIVE_H

# define ZO_ARCHIVE_H
# include <limits.h>
# include <stdio.h>
# include "../xtrmeta/xtrrewrite.h"

# if ULONG_MAX > 0xffffffffUL
typedef unsigned long zo_u64;
# elif defined(__GNUC__) || defined(__clang__)
__extension__ typedef unsigned long long zo_u64;
# elif defined(_MSC_VER)
typedef unsigned __int64 zo_u64;
# else /* if ULONG_MAX > 0xffffffffUL */
#  error zipopt needs a compiler-supported 64-bit integer type
# endif /* if ULONG_MAX > 0xffffffffUL */

typedef struct zo_entry
{
  zo_u64 local_offset, data_offset, data_end, record_end;
  zo_u64 csize, usize;
  unsigned long crc;
  unsigned method, flags, version_needed;
  unsigned name_len, has_fwkcs;
  unsigned central_extra_len, central_comment_len, local_extra_len;
  zo_u64 central_offset;
  unsigned char *name;
  xr_node xtr;
  unsigned xtr_local_seen;
} zo_entry;

typedef struct zo_archive
{
  FILE *fp;
  const char *path;
  zo_u64 filesize, cd_offset, cd_size, count, eocd_offset;
  unsigned archive_comment_len;
  zo_u64 initial_hash;
  zo_u64 source_device, source_inode, source_size;
  zo_u64 source_mtime, source_ctime;
  zo_u64 source_mtime_nsec, source_ctime_nsec;
  zo_entry *entries;
  char error[192];
} zo_archive;

int zo_archive_open (zo_archive *, const char *);
int zo_archive_at (zo_archive *, zo_u64, void *, size_t);

/* Returns false when the input was replaced or changed during processing. */
int zo_archive_unchanged (zo_archive *);
void zo_archive_close (zo_archive *);

#endif /* ifndef ZO_ARCHIVE_H */
