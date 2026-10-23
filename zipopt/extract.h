/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* Internal isolated extraction API */

#ifndef ZO_EXTRACT_H
# define ZO_EXTRACT_H

# include "archive.h"

/*
 * The output FILE must be writable and positioned at offset zero.
 * The API never uses the entry's name for selection or as a filesystem path.
 */

/* A failed decode may be due to the embedded decoder, output I/O, or an
 * independently checked length/CRC mismatch.  Preserve those distinctions
 * for ZipOpt's final publication gate. */
typedef struct zo_extract_report
{
  zo_u64 written;
  unsigned long crc;
  int unzip_status, unzip_errno;
  int size_overflow, write_failed, write_errno;
  int flush_failed, flush_errno;
} zo_extract_report;

int zo_extract_index_report (const zo_archive *, zo_u64 index, FILE *out,
                             zo_extract_report *);
int zo_extract_index (const zo_archive *, zo_u64 index, FILE *out);

#endif /* ifndef ZO_EXTRACT_H */
