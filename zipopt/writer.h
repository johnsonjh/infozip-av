/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* ZIP writer for zipopt */

#ifndef ZO_WRITER_H
# define ZO_WRITER_H

# include "archive.h"

typedef struct zo_outentry
{
  zo_u64 local_off, usize, csize;
  unsigned method, flags, version;
  int has_md5;
  int normalize_timestamp;
  unsigned char md5[16];
} zo_outentry;

typedef struct zo_writer
{
  zo_archive *source;
  FILE *stream;
  char *temporary, *destination;
  zo_outentry *entries;
  zo_u64 written;
  int failed, completed, sealed;
  int sde_active, fwkcs_requested;
  unsigned long sde_epoch;
} zo_writer;

int zo_writer_begin (zo_writer *, zo_archive *, const char *);

/* POSIX interrupt handling removes the named temporary output immediately. */
int zo_writer_install_interrupts (void);

/* Payload is either a seekable compressed file or original source data. */
int zo_writer_add (zo_writer *, zo_u64, FILE *, unsigned, unsigned, zo_u64);
int zo_writer_complete (zo_writer *);
/* Close the completed output before independent verification reopens it. */
int zo_writer_seal (zo_writer *);
int zo_writer_publish (zo_writer *);
void zo_writer_abort (zo_writer *);

#endif /* ifndef ZO_WRITER_H */
