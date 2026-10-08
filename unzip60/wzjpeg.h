/*
 * WZ-JPEG decompressor
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* See wzjpeg.c for implementation notes */

#ifndef IZ_WZJPEG_H
# define IZ_WZJPEG_H

# include <stddef.h>

typedef size_t (*wz96_read_fn) (void *, unsigned char *, size_t);

typedef int (*wz96_metadata_fn) (void *, const unsigned char *, size_t);

typedef struct
{
  unsigned long bundles;
  unsigned long scans;
  unsigned long stored_bundles;
  unsigned long lzma_bundles;
  unsigned long metadata_bytes;
  unsigned int width, height, components, slice_option;
  int reached_eoi;
} wz96_report;

int wz96_probe (wz96_read_fn, void *, unsigned long compressed_len,
                wz96_metadata_fn, void *, wz96_report *);

typedef size_t (*wz96_write_fn) (void *, const unsigned char *, size_t);

int wz96_decode (wz96_read_fn, void *, unsigned long, wz96_write_fn, void *,
                 unsigned long, wz96_report *);

#endif /* ifndef IZ_WZJPEG_H */
