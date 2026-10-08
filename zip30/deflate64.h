/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef ZIP_DEFLATE64_H
# define ZIP_DEFLATE64_H

typedef unsigned (*d64_read_func) (void *opaque, unsigned char *buf,
                                   unsigned size);
typedef int (*d64_write_func) (void *opaque, const unsigned char *buf,
                               unsigned size);

typedef struct d64_stats
{
  unsigned long input_size;
  unsigned long output_size;
  unsigned long blocks_stored;
  unsigned long blocks_fixed;
  unsigned long blocks_dynamic;
  unsigned long matches;
  unsigned long max_match;
  unsigned long max_distance;
} d64_stats;

/*
 * Encode one raw Deflate64 stream.  level is 1..9 or 11.  Returns 0 on success,
 * 1 for allocation failure, 2 for output failure, and 3 for invalid input.
 */

int d64_encode (d64_read_func read_cb, d64_write_func write_cb, void *opaque,
                int level, d64_stats *stats);

#endif /* ZIP_DEFLATE64_H */
