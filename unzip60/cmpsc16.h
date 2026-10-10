/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef IZIP_CMPSC16_H
# define IZIP_CMPSC16_H

# include <stddef.h>

typedef int (*cmpsc16_read_fn) (void *opaque); /* byte 0..255 or -1 */
typedef int (*cmpsc16_write_fn) (void *opaque, const unsigned char *, size_t);
/* success 0; corrupt -1; allocation failed -2 */
int cmpsc16_stream_decode (cmpsc16_read_fn, cmpsc16_write_fn, void *,
                           unsigned long output_hi, unsigned long output_lo);

#endif /* ifndef IZIP_CMPSC16_H */
