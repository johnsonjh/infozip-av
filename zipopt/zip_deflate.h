/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#ifndef ZO_ZIP_DEFLATE_H
# define ZO_ZIP_DEFLATE_H
int zo_zip_internal_deflate (unsigned (*read_cb) (void *, unsigned char *,
                                                  unsigned),
                             int (*write_cb) (void *, const unsigned char *,
                                              unsigned),
                             void *opaque, unsigned level);
#endif /* ifndef ZO_ZIP_DEFLATE_H */
