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

int zo_extract_index (const zo_archive *, zo_u64 index, FILE *out);

#endif /* ifndef ZO_EXTRACT_H */
