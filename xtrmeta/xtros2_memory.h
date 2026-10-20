/* SPDX-License-Identifier: MIT-0 */
/* Strict C89 bounded volatile-only Xtro metadata stream. The buffer never
 * spills to an application-created temporary pathname. The host OS may
 * independently page process memory: do not claim swap protection. */
#ifndef XTROS2_MEMORY_H
# define XTROS2_MEMORY_H
# include <stddef.h>
typedef struct xtr_os2_memory
{
  unsigned char *bytes;
  size_t length, capacity, position, limit;
} xtr_os2_memory;
void xtr_os2_memory_wipe (void *, size_t);
void xtr_os2_memory_init (xtr_os2_memory *, size_t limit);
int xtr_os2_memory_write (void *, const unsigned char *, size_t);
size_t xtr_os2_memory_read (void *, unsigned char *, size_t);
void xtr_os2_memory_rewind (xtr_os2_memory *);
void xtr_os2_memory_free (xtr_os2_memory *);
#endif /* ifndef XTROS2_MEMORY_H */
