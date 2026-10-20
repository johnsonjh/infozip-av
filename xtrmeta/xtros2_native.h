/* SPDX-License-Identifier: MIT-0 */
#ifndef XTROS2_NATIVE_H
# define XTROS2_NATIVE_H
# include <stddef.h>
/* Read complete FEA2LIST via native OS/2 DOSCALLS. Returns 0 for a
 * populated, validated list, 1 for none / unsupported volume, -1 on
 * any error. On success the caller owns *bytes and must free it. */
int xtr_os2_query_native_eas (const char *path, unsigned char **bytes,
                              size_t *length);
#endif /* ifndef XTROS2_NATIVE_H */
