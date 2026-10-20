/* SPDX-License-Identifier: MIT-0 */
#ifndef XTROS2_DECODE_H
# define XTROS2_DECODE_H
# include "xtros2_ea.h"
/* Convert an already decoded/ZIP-authenticated Xtro V1 payload to a native
 * OS/2 FEA2LIST after V1 digest, schema, record and native name validation.
 * Caller owns the resulting allocation. A ciphertext buffer is NOT accepted.
 */
int xtr_os2_decode_manifest (const unsigned char *bytes, size_t bytes_len,
                             const xtr_extra *outer, const unsigned char *sha,
                             xtr_os2_ea_equal_cb names_equal, void *context,
                             unsigned char **native, size_t *native_len);
#endif /* ifndef XTROS2_DECODE_H */
