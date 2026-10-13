/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * Copyright (c) 2025 Dr.W.X WangXuan95 <https://github.com/WangXuan95>
 */

#ifndef LPAQ8DEC_H
# define LPAQ8DEC_H

# include <stddef.h>

typedef int (*lpaq8_read_fn) (void *ctx); /* return 0..255 or -1 on failure */
typedef int (*lpaq8_write_fn) (void *ctx, const unsigned char *buf, size_t n);

# define LPAQ8_OK 0
# define LPAQ8_NOMEM 1
# define LPAQ8_UNSUPPORTED 2
# define LPAQ8_OUTPUT_ERROR 3
# define LPAQ8_INPUT_ERROR 4
# define LPAQ8_CRC_MISMATCH 5
# define LPAQ8_AMBIGUOUS 6

/*
 * Writes decoded prefilter data. For mode 2 this is NOT the original file.
 * Caller MUST verify one or both executable inverse candidates and CRC.
 */

int lpaq8_decode_stream (lpaq8_read_fn read_byte, void *read_ctx,
                         lpaq8_write_fn write_bytes, void *write_ctx,
                         size_t compressed_size, unsigned long expected_size,
                         unsigned int *mode_out);
/*
 * Transactional decode: writes NO output until stream canonicality, size,
 * ZIP CRC, and (if needed) the two EXE inverse candidates are validated.
 * Uses a temporary file so may return an I/O error if unavailable.
 */

int lpaq8_decode_verified (lpaq8_read_fn read_byte, void *read_ctx,
                           lpaq8_write_fn write_bytes, void *write_ctx,
                           size_t compressed_size, unsigned long expected_size,
                           unsigned long expected_crc, unsigned int *mode_out);

#endif /* ifndef LPAQ8DEC_H */
