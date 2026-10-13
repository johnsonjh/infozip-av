/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * Copyright (c) 2025 Dr.W.X WangXuan95 <https://github.com/WangXuan95>
 */

#ifndef LPAQ8ENC_H
# define LPAQ8ENC_H

typedef int (*lpaq8enc_read_fn) (void *context);
typedef int (*lpaq8enc_write_fn) (void *context, unsigned char byte);

# define LPAQ8ENC_OK 0
# define LPAQ8ENC_NOMEM 1
# define LPAQ8ENC_UNSUPPORTED 2
# define LPAQ8ENC_OUTPUT_ERROR 3
# define LPAQ8ENC_INPUT_ERROR 4

int lpaq8_encode_stream (lpaq8enc_read_fn read_byte, void *read_context,
                         lpaq8enc_write_fn write_byte, void *write_context,
                         unsigned long input_size, unsigned int level,
                         unsigned int mode);

#endif /* ifndef LPAQ8ENC_H */
