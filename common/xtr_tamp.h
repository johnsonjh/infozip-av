/*
 * Xtro-ZIP C89 amalgamation of Brian Pugh's Tamp C compressor/decompressor.
 * Upstream revision: 5279e7cf2322eb0a5f85acb9ca6de6d1b77561ea.
 * Adaptation: 16-bit-safe arithmetic, ANSI C89 syntax and portable state.
 *
 * MIT License
 *
 * Copyright (c) 2023 Brian Pugh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef XTR_TAMP_H
# define XTR_TAMP_H
# define TAMP_STREAM 0
# define TAMP_LAZY_MATCHING 1
# define TAMP_USE_EMBEDDED_MATCH 1
# define TAMP_MATCH_INDEX 0
# ifndef TAMP_COMMON_H
#  define TAMP_COMMON_H

#  ifdef __cplusplus
extern "C"
{
#  endif

#  include <limits.h>
  /* Strict C89 fixed-width types. */
  typedef unsigned char xtrt_u8;
  typedef signed char xtrt_s8;
  typedef unsigned short xtrt_u16;
  typedef signed short xtrt_s16;
#  if USHRT_MAX != 65535U
#   error "Tamp requires 16-bit unsigned short"
#  endif
#  if UINT_MAX == 0xffffffffUL
  typedef unsigned int xtrt_u32;
#  elif ULONG_MAX == 0xffffffffUL
typedef unsigned long xtrt_u32;
#  else
#   error "Tamp requires an exact 32-bit unsigned type"
#  endif
  typedef unsigned char xtrt_bool;

#  include <stdlib.h>

#  if ESP_PLATFORM
/* (External) code #including this header MUST use the SAME TAMP_ESP32 setting
 * that is used when */
/* building this lib! */

/* cppcheck-suppress missingInclude */
#   include "sdkconfig.h"
#  endif

/* Should the ESP32-optimized variant be built? */
#  ifdef CONFIG_TAMP_ESP32 /* CONFIG_... from Kconfig takes precedence */
#   if CONFIG_TAMP_ESP32
#    define TAMP_ESP32 1
#   else
#    define TAMP_ESP32 0
#   endif
#  endif

#  ifndef TAMP_ESP32 /* If not set via Kconfig, and not otherwise -D_efined, \
                      default TAMP_ESP32 to */
                   /* compatible version. */
#   define TAMP_ESP32 0
#  endif

/* ISO C89: no intrinsics, inline or compiler-specific attributes. */
#  define TAMP_LIKELY(c) (c)
#  define TAMP_UNLIKELY(c) (c)
#  define TAMP_ALWAYS_INLINE static
#  define TAMP_NOINLINE
#  define TAMP_OPTIMIZE_SIZE

/* TAMP_USE_MEMSET: Use libc memset (default: 1).
 * Set to 0 for environments without libc (e.g. MicroPython native modules).
 * When disabled, uses a volatile loop that prevents GCC from emitting a
 * memset call at the cost of inhibiting store coalescing. */
#  ifndef TAMP_USE_MEMSET
#   define TAMP_USE_MEMSET 1
#  endif

#  if TAMP_USE_MEMSET
#   include <string.h>
#   define TAMP_MEMSET(dst, val, n) memset ((dst), (val), (n))
#  else
#   define TAMP_MEMSET(dst, val, n)                                           \
  do                                                                          \
    {                                                                         \
      volatile unsigned char *_tamp_p = (volatile unsigned char *)(dst);      \
      for (size_t _tamp_i = 0; _tamp_i < (n); _tamp_i++)                      \
        _tamp_p[_tamp_i] = (val);                                             \
    }                                                                         \
  while (0)
#  endif

/* TAMP_STATIC_CONST: declaration prefix for file-local read-only tables.
 * Normally `static const`, but drops `static` on Xtensa MicroPython native
 * modules, where `static const` rodata returns incorrect values.
 * See micropython/micropython#14429. */
#  if defined(__XTENSA__) && defined(MICROPY_ENABLE_DYNRUNTIME)
#   define TAMP_STATIC_CONST const
#  else
#   define TAMP_STATIC_CONST static const
#  endif

/* Include stream API (tamp_compress_stream, tamp_decompress_stream).
 * Enabled by default. Disable with -DTAMP_STREAM=0 to save ~2.8KB.
 */
#  ifndef TAMP_STREAM
#   define TAMP_STREAM 1
#  endif

/* Work buffer size for stream API functions.
 * The buffer is allocated on the stack and split in half for input/output.
 * Larger values reduce I/O callback invocations, improving decompression
 * speed. Default of 32 bytes is safe for constrained stacks; 256+ bytes
 * recommended for better performance when stack space permits. Override via
 * compiler flag: -DTAMP_STREAM_WORK_BUFFER_SIZE=256
 */
#  ifndef TAMP_STREAM_WORK_BUFFER_SIZE
#   define TAMP_STREAM_WORK_BUFFER_SIZE 32
#  endif

/* Extended format support (RLE, extended match).
 * Enabled by default. Disable to save code size on minimal builds.
 *
 * TAMP_EXTENDED is the master switch (default: 1).
 * TAMP_EXTENDED_COMPRESS and TAMP_EXTENDED_DECOMPRESS default to
 * TAMP_EXTENDED, but can be individually overridden for compressor-only or
 * decompressor-only builds.
 */
#  ifndef TAMP_EXTENDED
#   define TAMP_EXTENDED 1
#  endif
#  ifndef TAMP_EXTENDED_DECOMPRESS
#   define TAMP_EXTENDED_DECOMPRESS TAMP_EXTENDED
#  endif
#  ifndef TAMP_EXTENDED_COMPRESS
#   define TAMP_EXTENDED_COMPRESS TAMP_EXTENDED
#  endif

/* Extended encoding constants */
#  if TAMP_EXTENDED_DECOMPRESS || TAMP_EXTENDED_COMPRESS
#   define TAMP_RLE_SYMBOL 12
#   define TAMP_EXTENDED_MATCH_SYMBOL 13
#   define TAMP_LEADING_EXTENDED_MATCH_BITS 3
#   define TAMP_LEADING_RLE_BITS 4
#   define TAMP_RLE_MAX_WINDOW 8
#  endif

  enum
  {
    /* Normal/Recoverable status >= 0 */
    TAMP_OK = 0,
    TAMP_OUTPUT_FULL = 1, /* Wasn't able to complete action due to full output
                             buffer. */
    TAMP_INPUT_EXHAUSTED = 2, /* Wasn't able to complete action due to
                                 exhausted input buffer. */

    /* Error codes < 0 */
    TAMP_ERROR = -1,        /* Generic error */
    TAMP_EXCESS_BITS = -2,  /* Provided symbol has more bits than conf->literal
                             */
    TAMP_INVALID_CONF = -3, /* Invalid configuration parameters. */
    TAMP_OOB = -4, /* Out-of-bounds access detected in compressed data. */
    /* Indicates malicious or corrupted input data attempting to */
    /* reference memory outside the decompressor window buffer. */

    /* Stream I/O error codes */
    TAMP_IO_ERROR = -10,   /* Generic I/O error from read/write callback */
    TAMP_READ_ERROR = -11, /* Read callback returned error */
    TAMP_WRITE_ERROR = -12 /* Write callback returned error */

    /* [100, 127] and [-128, -100] are reserved for user-defined callback
     * codes. tamp_callback_t returns are truncated to xtrt_s8; use these
     * ranges to avoid collisions with library status codes. */
  };
  typedef xtrt_s8 tamp_res;

  typedef struct TampConf
  {
    unsigned int window : 4;  /* number of window bits */
    unsigned int literal : 4; /* number of literal bits */
    unsigned int use_custom_dictionary
        : 1;                   /* Use a custom initialized dictionary. */
    unsigned int extended : 1; /* Extended format (RLE, extended match). Read
                                  from header bit [1]. */
    unsigned int dictionary_reset
        : 1; /* Stream may contain double-FLUSH dictionary resets. Implied by
                header byte 1 bit */
             /* [0] (more_header). */
    unsigned int append : 1; /* Initialize for appending to an existing stream
                                (FLUSH instead of header). */
#  if TAMP_LAZY_MATCHING
    unsigned int lazy_matching
        : 1; /* use Lazy Matching (spend 50-75% more CPU for around 0.5-2.0%
                better compression.) */
             /* only effects compression operations. */
#  endif
  } TampConf;

  /**
   * User-provided callback to be invoked periodically by the higher-level API.
   *
   * The callback fires once per compression/decompression cycle (i.e., once
   * per encoded or decoded token). For the stream API, it fires once per
   * read-chunk.
   *
   * In all contexts, bytes_processed tracks input bytes consumed and
   * total_bytes is the total input size (or 0 if unknown). This allows
   * computing a meaningful progress percentage as bytes_processed /
   * total_bytes.
   *
   * Non-stream API (total_bytes is known):
   *   tamp_compressor_compress_cb:   (input_consumed, total_input_size)
   *   tamp_decompressor_decompress_cb: (input_consumed, total_input_size)
   *
   * Stream API (total_bytes is 0; input size unknown):
   *   tamp_compress_stream:   (input_consumed, 0)
   *   tamp_decompress_stream: (input_consumed, 0)
   *
   * @param[in,out] user_data Arbitrary user-provided data.
   * @param[in] bytes_processed Input bytes consumed so far.
   * @param[in] total_bytes Total input size, or 0 if unknown (stream API).
   *
   * @return 0 to continue, or non-zero to abort. The return value is truncated
   *         to tamp_res (xtrt_s8) and propagated to the caller. Use values in
   *         [100, 127] or [-128, -100] for custom codes to avoid collisions.
   */
  typedef int (*tamp_callback_t) (void *user_data, size_t bytes_processed,
                                  size_t total_bytes);

  /**
   * Stream read callback type for file/stream-based operations.
   *
   * Should behave like fread(): read up to `size` bytes into `buffer`.
   * Returns plain int (not tamp_res) for compatibility with standard I/O
   * functions. The stream API translates negative returns to TAMP_READ_ERROR.
   *
   * @param[in] handle User-provided handle (e.g., FILE*, lfs_file_t*, FIL*)
   * @param[out] buffer Buffer to read data into
   * @param[in] size Maximum number of bytes to read
   *
   * @return Number of bytes actually read (0 for EOF), or negative (e.g., -1)
   * on error
   */
  typedef int (*tamp_read_t) (void *handle, unsigned char *buffer,
                              size_t size);

  /**
   * Stream write callback type for file/stream-based operations.
   *
   * Should behave like fwrite(): write `size` bytes from `buffer`.
   * Returns plain int (not tamp_res) for compatibility with standard I/O
   * functions. The stream API treats negative returns or incomplete writes
   * (fewer bytes than requested) as TAMP_WRITE_ERROR. Chunks are small (at
   * most TAMP_STREAM_WORK_BUFFER_SIZE/2 bytes), so writing the full amount is
   * expected.
   *
   * @param[in] handle User-provided handle (e.g., FILE*, lfs_file_t*, FIL*)
   * @param[in] buffer Buffer containing data to write
   * @param[in] size Number of bytes to write
   *
   * @return `size` on success, or negative (e.g., -1) on error
   */
  typedef int (*tamp_write_t) (void *handle, const unsigned char *buffer,
                               size_t size);

/*******************************************************************************
 * Built-in I/O handlers for common sources/sinks.
 *
 * Enable the ones you need by defining the appropriate macro in your build
 * system (e.g., -DTAMP_STREAM_STDIO=1):
 *
 *   - TAMP_STREAM_MEMORY  : Memory buffers (always available, no dependencies)
 *   - TAMP_STREAM_STDIO   : Standard C FILE* (POSIX, ESP-IDF VFS, etc.)
 *   - TAMP_STREAM_LITTLEFS: LittleFS filesystem
 *   - TAMP_STREAM_FATFS   : FatFs (ChaN's FAT filesystem)
 ******************************************************************************/

/* Memory buffer I/O */
#  if TAMP_STREAM_MEMORY

  /**
   * @brief Reader state for memory buffer input.
   *
   * Example:
   * @code
   * const unsigned char compressed_data[] = {...};
   * TampMemReader reader = {
   *     .data = compressed_data,
   *     .size = sizeof(compressed_data),
   *     .pos = 0
   * };
   * tamp_decompress_stream(tamp_stream_mem_read, &reader, ...);
   * @endcode
   */
  typedef struct TampMemReader
  {
    const unsigned char *data; /**< Pointer to input data */
    size_t size;               /**< Total size of input data */
    size_t pos;                /**< Current read position (initialize to 0) */
  } TampMemReader;

  /**
   * @brief Writer state for memory buffer output.
   *
   * Example:
   * @code
   * unsigned char output[4096];
   * TampMemWriter writer = {
   *     .data = output,
   *     .capacity = sizeof(output),
   *     .pos = 0
   * };
   * tamp_compress_stream(..., tamp_stream_mem_write, &writer, ...);
   * // writer.pos contains bytes written
   * @endcode
   */
  typedef struct TampMemWriter
  {
    unsigned char *data; /**< Pointer to output buffer */
    size_t capacity;     /**< Total capacity of output buffer */
    size_t pos;          /**< Current write position (initialize to 0) */
  } TampMemWriter;

  /**
   * @brief Read callback for memory buffers.
   * @param handle Pointer to TampMemReader.
   */
  int tamp_stream_mem_read (void *handle, unsigned char *buffer, size_t size);

  /**
   * @brief Write callback for memory buffers.
   * @param handle Pointer to TampMemWriter.
   * @return Bytes written, or -1 if buffer would overflow.
   */
  int tamp_stream_mem_write (void *handle, const unsigned char *buffer,
                             size_t size);

#  endif /* TAMP_STREAM_MEMORY */

/* POSIX / Standard C stdio (FILE*) */
#  if TAMP_STREAM_STDIO

  /**
   * @brief Read callback for stdio FILE*.
   * @param handle FILE* opened for reading.
   */
  int tamp_stream_stdio_read (void *handle, unsigned char *buffer,
                              size_t size);

  /**
   * @brief Write callback for stdio FILE*.
   * @param handle FILE* opened for writing.
   */
  int tamp_stream_stdio_write (void *handle, const unsigned char *buffer,
                               size_t size);

#  endif /* TAMP_STREAM_STDIO */

/* LittleFS */
#  if TAMP_STREAM_LITTLEFS

#   include "lfs.h"

  /**
   * @brief Bundle struct for LittleFS file operations.
   *
   * LittleFS API requires both the filesystem context and file handle.
   */
  typedef struct TampLfsFile
  {
    lfs_t *lfs;       /**< Pointer to mounted LittleFS instance */
    lfs_file_t *file; /**< Pointer to opened file handle */
  } TampLfsFile;

  /**
   * @brief Read callback for LittleFS.
   * @param handle Pointer to TampLfsFile.
   */
  int tamp_stream_lfs_read (void *handle, unsigned char *buffer, size_t size);

  /**
   * @brief Write callback for LittleFS.
   * @param handle Pointer to TampLfsFile.
   */
  int tamp_stream_lfs_write (void *handle, const unsigned char *buffer,
                             size_t size);

#  endif /* TAMP_STREAM_LITTLEFS */

/* FatFs (ChaN's FAT Filesystem) */
#  if TAMP_STREAM_FATFS

#   include "ff.h"

  /**
   * @brief Read callback for FatFs.
   * @param handle Pointer to FIL (FatFs file object).
   */
  int tamp_stream_fatfs_read (void *handle, unsigned char *buffer,
                              size_t size);

  /**
   * @brief Write callback for FatFs.
   * @param handle Pointer to FIL (FatFs file object).
   */
  int tamp_stream_fatfs_write (void *handle, const unsigned char *buffer,
                               size_t size);

#  endif /* TAMP_STREAM_FATFS */

  /**
   * @brief Pre-populate a window buffer with common characters.
   *
   * Uses a per-literal-size seed table so the dictionary only contains bytes
   * that are valid and useful for the given configuration:
   *   - literal=7,8: common english text/markup characters (" \0 0 e i > t o <
   * a n s \\n r / .")
   *   - literal=5,6: common english letters (" etaoinshrdlcumw") downshifted
   * to the target bit width
   *
   * For v1 backwards compatibility, callers should pass literal=8 when the
   * extended header flag is not set, regardless of the configured literal
   * value.
   *
   * @param[out] buffer Populated output buffer.
   * @param[in] size Size of output buffer in bytes.
   * @param[in] literal Number of literal bits (5-8). Selects the appropriate
   * seed character table.
   */
  void tamp_initialize_dictionary (unsigned char *buffer, size_t size,
                                   xtrt_u8 literal);

  /**
   * @brief Compute the minimum viable pattern size given window and literal
   * config parameters.
   *
   * @param[in] window Number of window bits. Valid values are [8, 15].
   * @param[in] literal Number of literal bits. Valid values are [5, 8].
   *
   * @return The minimum pattern size in bytes. Either 2 or 3.
   */
  xtrt_s8 tamp_compute_min_pattern_size (xtrt_u8 window, xtrt_u8 literal);

  /**
   * @brief Copy pattern from window to window, updating window_pos.
   *
   * Handles potential overlap between source and destination regions by
   * copying backwards when the destination would "catch up" to the source.
   *
   * IMPORTANT: Caller must validate that (window_offset + match_size) does not
   * exceed window bounds before calling this function. This function assumes
   * window_offset and match_size are pre-validated and does not perform
   * bounds checking on source reads.
   *
   * @param window Circular buffer (size must be power of 2)
   * @param window_pos Current write position (updated by this function)
   * @param window_offset Source position to copy from
   * @param match_size Number of bytes to copy
   * @param window_mask Bitmask for wrapping (window_size - 1)
   */
  void tamp_window_copy (unsigned char *window, xtrt_u16 *window_pos,
                         xtrt_u16 window_offset, xtrt_u8 match_size,
                         xtrt_u16 window_mask);

#  ifdef __cplusplus
}
#  endif

# endif

# ifndef TAMP_COMPRESSOR_H
#  define TAMP_COMPRESSOR_H

#  ifdef __cplusplus
extern "C"
{
#  endif

  /* Externally, do not directly edit ANY of these attributes.
   * Fields are ordered by access frequency for cache efficiency.
   */
  typedef struct TampCompressor
  {
#  if TAMP_ESP32 /* Avoid bitfields for speed. */
    /* HOT: accessed every iteration of the compression loop */
    unsigned char *window;   /* Pointer to window buffer */
    xtrt_u32 bit_buffer;     /* Bit buffer for output (32 bits) */
    xtrt_u32 window_pos;     /* Current position in window (15 bits used) */
    xtrt_u32 bit_buffer_pos; /* Bits currently in bit_buffer (6 bits used) */
    xtrt_u32 input_size;     /* Bytes in input buffer (5 bits used; 0-16) */
    xtrt_u32
        input_pos; /* Current position in input buffer (4 bits used; 0-15) */
    unsigned char input[16]; /* Input ring buffer */

    /* WARM: read frequently, often cached in locals */
    xtrt_u8 min_pattern_size; /* Minimum pattern size (2 bits used; 2 or 3) */
    xtrt_u8 last_was_flush; /* 1 if the most recently emitted token was a FLUSH
                               (no data since). */
    /* Suppresses an accidental double-FLUSH (a dictionary-reset signal). */
    TampConf conf;
#  else  /* Use bitfields for reduced memory-usage */
  /* HOT: accessed every iteration of the compression loop */
  unsigned char *window;  /* Pointer to window buffer */
  xtrt_u32 bit_buffer;    /* Bit buffer for output (32 bits) */
  xtrt_u16 window_pos;    /* Current position in window (15 bits used) */
  xtrt_u8 bit_buffer_pos; /* Bits currently in bit_buffer (6 bits used) */
  xtrt_u8 input_size;     /* Bytes in input buffer (5 bits used; 0-16) */
  xtrt_u8 input_pos; /* Current position in input buffer (4 bits used; 0-15) */
  unsigned char input[16]; /* Input ring buffer */

  /* WARM: read frequently, often cached in locals */
  xtrt_u8 min_pattern_size; /* Minimum pattern size (2 or 3) */
  TampConf conf;
#  endif /* TAMP_ESP32 */

    /* Fields interleaved to avoid internal padding when both LAZY_MATCHING and
     * EXTENDED_COMPRESS enabled */
#  if TAMP_LAZY_MATCHING
    xtrt_s16 cached_match_index; /* Lazy matching cache */
#  endif
#  if TAMP_EXTENDED_COMPRESS
    xtrt_u16 extended_match_position; /* Window position for extended match */
#  endif
#  if TAMP_LAZY_MATCHING
    xtrt_u8 cached_match_size;
#  endif
#  if TAMP_EXTENDED_COMPRESS
    xtrt_u8 rle_count;            /* Current RLE run length (max 241) */
    xtrt_u8 extended_match_count; /* Current extended match size (max ~134) */
#  endif
#  if !TAMP_ESP32
    /* 1 if the most recently emitted token was a FLUSH (no data since);
     * suppresses an */
    /* accidental double-FLUSH (a dictionary-reset signal). Placed at the
     * struct tail (in */
    /* existing padding) so it does NOT shift the trailing fields above to
     * higher offsets, */
    /* which would push them out of Cortex-M0+ small load/store immediate range
     * and bloat */
    /* unrelated functions. The ESP32 variant keeps it inline (free in
     * WARM-section padding). */
    xtrt_u8 last_was_flush;
#  endif
#  if TAMP_MATCH_INDEX
    xtrt_u16 *match_index; /* Optional caller-provided hash-chain index; see
                              tamp_compressor_set_match_index. */
#  endif
  } TampCompressor;

#  if TAMP_MATCH_INDEX
#   if TAMP_ESP32 || TAMP_USE_EMBEDDED_MATCH                                  \
    || !(defined(__x86_64__) || defined(__aarch64__) || defined(_M_X64)       \
         || defined(_M_ARM64))
#    error                                                                    \
    "TAMP_MATCH_INDEX is only supported with the desktop 64-bit match finder"
#   endif

/** Bytes of index memory tamp_compressor_set_match_index needs for a window
 * of 2^window_bits bytes. */
#   define TAMP_MATCH_INDEX_SIZE(window_bits)                                 \
  ((65536 + 3 * ((size_t)1 << (window_bits))) * sizeof (xtrt_u16))

  /**
   * @brief Speed up compression with a hash-chain index over the window.
   *
   * Output is byte-identical to compressing without an index. Call after
   * tamp_compressor_init; init and tamp_compressor_reset_dictionary detach the
   * index, so call again after either to keep using it.
   *
   * @param[in,out] compressor Initialized compressor.
   * @param[in] buffer At least TAMP_MATCH_INDEX_SIZE(conf.window) bytes,
   * 2-byte aligned.
   */
  void tamp_compressor_set_match_index (TampCompressor *compressor,
                                        void *buffer);
#  endif

  /**
   * @brief Initialize Tamp Compressor object.
   *
   * When conf->append is true, writes a FLUSH token to the internal bit buffer
   * instead of a header, enabling append-after-reboot on streams with
   * dictionary_reset enabled. Requires dictionary_reset=true and
   * use_custom_dictionary=false.
   *
   * @param[out] compressor Object to initialize.
   * @param[in] conf Compressor configuration. Set to NULL for default
   * (window=10, literal=8).
   * @param[in] window Pre-allocated window buffer. Size must agree with
   * conf->window. If conf.use_custom_dictionary is true, then the window must
   * be externally initialized.
   *
   * @return Tamp Status Code. Returns TAMP_INVALID_CONF if an invalid conf
   * state is provided.
   */
  tamp_res tamp_compressor_init (TampCompressor *compressor,
                                 const TampConf *conf, unsigned char *window);

  /**
   * @brief Sink data into input buffer.
   *
   * Copies bytes from `input` to the internal input buffer until the internal
   * input buffer is full, or the supplied input is exhausted.
   *
   * Somewhere between 0 and 16 bytes will be copied from the input.
   *
   * This is a computationally cheap/fast function.
   *
   * @param[in,out] compressor TampCompressor object to perform compression
   * with.
   * @param[in] input Pointer to the input data to be sinked into compressor.
   * @param[in] input_size Size of input.
   * @param[out] consumed_size Number of bytes of input consumed. May be NULL.
   */
  void tamp_compressor_sink (TampCompressor *compressor,
                             const unsigned char *input, size_t input_size,
                             size_t *consumed_size);

  /**
   * @brief Run a single compression iteration on the internal input buffer.
   *
   * This is a computationally intensive function.
   *
   * The most that will ever be written to output in a single invocation is:
   *
   *     (1 + 8 + WINDOW_BITS + 7) // 8
   *
   * or more simply:
   *
   *     (16 + WINDOW_BITS) // 8
   *
   * where // represents floor-division.  Explanation:
   *      * 1 - is_literal bit
   *      * 8 - maximum huffman code length
   *      * WINDOW_BITS - The number of bits to represent the match index. By
   * default, 10.
   *      * 7 - The internal bit buffer may have up to 7 bits from a previous
   * invocation. See NOTE below.
   *      * // 8 - Floor divide by 8 to get bytes; the upto remaining 7 bits
   * remain in the internal output bit buffer.
   *
   * NOTE: Unintuitively, tamp_compressor_poll partially flushes (flushing
   * multiples of 8-bits) the internal output bit buffer at the **beginning**
   * of the function call (not the end). This means that a **previous**
   * tamp_compressor_poll call may have placed up to (16 + WINDOW_BITS) bits in
   * the internal output bit buffer. The partial flush at the beginning of
   * tamp_compressor_poll clears as many whole-bytes as possible from this
   * buffer. After this flush, there remains up to 7 bits, to which the current
   * call's compressed token/literal is added to.
   *
   * A 3-byte output buffer should be able to handle any compressor
   * configuration.
   *
   * @param[in,out] compressor TampCompressor object to perform compression
   * with.
   * @param[out] output Pointer to a pre-allocated buffer to hold the output
   * compressed data.
   * @param[in] output_size Size of the pre-allocated output buffer.
   * @param[out] output_written_size Number of bytes written to output. May be
   * NULL.
   *
   * @return Tamp Status Code. Can return TAMP_OK, TAMP_OUTPUT_FULL, or
   * TAMP_EXCESS_BITS.
   */
  TAMP_NOINLINE tamp_res tamp_compressor_poll (TampCompressor *compressor,
                                               unsigned char *output,
                                               size_t output_size,
                                               size_t *output_written_size);
/* backwards compatibility for old naming */
#  define tamp_compressor_compress_poll tamp_compressor_poll

  /**
   * @brief Check if the compressor's input buffer is full.
   *
   * @param[in] compressor TampCompressor object to check.
   *
   * @return true if the compressor is full, false otherwise.
   */
  xtrt_bool tamp_compressor_full (const TampCompressor *compressor);

  /**
   * @brief Completely flush the internal bit buffer. Makes output "complete".
   *
   * @param[in,out] compressor TampCompressor object to flush.
   * @param[out] output Pointer to a pre-allocated buffer to hold the output
   * compressed data.
   * @param[in] output_size Size of the pre-allocated output buffer.
   * @param[out] output_written_size Number of bytes written to output. May be
   * NULL.
   * @param[in] write_token Write the FLUSH token, if appropriate. Set to true
   * if you want to continue using the compressor. Set to false if you are done
   * with the compressor, usually at the end of compression.
   *
   * @return Tamp Status Code. Can return TAMP_OK, or TAMP_OUTPUT_FULL.
   */
  tamp_res tamp_compressor_flush (TampCompressor *compressor,
                                  unsigned char *output, size_t output_size,
                                  size_t *output_written_size,
                                  xtrt_bool write_token);

  /**
   * @brief Reset the compressor dictionary and internal state.
   *
   * Writes a double-FLUSH token sequence to signal dictionary
   * re-initialization to the decompressor, then resets the window and all
   * internal compression state.
   *
   * The compressor continues to use the same configuration (window, literal,
   * etc.) but starts fresh with a re-initialized dictionary.
   *
   * The compressor must have been initialized with conf->dictionary_reset set.
   * This causes the header to include the more_header flag, which old
   * decompressors will reject rather than silently producing corrupt output.
   *
   * @param[in,out] compressor TampCompressor object to reset.
   * @param[out] output Pointer to a pre-allocated buffer to hold output data.
   * @param[in] output_size Size of the pre-allocated output buffer.
   * @param[out] output_written_size Number of bytes written to output. May be
   * NULL.
   *
   * @return Tamp Status Code. Can return TAMP_OK, TAMP_OUTPUT_FULL, or
   *         TAMP_INVALID_CONF if dictionary_reset was not set at init.
   */
  tamp_res tamp_compressor_reset_dictionary (TampCompressor *compressor,
                                             unsigned char *output,
                                             size_t output_size,
                                             size_t *output_written_size);

  /**
   * Callback-variant of tamp_compressor_compress.
   *
   * @param[in] callback User-provided function to be called every
   * compression-cycle. Receives (user_data, input_bytes_consumed,
   * total_input_size).
   * @param[in,out] user_data Passed along to callback.
   */
  tamp_res tamp_compressor_compress_cb (
      TampCompressor *compressor, unsigned char *output, size_t output_size,
      size_t *output_written_size, const unsigned char *input,
      size_t input_size, size_t *input_consumed_size, tamp_callback_t callback,
      void *user_data);

  /**
   * @brief Compress a chunk of data until input or output buffer is exhausted.
   *
   * @param[in,out] compressor TampCompressor object to perform compression
   * with.
   * @param[out] output Pointer to a pre-allocated buffer to hold the output
   * compressed data.
   * @param[in] output_size Size of the pre-allocated output buffer.
   * @param[out] output_written_size Number of bytes written to output. May be
   * NULL.
   * @param[in] input Pointer to the input data to be compressed.
   * @param[in] input_size Number of bytes in input data.
   * @param[out] input_consumed_size Number of bytes of input data consumed.
   * May be NULL.
   *
   * @return Tamp Status Code. Can return TAMP_OK, TAMP_OUTPUT_FULL, or
   * TAMP_EXCESS_BITS.
   */
  tamp_res tamp_compressor_compress (TampCompressor *compressor,
                                     unsigned char *output, size_t output_size,
                                     size_t *output_written_size,
                                     const unsigned char *input,
                                     size_t input_size,
                                     size_t *input_consumed_size);

  /**
   * Callback-variant of tamp_compressor_compress_and_flush.
   *
   * @param[in] callback User-provided function to be called every
   * compression-cycle. A final callback is issued after flushing to signal
   * completion.
   * @param[in,out] user_data Passed along to callback.
   */
  tamp_res tamp_compressor_compress_and_flush_cb (
      TampCompressor *compressor, unsigned char *output, size_t output_size,
      size_t *output_written_size, const unsigned char *input,
      size_t input_size, size_t *input_consumed_size, xtrt_bool write_token,
      tamp_callback_t callback, void *user_data);

  /**
   * @brief Compress a chunk of data until input or output buffer is exhausted.
   *
   * If the output buffer is full, buffer flushing will not be performed and
   * TAMP_OUTPUT_FULL will be returned. May be called again with an
   * appropriately updated pointers and sizes.
   *
   * @param[in,out] compressor TampCompressor object to perform compression
   * with.
   * @param[out] output Pointer to a pre-allocated buffer to hold the output
   * compressed data.
   * @param[in] output_size Size of the pre-allocated output buffer.
   * @param[out] output_written_size Number of bytes written to output. May be
   * NULL.
   * @param[in] input Pointer to the input data to be compressed.
   * @param[in] input_size Number of bytes in input data.
   * @param[out] input_consumed_size Number of bytes of input data consumed.
   * May be NULL.
   *
   * @return Tamp Status Code. Can return TAMP_OK, TAMP_OUTPUT_FULL, or
   * TAMP_EXCESS_BITS.
   */
  tamp_res tamp_compressor_compress_and_flush (
      TampCompressor *compressor, unsigned char *output, size_t output_size,
      size_t *output_written_size, const unsigned char *input,
      size_t input_size, size_t *input_consumed_size, xtrt_bool write_token);

#  if TAMP_STREAM
  /**
   * @brief Compress data from input source to output destination using
   * callbacks.
   *
   * High-level function that reads from an input source, compresses the data,
   * and writes to an output destination using user-provided I/O callbacks.
   * Works with any I/O backend (stdio, littlefs, fatfs, UART, etc.).
   *
   * Uses an internal **stack-allocated** work buffer sized by
   * TAMP_STREAM_WORK_BUFFER_SIZE (default 32 bytes). For better compression
   * performance, increase this via compiler flag:
   * -DTAMP_STREAM_WORK_BUFFER_SIZE=256
   *
   * Example with stdio:
   * @code
   * FILE *in = fopen("input.bin", "rb");
   * FILE *out = fopen("output.tamp", "wb");
   * unsigned char window[1024];
   * TampCompressor compressor;
   * tamp_compressor_init(&compressor, NULL, window);
   * tamp_compress_stream(
   *     &compressor,             // compressor: initialized compressor
   *     tamp_stream_stdio_read,  // read_cb: reads uncompressed input
   *     in,                      // read_handle: passed to read_cb
   *     tamp_stream_stdio_write, // write_cb: writes compressed output
   *     out,                     // write_handle: passed to write_cb
   *     NULL,                    // input_consumed_size: out, bytes read
   *     NULL,                    // output_written_size: out, bytes written
   *     NULL,                    // callback: progress callback
   *     NULL                     // user_data: passed to callback
   * );
   * fclose(in);
   * fclose(out);
   * @endcode
   *
   * @param[in,out] compressor Initialized TampCompressor (via
   * tamp_compressor_init).
   * @param[in] read_cb Callback to read uncompressed input data.
   * @param[in] read_handle Opaque handle passed to read_cb (e.g., input
   * FILE*).
   * @param[in] write_cb Callback to write compressed output data.
   * @param[in] write_handle Opaque handle passed to write_cb (e.g., output
   * FILE*).
   * @param[out] input_consumed_size Total input bytes read. May be NULL.
   * @param[out] output_written_size Total compressed bytes written. May be
   * NULL.
   * @param[in] callback Optional progress callback invoked periodically. May
   * be NULL. Receives (user_data, input_bytes_consumed, 0).
   * @param[in] user_data User data passed to progress callback.
   *
   * @return TAMP_OK on success, or an error code:
   *         - TAMP_READ_ERROR: read_cb returned a negative value
   *         - TAMP_WRITE_ERROR: write_cb returned a negative value or
   * incomplete write
   *         - Other tamp_res error codes from compression
   */
  tamp_res tamp_compress_stream (TampCompressor *compressor,
                                 tamp_read_t read_cb, void *read_handle,
                                 tamp_write_t write_cb, void *write_handle,
                                 size_t *input_consumed_size,
                                 size_t *output_written_size,
                                 tamp_callback_t callback, void *user_data);
#  endif /* TAMP_STREAM */

#  ifdef __cplusplus
}
#  endif

# endif

# ifndef TAMP_DECOMPRESSOR_H
#  define TAMP_DECOMPRESSOR_H

#  ifdef __cplusplus
extern "C"
{
#  endif

  /* Externally, do not directly edit ANY of these attributes.
   * Fields are ordered by access frequency for cache efficiency.
   */
  typedef struct
  {
    /* HOT: accessed every iteration of the decompression loop. */
    unsigned char *window; /* Pointer to window buffer */
    xtrt_u32 bit_buffer; /* Bit buffer for reading compressed data (32 bits) */
    xtrt_u16 window_pos; /* Current position in window (15 bits) */

    xtrt_u8 bit_buffer_pos;
    xtrt_u8 token_state;
    xtrt_u16 pending_window_offset;
    xtrt_u16 pending_match_size;

    /* WARM: read once at start of decompress, cached in locals */
    unsigned int conf_window : 4;      /* Window bits from config */
    unsigned int conf_literal : 4;     /* Literal bits from config */
    unsigned int min_pattern_size : 2; /* Minimum pattern size, 2 or 3 */
    unsigned int conf_extended : 1; /* Extended format enabled (from header) */
    unsigned int conf_dictionary_reset
        : 1; /* Stream may contain double-FLUSH dictionary resets (from header
                byte 1 bit [0] */
             /* / more_header) */

    /* COLD: rarely accessed (init or edge cases).
     * Bitfields save space; add new cold fields here. */
    xtrt_u8 skip_bytes;
    xtrt_u8 stashed_header_byte;
    unsigned int window_bits_max : 4; /* Max window bits buffer can hold */
    unsigned int configured : 1; /* Whether config has been set (authoritative
                                    "header complete" flag) */
    unsigned int header_bytes_read
        : 2; /* Before configured: header bytes consumed so far */
    unsigned int last_was_flush
        : 1; /* Previous token was FLUSH (for double-FLUSH dictionary reset
                detection) */
  } TampDecompressor;

  /**
   * @brief Read tamp header and populate configuration.
   *
   * Don't invoke if setting conf to NULL in tamp_decompressor_init.
   *
   * @param[out] conf Configuration read from header
   * @param[in] data Tamp compressed data.
   */
  tamp_res tamp_decompressor_read_header (TampConf *conf,
                                          const unsigned char *input,
                                          size_t input_size,
                                          size_t *input_consumed_size);

  /**
   * @brief Initialize decompressor object.
   *
   * @param[in,out] decompressor TampDecompressor object to perform
   * decompression with.
   * @param[in] conf Decompressor configuration. Set to NULL to perform an
   * implicit header read.
   * @param[in] window Pre-allocated window buffer.
   * @param[in] window_bits Number of window bits the buffer can accommodate
   * (8-15). Buffer must be at least (1 << window_bits) bytes. When conf is
   * NULL (implicit header read), the header's window size is validated against
   * this value.
   *
   * @return TAMP_OK on success, TAMP_INVALID_CONF if window_bits is invalid or
   * too small.
   */
  tamp_res tamp_decompressor_init (TampDecompressor *decompressor,
                                   const TampConf *conf, unsigned char *window,
                                   xtrt_u8 window_bits);

  /**
   * Callback-variant of tamp_decompressor_decompress.
   *
   * @param[in] callback User-provided function to be called every
   * decompression-cycle. Receives (user_data, input_bytes_consumed,
   * total_input_size).
   * @param[in,out] user_data Passed along to callback.
   */
  tamp_res tamp_decompressor_decompress_cb (
      TampDecompressor *decompressor, unsigned char *output,
      size_t output_size, size_t *output_written_size,
      const unsigned char *input, size_t input_size,
      size_t *input_consumed_size, tamp_callback_t callback, void *user_data);

  /**
   * @brief Decompress input data into an output buffer.
   *
   * Input data is **not** guaranteed to be consumed.  Imagine if a 6-byte
   * sequence has been encoded, and tamp_decompressor_decompress is called
   * multiple times with a 2-byte output buffer:
   *
   *     1.  On the 1st call, a few input bytes may be consumed, filling the
   * internal input buffer. The first 2 bytes of the 6-byte output sequence are
   * returned. The internal input buffer remains full.
   *     2.  On the 2nd call, no input bytes are consumed since the internal
   * input buffer is still full. The {3, 4} bytes of the 6-byte output sequence
   * are returned. The internal input buffer remains full.
   *     3.  On the 3rd call, no input bytes are consumed since the internal
   * input buffer is still full. The {5, 6} bytes of the 6-byte output sequence
   * are returned. The input buffer is no longer full since this sequence has
   * now been fully decoded.
   *     4.  On the 4th call, more input bytes are consumed, potentially
   * filling the internal input buffer. It is not strictly necessary for the
   * internal input buffer to be full to further decode the output. There
   * simply has to be enough to decode a token/literal. If there is not enough
   * bits in the internal input buffer, then TAMP_INPUT_EXHAUSTED will be
   * returned.
   *
   * @param[in,out] TampDecompressor object to perform decompression with.
   * @param[out] output Pointer to a pre-allocated buffer to hold the output
   * decompressed data.
   * @param[in] output_size Size of the pre-allocated buffer. Will decompress
   * up-to this many bytes.
   * @param[out] output_written_size Number of bytes written to output. May be
   * NULL.
   * @param[in] input Pointer to the compressed input data.
   * @param[in] input_size Number of bytes in input data.
   * @param[out] input_consumed_size Number of bytes of input data consumed.
   * May be NULL.
   *
   * @return Tamp Status Code. In cases of success, will return
   * TAMP_INPUT_EXHAUSTED or TAMP_OUTPUT_FULL, in lieu of TAMP_OK.
   */
  tamp_res tamp_decompressor_decompress (TampDecompressor *decompressor,
                                         unsigned char *output,
                                         size_t output_size,
                                         size_t *output_written_size,
                                         const unsigned char *input,
                                         size_t input_size,
                                         size_t *input_consumed_size);

#  if TAMP_STREAM
  /**
   * @brief Decompress data from input source to output destination using
   * callbacks.
   *
   * High-level function that reads compressed data, decompresses it,
   * and writes to an output destination using user-provided I/O callbacks.
   * Works with any I/O backend (stdio, littlefs, fatfs, UART, etc.).
   *
   * Uses an internal **stack-allocated** work buffer sized by
   * TAMP_STREAM_WORK_BUFFER_SIZE (default 32 bytes). For better decompression
   * performance, increase this via compiler flag:
   * -DTAMP_STREAM_WORK_BUFFER_SIZE=256
   *
   * Example with littlefs:
   * @code
   * lfs_file_t in, out;
   * lfs_file_open(&lfs, &in, "data.tamp", LFS_O_RDONLY);
   * lfs_file_open(&lfs, &out, "data.bin", LFS_O_WRONLY | LFS_O_CREAT);
   * unsigned char window[1024];
   * TampDecompressor decompressor;
   * tamp_decompressor_init(&decompressor, NULL, window, 10);
   * tamp_decompress_stream(
   *     &decompressor,         // decompressor: initialized decompressor
   *     tamp_stream_lfs_read,  // read_cb: reads compressed input
   *     &in,                   // read_handle: passed to read_cb
   *     tamp_stream_lfs_write, // write_cb: writes decompressed output
   *     &out,                  // write_handle: passed to write_cb
   *     NULL,                  // input_consumed_size: out, bytes read
   *     NULL,                  // output_written_size: out, bytes written
   *     NULL,                  // callback: progress callback
   *     NULL                   // user_data: passed to callback
   * );
   * lfs_file_close(&lfs, &in);
   * lfs_file_close(&lfs, &out);
   * @endcode
   *
   * @param[in,out] decompressor Initialized TampDecompressor (via
   * tamp_decompressor_init). When initialized with conf=NULL, the header will
   * be read from the stream automatically.
   * @param[in] read_cb Callback to read compressed input data.
   * @param[in] read_handle Opaque handle passed to read_cb.
   * @param[in] write_cb Callback to write decompressed output data.
   * @param[in] write_handle Opaque handle passed to write_cb.
   * @param[out] input_consumed_size Total compressed bytes read. May be NULL.
   * @param[out] output_written_size Total decompressed bytes written. May be
   * NULL.
   * @param[in] callback Optional progress callback invoked periodically. May
   * be NULL. Receives (user_data, input_bytes_consumed, 0).
   * @param[in] user_data User data passed to progress callback.
   *
   * @return TAMP_OK on success (stream fully decompressed), or an error code:
   *         - TAMP_READ_ERROR: read_cb returned a negative value
   *         - TAMP_WRITE_ERROR: write_cb returned a negative value or
   * incomplete write
   *         - TAMP_OOB: Corrupt/malicious data attempted out-of-bounds access
   *         - Other tamp_res error codes from decompression
   */
  tamp_res tamp_decompress_stream (TampDecompressor *decompressor,
                                   tamp_read_t read_cb, void *read_handle,
                                   tamp_write_t write_cb, void *write_handle,
                                   size_t *input_consumed_size,
                                   size_t *output_written_size,
                                   tamp_callback_t callback, void *user_data);
#  endif /* TAMP_STREAM */

#  ifdef __cplusplus
}
#  endif

# endif

#endif /* XTR_TAMP_H */
