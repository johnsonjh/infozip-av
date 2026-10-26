/* Xtro-ZIP Tamp C89 amalgamation */

/* Derived from Brian Pugh's MIT-licensed Tamp. */

#include "xtr_tamp.h"

#if TAMP_STREAM && TAMP_STREAM_WORK_BUFFER_SIZE < 4
# error "TAMP_STREAM_WORK_BUFFER_SIZE must be at least 4 bytes"
#endif /* if TAMP_STREAM && TAMP_STREAM_WORK_BUFFER_SIZE < 4 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if TAMP_STREAM_STDIO
# include <stdio.h>
#endif /* if TAMP_STREAM_STDIO */

/* Per-literal-size seed tables.  All 16 entries must be unique and fit within
 * (1 << literal) - 1.  literal=7,8 share the original table (all < 0x80). */
/* clang-format off */
TAMP_STATIC_CONST unsigned char  common_characters_8[] = {
  ' ',   0, '0', 'e', 'i',  '>', 't', 'o',
  '<', 'a', 'n', 's', '\n', 'r', '/', '.'
};
/* Common English characters, downshifted to 6 bits */
TAMP_STATIC_CONST unsigned char  common_characters_6[] = {
  ' ' & 0x3F, 'e' & 0x3F, 't' & 0x3F, 'a' & 0x3F, 'o' & 0x3F, 'i' & 0x3F, 'n' & 0x3F, 's' & 0x3F,
  'h' & 0x3F, 'r' & 0x3F, 'd' & 0x3F, 'l' & 0x3F, 'c' & 0x3F, 'u' & 0x3F, 'm' & 0x3F, 'w' & 0x3F
};
/* Common English characters, downshifted to 5 bits */
TAMP_STATIC_CONST unsigned char  common_characters_5[] = {
  ' ' & 0x1F, 'e' & 0x1F, 't' & 0x1F, 'a' & 0x1F, 'o' & 0x1F, 'i' & 0x1F, 'n' & 0x1F, 's' & 0x1F,
  'h' & 0x1F, 'r' & 0x1F, 'd' & 0x1F, 'l' & 0x1F, 'c' & 0x1F, 'u' & 0x1F, 'm' & 0x1F, 'w' & 0x1F
};
/* clang-format on */

static xtrt_u32
xorshift32 (xtrt_u32 *state)
{
  xtrt_u32 x = *state;

  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

TAMP_OPTIMIZE_SIZE void
tamp_initialize_dictionary (unsigned char *buffer, size_t size,
                            xtrt_u8 literal)
{
  xtrt_u32 seed = 3758097560; /* This was experimentally discovered with
                               * tools/find_seed.py */
  xtrt_u32 randbuf = 0;
  const unsigned char *chars;

  if (literal <= 5)
    {
      chars = common_characters_5;
    }
  else if (literal <= 6)
    {
      chars = common_characters_6;
    }
  else
    {
      chars = common_characters_8;
    }

  {
    size_t i;
    for (i = 0; i < size; i++)
      {
        if (TAMP_UNLIKELY ((i & 0x7) == 0))
          {
            randbuf = xorshift32 (&seed);
          }

        buffer[i] = chars[randbuf & 0x0F];
        randbuf >>= 4;
      }
  }
}

TAMP_OPTIMIZE_SIZE xtrt_s8
tamp_compute_min_pattern_size (xtrt_u8 window, xtrt_u8 literal)
{
  return 2 + (window > (10 + ((literal - 5) << 1)));
}

void
tamp_window_copy (unsigned char *window, xtrt_u16 *window_pos,
                  xtrt_u16 window_offset, xtrt_u8 match_size,
                  xtrt_u16 window_mask)
{
  /* Calculate distance from source to destination in circular buffer.
   * src_to_dst = (dst - src) & mask gives the forward distance. */
  const xtrt_u16 src_to_dst = (*window_pos - window_offset) & window_mask;

  /* Critical overlap case: destination is AHEAD of source and they overlap.
   * When dst > src by less than match_size, a forward copy corrupts data
   * because we write to positions before reading from them.
   *
   * Example: src=100, dst=105, match_size=8
   *   - Forward copy at i=5 would read window[105], but we already overwrote
   * it at i=0!
   *   - Must copy in REVERSE order (end to start) to read source bytes before
   * overwriting.
   */
  if (TAMP_UNLIKELY (src_to_dst < match_size && src_to_dst > 0))
    {
      /* Copy in reverse order: start from last byte, work backwards to first
       * byte. This ensures we read all overlapping source bytes before they're
       * overwritten. Destination wraps via mask; source doesn't need wrapping
       * (pre-validated bounds). */
      {
        xtrt_u8 i;
        for (i = match_size; i-- > 0;)
          {
            window[(*window_pos + i) & window_mask]
                = window[window_offset + i];
          }
      }
      *window_pos = (*window_pos + match_size) & window_mask;
    }
  else
    {
      {
        xtrt_u8 i;
        for (i = 0; i < match_size; i++)
          {
            window[*window_pos] = window[window_offset + i];
            *window_pos = (*window_pos + 1) & window_mask;
          }
      }
    }
}

/*******************************************************************************
 * Built-in I/O handler implementations
 ******************************************************************************/

#if TAMP_STREAM_MEMORY

int
tamp_stream_mem_read (void *handle, unsigned char *buffer, size_t size)
{
  TampMemReader *r = (TampMemReader *)handle;
  size_t available = r->size - r->pos;
  size_t to_read = (size < available) ? size : available;

  if (to_read > (size_t)INT_MAX)
    {
      to_read = (size_t)INT_MAX;
    }

  memcpy (buffer, r->data + r->pos, to_read);
  r->pos += to_read;
  return (int)to_read;
}

int
tamp_stream_mem_write (void *handle, const unsigned char *buffer, size_t size)
{
  TampMemWriter *w = (TampMemWriter *)handle;
  size_t available = w->capacity - w->pos;

  if (size > available)
    {
      return -1;
    }

  if (size > (size_t)INT_MAX)
    {
      return -1;
    }

  memcpy (w->data + w->pos, buffer, size);
  w->pos += size;
  return (int)size;
}

#endif /* TAMP_STREAM_MEMORY */

#if TAMP_STREAM_STDIO

int
tamp_stream_stdio_read (void *handle, unsigned char *buffer, size_t size)
{
  FILE *f = (FILE *)handle;
  size_t bytes_read = fread (buffer, 1, size, f);

  if (bytes_read == 0 && ferror (f))
    {
      return -1;
    }

  return (int)bytes_read;
}

int
tamp_stream_stdio_write (void *handle, const unsigned char *buffer,
                         size_t size)
{
  FILE *f = (FILE *)handle;
  size_t bytes_written = fwrite (buffer, 1, size, f);

  if (bytes_written < size && ferror (f))
    {
      return -1;
    }

  return (int)bytes_written;
}

#endif /* TAMP_STREAM_STDIO */

#if TAMP_STREAM_LITTLEFS

int
tamp_stream_lfs_read (void *handle, unsigned char *buffer, size_t size)
{
  TampLfsFile *f = (TampLfsFile *)handle;
  lfs_ssize_t result = lfs_file_read (f->lfs, f->file, buffer, size);

  return (int)result;
}

int
tamp_stream_lfs_write (void *handle, const unsigned char *buffer, size_t size)
{
  TampLfsFile *f = (TampLfsFile *)handle;
  lfs_ssize_t result = lfs_file_write (f->lfs, f->file, buffer, size);

  return (int)result;
}

#endif /* TAMP_STREAM_LITTLEFS */

#if TAMP_STREAM_FATFS

int
tamp_stream_fatfs_read (void *handle, unsigned char *buffer, size_t size)
{
  UINT bytes_read;
  FRESULT res = f_read ((FIL *)handle, buffer, (UINT)size, &bytes_read);

  if (res != FR_OK)
    {
      return -1;
    }

  return (int)bytes_read;
}

int
tamp_stream_fatfs_write (void *handle, const unsigned char *buffer,
                         size_t size)
{
  UINT bytes_written;
  FRESULT res = f_write ((FIL *)handle, buffer, (UINT)size, &bytes_written);

  if (res != FR_OK)
    {
      return -1;
    }

  return (int)bytes_written;
}

#endif /* TAMP_STREAM_FATFS */

#include <stdlib.h>

#define XTR_TAMP_MIN(x, y) (((x) < (y)) ? (x) : (y))
#define BUILD_BUG_ON(condition) ((void)sizeof (char[1 - 2 * !!(condition)]))

#if TAMP_EXTENDED_COMPRESS
/* Extended max pattern: min_pattern_size + 11 + EXTENDED_MATCH_MAX_EXTRA */
/* = min_pattern_size + 11 + (14 << 3) + 7 + 1 = min_pattern_size + 131 */
# define MAX_PATTERN_SIZE_EXTENDED                                            \
  (compressor->min_pattern_size + 11 + EXTENDED_MATCH_MAX_EXTRA)
# define MAX_PATTERN_SIZE                                                     \
  (compressor->conf.extended ? MAX_PATTERN_SIZE_EXTENDED                      \
                             : (compressor->min_pattern_size + 13))
#else /* if TAMP_EXTENDED_COMPRESS */
# define MAX_PATTERN_SIZE (compressor->min_pattern_size + 13)
#endif /* if TAMP_EXTENDED_COMPRESS */
#define WINDOW_SIZE (1UL << compressor->conf.window)
/* 0xF because sizeof(TampCompressor.input) == 16; */
#define input_add(offset) ((compressor->input_pos + offset) & 0xF)
#define read_input(offset) (compressor->input[input_add (offset)])
#define IS_LITERAL_FLAG (1 << compressor->conf.literal)

#if !TAMP_MATCH_INDEX
/* Real definition lives with the match index in
 * compressor_find_match_desktop.c. */
# define TAMP_INDEX_UPDATE(compressor, count)                                 \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif /* if !TAMP_MATCH_INDEX */

#define FLUSH_CODE (0xAB)

/* Internal return value for poll_extended_handling: signals caller to */
/* proceed with normal pattern matching rather than returning immediately. */
#define TAMP_POLL_CONTINUE ((tamp_res)127)

/* encodes [min_pattern_bytes, min_pattern_bytes + 14] pattern lengths (14 =
 * FLUSH pattern, used in secondary reads) */
TAMP_STATIC_CONST xtrt_u8 huffman_codes[]
    = { 0x0,  0x3,  0x8,  0xb,  0x14, 0x24, 0x26, 0x2b,
        0x4b, 0x54, 0x94, 0x95, 0xaa, 0x27, 0xab };
/* These bit lengths pre-add the 1 bit for the 0-value is_literal flag. */
TAMP_STATIC_CONST xtrt_u8 huffman_bits[]
    = { 0x2, 0x3, 0x5, 0x5, 0x6, 0x7, 0x7, 0x7,
        0x8, 0x8, 0x9, 0x9, 0x9, 0x7, 0x09 };

#if TAMP_EXTENDED_COMPRESS
# define RLE_MAX_COUNT ((14 << 4) + 15 + 2)           /* 241 */
# define EXTENDED_MATCH_MAX_EXTRA ((14 << 3) + 7 + 1) /* 120 */

/* Minimum output buffer space required for extended match token. */
/* Extended match: symbol (7 bits) + extended huffman (11 bits) + window pos
 * (15 bits) = 33 bits. */
/* With 7 bits in bit buffer, need up to 40 bits = 5 bytes. Add 1 byte margin.
 */
/* Pre-checking prevents OUTPUT_FULL mid-token, which would corrupt bit_buffer
 * on retry. */
# define EXTENDED_MATCH_MIN_OUTPUT_BYTES 6
#endif /* if TAMP_EXTENDED_COMPRESS */

static TAMP_NOINLINE void
write_to_bit_buffer (TampCompressor *compressor, xtrt_u32 bits, xtrt_u8 n_bits)
{
  compressor->bit_buffer_pos += n_bits;
  compressor->bit_buffer |= bits << (32 - compressor->bit_buffer_pos);
}

/**
 * @brief Partially flush the internal bit buffer.
 *
 * Flushes complete bytes from the bit buffer. Up to 7 bits may remain.
 *
 * @param[in,out] compressor Compressor state.
 * @param[in,out] output Output buffer pointer (updated on return).
 * @param[in,out] output_size Available space (updated on return).
 * @param[in,out] output_written_size Bytes written (accumulated).
 * @return TAMP_OK on success, TAMP_OUTPUT_FULL if output buffer is too small.
 */
static TAMP_NOINLINE TAMP_OPTIMIZE_SIZE tamp_res
partial_flush (TampCompressor *compressor, unsigned char **output,
               size_t *output_size, size_t *output_written_size)
{
  while (compressor->bit_buffer_pos >= 8 && *output_size)
    {
      *(*output)++ = compressor->bit_buffer >> 24;
      (*output_size)--;
      (*output_written_size)++;
      compressor->bit_buffer_pos -= 8;
      compressor->bit_buffer <<= 8;
    }
  return (compressor->bit_buffer_pos >= 8) ? TAMP_OUTPUT_FULL : TAMP_OK;
}

xtrt_bool
tamp_compressor_full (const TampCompressor *compressor)
{
  return compressor->input_size == sizeof (compressor->input);
}

/*
 * Platform-specific find_best_match implementations:
 *
 * 1. TAMP_ESP32: External implementation in espidf/tamp/compressor_esp32.cpp
 *
 * 2. Desktop 64-bit (x86_64, aarch64, Windows 64-bit):
 *    Included from compressor_find_match_desktop.c - uses bit manipulation
 *    and 64-bit loads for parallel match detection
 *
 * 3. Embedded/Default (Cortex-M0/M0+, other 32-bit):
 *    Defined below - single-byte-first comparison, safe for all architectures
 *
 * Set TAMP_USE_EMBEDDED_MATCH=1 to force the embedded implementation on
 * desktop (useful for testing the embedded code path on CI).
 */

#if TAMP_ESP32
extern void find_best_match (TampCompressor *compressor, xtrt_u16 *match_index,
                             xtrt_u8 *match_size);

#elif (defined(__x86_64__) || defined(__aarch64__) || defined(_M_X64)         \
       || defined(_M_ARM64))                                                  \
    && !TAMP_USE_EMBEDDED_MATCH
# include "compressor_find_match_desktop.c"

#else /* if TAMP_ESP32 */
/**
 * @brief Find the best match for the current input buffer.
 *
 * Embedded/32-bit implementation: uses single-byte-first comparison (faster on
 * simple cores).
 *
 * @param[in,out] compressor TampCompressor object to perform search on.
 * @param[out] match_index  If match_size is 0, this value is undefined.
 * @param[out] match_size Size of best found match.
 */
static TAMP_NOINLINE void
find_best_match (TampCompressor *compressor, xtrt_u16 *match_index,
                 xtrt_u8 *match_size)
{
  const unsigned char *window;
  xtrt_u8 max_pattern_size;
  xtrt_u32 window_size_minus_1;
  xtrt_u8 second_byte;
  xtrt_u8 first_byte;

  *match_size = 0;

  if (TAMP_UNLIKELY (compressor->input_size < compressor->min_pattern_size))
    {
      return;
    }

  first_byte = read_input (0);
  second_byte = read_input (1);
  window_size_minus_1 = WINDOW_SIZE - 1;
  max_pattern_size = XTR_TAMP_MIN (compressor->input_size, MAX_PATTERN_SIZE);
  window = compressor->window;

# if 0
  /* Word-at-a-time skip over bytes that can't start a match: ~3 cycles/byte */
  /* instead of ~9 on Cortex-M0+, and the scan dominates compression time. */
  const xtrt_u32 first_broadcast = first_byte * 0x01010101u;
# endif /* if 0 */

  {
    xtrt_u32 window_index;
    for (window_index = 0; window_index < window_size_minus_1; window_index++)
      {
        xtrt_u8 match_len;
        if (TAMP_LIKELY (window[window_index] != first_byte))
          {
# if 0
            xtrt_u32 wi = window_index + 1;
            if (TAMP_LIKELY(((uintptr_t)( window + wi ) & 3 ) == 0))
              {
                /* Aligned: skip 4 bytes per iteration until a word may hold */
                /* first_byte (zero-byte detect on the XOR; 0 positives */
                /* are fine, the byte loop re-checks). */
                typedef xtrt_u32 __attribute__(( may_alias )) tamp_word_alias;
                while (wi + 4 <= window_size_minus_1)
                  {
                    xtrt_u32 word = *(const tamp_word_alias*)( window + wi ) ^ first_broadcast;
                    if (( word - 0x01010101u ) & ~word & 0x80808080u)
                      {
                        break;
                      }

                    wi += 4;
                  }
              }

            window_index = wi - 1;  /* loop increment advances to wi */
# endif /* if 0 */
            continue;
          }

        if (TAMP_LIKELY (window[window_index + 1] != second_byte))
          {
            continue;
          }

        /* Found 2-byte match, now extend the match */
        match_len = 2;

        /* Extend match byte by byte with optimized bounds checking */
        {
          xtrt_u8 i;
          for (i = 2; i < max_pattern_size; i++)
            {
              if (TAMP_UNLIKELY ((window_index + i) > window_size_minus_1))
                {
                  break;
                }

              if (TAMP_LIKELY (window[window_index + i] != read_input (i)))
                {
                  break;
                }

              match_len = i + 1;
            }
        }

        /* Update best match if this is better */
        if (TAMP_UNLIKELY (match_len > *match_size))
          {
            *match_size = match_len;
            *match_index = window_index;
            /* Early termination if we found the maximum possible match */
            if (TAMP_UNLIKELY (*match_size == max_pattern_size))
              {
                return;
              }
          }
      }
  }
}

#endif /* if TAMP_ESP32 */

#if TAMP_LAZY_MATCHING
/**
 * @brief Check if writing a single byte will overlap with a future match
 * section.
 *
 * @param[in] write_pos Position where the single byte will be written.
 * @param[in] match_index Index in window where the match starts.
 * @param[in] match_size Size of the match to validate.
 * @return 1 if no overlap (match is safe), 0 if there's overlap.
 */
static xtrt_bool
validate_no_match_overlap (xtrt_u16 write_pos, xtrt_u16 match_index,
                           xtrt_u8 match_size)
{
  /* Check if write position falls within the match range [match_index,
   * match_index + match_size - 1] */
  return write_pos < match_index || write_pos >= match_index + match_size;
}
#endif /* if TAMP_LAZY_MATCHING */

TAMP_OPTIMIZE_SIZE tamp_res
tamp_compressor_init (TampCompressor *compressor, const TampConf *conf,
                      unsigned char *window)
{
  TampConf conf_default;
  xtrt_u8 window_bits;
  xtrt_u8 literal_bits;

  TAMP_MEMSET (&conf_default, 0, sizeof (conf_default));
  conf_default.window = 10;
  conf_default.literal = 8;
  conf_default.extended = 1;
  if (!conf)
    {
      conf = &conf_default;
    }

  window_bits = conf->window;
  literal_bits = conf->literal;
  if (window_bits < 8 || window_bits > 15)
    {
      return TAMP_INVALID_CONF;
    }

  if (literal_bits < 5 || literal_bits > 8)
    {
      return TAMP_INVALID_CONF;
    }

  if (conf->append && (!conf->dictionary_reset || conf->use_custom_dictionary))
    {
      return TAMP_INVALID_CONF;
    }

#if !TAMP_EXTENDED_COMPRESS
  if (conf->extended)
    {
      return TAMP_INVALID_CONF; /* Extended requested but not compiled in */
    }

#endif /* if !TAMP_EXTENDED_COMPRESS */

  TAMP_MEMSET (compressor, 0, sizeof (TampCompressor));

  compressor->conf = *conf; /* Single struct copy */
  compressor->window = window;
  compressor->min_pattern_size
      = tamp_compute_min_pattern_size (conf->window, conf->literal);

#if TAMP_LAZY_MATCHING
  compressor->cached_match_index = -1; /* Initialize cache as invalid */
#endif                                 /* if TAMP_LAZY_MATCHING */

  if (!conf->use_custom_dictionary)
    {
      tamp_initialize_dictionary (window, (size_t)(1UL << conf->window),
                                  conf->extended ? conf->literal : 8);
    }

  if (conf->append)
    {
      /* Write a FLUSH token (9 bits) padded to 16 bits. Combined with the */
      /* previous stream's trailing FLUSH, this triggers a dictionary reset. */
      write_to_bit_buffer (compressor, FLUSH_CODE, 9);
      compressor->bit_buffer_pos = 16;
      /* This FLUSH is the most recently emitted token; mark it so an immediate
       */
      /* redundant flush() doesn't append a second FLUSH and over-signal a
       * reset. */
      compressor->last_was_flush = 1;
    }
  else
    {
      /* Header byte 1:
       * [window:3][literal:2][use_custom_dictionary:1][extended:1][more_headers:1]
       */
      xtrt_u8 header = ((conf->window - 8) << 5) | ((conf->literal - 5) << 3)
                       | (conf->use_custom_dictionary << 2)
                       | (conf->extended << 1) | conf->dictionary_reset;
      write_to_bit_buffer (compressor, header, 8);
      /* Header byte 2 (if present): reserved bits, all zero from memset. */
      compressor->bit_buffer_pos += conf->dictionary_reset ? 8 : 0;
    }

  return TAMP_OK;
}

#if TAMP_EXTENDED_COMPRESS
/**
 * @brief Write extended huffman encoding (huffman + trailing bits).
 *
 * Used for both RLE count and extended match size encoding.
 *
 * @param[in,out] compressor Compressor with bit buffer.
 * @param[in] value The value to encode.
 * @param[in] trailing_bits Number of trailing bits (3 for extended match, 4
 * for RLE).
 */
static TAMP_NOINLINE TAMP_OPTIMIZE_SIZE void
write_extended_huffman (TampCompressor *compressor, xtrt_u8 value,
                        xtrt_u8 trailing_bits)
{
  xtrt_u8 code_index = value >> trailing_bits;

  /* Write huffman code (without literal flag) + trailing bits in one call */
  write_to_bit_buffer (compressor,
                       ((xtrt_u32)huffman_codes[code_index] << trailing_bits)
                           | (value & ((1 << trailing_bits) - 1)),
                       (huffman_bits[code_index] - 1) + trailing_bits);
}

/**
 * @brief Get the last byte written to the window.
 *
 * NOINLINE: called from 3 sites; outlining saves ~44 bytes on armv6m.
 */
static TAMP_NOINLINE TAMP_OPTIMIZE_SIZE xtrt_u8
get_last_window_byte (TampCompressor *compressor)
{
  xtrt_u16 prev_pos
      = (compressor->window_pos - 1) & ((1UL << compressor->conf.window) - 1);

  return compressor->window[prev_pos];
}

/**
 * @brief Search for extended match continuation using implicit pattern
 * comparison.
 *
 * Searches for pattern: window[current_pos:current_pos+current_count] +
 * input[0...] starting from current_pos. Returns the longest match found
 * (which may be at current_pos itself if O(1) extension works, or at a
 * different position).
 *
 * NOINLINE + Os: Called only during extended match continuation (rare path).
 * Outlining saves ~100 bytes in poll on armv6m.
 *
 * @param[in] compressor TampCompressor object
 * @param[in] current_pos Current match position in window (also search start)
 * @param[in] current_count Current match length
 * @param[out] new_pos Position of found match (only valid if new_count >
 * current_count)
 * @param[out] new_count Length of found match
 */
# if TAMP_ESP32
/* ESP32-optimized implementation in espidf/tamp/compressor_esp32.cpp (same
 * contract, but may return a different equally-long match position on ties).
 */
extern void find_extended_match (TampCompressor *compressor,
                                 xtrt_u16 current_pos, xtrt_u8 current_count,
                                 xtrt_u16 *new_pos, xtrt_u8 *new_count);
# else  /* if TAMP_ESP32 */
static TAMP_NOINLINE TAMP_OPTIMIZE_SIZE void
find_extended_match (TampCompressor *compressor, xtrt_u16 current_pos,
                     xtrt_u8 current_count, xtrt_u16 *new_pos,
                     xtrt_u8 *new_count)
{
  xtrt_u8 extend_byte;
  xtrt_u8 max_pattern;
  xtrt_u16 window_size;
  const unsigned char *window;

  /* Preconditions (guaranteed by caller): */
  /* - input_size > 0 */
  /* - current_pos + current_count < WINDOW_SIZE */
  /* - current_count < MAX_PATTERN_SIZE */
  *new_count = 0;
  window = compressor->window;
  window_size = WINDOW_SIZE;
  max_pattern = XTR_TAMP_MIN (current_count + compressor->input_size,
                              MAX_PATTERN_SIZE);
  extend_byte = read_input (0);

  {
    xtrt_u16 cand;
    for (cand = current_pos; cand + current_count + 1 <= window_size; cand++)
      {
        xtrt_u8 match_len;
        xtrt_u8 cand_max;
        xtrt_u8 i;
        /* Check extension byte first (most discriminating) */
        if (window[cand + current_count] != extend_byte)
          {
            continue;
          }

        /* Check if current_count bytes match (at cand==current_pos, compares
         * with self) */
        i = 0;
        while (i < current_count
               && window[cand + i] == window[current_pos + i])
          {
            i++;
          }
        if (i < current_count)
          {
            continue;
          }

        /* Found a match - extend as far as possible */
        cand_max = XTR_TAMP_MIN (max_pattern, window_size - cand);
        match_len = current_count + 1;
        for (i = current_count + 1; i < cand_max; i++)
          {
            if (window[cand + i] != read_input (i - current_count))
              {
                break;
              }

            match_len = i + 1;
          }

        if (match_len > *new_count)
          {
            *new_count = match_len;
            *new_pos = cand;
            if (match_len == max_pattern)
              {
                return;
              }
          }
      }
  }
}
# endif /* TAMP_ESP32 */

/**
 * @brief Write RLE token to bit buffer and update window.
 *
 * @param[in,out] compressor Compressor state.
 * @param[in] count Number of repeated bytes (must be >= 2).
 */
static TAMP_NOINLINE void
write_rle_token (TampCompressor *compressor, xtrt_u8 count)
{
  xtrt_u8 window_write;
  xtrt_u16 remaining;
  const xtrt_u16 window_mask = (1UL << compressor->conf.window) - 1;
  xtrt_u8 symbol = get_last_window_byte (compressor);

  /* Write RLE symbol (12) with literal flag */
  /* Note: symbols 12 and 13 are at indices 12 and 13 in huffman table (not
   * offset by min_pattern_size) */
  write_to_bit_buffer (compressor, huffman_codes[TAMP_RLE_SYMBOL],
                       huffman_bits[TAMP_RLE_SYMBOL]);
  /* Write extended huffman for count-2 */
  write_extended_huffman (compressor, count - 2, TAMP_LEADING_RLE_BITS);

  /* Write up to TAMP_RLE_MAX_WINDOW bytes to window (or until buffer end, no
   * wrap) */
  remaining = WINDOW_SIZE - compressor->window_pos;
  window_write
      = XTR_TAMP_MIN (XTR_TAMP_MIN (count, TAMP_RLE_MAX_WINDOW), remaining);
  {
    xtrt_u8 i;
    for (i = 0; i < window_write; i++)
      {
        compressor->window[compressor->window_pos] = symbol;
        compressor->window_pos = (compressor->window_pos + 1) & window_mask;
      }
  }
  TAMP_INDEX_UPDATE (compressor, window_write);
}

/**
 * @brief Write extended match token to bit buffer and update window.
 *
 * Token format: symbol (7 bits) + extended_huffman (up to 11 bits) +
 * window_pos (up to 15 bits) Total: up to 33 bits. We flush after
 * symbol+huffman (18 bits max) to ensure window_pos fits.
 *
 * @param[in,out] compressor Compressor state.
 * @param[in,out] output Output buffer pointer (updated on return).
 * @param[in,out] output_size Available space (updated on return).
 * @param[in,out] output_written_size Bytes written (accumulated).
 * @return TAMP_OK on success, TAMP_OUTPUT_FULL if output buffer is too small.
 */
# if TAMP_HAS_GCC_OPTIMIZE
#  pragma GCC push_options
#  pragma GCC optimize("-fno-reorder-blocks")
# endif /* if TAMP_HAS_GCC_OPTIMIZE */
static TAMP_NOINLINE tamp_res
write_extended_match_token (TampCompressor *compressor, unsigned char **output,
                            size_t *output_size, size_t *output_written_size)
{
  tamp_res res;
  xtrt_u8 window_write;
  xtrt_u16 position;
  xtrt_u16 remaining;
  xtrt_u8 count;
  xtrt_u16 wp;
  xtrt_u16 window_mask;

  /* Pre-check output space to prevent OUTPUT_FULL mid-token (would corrupt
   * bit_buffer) */
  if (TAMP_UNLIKELY (*output_size < EXTENDED_MATCH_MIN_OUTPUT_BYTES))
    {
      return TAMP_OUTPUT_FULL;
    }

  window_mask = (1UL << compressor->conf.window) - 1;
  count = compressor->extended_match_count;
  position = compressor->extended_match_position;

  /* Write symbol (7 bits) + extended huffman (up to 11 bits) = 18 bits max */
  /* With ≤7 bits already in buffer, total ≤25 bits - fits in 32-bit buffer */
  write_to_bit_buffer (compressor, huffman_codes[TAMP_EXTENDED_MATCH_SYMBOL],
                       huffman_bits[TAMP_EXTENDED_MATCH_SYMBOL]);
  write_extended_huffman (compressor,
                          count - compressor->min_pattern_size - 11 - 1,
                          TAMP_LEADING_EXTENDED_MATCH_BITS);

  /* Flush to make room for window position (up to 15 bits) */
  res = partial_flush (compressor, output, output_size, output_written_size);
  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  /* Write window position - with ≤7 bits remaining, up to 22 bits total - fits
   */
  write_to_bit_buffer (compressor, position, compressor->conf.window);

  /* Final flush */
  res = partial_flush (compressor, output, output_size, output_written_size);
  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  /* Write to window (up to end of buffer, no wrap). */
  /* Local xtrt_u16 matches tamp_window_copy signature; struct field may be
   * xtrt_u32 (TAMP_ESP32). */
  wp = compressor->window_pos;
  remaining = WINDOW_SIZE - wp;
  window_write = XTR_TAMP_MIN (count, remaining);
  tamp_window_copy (compressor->window, &wp, position, window_write,
                    window_mask);
  compressor->window_pos = wp;
  TAMP_INDEX_UPDATE (compressor, window_write);

  compressor->extended_match_count
      = 0; /* Position reset not needed - only read when count > 0 */

  return TAMP_OK;
}
# if TAMP_HAS_GCC_OPTIMIZE
#  pragma GCC pop_options
# endif /* if TAMP_HAS_GCC_OPTIMIZE */

/**
 * @brief Handle all extended-specific logic in poll (match continuation +
 * RLE).
 *
 * NOINLINE + Os: Extended paths are rarely executed. Outlining from poll saves
 * significant code size on register-constrained Cortex-M0+ where the compiler
 * otherwise spills heavily to stack (~48 bytes saved on armv6m).
 *
 * @param[out] match_index Pre-computed match position; only set when a match
 * was already found while deciding RLE-vs-pattern (see match_size).
 * @param[out] match_size Set (>= 2) together with match_index when returning
 *             TAMP_POLL_CONTINUE with a match already found, so the caller can
 * skip its own find_best_match. Left untouched otherwise.
 *
 * @return TAMP_OK if fully handled (caller should return TAMP_OK),
 *         TAMP_POLL_CONTINUE if caller should proceed to normal pattern
 * matching, other tamp_res on error.
 */
static TAMP_NOINLINE TAMP_OPTIMIZE_SIZE tamp_res
poll_extended_handling (TampCompressor *compressor, unsigned char **output,
                        size_t *output_size, size_t *output_written_size,
                        xtrt_u16 *match_index, xtrt_u8 *match_size)
{
  xtrt_bool rle_ended;
  xtrt_u8 rle_available;
  xtrt_u8 total_rle;
  xtrt_u8 last_byte;

  /* Handle extended match continuation */
  if (compressor->extended_match_count)
    {
      const xtrt_u8 max_ext_match
          = compressor->min_pattern_size + 11 + EXTENDED_MATCH_MAX_EXTRA;

      while (compressor->input_size > 0)
        {
          xtrt_u8 new_count;
          xtrt_u16 new_pos;
          const xtrt_u16 current_pos = compressor->extended_match_position;
          const xtrt_u8 current_count = compressor->extended_match_count;

          if (current_pos + current_count >= WINDOW_SIZE
              || current_count >= max_ext_match)
            {
              return write_extended_match_token (
                  compressor, output, output_size, output_written_size);
            }

# if TAMP_MATCH_INDEX
          if (!compressor->match_index
              || !find_extended_match_indexed (compressor, current_pos,
                                               current_count, &new_pos,
                                               &new_count))
# endif /* if TAMP_MATCH_INDEX */
            find_extended_match (compressor, current_pos, current_count,
                                 &new_pos, &new_count);

          if (new_count > current_count)
            {
              xtrt_u8 extra_bytes = new_count - current_count;
              compressor->extended_match_position = new_pos;
              compressor->extended_match_count = new_count;
              compressor->input_pos = input_add (extra_bytes);
              compressor->input_size -= extra_bytes;
              continue;
            }

          return write_extended_match_token (compressor, output, output_size,
                                             output_written_size);
        }
      return TAMP_OK;
    }

  /* Handle RLE accumulation */
  last_byte = get_last_window_byte (compressor);

  rle_available = 0;
  while (rle_available < compressor->input_size
         && compressor->rle_count + rle_available < RLE_MAX_COUNT
         && compressor->input[input_add (rle_available)] == last_byte)
    {
      rle_available++;
    }

  total_rle = compressor->rle_count + rle_available;
  rle_ended = (rle_available < compressor->input_size)
              || (total_rle >= RLE_MAX_COUNT);

  if (!rle_ended && total_rle > 0)
    {
      compressor->rle_count = total_rle;
      compressor->input_pos = input_add (rle_available);
      compressor->input_size -= rle_available;
      return TAMP_OK;
    }

  if (total_rle >= 2)
    {
      if (total_rle == rle_available && total_rle <= 6)
        {
          xtrt_u16 pattern_index;
          xtrt_u8 pattern_size;
          find_best_match (compressor, &pattern_index, &pattern_size);

          if (pattern_size > total_rle)
            {
              compressor->rle_count = 0;
              /* Hand the match to the caller so it doesn't repeat the search.
               */
              *match_index = pattern_index;
              *match_size = pattern_size;
              return TAMP_POLL_CONTINUE; /* Proceed to pattern matching */
            }
        }

      compressor->input_pos = input_add (rle_available);
      compressor->input_size -= rle_available;
      write_rle_token (compressor, total_rle);
      compressor->rle_count = 0;
      return TAMP_OK;
    }

  if (TAMP_UNLIKELY (compressor->rle_count == 1))
    {
      /* A lone run byte was consumed into rle_count by a previous poll and the
       */
      /* run then ended; RLE tokens require count >= 2 and the byte is no
       * longer */
      /* in the input buffer, so re-emit it as a literal (mirrors the */
      /* rle_count == 1 drain in tamp_compressor_flush). */
      const xtrt_u16 window_mask = (1UL << compressor->conf.window) - 1;
      write_to_bit_buffer (compressor, IS_LITERAL_FLAG | last_byte,
                           compressor->conf.literal + 1);
      compressor->window[compressor->window_pos] = last_byte;
      compressor->window_pos = (compressor->window_pos + 1) & window_mask;
      TAMP_INDEX_UPDATE (compressor, 1);
      compressor->rle_count = 0;
      return TAMP_OK;
    }

  return TAMP_POLL_CONTINUE; /* Proceed to pattern matching */
}
#endif /* TAMP_EXTENDED_COMPRESS */

#if TAMP_HAS_GCC_OPTIMIZE
# pragma GCC push_options
# pragma GCC optimize("-fno-schedule-insns2")
#endif /* if TAMP_HAS_GCC_OPTIMIZE */
TAMP_NOINLINE tamp_res
tamp_compressor_poll (TampCompressor *compressor, unsigned char *output,
                      size_t output_size, size_t *output_written_size)
{
  xtrt_u16 match_index;
  xtrt_u8 match_size;
  tamp_res res;
  /* Cache bitfield values for faster access in hot path */
  const xtrt_u8 conf_window = compressor->conf.window;
  const xtrt_u8 conf_literal = compressor->conf.literal;
  const xtrt_u16 window_mask = (1UL << conf_window) - 1;
  size_t output_written_size_proxy;

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  *output_written_size = 0;

  if (TAMP_UNLIKELY (compressor->input_size == 0))
    {
      return TAMP_OK;
    }

  /* Real data is being processed: any pending RLE/extended state drained by a
   */
  /* later flush() was also created here, so the next FLUSH won't be
   * "consecutive". */
  compressor->last_was_flush = 0;

  /* Make sure there's enough room in the bit buffer. */
  res = partial_flush (compressor, &output, &output_size, output_written_size);
  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  if (TAMP_UNLIKELY (output_size == 0))
    {
      return TAMP_OUTPUT_FULL;
    }

  match_size = 0;
  match_index = 0;

#if TAMP_EXTENDED_COMPRESS
  if (TAMP_UNLIKELY (compressor->conf.extended))
    {
      /* Handle extended match continuation + RLE (outlined for code size). */
      /* May pre-compute match_index/match_size (match_size becomes non-zero).
       */
      res = poll_extended_handling (compressor, &output, &output_size,
                                    output_written_size, &match_index,
                                    &match_size);
      if (res != TAMP_POLL_CONTINUE)
        {
# if TAMP_LAZY_MATCHING
          /* Extended handling consumed input and/or mutated the window, so any
           */
          /* match cached by lazy matching no longer matches the current input.
           */
          compressor->cached_match_index = -1;
# endif /* if TAMP_LAZY_MATCHING */
          return res;
        }

      /* TAMP_POLL_CONTINUE: proceed to pattern matching below */
    }

#endif /* TAMP_EXTENDED_COMPRESS */

#if TAMP_LAZY_MATCHING
  if (compressor->conf.lazy_matching)
    {
      /* Check if we have a cached match from lazy matching */
      if (TAMP_UNLIKELY (compressor->cached_match_index >= 0))
        {
          match_index = compressor->cached_match_index;
          match_size = compressor->cached_match_size;
          compressor->cached_match_index = -1; /* Clear cache after using */
        }
      else if (match_size == 0)
        { /* No match pre-computed by extended handling */
          find_best_match (compressor, &match_index, &match_size);
        }

      /* Lazy matching: if we have a good match, check if position i+1 has a
       * better match */
      if (match_size >= compressor->min_pattern_size && match_size <= 8
          && compressor->input_size > match_size + 2)
        {
          xtrt_u16 next_match_index;
          xtrt_u8 next_match_size;
          /* Temporarily advance input position to check next position */
          compressor->input_pos = input_add (1);
          compressor->input_size--;

          next_match_size = 0;
          next_match_index = 0;
          find_best_match (compressor, &next_match_index, &next_match_size);

          /* Restore input position */
          compressor->input_pos = input_add (-1);
          compressor->input_size++;

          /* If next position has a better match, and the match doesn't overlap
           * with the literal we are writing, emit */
          /* literal and cache the next match */
          if (next_match_size > match_size
              && validate_no_match_overlap (compressor->window_pos,
                                            next_match_index, next_match_size))
            {
              /* Force literal at current position, cache next match */
              compressor->cached_match_index = next_match_index;
              compressor->cached_match_size = next_match_size;
              match_size = 0; /* Will trigger literal write below */
            }
          else
            {
              compressor->cached_match_index = -1;
              /* Note: No V2 extended match check here - we're in the
               * match_size <= 8 branch, */
              /* so extended matches (which require match_size >
               * min_pattern_size + 11) are impossible. */
            }
        }
      else
        {
          compressor->cached_match_index = -1; /* Clear cache */
        }
    }
  else if (match_size == 0)
    { /* No match pre-computed by extended handling */
      find_best_match (compressor, &match_index, &match_size);
    }

#else /* if TAMP_LAZY_MATCHING */
  if (match_size == 0)
    {
      find_best_match (compressor, &match_index, &match_size);
    }

#endif /* if TAMP_LAZY_MATCHING */

  /* Shared token/literal writing logic */
  if (TAMP_UNLIKELY (match_size < compressor->min_pattern_size))
    {
      unsigned char c;
      /* Write LITERAL */
      match_size = 1;
      c = read_input (0);
      if (TAMP_UNLIKELY (c >> conf_literal))
        {
          return TAMP_EXCESS_BITS;
        }

      write_to_bit_buffer (compressor, (1 << conf_literal) | c,
                           conf_literal + 1);
    }
  else
    {
      xtrt_u8 huffman_index;
#if TAMP_EXTENDED_COMPRESS
      /* Extended: Start extended match continuation */
      if (compressor->conf.extended
          && match_size > compressor->min_pattern_size + 11)
        {
          compressor->extended_match_count = match_size;
          compressor->extended_match_position = match_index;
          /* Consume matched bytes from input */
          compressor->input_pos = input_add (match_size);
          compressor->input_size -= match_size;
          /* Return - continuation code at start of poll will try to extend or
           * emit */
          return TAMP_OK;
        }

#endif /* TAMP_EXTENDED_COMPRESS */
      /* Write TOKEN (huffman code + window position) */
      huffman_index = match_size - compressor->min_pattern_size;
      /* On 16-bit C, unsigned char promotes to 16-bit int: shift as an
       * explicitly unsigned 32-bit value to retain the Huffman prefix. */
      write_to_bit_buffer (
          compressor,
          ((xtrt_u32)huffman_codes[huffman_index] << conf_window)
              | match_index,
          huffman_bits[huffman_index] + conf_window);
    }

  /* Populate Window */
  {
    xtrt_u8 i;
    for (i = 0; i < match_size; i++)
      {
        compressor->window[compressor->window_pos] = read_input (0);
        compressor->window_pos = (compressor->window_pos + 1) & window_mask;
        compressor->input_pos = input_add (1);
      }
  }
  TAMP_INDEX_UPDATE (compressor, match_size);
  compressor->input_size -= match_size;

  return TAMP_OK;
}
#if TAMP_HAS_GCC_OPTIMIZE
# pragma GCC pop_options
#endif /* if TAMP_HAS_GCC_OPTIMIZE */

void
tamp_compressor_sink (TampCompressor *compressor, const unsigned char *input,
                      size_t input_size, size_t *consumed_size)
{
  size_t consumed_size_proxy;

  if (TAMP_LIKELY (consumed_size))
    {
      *consumed_size = 0;
    }
  else
    {
      consumed_size = &consumed_size_proxy;
    }

  {
    size_t i;
    for (i = 0; i < input_size; i++)
      {
        if (TAMP_UNLIKELY (tamp_compressor_full (compressor)))
          {
            break;
          }

        compressor->input[input_add (compressor->input_size)] = input[i];
        compressor->input_size += 1;
        (*consumed_size)++;
      }
  }
}

TAMP_OPTIMIZE_SIZE tamp_res
tamp_compressor_compress_cb (TampCompressor *compressor, unsigned char *output,
                             size_t output_size, size_t *output_written_size,
                             const unsigned char *input, size_t input_size,
                             size_t *input_consumed_size,
                             tamp_callback_t callback, void *user_data)
{
  tamp_res res;
  size_t input_consumed_size_proxy = 0, output_written_size_proxy = 0;
  size_t total_input_size = input_size;

  if (TAMP_LIKELY (output_written_size))
    {
      *output_written_size = 0;
    }
  else
    {
      output_written_size = &output_written_size_proxy;
    }

  if (TAMP_LIKELY (input_consumed_size))
    {
      *input_consumed_size = 0;
    }
  else
    {
      input_consumed_size = &input_consumed_size_proxy;
    }

  while (input_size > 0 && output_size > 0)
    {
      {
        /* Sink Data into input buffer. */
        size_t consumed;
        tamp_compressor_sink (compressor, input, input_size, &consumed);
        input += consumed;
        input_size -= consumed;
        (*input_consumed_size) += consumed;
      }
      if (TAMP_LIKELY (tamp_compressor_full (compressor)))
        {
          /* Input buffer is full and ready to start compressing. */
          size_t chunk_output_written_size;
          res = tamp_compressor_poll (compressor, output, output_size,
                                      &chunk_output_written_size);
          output += chunk_output_written_size;
          output_size -= chunk_output_written_size;
          (*output_written_size) += chunk_output_written_size;
          if (TAMP_UNLIKELY (res != TAMP_OK))
            {
              return res;
            }

          if (TAMP_UNLIKELY (
                  callback
                  && (res = callback (user_data, *input_consumed_size,
                                      total_input_size))))
            {
              return (tamp_res)res;
            }
        }
    }
  return TAMP_OK;
}

#if TAMP_HAS_GCC_OPTIMIZE
# pragma GCC push_options
# pragma GCC optimize("-fno-tree-pre")
#endif /* if TAMP_HAS_GCC_OPTIMIZE */
tamp_res
tamp_compressor_flush (TampCompressor *compressor, unsigned char *output,
                       size_t output_size, size_t *output_written_size,
                       xtrt_bool write_token)
{
  tamp_res res;
  size_t chunk_output_written_size;
  size_t output_written_size_proxy;

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  *output_written_size = 0;

flush_check:
  /* Flush pending bits before checking for more work */
  chunk_output_written_size = 0;
  res = partial_flush (compressor, &output, &output_size, output_written_size);
  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  if (TAMP_LIKELY (compressor->input_size))
    {
      res = tamp_compressor_poll (compressor, output, output_size,
                                  &chunk_output_written_size);
    }

#if TAMP_EXTENDED_COMPRESS
  else if (compressor->conf.extended && compressor->rle_count >= 1)
    {
      if (compressor->rle_count == 1)
        {
          xtrt_u16 window_mask;
          /* Single byte - write as literal (can't use RLE token for count < 2)
           */
          xtrt_u8 literal = get_last_window_byte (compressor);
          write_to_bit_buffer (compressor, IS_LITERAL_FLAG | literal,
                               compressor->conf.literal + 1);

          /* Write to window */
          window_mask = (1UL << compressor->conf.window) - 1;
          compressor->window[compressor->window_pos] = literal;
          compressor->window_pos = (compressor->window_pos + 1) & window_mask;
          TAMP_INDEX_UPDATE (compressor, 1);
        }
      else
        {
          /* count >= 2: write as RLE token */
          write_rle_token (compressor, compressor->rle_count);
        }

      compressor->rle_count = 0;
    }
  else if (compressor->conf.extended && compressor->extended_match_count)
    {
      res = write_extended_match_token (compressor, &output, &output_size,
                                        output_written_size);
    }
#endif /* TAMP_EXTENDED_COMPRESS */
  else
    {
      goto flush_done;
    }
  (*output_written_size) += chunk_output_written_size;
  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  output_size -= chunk_output_written_size;
  output += chunk_output_written_size;
  goto flush_check;

flush_done:
  /* At this point, up to 7 bits may remain in the compressor->bit_buffer */
  /* The output buffer may have 0 bytes remaining. */
  /* Suppress a redundant second consecutive FLUSH. Two FLUSH tokens with no
   * data */
  /* between them are the double-FLUSH dictionary-reset signal: a decompressor
   * on a */
  /* dictionary_reset stream would re-initialize its window, but THIS
   * compressor's */
  /* window is not reset here, desyncing the two and corrupting all later
   * output. */
  /* The sanctioned reset path, tamp_compressor_reset_dictionary(), clears */
  /* last_was_flush before each flush so it can still emit the real
   * double-FLUSH. */
  if (write_token && !compressor->last_was_flush
      && (compressor->bit_buffer_pos || compressor->conf.dictionary_reset))
    {
      /* We don't want to write the FLUSH token to the bit_buffer unless */
      /* we are confident that it'll wind up in the output buffer */
      /* in THIS function call. */
      /* Otherwise, if we wind up with a TAMP_OUTPUT_FULL result, we could */
      /* end up accidentally writing multiple FLUSH tokens. */
      if (TAMP_UNLIKELY (output_size < 2))
        {
          return TAMP_OUTPUT_FULL;
        }

      write_to_bit_buffer (compressor, FLUSH_CODE, 9);
      compressor->last_was_flush = 1;
    }

  /* At this point, up to 16 bits may remain in the compressor->bit_buffer */
  /* The output buffer may have 0 bytes remaining. */

  /* Flush whole bytes, then write trailing partial byte */
  res = partial_flush (compressor, &output, &output_size, output_written_size);
  if (compressor->bit_buffer_pos)
    {
      if (TAMP_UNLIKELY (output_size == 0))
        {
          return TAMP_OUTPUT_FULL;
        }

      *output = compressor->bit_buffer >> 24;
      (*output_written_size)++;
      compressor->bit_buffer_pos = 0;
      compressor->bit_buffer = 0;
    }

  return res;
}
#if TAMP_HAS_GCC_OPTIMIZE
# pragma GCC pop_options
#endif /* if TAMP_HAS_GCC_OPTIMIZE */

TAMP_OPTIMIZE_SIZE tamp_res
tamp_compressor_compress_and_flush_cb (
    TampCompressor *compressor, unsigned char *output, size_t output_size,
    size_t *output_written_size, const unsigned char *input, size_t input_size,
    size_t *input_consumed_size, xtrt_bool write_token,
    tamp_callback_t callback, void *user_data)
{
  tamp_res res;
  size_t flush_size;
  size_t output_written_size_proxy;

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  res = tamp_compressor_compress_cb (compressor, output, output_size,
                                     output_written_size, input, input_size,
                                     input_consumed_size, callback, user_data);
  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  res = tamp_compressor_flush (compressor, output + *output_written_size,
                               output_size - *output_written_size, &flush_size,
                               write_token);

  (*output_written_size) += flush_size;

  if (TAMP_UNLIKELY (res != TAMP_OK))
    {
      return res;
    }

  /* Final callback to signal 100% completion (compress_cb's last callback may
   */
  /* have reported less than input_size if the final sink didn't trigger a
   * poll). */
  if (TAMP_UNLIKELY (callback))
    {
      int cb_res = callback (user_data, input_size, input_size);
      if (TAMP_UNLIKELY (cb_res))
        {
          return (tamp_res)cb_res;
        }
    }

  return TAMP_OK;
}

TAMP_OPTIMIZE_SIZE tamp_res
tamp_compressor_reset_dictionary (TampCompressor *compressor,
                                  unsigned char *output, size_t output_size,
                                  size_t *output_written_size)
{
  size_t output_written_size_proxy;
  TampConf conf;
  tamp_res res;

  if (!compressor->conf.dictionary_reset)
    {
      return TAMP_INVALID_CONF;
    }

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  *output_written_size = 0;

  /* Write 2 FLUSH tokens for the double-FLUSH reset signal. The first drains
   */
  /* any pending data. dictionary_reset being set guarantees flush() writes a
   */
  /* FLUSH token even when bit_buffer_pos is 0. */
  {
    xtrt_u8 i;
    for (i = 0; i < 2; i++)
      {
        size_t flush_written_size;
        /* Bypass the double-FLUSH suppression in flush(): here we *intend* to
         * emit */
        /* two consecutive FLUSH tokens, paired with the dictionary re-init
         * below. */
        compressor->last_was_flush = 0;
        res = tamp_compressor_flush (compressor, output, output_size,
                                     &flush_written_size, 1);
        *output_written_size += flush_written_size;
        if (TAMP_UNLIKELY (res != TAMP_OK))
          {
            return res;
          }

        output += flush_written_size;
        output_size -= flush_written_size;
      }
  }

  /* Re-initialize compressor, then discard the header it writes to the bit
   * buffer. */
  /* Copy conf because tamp_compressor_init zeroes the struct before reading
   * it. */
  conf = compressor->conf;
  conf.use_custom_dictionary = 0;
  res = tamp_compressor_init (compressor, &conf, compressor->window);
  compressor->bit_buffer = 0;
  compressor->bit_buffer_pos = 0;

  return res;
}

#if TAMP_STREAM

# if TAMP_EXTENDED_COMPRESS                                                   \
    && (TAMP_STREAM_WORK_BUFFER_SIZE / 2) < EXTENDED_MATCH_MIN_OUTPUT_BYTES
/* A smaller buffer deadlocks tamp_compress_stream: write_extended_match_token
 */
/* returns TAMP_OUTPUT_FULL forever because the token can never fit. */
#  error                                                                      \
    "TAMP_STREAM_WORK_BUFFER_SIZE must be at least 12 bytes when extended compression is enabled"
# endif /* if TAMP_EXTENDED_COMPRESS && ( TAMP_STREAM_WORK_BUFFER_SIZE / 2 )  \
          < EXTENDED_MATCH_MIN_OUTPUT_BYTES */

TAMP_OPTIMIZE_SIZE tamp_res
tamp_compress_stream (TampCompressor *compressor, tamp_read_t read_cb,
                      void *read_handle, tamp_write_t write_cb,
                      void *write_handle, size_t *input_consumed_size,
                      size_t *output_written_size, tamp_callback_t callback,
                      void *user_data)
{
  size_t input_consumed_size_proxy, output_written_size_proxy;

  if (!input_consumed_size)
    {
      input_consumed_size = &input_consumed_size_proxy;
    }

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  *input_consumed_size = 0;
  *output_written_size = 0;

  unsigned char input_buffer[TAMP_STREAM_WORK_BUFFER_SIZE / 2];
  unsigned char output_buffer[TAMP_STREAM_WORK_BUFFER_SIZE / 2];

  /* Main compression loop */
  while (1)
    {
      int bytes_read
          = read_cb (read_handle, input_buffer, sizeof (input_buffer));
      if (TAMP_UNLIKELY (bytes_read < 0))
        {
          return TAMP_READ_ERROR;
        }

      if (bytes_read == 0)
        {
          break;
        }

      *input_consumed_size += bytes_read;

      size_t input_pos = 0;
      while (input_pos < (size_t)bytes_read)
        {
          size_t chunk_consumed, chunk_written;

          tamp_res res = tamp_compressor_compress (
              compressor, output_buffer, sizeof (output_buffer),
              &chunk_written, input_buffer + input_pos, bytes_read - input_pos,
              &chunk_consumed);
          if (TAMP_UNLIKELY (res < TAMP_OK))
            {
              return res;
            }

          input_pos += chunk_consumed;

          if (TAMP_LIKELY (chunk_written > 0))
            {
              int bytes_written
                  = write_cb (write_handle, output_buffer, chunk_written);
              if (TAMP_UNLIKELY (bytes_written < 0
                                 || (size_t)bytes_written != chunk_written))
                {
                  return TAMP_WRITE_ERROR;
                }

              *output_written_size += chunk_written;
            }
        }

      if (TAMP_UNLIKELY (callback))
        {
          int cb_res = callback (user_data, *input_consumed_size, 0);
          if (TAMP_UNLIKELY (cb_res))
            {
              return (tamp_res)cb_res;
            }
        }
    }

  /* Flush remaining data */
  while (1)
    {
      size_t chunk_written;
      tamp_res res
          = tamp_compressor_flush (compressor, output_buffer,
                                   sizeof (output_buffer), &chunk_written, 0);
      if (TAMP_UNLIKELY (res < TAMP_OK))
        {
          return res;
        }

      if (TAMP_LIKELY (chunk_written > 0))
        {
          int bytes_written
              = write_cb (write_handle, output_buffer, chunk_written);
          if (TAMP_UNLIKELY (bytes_written < 0
                             || (size_t)bytes_written != chunk_written))
            {
              return TAMP_WRITE_ERROR;
            }

          *output_written_size += chunk_written;
        }

      if (res == TAMP_OK)
        {
          break;
        }
    }

  return TAMP_OK;
}

#endif /* TAMP_STREAM */

/* Normal, externally linkable C89 wrappers avoid unused file-local inline
 * bodies in programs that require only compression or decompression. */
tamp_res
tamp_compressor_compress (TampCompressor *compressor, unsigned char *output,
                          size_t output_size, size_t *output_written_size,
                          const unsigned char *input, size_t input_size,
                          size_t *input_consumed_size)
{
  return tamp_compressor_compress_cb (compressor, output, output_size,
                                      output_written_size, input, input_size,
                                      input_consumed_size, NULL, NULL);
}

tamp_res
tamp_compressor_compress_and_flush (
    TampCompressor *compressor, unsigned char *output, size_t output_size,
    size_t *output_written_size, const unsigned char *input, size_t input_size,
    size_t *input_consumed_size, xtrt_bool write_token)
{
  return tamp_compressor_compress_and_flush_cb (
      compressor, output, output_size, output_written_size, input, input_size,
      input_consumed_size, write_token, NULL, NULL);
}

tamp_res
tamp_decompressor_decompress (TampDecompressor *decompressor,
                              unsigned char *output, size_t output_size,
                              size_t *output_written_size,
                              const unsigned char *input, size_t input_size,
                              size_t *input_consumed_size)
{
  return tamp_decompressor_decompress_cb (
      decompressor, output, output_size, output_written_size, input,
      input_size, input_consumed_size, NULL, NULL);
}

/* Copy primitives for the hot paths. Platform-specific implementations live
 * with their platform component; TAMP_ESP32 builds already require the espidf
 * component sources on the include path (same contract as the extern
 * find_best_match in compressor.c). On generic targets the macros expand to
 * the plain byte loops / tamp_window_copy call they replaced (macros, not
 * inline functions: Cortex-M0+ codegen is sensitive to function boundaries).
 */
#if TAMP_ESP32
# include "private/tamp_copy.h"
#else /* if TAMP_ESP32 */

/* Copy count bytes from src to the output cursor and advance it. */
# define TAMP_COPY_TO_OUTPUT(out, src, count)                                 \
  do                                                                          \
    {                                                                         \
      xtrt_u8 _tamp_i;                                                        \
      for (_tamp_i = 0; _tamp_i < (count); _tamp_i++)                         \
        {                                                                     \
          *(out)++ = (src)[_tamp_i];                                          \
        }                                                                     \
    }                                                                         \
  while (0)

# define TAMP_WINDOW_COPY(window, window_pos, window_offset, match_size,      \
                         window_mask)                                         \
  tamp_window_copy ((window), (window_pos), (window_offset), (match_size),    \
                    (window_mask))

#endif /* TAMP_ESP32 */

#define XTR_TAMP_FLUSH 14

#if TAMP_EXTENDED_DECOMPRESS
/* Token state for extended decode suspend/resume (2 bits).
 * TOKEN_RLE and TOKEN_EXT_MATCH_FRESH are arranged so that:
 *     token_state = match_size - (TAMP_RLE_SYMBOL - 1)
 * maps TAMP_RLE_SYMBOL (12) -> 1 and TAMP_EXTENDED_MATCH_SYMBOL (13) -> 2.
 */
# define TOKEN_NONE 0
# define TOKEN_RLE 1
# define TOKEN_EXT_MATCH_FRESH 2
# define TOKEN_EXT_MATCH 3 /* Resume: have match_size, need window_offset */
#endif                    /* if TAMP_EXTENDED_DECOMPRESS */

/**
 * Huffman lookup table indexed by 7 bits (after first "1" bit consumed).
 * Upper 4 bits = additional bits to consume, lower 4 bits = symbol (14 =
 * FLUSH).
 *
 * Note: A 64-byte table with special-cased symbol 1 was tried but was ~10%
 * slower and only saved 8 bytes in final firmware due to added branch logic.
 */
TAMP_STATIC_CONST xtrt_u8 HUFFMAN_TABLE[128] = {
  50, 50, 50, 50, 50,  50,  50,  50,  50,  50,  50,  50,  50, 50, 50, 50,
  85, 85, 85, 85, 122, 123, 104, 104, 86,  86,  86,  86,  93, 93, 93, 93,
  68, 68, 68, 68, 68,  68,  68,  68,  105, 105, 124, 126, 87, 87, 87, 87,
  51, 51, 51, 51, 51,  51,  51,  51,  51,  51,  51,  51,  51, 51, 51, 51,
  17, 17, 17, 17, 17,  17,  17,  17,  17,  17,  17,  17,  17, 17, 17, 17,
  17, 17, 17, 17, 17,  17,  17,  17,  17,  17,  17,  17,  17, 17, 17, 17,
  17, 17, 17, 17, 17,  17,  17,  17,  17,  17,  17,  17,  17, 17, 17, 17,
  17, 17, 17, 17, 17,  17,  17,  17,  17,  17,  17,  17,  17, 17, 17, 17
};

/**
 * @brief Decode huffman symbol + optional trailing bits from bit buffer.
 *
 * Modifies bit_buffer and bit_buffer_pos in place. Caller is responsible
 * for committing to decompressor state if needed.
 *
 * @param bit_buffer Pointer to bit buffer (modified in place)
 * @param bit_buffer_pos Pointer to bit position (modified in place)
 * @param trailing_bits Number of trailing bits to read (0, 3, or 4)
 * @param result Output: (huffman << trailing_bits) + trailing (max 239 for
 * trailing_bits=4)
 * @return TAMP_OK on success, TAMP_INPUT_EXHAUSTED if more bits needed
 */
static tamp_res
decode_huffman (xtrt_u32 *bit_buffer, xtrt_u8 *bit_buffer_pos,
                xtrt_u8 trailing_bits, xtrt_u8 *result)
{
  xtrt_s8 huffman_value;

  /* Need at least 1 bit for huffman, plus trailing bits */
  if (TAMP_UNLIKELY (*bit_buffer_pos < 1 + trailing_bits))
    {
      return TAMP_INPUT_EXHAUSTED;
    }

  /* Decode huffman symbol */
  (*bit_buffer_pos)--;
  if (TAMP_LIKELY ((*bit_buffer >> 31) == 0))
    {
      /* Symbol 0: code "0" */
      *bit_buffer <<= 1;
      huffman_value = 0;
    }
  else
    {
      xtrt_u8 bit_len;
      xtrt_u8 code;
      /* All other symbols: use 128-entry table indexed by next 7 bits */
      *bit_buffer <<= 1;
      code = HUFFMAN_TABLE[*bit_buffer >> (32 - 7)];
      bit_len = code >> 4;
      if (TAMP_UNLIKELY (*bit_buffer_pos < bit_len + trailing_bits))
        {
          return TAMP_INPUT_EXHAUSTED;
        }

      *bit_buffer <<= bit_len;
      *bit_buffer_pos -= bit_len;
      huffman_value = code & 0xF;
    }

  /* Read trailing bits (skip if trailing_bits==0 to avoid undefined shift) */
  if (trailing_bits)
    {
      xtrt_u8 trailing = *bit_buffer >> (32 - trailing_bits);
      *bit_buffer <<= trailing_bits;
      *bit_buffer_pos -= trailing_bits;
      *result = (huffman_value << trailing_bits) + trailing;
    }
  else
    {
      *result = huffman_value;
    }

  return TAMP_OK;
}

#if TAMP_EXTENDED_DECOMPRESS

/**
 * @brief Decode RLE token and write repeated bytes to output.
 *
 * RLE format: huffman(count_high) + trailing_bits(count_low)
 * rle_count = (count_high << 4) + count_low + 2
 */
static tamp_res
decode_rle (TampDecompressor *d, unsigned char **output,
            const unsigned char *output_end, size_t *output_written_size)
{
  xtrt_u8 to_write;
  size_t output_space;
  xtrt_u8 remaining_count;
  xtrt_u8 symbol;
  xtrt_u16 prev_pos;
  xtrt_u8 rle_count; /* max 241: (14 << 4) + 15 + 2 */
  xtrt_u8 skip = d->skip_bytes;

  if (skip > 0)
    {
      /* Resume from output-full: rle_count saved in pending_window_offset */
      rle_count = d->pending_window_offset;
    }
  else
    {
      /* Fresh decode */
      xtrt_u32 bit_buffer = d->bit_buffer;
      xtrt_u8 bit_buffer_pos = d->bit_buffer_pos;
      xtrt_u8 raw;
      tamp_res res = decode_huffman (&bit_buffer, &bit_buffer_pos,
                                     TAMP_LEADING_RLE_BITS, &raw);
      if (res != TAMP_OK)
        {
          return res;
        }

      d->bit_buffer = bit_buffer;
      d->bit_buffer_pos = bit_buffer_pos;
      rle_count = raw + 2;
    }

  /* Get the byte to repeat (last written byte) */
  prev_pos = (d->window_pos - 1) & ((1u << d->conf_window) - 1);
  symbol = d->window[prev_pos];

  /* Calculate how many to write this call */
  remaining_count = rle_count - skip;
  output_space = output_end - *output;

  if (TAMP_UNLIKELY (remaining_count > output_space))
    {
      /* Partial write - save state for resume */
      to_write = output_space;
      d->skip_bytes = skip + to_write;
      d->token_state = TOKEN_RLE;
      d->pending_window_offset = rle_count;
    }
  else
    {
      /* Complete write */
      to_write = remaining_count;
      d->skip_bytes = 0;
      d->token_state = TOKEN_NONE;
    }

  /* Write repeated bytes to output */
  TAMP_MEMSET (*output, symbol, to_write);
  *output += to_write;
  *output_written_size += to_write;

  /* Update window only on first chunk (skip==0).
   * Write up to TAMP_RLE_MAX_WINDOW or until end of buffer (no wrap). */
  if (skip == 0)
    {
      const xtrt_u16 window_size = 1u << d->conf_window;
      xtrt_u16 remaining = window_size - d->window_pos;
      xtrt_u8 window_write
          = XTR_TAMP_MIN (XTR_TAMP_MIN (rle_count, TAMP_RLE_MAX_WINDOW),
                          remaining); /* max 8 */
      {
        xtrt_u8 i;
        for (i = 0; i < window_write; i++)
          {
            d->window[d->window_pos++] = symbol;
          }
      }
      d->window_pos &= (window_size - 1);
    }

  return (d->token_state == TOKEN_NONE) ? TAMP_OK : TAMP_OUTPUT_FULL;
}

/**
 * @brief Decode extended match token and copy from window to output.
 *
 * NEW FORMAT: huffman(size_high) + trailing_bits(size_low) + window_offset
 * match_size = (size_high << 3) + size_low + min_pattern_size + 12
 *
 * State machine:
 * - Fresh: decode huffman+trailing, then window_offset
 * - TOKEN_EXT_MATCH: have match_size, need window_offset
 * - Output-full resume (skip > 0): have both match_size and window_offset
 */
static tamp_res
decode_extended_match (TampDecompressor *d, unsigned char **output,
                       const unsigned char *output_end,
                       size_t *output_written_size)
{
  xtrt_u8 to_write;
  size_t output_space;
  xtrt_u16 src_offset;
  xtrt_u8 remaining_count;
  xtrt_u32 window_size;
  const xtrt_u8 conf_window = d->conf_window;
  xtrt_u16 window_offset;
  xtrt_u8 match_size; /* max 134: (14<<3)+7 + 3 + 12 */
  xtrt_u8 skip = d->skip_bytes;

  if (skip > 0)
    {
      /* Resume from output-full: both values saved */
      window_offset = d->pending_window_offset;
      match_size = d->pending_match_size;
    }
  else if (d->token_state == TOKEN_EXT_MATCH)
    {
      /* Resume: have match_size, need window_offset */
      match_size = d->pending_match_size;

      if (TAMP_UNLIKELY (d->bit_buffer_pos < conf_window))
        {
          return TAMP_INPUT_EXHAUSTED;
        }

      window_offset = d->bit_buffer >> (32 - conf_window);
      d->bit_buffer <<= conf_window;
      d->bit_buffer_pos -= conf_window;
    }
  else
    {
      /* Fresh decode: huffman+trailing first, then window_offset */
      xtrt_u32 bit_buffer = d->bit_buffer;
      xtrt_u8 bit_buffer_pos = d->bit_buffer_pos;
      xtrt_u8 raw;
      tamp_res res = decode_huffman (&bit_buffer, &bit_buffer_pos,
                                     TAMP_LEADING_EXTENDED_MATCH_BITS, &raw);
      if (res != TAMP_OK)
        {
          return res;
        }

      match_size = raw + d->min_pattern_size + 12;

      /* Now decode window_offset */
      if (TAMP_UNLIKELY (bit_buffer_pos < conf_window))
        {
          /* Save match_size and return */
          d->bit_buffer = bit_buffer;
          d->bit_buffer_pos = bit_buffer_pos;
          d->token_state = TOKEN_EXT_MATCH;
          d->pending_match_size = match_size;
          return TAMP_INPUT_EXHAUSTED;
        }

      window_offset = bit_buffer >> (32 - conf_window);
      bit_buffer <<= conf_window;
      bit_buffer_pos -= conf_window;
      d->bit_buffer = bit_buffer;
      d->bit_buffer_pos = bit_buffer_pos;
    }

  /* Security check: validate window bounds */
  window_size = (1u << conf_window);
  if (TAMP_UNLIKELY ((xtrt_u32)window_offset >= window_size
                     || (xtrt_u32)window_offset + (xtrt_u32)match_size
                            > window_size))
    {
      return TAMP_OOB;
    }

  /* Calculate how many to write this call */
  remaining_count = match_size - skip;
  output_space = output_end - *output;

  if (TAMP_UNLIKELY (remaining_count > output_space))
    {
      /* Partial write - save state for resume */
      to_write = output_space;
      d->skip_bytes = skip + output_space;
      d->token_state = TOKEN_EXT_MATCH; /* Reuse for output-full */
      d->pending_window_offset = window_offset;
      d->pending_match_size = match_size;
    }
  else
    {
      /* Complete write */
      to_write = remaining_count;
      d->skip_bytes = 0;
      d->token_state = TOKEN_NONE;
    }

  /* Copy from window to output */
  src_offset = window_offset + skip;
  TAMP_COPY_TO_OUTPUT (*output, d->window + src_offset, to_write);
  *output_written_size += to_write;

  /* Update window only on complete decode.
   * Write up to end of buffer (no wrap), matching RLE behavior. */
  if (d->token_state == TOKEN_NONE)
    {
      xtrt_u16 wp = d->window_pos;
      xtrt_u16 remaining = window_size - wp;
      xtrt_u8 window_write = (match_size < remaining) ? match_size : remaining;
      TAMP_WINDOW_COPY (d->window, &wp, window_offset, window_write,
                        window_size - 1);
      d->window_pos = wp;
    }

  return (d->token_state == TOKEN_NONE) ? TAMP_OK : TAMP_OUTPUT_FULL;
}
#endif /* TAMP_EXTENDED_DECOMPRESS */

tamp_res
tamp_decompressor_read_header (TampConf *conf, const unsigned char *input,
                               size_t input_size, size_t *input_consumed_size)
{
  size_t header_size;

  if (input_consumed_size)
    {
      (*input_consumed_size) = 0;
    }

  if (input_size == 0)
    {
      return TAMP_INPUT_EXHAUSTED;
    }

  /* Validate all header bytes before mutating conf. */
  header_size = 1 + (input[0] & 0x1);
  if (input_size < header_size)
    {
      return TAMP_INPUT_EXHAUSTED;
    }

  /* All bits in byte 2 are reserved for future use; reject if any are set. */
  if (header_size >= 2 && input[1])
    {
      return TAMP_INVALID_CONF;
    }

  conf->window = ((input[0] >> 5) & 0x7) + 8;
  conf->literal = ((input[0] >> 3) & 0x3) + 5;
  conf->use_custom_dictionary = ((input[0] >> 2) & 0x1);
  conf->extended = ((input[0] >> 1) & 0x1);
  /* more_header (byte 1 bit 0) implies dictionary_reset. */
  conf->dictionary_reset = input[0] & 0x1;

  if (input_consumed_size)
    {
      (*input_consumed_size) += header_size;
    }

  return TAMP_OK;
}

/**
 * Populate the rest of the decompressor structure after the following fields
 * have been populated:
 *   * window
 *   * window_bits_max
 */
static TAMP_OPTIMIZE_SIZE tamp_res
tamp_decompressor_populate_from_conf (TampDecompressor *decompressor,
                                      xtrt_u8 conf_window,
                                      xtrt_u8 conf_literal,
                                      xtrt_u8 conf_use_custom_dictionary,
                                      xtrt_u8 conf_extended,
                                      xtrt_u8 conf_dictionary_reset)
{
  if (conf_window < 8 || conf_window > 15)
    {
      return TAMP_INVALID_CONF;
    }

  if (conf_literal < 5 || conf_literal > 8)
    {
      return TAMP_INVALID_CONF;
    }

  if (conf_window > decompressor->window_bits_max)
    {
      return TAMP_INVALID_CONF;
    }

#if !TAMP_EXTENDED_DECOMPRESS
  /* Reject before committing any state: marking the decompressor configured
   * and */
  /* then returning an error would let a retrying caller decode the extended */
  /* stream as classic format. */
  if (conf_extended)
    {
      return TAMP_INVALID_CONF; /* Extended stream but extended support not
                                 * compiled in */
    }

#endif /* if !TAMP_EXTENDED_DECOMPRESS */
  if (!conf_use_custom_dictionary)
    {
      tamp_initialize_dictionary (decompressor->window,
                                  (size_t)(1UL << conf_window),
                                  conf_extended ? conf_literal : 8);
    }

  decompressor->conf_window = conf_window;
  decompressor->conf_literal = conf_literal;
  decompressor->min_pattern_size
      = tamp_compute_min_pattern_size (conf_window, conf_literal);
  decompressor->configured = 1;
  decompressor->conf_extended = conf_extended;
  decompressor->conf_dictionary_reset = conf_dictionary_reset;

  return TAMP_OK;
}

tamp_res
tamp_decompressor_init (TampDecompressor *decompressor, const TampConf *conf,
                        unsigned char *window, xtrt_u8 window_bits)
{
  tamp_res res = TAMP_OK;

  /* Validate window_bits parameter */
  if (window_bits < 8 || window_bits > 15)
    {
      return TAMP_INVALID_CONF;
    }

  TAMP_MEMSET (decompressor, 0, sizeof (TampDecompressor));
  decompressor->window = window;
  decompressor->window_bits_max = window_bits;
  if (conf)
    {
      res = tamp_decompressor_populate_from_conf (
          decompressor, conf->window, conf->literal,
          conf->use_custom_dictionary, conf->extended, conf->dictionary_reset);
    }

  return res;
}

/**
 * @brief Refill bit buffer from input stream.
 *
 * Consumes bytes from input until bit_buffer has at least 25 bits or input is
 * exhausted.
 *
 * NOTE: NOINLINE saves ~192 bytes on armv6m but causes ~10% decompression
 * speed regression. Keep this inlined for performance.
 */
static void
refill_bit_buffer (TampDecompressor *d, const unsigned char **input,
                   const unsigned char *input_end, size_t *input_consumed_size)
{
  while (*input != input_end && d->bit_buffer_pos <= 24)
    {
      d->bit_buffer_pos += 8;
      d->bit_buffer |= (xtrt_u32) * (*input) << (32 - d->bit_buffer_pos);
      (*input)++;
      (*input_consumed_size)++;
    }
}

#if TAMP_HAS_GCC_OPTIMIZE
# pragma GCC push_options
# pragma GCC optimize("-fno-tree-pre")
#endif /* if TAMP_HAS_GCC_OPTIMIZE */
tamp_res
tamp_decompressor_decompress_cb (TampDecompressor *decompressor,
                                 unsigned char *output, size_t output_size,
                                 size_t *output_written_size,
                                 const unsigned char *input, size_t input_size,
                                 size_t *input_consumed_size,
                                 tamp_callback_t callback, void *user_data)
{
  xtrt_bool extended_enabled;
  xtrt_u16 window_mask;
  xtrt_u8 min_pattern_size;
  xtrt_u8 conf_literal;
  xtrt_u8 conf_window;
  size_t input_consumed_size_proxy;
  size_t output_written_size_proxy;
  tamp_res res;
  const unsigned char *input_end = input + input_size;
  const unsigned char *output_end = output + output_size;

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  if (!input_consumed_size)
    {
      input_consumed_size = &input_consumed_size_proxy;
    }

  *input_consumed_size = 0;
  *output_written_size = 0;

  if (TAMP_UNLIKELY (!decompressor->configured))
    {
      /* Try reading header directly from input. read_header handles */
      /* variable-length headers (1-2 bytes based on more_headers bit). */
      /* If the first byte indicates a 2-byte header but only 1 byte is */
      /* available, stash it and return INPUT_EXHAUSTED. */
      size_t header_consumed;
      TampConf conf;
      if (TAMP_UNLIKELY (decompressor->header_bytes_read))
        {
          size_t new_consumed;
          /* Second call: prepend stashed first byte. */
          unsigned char header_buf[2];
          header_buf[0] = decompressor->stashed_header_byte;
          header_buf[1] = 0;
          if (input != input_end)
            {
              header_buf[1] = *input;
            }

          res = tamp_decompressor_read_header (
              &conf, header_buf, 1 + (input != input_end), &header_consumed);
          if (res != TAMP_OK)
            {
              return res;
            }

          /* First byte was already consumed in prior call; only count new
           * bytes. */
          new_consumed = header_consumed - 1;
          input += new_consumed;
          (*input_consumed_size) += new_consumed;
        }
      else
        {
          res = tamp_decompressor_read_header (&conf, input, input_end - input,
                                               &header_consumed);
          if (res == TAMP_INPUT_EXHAUSTED && input != input_end)
            {
              /* Have first byte but need second; stash and retry next call. */
              decompressor->stashed_header_byte = *input;
              decompressor->header_bytes_read = 1;
              (*input_consumed_size)++;
              return TAMP_INPUT_EXHAUSTED;
            }

          if (res != TAMP_OK)
            {
              return res;
            }

          input += header_consumed;
          (*input_consumed_size) += header_consumed;
        }

      res = tamp_decompressor_populate_from_conf (
          decompressor, conf.window, conf.literal, conf.use_custom_dictionary,
          conf.extended, conf.dictionary_reset);
      if (res != TAMP_OK)
        {
          return res;
        }

      decompressor->skip_bytes
          = 0; /* Clear stale stashed_header_byte (shares union storage) */
    }

  /* Cache bitfield values in local variables for faster access */
  conf_window = decompressor->conf_window;
  conf_literal = decompressor->conf_literal;
  min_pattern_size = decompressor->min_pattern_size;

  window_mask = (1UL << conf_window) - 1;
#if TAMP_EXTENDED_DECOMPRESS
  extended_enabled = decompressor->conf_extended;
#endif /* if TAMP_EXTENDED_DECOMPRESS */

  while (input != input_end
         || (decompressor->bit_buffer_pos || decompressor->token_state))
    {
      if (TAMP_UNLIKELY (output == output_end))
        {
          return TAMP_OUTPUT_FULL;
        }

      /* Populate the bit buffer */
      refill_bit_buffer (decompressor, &input, input_end, input_consumed_size);

#if TAMP_EXTENDED_DECOMPRESS
      /* Handle extended tokens - either resuming or fresh from match_size
       * detection below. */
      if (TAMP_UNLIKELY (decompressor->token_state))
        {
        extended_dispatch:
          if (decompressor->token_state == TOKEN_RLE)
            {
              res = decode_rle (decompressor, &output, output_end,
                                output_written_size);
            }
          else
            {
              res = decode_extended_match (decompressor, &output, output_end,
                                           output_written_size);
            }

          if (res == TAMP_INPUT_EXHAUSTED)
            {
              xtrt_u8 old_bit_pos = decompressor->bit_buffer_pos;
              refill_bit_buffer (decompressor, &input, input_end,
                                 input_consumed_size);
              /* If we couldn't get more bits and input is exhausted, stop.
               * Otherwise the loop would run forever with token_state set. */
              if (decompressor->bit_buffer_pos == old_bit_pos
                  && input == input_end)
                {
                  return TAMP_INPUT_EXHAUSTED;
                }

              continue;
            }

          if (res != TAMP_OK)
            {
              return res;
            }

          continue;
        }

#endif /* TAMP_EXTENDED_DECOMPRESS */

      if (TAMP_UNLIKELY (decompressor->bit_buffer_pos == 0))
        {
          return TAMP_INPUT_EXHAUSTED;
        }

      /* Hint that patterns are more likely than literals */
      if (TAMP_UNLIKELY (decompressor->bit_buffer >> 31))
        {
          /* is literal */
          if (TAMP_UNLIKELY (decompressor->last_was_flush))
            {
              decompressor->last_was_flush = 0;
            }

          if (TAMP_UNLIKELY (decompressor->bit_buffer_pos
                             < (1 + conf_literal)))
            {
              return TAMP_INPUT_EXHAUSTED;
            }

          decompressor->bit_buffer <<= 1; /* shift out the is_literal flag */

          /* Copy literal to output */
          *output = decompressor->bit_buffer >> (32 - conf_literal);
          decompressor->bit_buffer <<= conf_literal;
          decompressor->bit_buffer_pos -= (1 + conf_literal);

          /* Update window */
          decompressor->window[decompressor->window_pos] = *output;
          decompressor->window_pos
              = (decompressor->window_pos + 1) & window_mask;

          output++;
          (*output_written_size)++;
        }
      else
        {
          size_t remaining;
          xtrt_u32 window_size;
          xtrt_u8 match_size_u8;
          /* is token; attempt a decode */
          /* copy the bit buffers so that we can abort at any time */
          xtrt_u32 bit_buffer = decompressor->bit_buffer;
          xtrt_u16 window_offset;
          xtrt_u16 window_offset_skip;
          xtrt_u8 bit_buffer_pos = decompressor->bit_buffer_pos;
          xtrt_s8 match_size;
          xtrt_s8 match_size_skip;

          /* shift out the is_literal flag */
          bit_buffer <<= 1;
          bit_buffer_pos--;

          if (decode_huffman (&bit_buffer, &bit_buffer_pos, 0, &match_size_u8)
              != TAMP_OK)
            {
              return TAMP_INPUT_EXHAUSTED;
            }

          match_size = match_size_u8;

          if (TAMP_UNLIKELY (match_size == XTR_TAMP_FLUSH))
            {
              /* flush bit_buffer to the nearest byte and skip the remainder of
               * decoding */
              decompressor->bit_buffer = bit_buffer << (bit_buffer_pos & 7);
              decompressor->bit_buffer_pos
                  = bit_buffer_pos & ~7; /* Round bit_buffer_pos down to
                                          * nearest multiple of 8. */
              if (decompressor->conf_dictionary_reset
                  && decompressor->last_was_flush)
                {
                  /* Double-FLUSH: reset dictionary. */
                  decompressor->window_pos = 0;
                  tamp_initialize_dictionary (
                      decompressor->window, (size_t)(1UL << conf_window),
                      decompressor->conf_extended ? conf_literal : 8);
                }

              decompressor->last_was_flush = 1;
              continue;
            }

          if (TAMP_UNLIKELY (decompressor->last_was_flush))
            {
              decompressor->last_was_flush = 0;
            }

#if TAMP_EXTENDED_DECOMPRESS
          /* Check for extended symbols (RLE=12, extended match=13).
           * Convert match_size to token_state via subtraction (see TOKEN_*
           * defines). */
          if (TAMP_UNLIKELY (extended_enabled
                             && match_size >= TAMP_RLE_SYMBOL))
            {
              decompressor->bit_buffer = bit_buffer;
              decompressor->bit_buffer_pos = bit_buffer_pos;
              decompressor->token_state = match_size - (TAMP_RLE_SYMBOL - 1);
              goto extended_dispatch;
            }

#endif /* TAMP_EXTENDED_DECOMPRESS */

          if (TAMP_UNLIKELY (bit_buffer_pos < conf_window))
            {
              /* There are not enough bits to decode window offset */
              return TAMP_INPUT_EXHAUSTED;
            }

          match_size += min_pattern_size;
          window_offset = bit_buffer >> (32 - conf_window);

          /* Security check: validate that the pattern reference (offset +
           * size) does not */
          /* exceed window bounds. Malicious compressed data could craft
           * out-of-bounds */
          /* references to read past the window buffer, potentially leaking
           * memory. */
          /* Cast to xtrt_u32 prevents signed integer overflow. */
          window_size = (1u << conf_window);
          if (TAMP_UNLIKELY ((xtrt_u32)window_offset >= window_size
                             || (xtrt_u32)window_offset + (xtrt_u32)match_size
                                    > window_size))
            {
              return TAMP_OOB;
            }

          /* Apply skip_bytes */
          match_size_skip = match_size - decompressor->skip_bytes;
          window_offset_skip = window_offset + decompressor->skip_bytes;

          /* Check if we are output-buffer-limited, and if so to set
           * skip_bytes. */
          /* Next tamp_decompressor_decompress_cb we will re-decode the same */
          /* token, and skip the first skip_bytes of it. */
          /* Otherwise, update the decompressor buffers */
          remaining = output_end - output;
          if (TAMP_UNLIKELY ((xtrt_u8)match_size_skip > remaining))
            {
              decompressor->skip_bytes += remaining;
              match_size_skip = remaining;
            }
          else
            {
              decompressor->skip_bytes = 0;
              decompressor->bit_buffer = bit_buffer << conf_window;
              decompressor->bit_buffer_pos = bit_buffer_pos - conf_window;
            }

          /* Copy pattern to output */
          TAMP_COPY_TO_OUTPUT (output,
                               decompressor->window + window_offset_skip,
                               match_size_skip);
          (*output_written_size) += match_size_skip;

          if (TAMP_LIKELY (decompressor->skip_bytes == 0))
            {
              xtrt_u16 wp = decompressor->window_pos;
              TAMP_WINDOW_COPY (decompressor->window, &wp, window_offset,
                                match_size, window_mask);
              decompressor->window_pos = wp;
            }
        }

      if (TAMP_UNLIKELY (callback
                         && (res = callback (user_data, *input_consumed_size,
                                             input_size))))
        {
          return (tamp_res)res;
        }
    }
  return TAMP_INPUT_EXHAUSTED;
}
#if TAMP_HAS_GCC_OPTIMIZE
# pragma GCC pop_options
#endif /* if TAMP_HAS_GCC_OPTIMIZE */

#if TAMP_STREAM

TAMP_OPTIMIZE_SIZE tamp_res
tamp_decompress_stream (TampDecompressor *decompressor, tamp_read_t read_cb,
                        void *read_handle, tamp_write_t write_cb,
                        void *write_handle, size_t *input_consumed_size,
                        size_t *output_written_size, tamp_callback_t callback,
                        void *user_data)
{
  size_t input_consumed_size_proxy, output_written_size_proxy;

  if (!input_consumed_size)
    {
      input_consumed_size = &input_consumed_size_proxy;
    }

  if (!output_written_size)
    {
      output_written_size = &output_written_size_proxy;
    }

  *input_consumed_size = 0;
  *output_written_size = 0;

  unsigned char input_buffer[TAMP_STREAM_WORK_BUFFER_SIZE / 2];
  unsigned char output_buffer[TAMP_STREAM_WORK_BUFFER_SIZE / 2];
  const size_t input_buffer_size = sizeof (input_buffer);
  const size_t output_buffer_size = sizeof (output_buffer);

  size_t input_pos = 0;
  size_t input_available = 0;
  xtrt_bool eof_reached = 0;

  while (1)
    {
      if (input_available == 0 && !eof_reached)
        {
          int bytes_read
              = read_cb (read_handle, input_buffer, input_buffer_size);
          if (TAMP_UNLIKELY (bytes_read < 0))
            {
              return TAMP_READ_ERROR;
            }

          eof_reached = (bytes_read == 0);
          input_pos = 0;
          input_available = bytes_read;
          *input_consumed_size += bytes_read;
        }

      size_t chunk_consumed, chunk_written;

      tamp_res res = tamp_decompressor_decompress (
          decompressor, output_buffer, output_buffer_size, &chunk_written,
          input_buffer + input_pos, input_available, &chunk_consumed);
      if (TAMP_UNLIKELY (res < TAMP_OK))
        {
          return res;
        }

      input_pos += chunk_consumed;
      input_available -= chunk_consumed;

      if (TAMP_LIKELY (chunk_written > 0))
        {
          int bytes_written
              = write_cb (write_handle, output_buffer, chunk_written);
          if (TAMP_UNLIKELY (bytes_written < 0
                             || (size_t)bytes_written != chunk_written))
            {
              return TAMP_WRITE_ERROR;
            }

          *output_written_size += chunk_written;
        }

      if (TAMP_UNLIKELY (res == TAMP_INPUT_EXHAUSTED && eof_reached))
        {
          break;
        }

      if (TAMP_UNLIKELY (callback))
        {
          int cb_res = callback (user_data, *input_consumed_size, 0);
          if (TAMP_UNLIKELY (cb_res))
            {
              return (tamp_res)cb_res;
            }
        }
    }

  return TAMP_OK;
}

#endif /* TAMP_STREAM */
