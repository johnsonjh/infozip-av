/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * Copyright (c) 2025 Dr.W.X WangXuan95 <https://github.com/WangXuan95>
 */

#define IZLP_BLOCK 32768U
#define IZLP_BUF 4096U

struct izlp_zip_ctx
{
  FILE *stage;
  struct small_store_state *store;
  unsigned char in[IZLP_BLOCK];
  unsigned char out[IZLP_BUF];
  size_t rdpos, rdlen, wrlen;
  unsigned long input_pos;
  zoff_t written;
  int mode, failed;
};

/*
 * PAQZIP wrapper independent 32KiB mode-2 preprocessing;
 * the last eight bytes of each buffer are left unchanged
 */

static void
izlp_exe_forward (unsigned char *data, size_t len, unsigned long offset)
{
  size_t i, end = len > 8U ? len - 8U : 0U;

  for (i = 0; i < end; ++i)
    {
      unsigned long value, target;
      if ((data[i] & 254U) != 232U)
        {
          continue;
        }

      value = (unsigned long)data[i + 1U] | ((unsigned long)data[i + 2U] << 8)
              | ((unsigned long)data[i + 3U] << 16)
              | ((unsigned long)data[i + 4U] << 24);
      if ((value & 0xffc00000UL) != 0UL
          && (value & 0xffc00000UL) != 0xffc00000UL)
        {
          continue;
        }

      target = (value + offset + (unsigned long)i) & 0x007fffffUL;
      if (target & 0x00400000UL)
        {
          target |= 0xff800000UL;
        }

      data[i + 1U] = (unsigned char)target;
      data[i + 2U] = (unsigned char)(target >> 8);
      data[i + 3U] = (unsigned char)(target >> 16);
      data[i + 4U] = (unsigned char)(target >> 24);
    }
}

static int
izlp_zip_read (void *opaque)
{
  struct izlp_zip_ctx *ctx = (struct izlp_zip_ctx *)opaque;

  if (ctx->failed)
    {
      return -1;
    }

  if (ctx->rdpos == ctx->rdlen)
    {
      ctx->rdlen = fread (ctx->in, 1U, sizeof (ctx->in), ctx->stage);
      ctx->rdpos = 0U;
      if (ctx->rdlen == 0U)
        {
          ctx->failed = 1;
          return -1;
        }

      if (ctx->mode == 2)
        {
          izlp_exe_forward (ctx->in, ctx->rdlen, ctx->input_pos);
        }

      ctx->input_pos += (unsigned long)ctx->rdlen;
    }

  return (int)ctx->in[ctx->rdpos++];
}

static int
izlp_zip_flush (struct izlp_zip_ctx *ctx)
{
  if (ctx->failed)
    {
      return 1;
    }

  if (ctx->wrlen)
    {
      uzoff_t max_pos = (sizeof (zoff_t) < sizeof (uzoff_t))
                            ? (uzoff_t)LONG_MAX
                            : (((uzoff_t)-1) >> 1);
      if (ctx->written < (zoff_t)0
          || (uzoff_t)ctx->written > max_pos - (uzoff_t)ctx->wrlen)
        {
          ctx->failed = 1;
          return 1;
        }

      if (small_store_write (ctx->store, ctx->out, (unsigned)ctx->wrlen)
          != (unsigned)ctx->wrlen)
        {
          ctx->failed = 1;
          return 1;
        }

      ctx->written += (zoff_t)ctx->wrlen;
      ctx->wrlen = 0;
    }

  return 0;
}

static int
izlp_zip_write (void *opaque, unsigned char b)
{
  struct izlp_zip_ctx *ctx = (struct izlp_zip_ctx *)opaque;

  if (ctx->failed)
    {
      return 1;
    }

  ctx->out[ctx->wrlen++] = b;
  return ctx->wrlen == sizeof (ctx->out) ? izlp_zip_flush (ctx) : 0;
}

local zoff_t
lpaq8filecompress (z_entry, cmpr_method)
struct zlist far *z_entry;
int *cmpr_method;
{
  struct izlp_zip_ctx ctx;
  struct small_store_state store_test;
  FILE *stage = NULL;
  unsigned char buffer[IZLP_BLOCK];
  unsigned long count = 0UL;
  unsigned n;
  size_t hdr_n, i;
  int level_num = (level == 11) ? 9 : level;
  int mode = 0;
  int high = 0;
  int status;
  zoff_t result;

  if (level_num < 1 || level_num > 9)
    {
      ziperr (ZE_PARMS, "LPAQ8 compression level must be 1..9");
    }

  small_store_init (&store_test, (size_t)SBSZ);
  stage = tmpfile ();
  if (!stage)
    {
      small_store_discard (&store_test);
      ziperr (ZE_TEMP, "LPAQ8 needs a temporary input file");
    }

  /* Spool through Zip normal input path */
  for (;;)
    {
      n = small_store_read (&store_test, (char *)buffer, sizeof (buffer));
      if (n == (unsigned)EOF || n == 0U)
        {
          break;
        }

      if (count > 0x7ffffffeUL - (unsigned long)n)
        {
          fclose (stage);
          small_store_discard (&store_test);
          ziperr (ZE_BIG, "LPAQ8 input exceeds historical 31-bit limit");
        }

      count += (unsigned long)n;
      if (file_binary_final == 0 && !is_text_buf ((char *)buffer, n))
        {
          file_binary_final = 1;
        }

      if (fwrite (buffer, 1U, (size_t)n, stage) != (size_t)n)
        {
          fclose (stage);
          small_store_discard (&store_test);
          ziperr (ZE_TEMP, "LPAQ8 temporary input write failed");
        }
    }

  if (ferror (stage) || fseek (stage, 0L, SEEK_SET) != 0)
    {
      fclose (stage);
      small_store_discard (&store_test);
      ziperr (ZE_TEMP, "LPAQ8 temporary input seek failed");
    }

  /* Match historical PAQZIP's initial-buffer heuristic: only 7-bit
   * data selects text mode, regardless of file extension. */
  hdr_n = fread (buffer, 1U, sizeof (buffer), stage);
  if (ferror (stage))
    {
      fclose (stage);
      small_store_discard (&store_test);
      ziperr (ZE_TEMP, "LPAQ8 temporary input read failed");
    }

  for (i = 0; i < hdr_n; ++i)
    {
      if (buffer[i] > 0x7fU)
        {
          high = 1;
          break;
        }
    }

  if (!high)
    {
      mode = 1;
    }
  else if (lpaq8_l2_enable && hdr_n >= 2U && buffer[0] == 'M'
           && buffer[1] == 'Z')
    {
      mode = 2;
    }

  if (fseek (stage, 0L, SEEK_SET) != 0)
    {
      fclose (stage);
      small_store_discard (&store_test);
      ziperr (ZE_TEMP, "LPAQ8 temporary input rewind failed");
    }

  memset (&ctx, 0, sizeof (ctx));
  ctx.stage = stage;
  ctx.store = &store_test;
  ctx.mode = mode;
  status
      = lpaq8_encode_stream (izlp_zip_read, &ctx, izlp_zip_write, &ctx, count,
                             (unsigned int)level_num, (unsigned int)mode);
  if (status == LPAQ8ENC_OK && izlp_zip_flush (&ctx) != 0)
    {
      status = LPAQ8ENC_OUTPUT_ERROR;
    }

  if (fclose (stage) != 0 && status == LPAQ8ENC_OK)
    {
      status = LPAQ8ENC_INPUT_ERROR;
    }

  if (status != LPAQ8ENC_OK)
    {
      small_store_discard (&store_test);
      if (ctx.failed || status == LPAQ8ENC_OUTPUT_ERROR)
        {
          ziperr (ZE_TEMP, "LPAQ8 output or input I/O failed");
        }

      if (status == LPAQ8ENC_NOMEM)
        {
          ziperr (ZE_MEM, "LPAQ8 predictor allocation failed");
        }

      ziperr (ZE_READ, "LPAQ8 compression failed");
    }

  z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
  result = small_store_finish (&store_test, cmpr_method, ctx.written);
  return result;
}
