/*
 * ZIP method 97 WavPack decompression adapter
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

#include <limits.h>
#include <string.h>
#include <wavpack/wavpack.h>

typedef struct
{
  zoff_t left;
  int64_t length;
  int64_t position;
  int pushed;
  int last;
  int error;
  unsigned char first[32];
  unsigned first_have;
#ifdef REENTRANT
  Uz_Globs *pG;
#endif /* ifdef REENTRANT */
} wz97_input;

static int32_t
wz97_read (void *opaque, void *buffer, int32_t count)
{
  wz97_input *s = (wz97_input *)opaque;
  uch *out = (uch *)buffer;
  int32_t total = 0;

#ifdef REENTRANT
  Uz_Globs *pG = s->pG;
#endif /* ifdef REENTRANT */
  if (count < 0 || (count > 0 && buffer == NULL))
    {
      s->error = 1;

      return 0;
    }

  if (count && s->pushed >= 0)
    {
      out[total++] = (uch)s->pushed;
      s->last = s->pushed;
      s->pushed = -1;
      --s->left;
      ++s->position;
    }

  while (total < count && s->left > 0)
    {
      int32_t n;

      if (G.incnt <= 0)
        {
          if (G.csize <= 0 || fillinbuf (__G) == 0)
            {
              s->error = 1;

              break;
            }
        }

      if (G.incnt <= 0)
        {
          s->error = 1;

          break;
        }

      n = count - total;

      if (n > G.incnt)
        {
          n = G.incnt;
        }

      if ((zoff_t)n > s->left)
        {
          n = (int32_t)s->left;
        }

      memcpy (out + total, G.inptr, (size_t)n);

      if (s->first_have < sizeof (s->first))
        {
          unsigned nprobe = (unsigned)n;

          if (nprobe > sizeof (s->first) - s->first_have)
            {
              nprobe = sizeof (s->first) - s->first_have;
            }

          memcpy (s->first + s->first_have, out + total, nprobe);
          s->first_have += nprobe;
        }

      G.inptr += n;
      G.incnt -= n;
      s->left -= (zoff_t)n;
      total += n;
      s->position += n;
      s->last = out[total - 1];
    }

  return total;
}

static int32_t
wz97_write (void *opaque, void *buffer, int32_t count)
{
  (void)opaque;
  (void)buffer;
  (void)count;

  return 0;
}

static int64_t
wz97_pos (void *opaque)
{
  return ((wz97_input *)opaque)->position;
}

static int
wz97_seek_abs (void *opaque, int64_t position)
{
  (void)opaque;
  (void)position;

  return -1;
}

static int
wz97_seek_rel (void *opaque, int64_t offset, int whence)
{
  (void)opaque;
  (void)offset;
  (void)whence;

  return -1;
}

static int
wz97_push (void *opaque, int c)
{
  wz97_input *s = (wz97_input *)opaque;

  if (c < 0 || c > 255 || s->pushed >= 0 || !s->position || s->last != c)
    {
      return -1;
    }

  s->pushed = c;
  ++s->left;
  --s->position;

  return c;
}

static int64_t
wz97_length (void *opaque)
{
  return ((wz97_input *)opaque)->length;
}

static int
wz97_seekable (void *opaque)
{
  (void)opaque;

  return 0;
}

static int
wz97_truncate (void *opaque)
{
  (void)opaque;

  return -1;
}

static int
wz97_close (void *opaque)
{
  (void)opaque;

  return 0; /* UnZip owns the ZIP input */
}

static WavpackStreamReader64 wz97_reader
    = { wz97_read, wz97_write,  wz97_pos,      wz97_seek_abs, wz97_seek_rel,
        wz97_push, wz97_length, wz97_seekable, wz97_truncate, wz97_close };

static int
wz97_emit (__GPRO__ const uch *data, unsigned len, zusz_t *remaining,
           unsigned outsize)
{
  unsigned n;
  int r;

  if ((zusz_t)len > *remaining)
    {
      return PK_ERR;
    }

  *remaining -= len;

  while (len)
    {
      n = len < outsize ? len : outsize;
      memcpy (redirSlide, data, n);
      r = FLUSH (n);

      if (r != PK_COOL)
        {
          return r;
        }

      data += n;
      len -= n;
    }

  return PK_COOL;
}

static int
uz_wavpack_decompress (__G) __GDEF
{
  wz97_input stream;
  WavpackContext *ctx = NULL;
  int32_t *samples = NULL;
  uch *bytes = NULL;
  int channels, width, mode, r = PK_ERR;
  unsigned outsize = WSIZE;
  uint32_t got, nw, sample_count;
  unsigned i, j, nbytes, chunk;
  uint32_t wrapper_len;
  unsigned char *wrapper;
  int64_t expected_samples;
  zusz_t remaining;
  char error[128];

  /* Check before addition: a malformed ZIP64 size must not overflow the
   * signed input counter, even transiently.  WavPack uses int64_t lengths. */
  if (G.csize < 0 || G.incnt < 0 ||
      (uint64_t)G.csize > (uint64_t)INT64_MAX - (uint64_t)G.incnt)
    return PK_ERR;
  stream.length = (int64_t)G.csize + (int64_t)G.incnt;
  if (stream.length <= 0 ||
      (sizeof(zoff_t) < sizeof(int64_t) &&
       stream.length > (int64_t)LONG_MAX))
    return PK_ERR;
  stream.left = (zoff_t)stream.length;
  stream.position = 0;
  stream.pushed = -1;
  stream.last = -1;
  stream.error = 0;
  stream.first_have = 0;
#ifdef REENTRANT
  stream.pG = pG;
#endif /* ifdef REENTRANT */
  remaining = G.lrec.ucsize;
#if (defined(DLL) && !defined(NO_SLIDE_REDIR))
  if (G.redirect_slide)
    {
      outsize = G.redirect_size;
      redirSlide = G.redirect_buffer;
    }
  else
    {
      redirSlide = slide;
    }

  if (!outsize)
    {
      return PK_ERR;
    }

#endif /* if ( defined( DLL ) && !defined( NO_SLIDE_REDIR )) */
  error[0] = 0;
  ctx = WavpackOpenFileInputEx64 (&wz97_reader, &stream, NULL, error,
                                  OPEN_WRAPPER, 0);
  if (!ctx)
    {
      return PK_ERR;
    }

  if (stream.error || stream.first_have < 10
      || memcmp (stream.first, "wvpk", 4) != 0
      || ((unsigned)stream.first[8] | ((unsigned)stream.first[9] << 8))
             < 0x402U
      || ((unsigned)stream.first[8] | ((unsigned)stream.first[9] << 8))
             >= 0x410U
      || !(WavpackGetMode (ctx) & MODE_LOSSLESS) || WavpackLossyBlocks (ctx)
      || WavpackGetFileFormat (ctx) != WP_FORMAT_WAV)
    {
      goto finish;
    }

  channels = WavpackGetNumChannels (ctx);
  width = WavpackGetBytesPerSample (ctx);
  mode = WavpackGetMode (ctx);
  expected_samples = WavpackGetNumSamples64 (ctx);

  if (channels < 1 || channels > 4096 || width < 1 || width > 4
      || (mode & MODE_FLOAT && width != 4) || expected_samples <= 0
      || (uint64_t)expected_samples
             > (uint64_t)remaining / ((unsigned)channels * width))
    {
      goto finish;
    }

  wrapper_len = WavpackGetWrapperBytes (ctx);
  wrapper = WavpackGetWrapperData (ctx);

  if (wrapper_len < 12 || !wrapper || (zusz_t)wrapper_len > remaining
      || memcmp (wrapper, "RIFF", 4) != 0
      || memcmp (wrapper + 8, "WAVE", 4) != 0)
    {
      goto finish;
    }

  r = wz97_emit (__G__ wrapper, (unsigned)wrapper_len, &remaining, outsize);

  if (r != PK_COOL)
    {
      goto finish;
    }

  WavpackFreeWrapper (ctx);

  sample_count = 4096U / ((unsigned)channels * width);

  if (sample_count < 1)
    {
      sample_count = 1;
    }

  if (sample_count > 1024)
    {
      sample_count = 1024;
    }

  nbytes = sample_count * (unsigned)channels * width;
  samples = (int32_t *)malloc ((size_t)sample_count * (unsigned)channels
                               * sizeof (int32_t));
  bytes = (uch *)malloc ((size_t)nbytes);

  if (!samples || !bytes)
    {
      r = PK_MEM3;
      goto finish;
    }

  while (expected_samples > 0)
    {
      uint32_t count
          = (uint32_t)(expected_samples < sample_count ? expected_samples
                                                       : sample_count);
      got = WavpackUnpackSamples (ctx, samples, count);

      if (stream.error || got != count)
        {
          r = PK_ERR;
          goto finish;
        }

      nw = got * (uint32_t)channels;

      for (i = 0; i < nw; i++)
        {
          uint32_t value = (uint32_t)samples[i];

          if (width == 1)
            {
              value += 128U;
            }

          for (j = 0; j < (unsigned)width; j++)
            {
              bytes[i * (unsigned)width + j] = (uch)(value >> (8U * j));
            }
        }

      chunk = (unsigned)(nw * (uint32_t)width);
      r = wz97_emit (__G__ bytes, chunk, &remaining, outsize);

      if (r != PK_COOL)
        {
          goto finish;
        }

      expected_samples -= got;
    }

  if (WavpackUnpackSamples (ctx, samples, 1) != 0 || stream.error
      || WavpackGetNumErrors (ctx) != 0 || WavpackLossyBlocks (ctx))
    {
      r = PK_ERR;
      goto finish;
    }

  wrapper_len = WavpackGetWrapperBytes (ctx);
  wrapper = WavpackGetWrapperData (ctx);

  if ((wrapper_len && !wrapper) || (zusz_t)wrapper_len > remaining)
    {
      r = PK_ERR;
      goto finish;
    }

  if (wrapper_len)
    {
      r = wz97_emit (__G__ wrapper, (unsigned)wrapper_len, &remaining,
                     outsize);
      if (r != PK_COOL)
        {
          goto finish;
        }
    }

  if (remaining || stream.left || stream.pushed >= 0)
    {
      r = PK_ERR;
    }
  else
    {
      r = PK_COOL;
    }

finish:
  free (samples);
  free (bytes);
  WavpackCloseFile (ctx);

  return r;
}
