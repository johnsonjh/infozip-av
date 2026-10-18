/*
 * WinZip-compatible ZIP method 97 lossless WAV encoder.
 * SPDX-License-Identifier: MIT-0
 *
 * Only exact, bounded RIFF/WAVE PCM and IEEE float layouts are accepted.
 * The source WAV is reconstructed by libwavpack's header/trailer wrappers.
 * Never use WavpackSetConfiguration64(): it can create 0x410 streams.
 */

#include "wavpack_encoder.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wavpack/wavpack.h>

#define ZO_WV_WRAPPER_MAX 16777216UL
#define ZO_WV_FRAMES 1024U

typedef struct
{
  unsigned channels, width, float_audio, rate, mask;
  unsigned long data_offset, data_size, total_size;
} zo_wv_info;

typedef struct
{
  FILE *output;
  zo_u64 written;
  int failed;
  int io_failed;
  unsigned count;
} zo_wv_sink;

static unsigned
zo_wv_u16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned long
zo_wv_u32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);

}

static int
zo_wv_get (FILE *f, unsigned long pos, unsigned char *p, size_t n)
{
  return pos <= (unsigned long)LONG_MAX && fseek (f, (long)pos, SEEK_SET) == 0
         && fread (p, 1, n, f) == n;
}

/*
 * precisely one fmt chunk before the first data chunk;
 * all chunks must fit the declared RIFF length.
 * skip unknown or compressed formats without invoking libwavpack
 */

static int
zo_wv_parse (FILE *f, zo_wv_info *v)
{
  unsigned char head[40], fmt[40];
  unsigned long pos, end, len, next;
  unsigned found_fmt = 0, found_data = 0;
  unsigned tag, width, channels, bits, align, mask = 0;
  long flen;

  if (fseek (f, 0, SEEK_END) != 0 || (flen = ftell (f)) < 0)
    {
      return 0;
    }

  if ((unsigned long)flen < 44UL || !zo_wv_get (f, 0, head, 12)
      || memcmp (head, "RIFF", 4) || memcmp (head + 8, "WAVE", 4)
      || zo_wv_u32 (head + 4) != (unsigned long)flen - 8UL)
    {
      return 0;
    }

  end = (unsigned long)flen;
  pos = 12UL;
  memset (v, 0, sizeof (*v));
  v->total_size = end;

  while (pos < end)
    {
      if (end - pos < 8UL || !zo_wv_get (f, pos, head, 8))
        {
          return 0;
        }

      len = zo_wv_u32 (head + 4);

      if (len > end - pos - 8UL || (len & 1UL) > end - pos - 8UL - len)
        {
          return 0;
        }

      next = pos + 8UL + len + (len & 1UL);

      if (!memcmp (head, "fmt ", 4))
        {
          if (found_fmt || found_data || len < 16UL || len > sizeof (fmt)
              || !zo_wv_get (f, pos + 8UL, fmt, (size_t)len))
            {
              return 0;
            }

          tag = zo_wv_u16 (fmt);
          channels = zo_wv_u16 (fmt + 2);
          bits = zo_wv_u16 (fmt + 14);
          align = zo_wv_u16 (fmt + 12);
          v->rate = (unsigned)zo_wv_u32 (fmt + 4);

          if (tag == 0xfffeU)
            {
              static const unsigned char guid_tail[14]
                  = { 0, 0, 0,    0, 0x10, 0,    0x80,
                      0, 0, 0xaa, 0, 0x38, 0x9b, 0x71 };

              if (len < 40UL || zo_wv_u16 (fmt + 16) < 22U
                  || zo_wv_u16 (fmt + 16) > len - 18UL
                  || zo_wv_u16 (fmt + 18) > bits
                  || memcmp (fmt + 26, guid_tail, 14))
                {
                  return 0;
                }

              tag = zo_wv_u16 (fmt + 24);
              mask = (unsigned)zo_wv_u32 (fmt + 20);
            }

          if ((tag != 1U && tag != 3U) || channels < 1U || channels > 8U
              || v->rate == 0U || v->rate > (unsigned)INT_MAX || bits < 8U
              || bits > 32U || (bits & 7U) || (tag == 3U && bits != 32U)
              || align != channels * (bits / 8U)
              || (zo_u64)zo_wv_u32 (fmt + 8) != (zo_u64)v->rate * align)
            {
              return 0;
            }

          width = bits / 8U;
          v->channels = channels;
          v->width = width;
          v->float_audio = tag == 3U;
          v->mask = mask;
          found_fmt = 1;
        }
      else if (!memcmp (head, "data", 4))
        {
          if (!found_fmt || found_data || len == 0UL
              || len % (v->channels * v->width) != 0UL)
            {
              return 0;
            }

          v->data_offset = pos + 8UL;
          v->data_size = len;
          found_data = 1;
        }

      pos = next;
    }
  if (!found_data || v->data_offset > ZO_WV_WRAPPER_MAX
      || end - v->data_offset - v->data_size > ZO_WV_WRAPPER_MAX
      || v->data_size / (v->channels * v->width) >= 0xffffffffUL)
    {
      return 0;
    }

  return 1;
}

static int
zo_wv_output (void *opaque, void *block, int32_t count)
{
  zo_wv_sink *s = (zo_wv_sink *)opaque;
  const unsigned char *p = (const unsigned char *)block;

  if (s->failed)
    {
      return 0;
    }

  if (count < 32 || memcmp (p, "wvpk", 4) != 0
      || zo_wv_u32 (p + 4) != (unsigned long)count - 8UL
      || zo_wv_u16 (p + 8) != 0x407U
      || (zo_u64)count > ((zo_u64)-1) - s->written)
    {
      s->failed = 1;

      return 0;
    }

  ++s->count;

  if (fwrite (p, 1, (size_t)count, s->output) != (size_t)count)
    {
      s->failed = 1;
      s->io_failed = 1;

      return 0;
    }

  s->written += (zo_u64)count;

  return 1;
}

int
zo_wavpack_encode (FILE *in, FILE *out, zo_u64 *size, unsigned level,
                   unsigned extra)
{
  zo_wv_info info;
  zo_wv_sink sink;
  WavpackContext *wp = NULL;
  WavpackConfig config;
  unsigned char *prefix = NULL, *trailer = NULL;
  unsigned char pcm[ZO_WV_FRAMES * 8U * 4U];
  int32_t samples[ZO_WV_FRAMES * 8U];
  unsigned long tail, remaining, nframes;
  unsigned n, i, j, width, count;
  int result = 0;

  if (level < 1U || level > 4U || extra > 6U || !size)
    {
      return 0;
    }

  if (!zo_wv_parse (in, &info))
    {
      return ferror (in) ? -1 : 0;
    }

  width = info.width;
  tail = info.total_size - info.data_offset - info.data_size;
  prefix = (unsigned char *)malloc ((size_t)info.data_offset);

  if (tail)
    {
      trailer = (unsigned char *)malloc ((size_t)tail);
    }

  if (!prefix || (tail && !trailer))
    {
      goto done;
    }

  if (!zo_wv_get (in, 0UL, prefix, (size_t)info.data_offset)
      || (tail
          && !zo_wv_get (in, info.data_offset + info.data_size, trailer,
                         (size_t)tail)))
    {
      result = -1;
      goto done;
    }

  memset (&sink, 0, sizeof (sink));
  sink.output = out;
  wp = WavpackOpenFileOutput (zo_wv_output, &sink, NULL);

  if (!wp || !WavpackAddWrapper (wp, prefix, (uint32_t)info.data_offset))
    {
      goto done;
    }

  memset (&config, 0, sizeof (config));
  config.bits_per_sample = (int)(width * 8U);
  config.bytes_per_sample = (int)width;
  config.sample_rate = (int)info.rate;
  config.num_channels = (int)info.channels;
  config.channel_mask = (int32_t)info.mask;

  if (info.float_audio)
    {
      config.float_norm_exp = 127;
    }

  if (level == 1U)
    {
      config.flags |= CONFIG_FAST_FLAG;
    }

  if (level == 3U)
    {
      config.flags |= CONFIG_HIGH_FLAG;
    }

  if (level == 4U)
    {
      config.flags |= CONFIG_VERY_HIGH_FLAG;
    }

  if (extra)
    {
      config.flags |= CONFIG_EXTRA_MODE;
      config.xmode = (int)extra;
    }

  /* legacy API forces CONFIG_COMPATIBLE_WRITE and 0x407 */
  nframes = info.data_size / (info.channels * width);

  if (!WavpackSetConfiguration (wp, &config, (uint32_t)nframes)
      || !WavpackPackInit (wp))
    {
      goto done;
    }

  remaining = nframes;

  if (fseek (in, (long)info.data_offset, SEEK_SET) != 0)
    {
      result = -1;

      goto done;
    }

  while (remaining)
    {
      count = remaining < ZO_WV_FRAMES ? (unsigned)remaining : ZO_WV_FRAMES;
      n = count * info.channels * width;

      if (fread (pcm, 1, n, in) != n)
        {
          result = -1;

          goto done;
        }

      for (i = 0; i < count * info.channels; ++i)
        {
          uint32_t value = 0;

          for (j = 0; j < width; ++j)
            {
              value |= (uint32_t)pcm[i * width + j] << (8U * j);
            }

          if (width == 1U)
            {
              value = (uint32_t)((int)pcm[i] - 128);
            }
          else if (width < 4U && (value & (1UL << (width * 8U - 1U))))
            {
              value |= ~((uint32_t)((1UL << (width * 8U)) - 1UL));
            }

          memcpy (&samples[i], &value, sizeof (value));
        }

      if (!WavpackPackSamples (wp, samples, (uint32_t)count))
        {
          goto done;
        }

      remaining -= count;
    }

  /*
   * Flush audio before adding trailer: WavPack otherwise may attach the
   * trailer metadata to the audio block, where decoder cannot recover it.
   */

  if (!WavpackFlushSamples (wp)
      || (tail
          && (!WavpackAddWrapper (wp, trailer, (uint32_t)tail)
              || !WavpackFlushSamples (wp)))
      || sink.failed || !sink.count)
    {
      goto done;
    }

  if (fflush (out) != 0)
    {
      result = -1;

      goto done;
    }

  *size = sink.written;
  result = 1;

done:
  if (wp)
    {
      WavpackCloseFile (wp);
    }

  if ((wp && sink.io_failed) || ferror (in) || ferror (out))
    {
      result = -1;
    }

  free (prefix);
  free (trailer);

  return result;
}
