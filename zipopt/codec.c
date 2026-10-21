/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/*
 * zipopt compression adapters, built directly from cu43's codec sources.
 * This translation unit contains no Zip global archive state.
 */

#define _FILE_OFFSET_BITS 64

#include "../zip30/deflate64.h"
#include "../zip30/pkdcl.h"
#include "../zip30/ppmd8.h"
#include "../zip30/zopfli.h"

#include "codec.h"

extern int zo_legacy_huffman_optimize_extra;

#include "zip_deflate.h"

#ifdef ZO_WITH_WAVPACK
# include "wavpack_encoder.h"
#endif

#include <limits.h>
#include <stdlib.h>
#include <string.h>
/* Unix retains the original all-codecs build; Windows selects each static
 * dependency independently.  An unavailable candidate is never attempted. */
#ifndef ZO_NO_EXTERNAL_CODECS
# if !defined(ZO_SELECT_EXTERNAL_CODECS) || defined(ZO_WITH_BZIP2)
#  define ZO_BUILD_BZIP2 1
#  include <bzlib.h>
# endif
# if !defined(ZO_SELECT_EXTERNAL_CODECS) || defined(ZO_WITH_LZMA)
#  define ZO_BUILD_LZMA 1
#  include <lzma.h>
# endif
# if !defined(ZO_SELECT_EXTERNAL_CODECS) || defined(ZO_WITH_ZSTD)
#  define ZO_BUILD_ZSTD 1
#  include <zstd.h>
# endif
#endif

#if defined(ZO_USE_ZLIB_NG)
# include <zlib-ng.h>
#elif defined(ZO_USE_ZLIB)
# include <zlib.h>
#endif /* if defined( ZO_USE_ZLIB_NG ) */

/* The source amalgamation mirrors the existing zipup.c strategy. */
#include "../zip30/deflate64.c"
#include "../zip30/implode6.c"
#include "../zip30/reduce.c"
#include "../zip30/shrink.c"

#ifndef ZO_SHARED_UNZIP_CODECS
# include "../zip30/pkdcl.c"
# include "../zip30/ppmd8.c"
#endif /* ifndef ZO_SHARED_UNZIP_CODECS */

#include "../zip30/ppmd8enc.c"
#include "../zip30/zopfli.c"

const zo_candidate zo_candidates[] = { { "store",              0,  0,    0 },
                                       { "shrink",             1,  0,    0 },
                                       { "reduce-l1",          2,  1,    0 },
                                       { "reduce-l2",          3,  2,    0 },
                                       { "reduce-l3",          4,  3,    0 },
                                       { "reduce-l4",          5,  4,    0 },
                                       { "implode-4k-2",       6,  4096, 0 },
                                       { "implode-4k-3",       6,  4096, 4 },
                                       { "implode-8k-2",       6,  8192, 2 },
                                       { "implode-8k-3",       6,  8192, 6 },
                                       { "deflate",            8,  11,   2 },
                                       { "deflate64",          9,  11,   2 },
                                       { "dcl-implode-binary", 10, 0,    0 },
                                       { "dcl-implode-ascii",  10, 1,    0 },
                                       { "bzip2",              12, 9,    0 },
                                       { "lzma",               14, 9,    2 },
                                       { "zstd",               93, 22,   0 },
                                       { "xz",                 95, 9,    0 },
                                       { "ppmd",               98, 9,    0 },
                                       { "wavpack",            97, 0,    0 } };
const unsigned zo_candidate_count
    = sizeof (zo_candidates) / sizeof (zo_candidates[0]);

int
zo_candidate_available (unsigned id)
{
  if (id >= zo_candidate_count)
    return 0;
#ifndef ZO_BUILD_BZIP2
  if (id == 14U) return 0;
#endif
#ifndef ZO_BUILD_LZMA
  if (id == 15U || id == 17U) return 0;
#endif
#ifndef ZO_BUILD_ZSTD
  if (id == 16U) return 0;
#endif
#ifndef ZO_WITH_WAVPACK
  if (zo_candidates[id].method == 97U) return 0;
#endif
  return 1;
}
struct zo_io
{
  FILE *in, *out;
  zo_u64 written;
  int failed;
  int io_failed;
};

static unsigned
zo_rd (void *v, unsigned char *buf, unsigned size)
{
  struct zo_io *s = (struct zo_io *)v;
  size_t n;

  if (s->failed)
    {
      return 0;
    }

  n = fread (buf, 1, (size_t)size, s->in);

  if (ferror (s->in))
    {
      s->failed = 1;
      s->io_failed = 1;
    }

  return (unsigned)n;
}

static int
zo_wr (void *v, const unsigned char *p, unsigned size)
{
  struct zo_io *s = (struct zo_io *)v;

  if (s->failed)
    {
      return 1;
    }

  if ((zo_u64)size > ((zo_u64)-1) - s->written
      || fwrite (p, 1, (size_t)size, s->out) != (size_t)size)
    {
      s->failed = 1;
      s->io_failed = 1;
      return 1;
    }

  s->written += (zo_u64)size;

  return 0;
}

static unsigned short
zo_dcl_rd (unsigned char *buf, unsigned short *want, void *v)
{
  return (unsigned short)zo_rd (v, buf, (unsigned)*want);
}

static void
zo_dcl_wr (unsigned char *buf, unsigned short *want, void *v)
{
  if (zo_wr (v, buf, (unsigned)*want) != 0)
    {
      *want = 0;
    }
}

static int
zo_copy (struct zo_io *s)
{
  unsigned char buf[32768];
  unsigned n;

  while ((n = zo_rd (s, buf, sizeof (buf))) != 0)
    {
      if (zo_wr (s, buf, n))
        {
          return 0;
        }
    }

  return !s->failed;
}

#ifdef ZO_BUILD_BZIP2
static int
zo_bzip (struct zo_io *s, int level)
{
  bz_stream bs;
  unsigned char in[16384], out[16384];
  int rc, flush, finished = 0;

  memset (&bs, 0, sizeof (bs));

  if (BZ2_bzCompressInit (&bs, level, 0, 30) != BZ_OK)
    {
      return 0;
    }

  bs.next_in = (char *)in;
  bs.avail_in = 0;
  bs.next_out = (char *)out;
  bs.avail_out = sizeof (out);

  while (!finished && !s->failed)
    {
      if (bs.avail_in == 0)
        {
          bs.avail_in = zo_rd (s, in, sizeof (in));
          bs.next_in = (char *)in;
        }

      flush = (bs.avail_in == 0) ? BZ_FINISH : BZ_RUN;
      rc = BZ2_bzCompress (&bs, flush);

      if (rc != BZ_RUN_OK && rc != BZ_FINISH_OK && rc != BZ_STREAM_END)
        {
          s->failed = 1;
          break;
        }

      if (bs.avail_out == 0 || rc == BZ_STREAM_END)
        {
          if (zo_wr (s, out, sizeof (out) - bs.avail_out))
            {
              break;
            }

          bs.next_out = (char *)out;
          bs.avail_out = sizeof (out);
        }

      if (rc == BZ_STREAM_END)
        {
          finished = 1;
        }
    }

  BZ2_bzCompressEnd (&bs);

  return finished && !s->failed;
}
#endif /* ZO_BUILD_BZIP2 */

#ifdef ZO_BUILD_LZMA
static int
zo_xz_lzma (struct zo_io *s, int xz, unsigned level)
{
  lzma_stream ls = LZMA_STREAM_INIT;
  lzma_options_lzma opt;
  lzma_filter filters[2];
  unsigned char in[16384], out[16384], header[9];
  uint32_t props;
  lzma_ret rc;
  int finished = 0;

  if (xz)
    {
      if (lzma_easy_encoder (&ls, level, LZMA_CHECK_NONE) != LZMA_OK)
        {
          return 0;
        }
    }
  else
    {
      if (lzma_lzma_preset (&opt, level))
        {
          return 0;
        }

      filters[0].id = LZMA_FILTER_LZMA1;
      filters[0].options = &opt;
      filters[1].id = LZMA_VLI_UNKNOWN;
      filters[1].options = NULL;

      if (lzma_properties_size (&props, &filters[0]) != LZMA_OK || props != 5)
        {
          return 0;
        }

      if (lzma_properties_encode (&filters[0], header + 4) != LZMA_OK)
        {
          return 0;
        }

      header[0] = 9;
      header[1] = 4;
      header[2] = 5;
      header[3] = 0;

      if (zo_wr (s, header, 9))
        {
          return 0;
        }

      if (lzma_raw_encoder (&ls, filters) != LZMA_OK)
        {
          return 0;
        }
    }

  ls.next_in = NULL;
  ls.avail_in = 0;
  ls.next_out = out;
  ls.avail_out = sizeof (out);

  while (!finished && !s->failed)
    {
      if (ls.avail_in == 0)
        {
          ls.avail_in = zo_rd (s, in, sizeof (in));
          ls.next_in = in;
        }

      rc = lzma_code (&ls, ls.avail_in == 0 ? LZMA_FINISH : LZMA_RUN);

      if (rc != LZMA_OK && rc != LZMA_STREAM_END)
        {
          s->failed = 1;

          break;
        }

      if (ls.avail_out == 0 || rc == LZMA_STREAM_END)
        {
          if (zo_wr (s, out, sizeof (out) - ls.avail_out))
            {
              break;
            }

          ls.next_out = out;
          ls.avail_out = sizeof (out);
        }

      if (rc == LZMA_STREAM_END)
        {
          finished = 1;
        }
    }

  lzma_end (&ls);

  return finished && !s->failed;
}
#endif /* ZO_BUILD_LZMA */

#ifdef ZO_BUILD_ZSTD
static int
zo_zstd (struct zo_io *s, int level)
{
  ZSTD_CCtx *ctx;
  unsigned char in[16384], out[16384];
  ZSTD_inBuffer ib;
  ZSTD_outBuffer ob;
  ZSTD_EndDirective action;
  size_t rc;
  int end = 0, done = 0;

  ctx = ZSTD_createCCtx ();

  if (!ctx)
    {
      return 0;
    }

  rc = ZSTD_CCtx_setParameter (ctx, ZSTD_c_compressionLevel, level);

  if (ZSTD_isError (rc))
    {
      ZSTD_freeCCtx (ctx);
      return 0;
    }

  rc = ZSTD_CCtx_setParameter (ctx, ZSTD_c_checksumFlag, 0);

  if (ZSTD_isError (rc))
    {
      ZSTD_freeCCtx (ctx);
      return 0;
    }

  ib.src = in;
  ib.pos = 0;
  ib.size = 0;

  while (!done && !s->failed)
    {
      if (ib.pos == ib.size && !end)
        {
          ib.size = zo_rd (s, in, sizeof (in));
          ib.pos = 0;

          if (ib.size == 0)
            {
              end = 1;
            }
        }

      action = end ? ZSTD_e_end : ZSTD_e_continue;
      ob.dst = out;
      ob.pos = 0;
      ob.size = sizeof (out);
      rc = ZSTD_compressStream2 (ctx, &ob, &ib, action);

      if (ZSTD_isError (rc) || zo_wr (s, out, (unsigned)ob.pos))
        {
          s->failed = 1;
          break;
        }

      if (end && rc == 0)
        {
          done = 1;
        }
    }

  ZSTD_freeCCtx (ctx);

  return done && !s->failed;
}

#endif /* ZO_BUILD_ZSTD */

#define ZO_PPMD_OUTPUT 16384U
struct zo_ppmd
{
  IByteOut vt;
  struct zo_io *io;
  unsigned char buf[ZO_PPMD_OUTPUT];
  unsigned n;
};

static void *
zo_pa (ISzAllocPtr a, size_t n)
{
  (void)a;

  return malloc (n);
}

static void
zo_pf (ISzAllocPtr a, void *p)
{
  (void)a;
  free (p);
}

static ISzAlloc zo_allocator = { zo_pa, zo_pf };

static void
zo_ppmd_flush (struct zo_ppmd *p)
{
  if (p->n && !p->io->failed)
    {
      zo_wr (p->io, p->buf, p->n);
    }

  p->n = 0;
}

static void
zo_ppmd_putchar (IByteOutPtr v, Byte b)
{
  struct zo_ppmd *p = (struct zo_ppmd *)v;

  if (p->io->failed)
    {
      return;
    }

  p->buf[p->n++] = b;

  if (p->n == ZO_PPMD_OUTPUT)
    {
      zo_ppmd_flush (p);
    }
}

static int
zo_ppmd (struct zo_io *s, unsigned level)
{
  CPpmd8 m;
  struct zo_ppmd pp;
  unsigned char in[8192];
  unsigned n, i;
  static const unsigned char orders[9] = { 6, 7, 8, 8, 8, 8, 10, 12, 16 };
  static const unsigned short memories[9]
      = { 2, 4, 8, 16, 32, 50, 64, 128, 256 };
  unsigned order = orders[level - 1U], mem_mb = memories[level - 1U];
  unsigned props = (order - 1U) | ((mem_mb - 1U) << 4);
  unsigned char h[2];

  h[0] = (unsigned char)props;
  h[1] = (unsigned char)(props >> 8);

  if (zo_wr (s, h, 2))
    {
      return 0;
    }

  memset (&pp, 0, sizeof (pp));
  pp.vt.Write = zo_ppmd_putchar;
  pp.io = s;
  Ppmd8_Construct (&m);

  if (!Ppmd8_Alloc (&m, (size_t)mem_mb << 20, &zo_allocator))
    {
      return 0;
    }

  m.Stream.Out = &pp.vt;
  Ppmd8_Init_RangeEnc (&m);
  Ppmd8_Init (&m, order, PPMD8_RESTORE_METHOD_RESTART);

  while ((n = zo_rd (s, in, sizeof (in))) != 0 && !s->failed)
    {
      for (i = 0; i < n; i++)
        {
          Ppmd8_EncodeSymbol (&m, (int)in[i]);
        }
    }

  if (!s->failed)
    {
      Ppmd8_EncodeSymbol (&m, PPMD8_SYM_END);
      Ppmd8_Flush_RangeEnc (&m);
      zo_ppmd_flush (&pp);
    }

  Ppmd8_Free (&m, &zo_allocator);

  return !s->failed;
}

/*
 * Deflate through an selected external backend
 */

#if defined(ZO_USE_ZLIB_NG) || defined(ZO_USE_ZLIB)
static int
zo_deflate (struct zo_io *s, unsigned level)
{
# if defined(ZO_USE_ZLIB_NG)
  zng_stream z;
# else  /* if defined( ZO_USE_ZLIB_NG ) */
  z_stream z;
# endif /* if defined( ZO_USE_ZLIB_NG ) */
  unsigned char input[16384], output[16384];
  int rc, flush, done = 0;
  unsigned n;

  memset (&z, 0, sizeof (z));
# if defined(ZO_USE_ZLIB_NG)
  if (zng_deflateInit2 (&z, (int)level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)
      != Z_OK)
# else  /* if defined( ZO_USE_ZLIB_NG ) */
  if (deflateInit2 (&z, (int)level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)
      != Z_OK)
# endif /* if defined( ZO_USE_ZLIB_NG ) */
    {
      return 0;
    }

  z.next_in = Z_NULL;
  z.avail_in = 0;

  while (!done && !s->failed)
    {
      if (z.avail_in == 0)
        {
          n = zo_rd (s, input, sizeof (input));
          z.next_in = input;
          z.avail_in = n;
        }

      flush = z.avail_in == 0 ? Z_FINISH : Z_NO_FLUSH;

      do
        {
          z.next_out = output;
          z.avail_out = sizeof (output);
# if defined(ZO_USE_ZLIB_NG)
          rc = zng_deflate (&z, flush);
# else  /* if defined( ZO_USE_ZLIB_NG ) */
          rc = deflate (&z, flush);
# endif /* if defined( ZO_USE_ZLIB_NG ) */
          if ((rc != Z_OK && rc != Z_STREAM_END)
              || zo_wr (s, output, (unsigned)(sizeof (output) - z.avail_out)))
            {
              s->failed = 1;
              break;
            }

          if (rc == Z_STREAM_END)
            {
              done = 1;
            }
        }
      while (!s->failed && !done && z.avail_out == 0);
    }
# if defined(ZO_USE_ZLIB_NG)
  zng_deflateEnd (&z);
# else  /* if defined( ZO_USE_ZLIB_NG ) */
  deflateEnd (&z);
# endif /* if defined( ZO_USE_ZLIB_NG ) */
  return done && !s->failed;
}
#endif /* ZO_USE_ZLIB_NG || ZO_USE_ZLIB */

#define ZO_Z_CHUNK 1000000U
#define ZO_Z_HISTORY 32768U

static int
zo_zopfli_part (struct zo_io *s, ZopfliOptions *o, int final,
                const unsigned char *p, size_t start, size_t end,
                unsigned char *bp, unsigned char *carry)
{
  unsigned char *out = NULL;
  size_t n = 0, w;

  if (*bp)
    {
      out = (unsigned char *)malloc (1);

      if (!out)
        {
          return 0;
        }

      out[0] = *carry;
      n = 1;
    }

  if (!ZopfliDeflatePart (o, 2, final, p, start, end, bp, &out, &n))
    {
      /* Encoder released all partial output and reports a failed candidate. */
      return 0;
    }

  if (!out || (!final && *bp && n < 1))
    {
      free (out);

      return 0;
    }

  w = (final || *bp == 0) ? n : n - 1;

  if (!final && *bp)
    {
      *carry = out[n - 1];
    }

  if (w > ((size_t)(unsigned)-1) || zo_wr (s, out, (unsigned)w))
    {
      free (out);

      return 0;
    }

  free (out);

  return 1;
}

static unsigned
zo_chunk (struct zo_io *s, unsigned char *p, unsigned n, int *eof)
{
  unsigned total = 0, got;

  *eof = 0;

  while (total < n)
    {
      got = zo_rd (s, p + total, n - total);

      if (!got)
        {
          *eof = 1;

          break;
        }

      total += got;
    }

  return total;
}

static int
zo_zopfli (struct zo_io *s, unsigned iterations)
{
  unsigned char *work, *next;
  unsigned len, forward;
  unsigned history = 0;
  unsigned char bp = 0, carry = 0;
  int eof = 0, next_eof = 0, final, ok = 1;
  ZopfliOptions opts;

  work = (unsigned char *)malloc (ZO_Z_CHUNK + ZO_Z_HISTORY);
  next = (unsigned char *)malloc (ZO_Z_CHUNK);

  if (!work || !next)
    {
      free (work);
      free (next);

      return 0;
    }

  ZopfliInitOptions (&opts);
  opts.numiterations = (int)iterations;
  len = zo_chunk (s, work, ZO_Z_CHUNK, &eof);
  forward = eof ? 0 : zo_chunk (s, next, ZO_Z_CHUNK, &next_eof);

  for (;;)
    {
      final = eof || (next_eof && forward == 0);

      if (!zo_zopfli_part (s, &opts, final, work, history, history + len, &bp,
                           &carry))
        {
          ok = 0;

          break;
        }

      if (final)
        {
          break;
        }

      {
        unsigned total = history + len;
        unsigned keep = total < ZO_Z_HISTORY ? total : ZO_Z_HISTORY;

        memmove (work, work + total - keep, keep);
        history = keep;
      }

      memcpy (work + history, next, forward);
      len = forward;
      eof = next_eof;
      forward = eof ? 0 : zo_chunk (s, next, ZO_Z_CHUNK, &next_eof);
    }

  free (work);
  free (next);

  return ok && !s->failed;
}

int
zo_compress (unsigned id, FILE *in, FILE *out, zo_u64 *compressed,
             const zo_settings *settings)
{
  struct zo_io s;
  const zo_candidate *c;
  d64_stats stats;
  int rc = 1;

  if (!in || !out || !compressed || !settings || id >= zo_candidate_count
      || settings->zopfli_iterations < 1U
      || settings->zopfli_iterations > 10000U || !zo_candidate_available (id))
    {
      return 0;
    }

  /* A failed seek is an input I/O failure, not a codec failure. */
  if (fseek (in, 0L, SEEK_SET) != 0)
    {
      return ZO_COMPRESS_FATAL;
    }

  s.in = in;
  s.out = out;
  s.written = 0;
  s.failed = 0;
  s.io_failed = 0;
  c = &zo_candidates[id];

  if (id == 16U)
    {
      if (settings->levels[id] < 1U || settings->levels[id] > 22U)
        {
          return 0;
        }
    }
  else if ((id == 10U || id == 11U || id == 14U || id == 15U || id == 17U
            || id == 18U)
           && (settings->levels[id] < 1U
               || settings->levels[id] > (id == 10U || id == 11U ? 11U : 9U)))
    {
      return 0;
    }

  ZopfliSetHuffmanOptimizeExtra(settings->huffman_optimize_extra);
  d64_set_huffman_optimize_extra(settings->huffman_optimize_extra);
  zo_legacy_huffman_optimize_extra = settings->huffman_optimize_extra;

  switch (id)
    {
    case 0:
      rc = zo_copy (&s);

      break;

    case 1:
      rc = shk_encode (zo_rd, zo_wr, &s) == 0;

      break;

    case 2:
    case 3:
    case 4:
    case 5:
      rc = red_encode (zo_rd, zo_wr, &s, c->parameter) == 0;

      break;

    case 6:
    case 7:
    case 8:
    case 9:
      rc = im6_encode (zo_rd, zo_wr, &s, c->parameter, (c->flags & 4) ? 3 : 2)
           == 0;

      break;

    case 10:
      if (settings->disable_zopfli || settings->levels[id] != 11U)
        {
          unsigned dlevel
              = settings->levels[id] == 11U ? 9U : settings->levels[id];
#if defined(ZO_USE_ZLIB_NG) || defined(ZO_USE_ZLIB)
          rc = settings->huffman_optimize_extra ?
              zo_zip_internal_deflate (zo_rd, zo_wr, &s, dlevel) :
              zo_deflate (&s, dlevel);
#else  /* if defined( ZO_USE_ZLIB_NG ) || defined( ZO_USE_ZLIB ) */
          rc = zo_zip_internal_deflate (zo_rd, zo_wr, &s, dlevel);
#endif /* if defined( ZO_USE_ZLIB_NG ) || defined( ZO_USE_ZLIB ) */
        }
      else
        {
          rc = zo_zopfli (&s, settings->zopfli_iterations);
        }

      break;

    case 11:
      memset (&stats, 0, sizeof (stats));
      rc = d64_encode (zo_rd, zo_wr, &s, (int)settings->levels[id], &stats)
           == 0;

      break;

    case 12:
    case 13:
      rc = pkdcl_implode_ex (
               zo_dcl_rd, zo_dcl_wr, &s,
               id == 12 ? PKDCL_CMP_BINARY : PKDCL_CMP_ASCII, PKDCL_DICT_AUTO,
               PKDCL_FLAG_EXTRA
                   | (settings->levels[id] == 11U ? PKDCL_FLAG_OPTIMAL : 0U))
           == PKDCL_CMP_NO_ERROR;

      break;

    case 14:
#ifndef ZO_BUILD_BZIP2
      rc = 0;
#else
      rc = zo_bzip (&s, (int)settings->levels[id]);
#endif

      break;

    case 15:
#ifndef ZO_BUILD_LZMA
      rc = 0;
#else
      rc = zo_xz_lzma (&s, 0, settings->levels[id]);
#endif

      break;

    case 16:
#ifndef ZO_BUILD_ZSTD
      rc = 0;
#else
      rc = zo_zstd (&s, (int)settings->levels[id]);
#endif

      break;

    case 17:
#ifndef ZO_BUILD_LZMA
      rc = 0;
#else
      rc = zo_xz_lzma (&s, 1, settings->levels[id]);
#endif

      break;

    case 18:
      rc = zo_ppmd (&s, settings->levels[id]);

      break;

    case 19:
#ifdef ZO_WITH_WAVPACK
      {
        zo_u64 wavpack_size = 0;
        int wr = zo_wavpack_encode(in, out, &wavpack_size,
                                   settings->wavpack_level,
                                   settings->wavpack_extra_level);
        if (wr < 0) return ZO_COMPRESS_FATAL;
        if (wr > 0) s.written = wavpack_size;
        rc = wr > 0;
      }
#else
      rc = 0;
#endif
      break;

    default:
      rc = 0;

      break;
    }

  /* An incomplete candidate must never hide a failed read or write.
   * Report those failures even if the codec also reported failure. */
  if (s.io_failed || ferror (in) || ferror (out))
    {
      return ZO_COMPRESS_FATAL;
    }

  if (!rc || s.failed)
    {
      return ZO_COMPRESS_FAILED;
    }

  if (fflush (out) != 0)
    {
      return ZO_COMPRESS_FATAL;
    }

  *compressed = s.written;

  return ZO_COMPRESS_OK;
}
