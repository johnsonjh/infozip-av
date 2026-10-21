/* Compile/link only: cover the streaming interfaces used for methods 20/93. */

#include <zstd.h>

int
main (void)
{
  ZSTD_CStream *c = ZSTD_createCStream ();
  ZSTD_DStream *d = ZSTD_createDStream ();
  ZSTD_inBuffer in;
  ZSTD_outBuffer out;
  size_t r;

  in.src = 0;
  in.size = 0;
  in.pos = 0;
  out.dst = 0;
  out.size = 0;
  out.pos = 0;
  r = ZSTD_CCtx_setParameter (c, ZSTD_c_compressionLevel, 1);
  r = ZSTD_CCtx_setPledgedSrcSize (c, 0);
  r = ZSTD_compressStream2 (c, &out, &in, ZSTD_e_end);
  r = ZSTD_decompressStream (d, &out, &in);
  (void)ZSTD_freeCStream (c);
  (void)ZSTD_freeDStream (d);
  return ZSTD_versionNumber () == 0 || ZSTD_versionString () == 0
         || (ZSTD_isError (r) && r == 0);
}
