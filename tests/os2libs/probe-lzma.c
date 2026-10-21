/* Compile/link only: the native OS/2 executable is never run on Linux.
 * Exercise every liblzma symbol consumed by Xtro-ZIP's method 14/95/96
 * implementations, not merely the easy-encoder convenience API. */

#include <lzma.h>
int
main (void)
{
  lzma_stream e = LZMA_STREAM_INIT;
  lzma_stream d = LZMA_STREAM_INIT;
  lzma_options_lzma opt;
  lzma_filter filters[2];
  uint32_t n = 0;
  uint8_t props[16];
  lzma_ret r;

  r = lzma_easy_encoder (&e, 1, LZMA_CHECK_CRC32);
  r = lzma_stream_decoder (&d, 1024 * 1024, 0);
  (void)lzma_lzma_preset (&opt, 1);
  lzma_set_ext_size (opt, 0);
  filters[0].id = LZMA_FILTER_LZMA1EXT;
  filters[0].options = &opt;
  filters[1].id = LZMA_VLI_UNKNOWN;
  filters[1].options = 0;
  r = lzma_properties_size (&n, &filters[0]);
  r = lzma_properties_encode (&filters[0], props);
  r = lzma_properties_decode (&filters[0], 0, props, 5);
  r = lzma_raw_encoder (&e, filters);
  r = lzma_raw_decoder (&d, filters);
  r = lzma_code (&d, LZMA_RUN);
  lzma_end (&e);
  lzma_end (&d);
  return lzma_version_number () == 0 || lzma_version_string () == 0
         || (int)r == -1;
}
