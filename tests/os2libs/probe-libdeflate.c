#include <libdeflate.h>

int
main (void)
{
  struct libdeflate_compressor *c;
  struct libdeflate_decompressor *d;

  c = libdeflate_alloc_compressor (6);
  d = libdeflate_alloc_decompressor ();

  if (c)
    {
      libdeflate_free_compressor (c);
    }

  if (d)
    {
      libdeflate_free_decompressor (d);
    }

  return c == 0 || d == 0;
}
