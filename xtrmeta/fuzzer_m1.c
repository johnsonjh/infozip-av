/* MIT-0. Optional LLVM libFuzzer entry point for M1 manifest validator. */

#include "xtrv1.h"
#include <string.h>

typedef struct fuzz_buf
{
  const unsigned char *data;
  size_t len, pos;
} fuzz_buf;

static size_t
read_data (void *ptr, unsigned char *out, size_t n)
{
  fuzz_buf *b = (fuzz_buf *)ptr;

  if (n > b->len - b->pos)
    {
      n = b->len - b->pos;
    }

  if (n > 31)
    {
      n = 31;
    }

  if (n)
    {
      memcpy (out, b->data + b->pos, n);
    }

  b->pos += n;
  return n;
}

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
  fuzz_buf b;
  xtr_reader source;
  xtr1_policy p;
  xtr1_digest dig;
  xtr_extra extra;
  xtr_sha256 sha;
  unsigned char digest[32];
  xtr_u64 length;

  if (size < 36 || size > 100000)
    {
      return 0;
    }

  memset (&extra, 0, sizeof (extra));
  memset (&source, 0, sizeof (source));
  memset (&p, 0, sizeof (p));
  extra.mode = 2;
  memcpy (extra.owner, data + 8, 16);
  extra.count = (unsigned long)data[24] | ((unsigned long)data[25] << 8)
                | ((unsigned long)data[26] << 16)
                | ((unsigned long)data[27] << 24);
  extra.manifest_len.lo = (unsigned long)size;
  extra.manifest_len.hi = 0;
  extra.crc32 = xtr_crc32_update (0, data, size);
  xtr_sha256_init (&sha);
  xtr_sha256_update (&sha, data, size);
  xtr_sha256_final (&sha, digest);
  p.max_records = 100;
  p.max_field = 8192;
  p.max_manifest.lo = 100000;
  p.max_manifest.hi = 0;
  b.data = data;
  b.len = size;
  b.pos = 0;
  source.context = &b;
  source.read = read_data;
  length.lo = (unsigned long)size;
  length.hi = 0;
  (void)xtr1_check_manifest (&source, length, &extra, digest, &p, &dig);
  return 0;
}
