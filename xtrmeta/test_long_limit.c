/* MIT-0. Synthetic >4 GiB limits must not truncate on C89/32-bit hosts. */
#include "xtrv1.h"
#include <stdio.h>
#include <string.h>
static int checks = 0, failures = 0, outputs = 0;
#define C(x)                                                                  \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL %d %s\n", __LINE__, #x);                     \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)
static int
sinkwrite (void *c, const unsigned char *b, size_t n)
{
  (void)c;
  (void)b;
  outputs++;
  return n ? 0 : 0;
}
static size_t
early_eof (void *c, unsigned char *b, size_t n)
{
  (void)c;
  (void)b;
  (void)n;
  return 0;
}
int
main (void)
{
  xtr1_policy p;
  xtr1_sink s;
  xtr1_source v;
  xtr1_digest d;
  unsigned char owner[16], tlv[10];

  memset (&p, 0, sizeof (p));
  memset (&v, 0, sizeof (v));
  memset (owner, 0x7d, 16);
  p.max_records = 100;
  p.max_field = 1024;
  p.max_manifest.lo = 0xffffffffUL;
  s.write = sinkwrite;
  s.context = 0;
  tlv[0] = 1;
  tlv[1] = 0;
  tlv[2] = 0;
  tlv[3] = 0;
  tlv[4] = 2;
  tlv[5] = 0;
  tlv[6] = 0;
  tlv[7] = 0;
  tlv[8] = 1;
  tlv[9] = 0;
  v.record.type = 1;
  v.record.origin = 1;
  v.record.name_len = 4;
  v.record.native_len = 10;
  v.record.value_len.hi = 1;
  v.record.value_len.lo = 4096;
  v.name = (const unsigned char *)"name";
  v.native = tlv;
  v.read_value = early_eof;
  C (xtr1_write_manifest (owner, &v, 1, 0, &p, &s, &d) == XTR_LIMIT);
  C (outputs == 0); /* Never publish after a predictable size failure. */
  p.max_manifest.hi = 2;
  C (xtr1_write_manifest (owner, &v, 1, 0, &p, &s, &d) == XTR_IO);
  C (outputs > 0); /* Unpredictable I/O failures require M2 staging. */
  printf ("synthetic 64-bit bounds: %d assertions, %d failures\n", checks,
          failures);
  return failures != 0;
}
