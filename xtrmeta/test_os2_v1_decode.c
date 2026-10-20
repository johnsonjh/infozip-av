/* SPDX-License-Identifier: MIT-0 */
/* End-to-end OS/2 EA record encode / in-memory decode and tamper regressions.
 */
#include "xtros2_decode.h"
#include "xtros2_ea.h"
#include "xtros2_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void
require (int ok, const char *why)
{
  if (!ok)
    {
      fprintf (stderr, "FAIL: %s\n", why);
      exit (1);
    }
}
static int
name_equal (const unsigned char *a, size_t n, const unsigned char *b, size_t m,
            void *context)
{
  size_t i;

  (void)context;
  if (n != m)
    {
      return 0;
    }

  for (i = 0; i < n; i++)
    {
      unsigned x = a[i], y = b[i];
      if (x >= 'a' && x <= 'z')
        {
          x -= 32U;
        }

      if (y >= 'a' && y <= 'z')
        {
          y -= 32U;
        }

      if (x != y)
        {
          return 0;
        }
    }

  return 1;
}
static void
make_test (int encrypted)
{
  static const unsigned char id[16]
      = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53 };
  static const unsigned char name[] = "SYMLINK";
  static const unsigned char val[]
      = { 0xfd, 0xff, 7, 0, 'a', '/', 'b', '/', 'c', '/', 'd' };
  xtr_os2_ea_item item, output_item;
  xtr_os2_ea_source source;
  xtr_os2_memory mem;
  xtr1_sink sink;
  xtr1_digest digest;
  xtr1_policy policy;
  xtr_extra outer;
  unsigned char *native = NULL;
  size_t native_len = 0, count = 0;
  int rc;

  memset (&item, 0, sizeof (item));
  item.name = name;
  item.name_len = sizeof (name) - 1U;
  item.value = val;
  item.value_len = sizeof (val);
  item.flags = 0x80U;
  require (xtr_os2_ea_source_init (&source, &item) == 0, "native TLV");
  memset (&policy, 0, sizeof (policy));
  policy.max_records = 64;
  policy.max_field = 65536UL;
  policy.max_manifest.lo = 1024UL * 1024UL;
  xtr_os2_memory_init (&mem, 1024U * 1024U);
  sink.context = &mem;
  sink.write = xtr_os2_memory_write;
  require (xtr1_write_manifest (id, &source.source, 1, encrypted, &policy,
                                &sink, &digest)
               == XTR_OK,
           "serialize");
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, id, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.flags = encrypted ? XTR_V1_ENCRYPTED : 0U;
  if (!encrypted)
    {
      outer.count = digest.count;
      outer.manifest_len = digest.manifest_length;
      outer.crc32 = digest.crc32;
    }

  rc = xtr_os2_decode_manifest (mem.bytes, mem.length, &outer,
                                encrypted ? NULL : digest.sha256, name_equal,
                                NULL, &native, &native_len);
  require (rc == XTR_OK, "full manifest decode");
  require (xtr_os2_ea_parse_ex (native, native_len, &output_item, 1, &count,
                                name_equal, NULL)
                   == 0
               && count == 1,
           "native EA parse");
  require (output_item.name_len == item.name_len
               && memcmp (output_item.name, item.name, item.name_len) == 0
               && output_item.value_len == item.value_len
               && memcmp (output_item.value, item.value, item.value_len) == 0
               && output_item.flags == item.flags,
           "native EA byte preservation");
  free (native);
  native = NULL;
  native_len = 0;
  mem.bytes[mem.length / 2U] ^= 0x20U;
  require (xtr_os2_decode_manifest (mem.bytes, mem.length, &outer,
                                    encrypted ? NULL : digest.sha256,
                                    name_equal, NULL, &native, &native_len)
               != XTR_OK,
           "reject tampering");
  require (!native && !native_len, "reject without output");
  mem.bytes[mem.length / 2U] ^= 0x20U;
  require (xtr_os2_decode_manifest (mem.bytes, mem.length - 1U, &outer,
                                    encrypted ? NULL : digest.sha256,
                                    name_equal, NULL, &native, &native_len)
               != XTR_OK,
           "reject truncation");
  require (!native && !native_len, "no output after truncation");
  xtr_os2_memory_free (&mem);
}
int
main (void)
{
  xtr_os2_memory limited;
  unsigned char buf[4] = { 1, 2, 3, 4 };

  make_test (0);
  make_test (1);
  xtr_os2_memory_init (&limited, 3U);
  require (xtr_os2_memory_write (&limited, buf, 3U) == 0,
           "bounded memory store");
  require (xtr_os2_memory_write (&limited, buf, 1U) != 0,
           "over-capacity refusal");
  xtr_os2_memory_free (&limited);
  puts ("OS/2 V1 manifest/native EA decode, XTCS, corruption, memory quotas: "
        "PASS");
  return 0;
}
