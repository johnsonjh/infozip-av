/* SPDX-License-Identifier: MIT-0 */
/* Native OS/2 EA value -> canonical Xtro V1 manifest -> digest verification.
 */
#include "xtros2_ea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct memio
{
  unsigned char b[2048];
  size_t used, pos;
} memio;
static int
writecb (void *p, const unsigned char *b, size_t n)
{
  memio *m = (memio *)p;

  if (n > sizeof (m->b) - m->used)
    {
      return 1;
    }

  memcpy (m->b + m->used, b, n);
  m->used += n;
  return 0;
}
static size_t
readcb (void *p, unsigned char *b, size_t n)
{
  memio *m = (memio *)p;
  size_t want = m->used - m->pos;

  if (n > want)
    {
      n = want;
    }

  if (n)
    {
      memcpy (b, m->b + m->pos, n);
    }

  m->pos += n;
  return n;
}
static void
require (int ok, const char *msg)
{
  if (!ok)
    {
      fprintf (stderr, "FAIL: %s\n", msg);
      exit (1);
    }
}
int
main (void)
{
  static const unsigned char id[16]
      = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  static const unsigned char name[] = { '.', 'E', 'A' };
  static const unsigned char value[] = { 0xff, 0xfd, 0x02, 0x00, 'A', 0 };
  xtr_os2_ea_item item;
  xtr_os2_ea_source s;
  xtr1_policy p;
  xtr1_digest dig, other;
  xtr_extra outer;
  xtr1_sink sink;
  xtr_reader rdr;
  memio io;

  memset (&p, 0, sizeof (p));
  p.max_records = 16;
  p.max_field = 65536UL;
  p.max_manifest.lo = 1024UL * 1024UL;
  memset (&item, 0, sizeof (item));
  item.name = name;
  item.name_len = sizeof (name);
  item.value = value;
  item.value_len = sizeof (value);
  item.flags = 0x80;
  require (xtr_os2_ea_source_init (&s, &item) == 0, "prepare source");
  memset (&io, 0, sizeof (io));
  sink.write = writecb;
  sink.context = &io;
  require (xtr1_write_manifest (id, &s.source, 1, 0, &p, &sink, &dig)
               == XTR_OK,
           "canonical OS/2 manifest creation");
  require (dig.schema_supported && dig.count == 1U, "recognized interface 10");
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, id, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  memset (&rdr, 0, sizeof (rdr));
  rdr.context = &io;
  rdr.read = readcb;
  require (xtr1_check_manifest (&rdr, dig.manifest_length, &outer, dig.sha256,
                                &p, &other)
               == XTR_OK,
           "full digest verification");
  require (other.schema_supported, "native OS/2 payload recognized");
  io.pos = 0;
  io.b[io.used - 1] ^= 1U;
  require (xtr1_check_manifest (&rdr, dig.manifest_length, &outer, dig.sha256,
                                &p, &other)
               == XTR_CORRUPT,
           "tamper detection");
  /* Encrypted transport has XTCS internal: the generic verifier checks it
   * after the ZIP codec has authenticated/decrypted the companion. */
  io.used = io.pos = 0;
  s.position = 0;
  require (xtr1_write_manifest (id, &s.source, 1, 1, &p, &sink, &dig)
               == XTR_OK,
           "XTCS generation");
  require (io.used == dig.manifest_length.lo + 36UL, "XTCS length");
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, id, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.flags = XTR_V1_ENCRYPTED;
  io.pos = 0;
  {
    xtr_u64 enc_len = dig.manifest_length;
    enc_len.lo += 36;
    require (xtr1_check_manifest (&rdr, enc_len, &outer, NULL, &p, &other)
                 == XTR_OK,
             "XTCS digest validation");
  }
  puts ("OS/2 -> Xtro V1 manifest and encrypted XTCS verification: PASS");
  return 0;
}
