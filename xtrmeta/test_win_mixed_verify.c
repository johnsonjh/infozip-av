/* SPDX-License-Identifier: MIT-0 */
/* Pure-host W3C2 mixed manifest verifier tests, no native NTFS claims. */
#include "xtrwin_ads_record.h"
#include "xtrwin_mixed_verify.h"
#include "xtrwin_restore_plan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned count, failed;
#define CHECK(v)                                                              \
  do                                                                          \
    {                                                                         \
      count++;                                                                \
      if (!(v))                                                               \
        {                                                                     \
          failed++;                                                           \
          fprintf (stderr, "failure at line %d\n", __LINE__);                 \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct test_bytes
{
  const unsigned char *ptr;
  size_t size, at;
} test_bytes;
static size_t
feed (void *ctx, unsigned char *out, size_t n)
{
  test_bytes *t = (test_bytes *)ctx;

  if (n > t->size - t->at)
    {
      n = t->size - t->at;
    }

  if (n)
    {
      memcpy (out, t->ptr + t->at, n);
    }

  t->at += n;
  return n;
}
static int
sink (void *ctx, const unsigned char *p, size_t n)
{
  return fwrite (p, 1, n, (FILE *)ctx) == n ? 0 : 1;
}
static unsigned char large[2U * 1024U * 1024U];
static int
exercise (int encrypted, int flags, int invalid, int duplicate, int empty)
{
  static const unsigned char owner[16] = { 1, 2, 3, 4 };
  static const unsigned char value[] = { 'a', 'b', 'c' };
  static const unsigned char ns[] = { 'n', 't' };
  static const unsigned char ea_name[] = { 'T', 'E', 'S', 'T' };
  static const unsigned short stream_utf16[] = { 's', 'n', 'o', 'w', 0x96eaU };
  xtr_ads_name stream;
  xtr1_source sources[3];
  xtr1_digest digest;
  xtr1_sink writer;
  xtr1_policy policy;
  xtr_extra outer;
  xtr_win_mixed_summary summary;
  unsigned char ea_tlv[19], ads_tlv[22], ads_tlv2[22];
  test_bytes contents[3];
  unsigned short stream_raw[13];
  size_t i;
  xtr_u64 value_length;
  FILE *f = tmpfile ();
  int rc;

  if (!f)
    {
      return 1;
    }

  memset (sources, 0, sizeof (sources));
  memset (contents, 0, sizeof (contents));
  memset (ea_tlv, 0, sizeof (ea_tlv));
  ea_tlv[0] = 1;
  ea_tlv[4] = 2;
  ea_tlv[8] = 8;
  ea_tlv[10] = 3;
  ea_tlv[14] = 1;
  ea_tlv[18] = (unsigned char)flags;
  if (invalid == 1)
    {
      ea_tlv[8] = 9;
    }

  sources[0].record.type = 1;
  sources[0].record.origin = 7;
  sources[0].record.ns_len = 2;
  sources[0].record.name_len = 4;
  sources[0].record.native_len = 19;
  sources[0].record.value_len.lo = empty ? 0UL : 3UL;
  sources[0].ns = ns;
  sources[0].name = ea_name;
  sources[0].native = ea_tlv;
  contents[0].ptr = value;
  contents[0].size = empty ? 0U : 3U;
  sources[0].read_value = feed;
  sources[0].value_context = &contents[0];
  stream_raw[0] = ':';
  for (i = 0; i < 5U; i++)
    {
      stream_raw[i + 1U] = stream_utf16[i];
    }

  stream_raw[6] = ':';
  stream_raw[7] = '$';
  stream_raw[8] = 'D';
  stream_raw[9] = 'A';
  stream_raw[10] = 'T';
  stream_raw[11] = 'A';
  CHECK (xtr_ads_parse_stream (stream_raw, 12U, &stream) == XTR_ADS_OK);
  contents[1].ptr = large;
  contents[1].size = sizeof (large);
  value_length.lo = (unsigned long)sizeof (large);
  value_length.hi = 0;
  CHECK (xtr_ads_record_source (&stream, value_length, feed, &contents[1],
                                &sources[1], ads_tlv)
         == XTR_OK);
  if (invalid == 2)
    {
      ads_tlv[18] = 0x90;
    }

  if (invalid == 3)
    {
      sources[1].record.origin = 1;
    }

  if (duplicate)
    {
      contents[2].ptr = large;
      contents[2].size = 0;
      value_length.lo = 0;
      CHECK (xtr_ads_record_source (&stream, value_length, feed, &contents[2],
                                    &sources[2], ads_tlv2)
             == XTR_OK);
    }

  memset (&policy, 0, sizeof (policy));
  policy.max_records = 1024;
  policy.max_field = 1024UL * 1024UL;
  policy.max_manifest.lo = 32UL * 1024UL * 1024UL;
  writer.context = f;
  writer.write = sink;
  rc = xtr1_write_manifest (owner, sources, duplicate ? 3U : 2U, encrypted,
                            &policy, &writer, &digest);
  if (rc != XTR_OK)
    {
      fclose (f);
      return duplicate ? 0 : 1;
    }

  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, owner, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.flags = encrypted ? XTR_V1_ENCRYPTED : 0;
  if (!encrypted)
    {
      outer.count = digest.count;
      outer.crc32 = digest.crc32;
      outer.manifest_len = digest.manifest_length;
    }

  value_length = digest.manifest_length;
  if (encrypted)
    {
      value_length.lo += 36UL;
    }

  rc = xtr_win_mixed_verify (f, value_length, &outer,
                             encrypted ? NULL : digest.sha256, &summary);
  if (invalid || duplicate || flags == 4)
    {
      CHECK (rc != XTR_OK);
    }
  else
    {
      CHECK (rc == XTR_OK);
      CHECK (summary.ea_count == 1UL);
      CHECK (summary.ads_count == 1UL);
      CHECK (summary.ea_bytes.lo == (empty ? 0UL : 3UL));
      CHECK (summary.ads_bytes.lo == (unsigned long)sizeof (large));
      CHECK (summary.has_zero_ea == (unsigned)empty);
      {
        xtr_win_restore_plan p;
        unsigned mode;
        for (mode = 1U; mode <= 3U; mode++)
          {
            CHECK (xtr_win_restore_plan_load (f, value_length, &outer,
                                              encrypted ? NULL : digest.sha256,
                                              mode, &p)
                   == XTR_OK);
            if (mode & XTR_WIN_SELECT_EA)
              {
                CHECK (p.eas.count == 1U);
                CHECK (p.eas.items[0].flags == (unsigned)flags);
                CHECK (p.eas.items[0].value_len == (empty ? 0U : 3U));
              }
            else
              {
                CHECK (p.eas.count == 0U);
              }

            if (mode & XTR_WIN_SELECT_ADS)
              {
                CHECK (p.ads_count == 1U);
                CHECK (p.ads[0].length == (unsigned long)sizeof (large));
                CHECK (p.ads[0].name.utf16_len == 5U);
                CHECK (fseek (f, p.ads[0].offset, SEEK_SET) == 0);
                {
                  unsigned char byte;
                  CHECK (fread (&byte, 1, 1, f) == 1 && byte == large[0]);
                }
              }
            else
              {
                CHECK (p.ads_count == 0U);
              }

            xtr_win_restore_plan_free (&p);
          }
      }
    }

  if (!invalid && !duplicate && flags != 4)
    {
      static const unsigned char garbage = 0x23U;
      if (fseek (f, 57L, SEEK_SET) == 0 && fwrite (&garbage, 1, 1, f) == 1)
        {
          CHECK (xtr_win_mixed_verify (f, value_length, &outer,
                                       encrypted ? NULL : digest.sha256,
                                       &summary)
                 != XTR_OK);
        }
    }

  fclose (f);
  return 0;
}
int
main (void)
{
  unsigned i;

  for (i = 0; i < sizeof (large); i++)
    {
      large[i] = (unsigned char)((i * 13U + 7U) & 255U);
    }

  CHECK (exercise (0, 0, 0, 0, 0) == 0);
  CHECK (exercise (1, 128, 0, 0, 0) == 0);
  CHECK (exercise (0, 0, 0, 0, 1) == 0);
  CHECK (exercise (0, 4, 0, 0, 0) == 0);
  CHECK (exercise (0, 128, 1, 0, 0) == 0);
  CHECK (exercise (0, 0, 2, 0, 0) == 0);
  CHECK (exercise (0, 0, 3, 0, 0) == 0);
  CHECK (exercise (0, 0, 0, 1, 0) == 0);
  printf ("Windows W3C2 mixed-manifest verification: %u checks, %u failed\n",
          count, failed);
  return failed != 0;
}
