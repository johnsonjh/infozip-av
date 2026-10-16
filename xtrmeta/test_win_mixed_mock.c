/* SPDX-License-Identifier: MIT-0 */
/* Pure host-simulated NT interfaces: no claim of native Windows support. */
#define _WIN32 1
#include "xtrv1.h"
#include "xtrwin_ads_native.h"
#include "xtrwin_ads_stream.h"
#include "xtrwin_mixed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int mode;
static unsigned mock_ea_flags = 0x80U;
static unsigned checks, failed;
#define CHECK(e)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(e))                                                               \
        {                                                                     \
          failed++;                                                           \
          fprintf (stderr, "FAIL line %d\n", __LINE__);                       \
        }                                                                     \
    }                                                                         \
  while (0)
int
CompareStringOrdinal (LPCWCH x, int nx, LPCWCH y, int ny, int ignore)
{
  int i;

  if (mode == 5)
    {
      return 0;
    }

  for (i = 0; i < nx && i < ny; i++)
    {
      unsigned a = x[i], b = y[i];
      if (ignore)
        {
          if (a >= 'a' && a <= 'z')
            {
              a -= 32;
            }

          if (b >= 'a' && b <= 'z')
            {
              b -= 32;
            }
        }

      if (a != b)
        {
          return a < b ? 1 : 3;
        }
    }

  return nx == ny ? 2 : nx < ny ? 1 : 3;
}
int
xtr_win_nt_snapshot_handle (void *handle, xtr_win_ea_list *output)
{
  xtr_win_ea *e;

  (void)handle;
  memset (output, 0, sizeof (*output));
  if (mode == 4)
    {
      return XTR_IO;
    }

  e = (xtr_win_ea *)calloc (1, sizeof (*e));
  if (!e)
    {
      return XTR_LIMIT;
    }

  e->name = (unsigned char *)malloc (5);
  e->value = (unsigned char *)malloc (3);
  if (!e->name || !e->value)
    {
      free (e->name);
      free (e->value);
      free (e);
      return XTR_LIMIT;
    }

  memcpy (e->name, "TEST", 5);
  memcpy (e->value, "abc", 3);
  e->name_len = 4;
  e->value_len = 3;
  e->flags = mock_ea_flags;
  output->items = e;
  output->count = 1;
  return XTR_OK;
}
int
xtr_win_ads_enumerate_handle (HANDLE h, xtr_ads_visit_cb visit, void *ctx)
{
  xtr_ads_name n;
  unsigned short name[]
      = { ':', 'm', 'e', 'm', 'o', ':', '$', 'D', 'A', 'T', 'A' };

  (void)h;
  if (mode == 3)
    {
      return 2;
    }

  if (xtr_ads_parse_stream (name, 11, &n) != 0)
    {
      return 1;
    }

  if (visit (ctx, &n, 0, 131072UL))
    {
      return 1;
    }

  if (mode == 2 || mode == 5)
    {
      name[1] = 'M';
      if (xtr_ads_parse_stream (name, 11, &n) != 0)
        {
          return 1;
        }

      if (visit (ctx, &n, 0, 131072UL))
        {
          return 1;
        }
    }

  return 0;
}
int
xtr_win_ads_read_stream (HANDLE h, const xtr_ads_name *name, unsigned long hi,
                         unsigned long lo, xtr_ads_bytes_cb callback,
                         void *ctx)
{
  unsigned char bytes[16384];
  unsigned long off = 0;
  unsigned i;

  (void)h;
  (void)name;
  if (mode == 1 || hi || lo != 131072UL)
    {
      return 1;
    }

  while (off < lo)
    {
      for (i = 0; i < sizeof (bytes); i++)
        {
          bytes[i] = (unsigned char)((off + i) * 19UL + 7UL);
        }

      if (callback (ctx, bytes, sizeof (bytes)))
        {
          return 1;
        }

      off += sizeof (bytes);
    }
  return 0;
}
static size_t
reader (void *p, unsigned char *b, size_t n)
{
  return fread (b, 1, n, (FILE *)p);
}
static void
verify (int both)
{
  FILE *stage = tmpfile (), *spool = tmpfile ();
  unsigned char id[16] = { 1 }, sha[32];
  xtr_extra ex;
  xtr1_policy policy;
  xtr1_digest written, checked;
  xtr_reader input;
  long length;
  int r;

  CHECK (stage != NULL && spool != NULL);
  if (!stage || !spool)
    {
      return;
    }

  r = xtr_win_mixed_capture ((void *)1, id, stage, spool, both, 0, &written);
  if (mode == 0)
    {
      CHECK (r == XTR_OK);
      CHECK (written.count == (unsigned long)(both ? 2 : 1));
      CHECK (fseek (stage, 0, SEEK_END) == 0);
      length = ftell (stage);
      CHECK (length > 131072L);
      CHECK (fseek (stage, 0, SEEK_SET) == 0);
      memset (&ex, 0, sizeof (ex));
      ex.mode = XTR_V1_COMPANION;
      memcpy (ex.owner, id, 16);
      ex.count = written.count;
      ex.crc32 = written.crc32;
      ex.manifest_len = written.manifest_length;
      memset (&policy, 0, sizeof (policy));
      policy.max_records = 1024;
      policy.max_field = 1048576;
      policy.max_manifest.lo = 32UL * 1024UL * 1024UL;
      memset (&input, 0, sizeof (input));
      input.context = stage;
      input.read = reader;
      memcpy (sha, written.sha256, 32);
      CHECK (xtr1_check_manifest (&input, written.manifest_length, &ex, sha,
                                  &policy, &checked)
             == XTR_OK);
      CHECK (checked.schema_supported == 1);
      if (both)
        {
          /* First record has namespace "nt", name "TEST", and a 19-byte
           * native TLV. Check the flags byte in the ACTUAL serializer
           * output, not only the mock snapshot input. */
          long flags_offset = 36L + 28L + 2L + 4L + 18L;
          CHECK (fseek (stage, flags_offset, SEEK_SET) == 0);
          CHECK (fgetc (stage) == (int)mock_ea_flags);
        }
    }
  else
    {
      CHECK (r != XTR_OK);
    }

  fclose (spool);
  fclose (stage);
}
static void
encrypted_test (void)
{
  FILE *stage = tmpfile (), *spool = tmpfile ();
  unsigned char id[16] = { 1 };
  xtr_extra outer;
  xtr1_policy policy;
  xtr1_digest written, checked;
  xtr_reader input;
  xtr_u64 encoded;
  int rc;

  CHECK (stage != NULL && spool != NULL);
  if (!stage || !spool)
    {
      return;
    }

  rc = xtr_win_mixed_capture ((void *)1, id, stage, spool, 1, 1, &written);
  CHECK (rc == XTR_OK && written.count == 2UL);
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, id, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.flags = XTR_V1_ENCRYPTED;
  encoded = written.manifest_length;
  encoded.lo += 36UL;
  memset (&policy, 0, sizeof (policy));
  policy.max_records = 1024UL;
  policy.max_field = 1048576UL;
  policy.max_manifest.lo = 32UL * 1024UL * 1024UL;
  memset (&input, 0, sizeof (input));
  input.context = stage;
  input.read = reader;
  CHECK (fseek (stage, 0, SEEK_SET) == 0);
  CHECK (xtr1_check_manifest (&input, encoded, &outer, NULL, &policy, &checked)
         == XTR_OK);
  CHECK (checked.count == 2UL && checked.schema_supported == 1);
  fclose (spool);
  fclose (stage);
}
int
main (void)
{
  mode = 0;
  mock_ea_flags = 0U;
  verify (1);
  mock_ea_flags = 0x80U;
  verify (1);
  verify (0);
  encrypted_test ();
  mode = 1;
  verify (1);
  mode = 2;
  verify (1);
  mode = 3;
  verify (1);
  mode = 4;
  verify (1);
  mode = 5;
  verify (1);
  printf ("Windows mixed EA/ADS manifest mock: %u checks, %u failures\n",
          checks, failed);
  return failed ? 1 : 0;
}
