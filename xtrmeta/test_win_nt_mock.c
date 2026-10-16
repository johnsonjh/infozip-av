/* SPDX-License-Identifier: MIT-0 */
/* Simulates Windows NT's incremental EA enumerator, including STATUS_SUCCESS
 * returning ONE record, to prevent silent loss of trailing EAs. All native
 * code is compiled under C89 using a private ABI header; no Windows host is
 * simulated or certified by this test. */
#include "mock_win32/windows.h"
#include "xtrwin_nt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long checks, failures;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #x);               \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)
#include "xtrwin_nt_abi.h"
typedef struct mock_file
{
  xtr_win_ea_list current;
  size_t cursor;
  int reparse;
  int deny_set;
  unsigned queries, sets;
} mock_file;
static int
cl (const xtr_win_ea_list *in, xtr_win_ea_list *out)
{
  unsigned char *raw = NULL;
  size_t n = 0;
  int rc = xtr_win_ea_pack (in, &raw, &n);

  if (rc == XTR_OK)
    {
      rc = xtr_win_ea_parse (raw, n, out);
    }

  free (raw);
  return rc;
}
static int
equalname (const xtr_win_ea *a, const xtr_win_ea *b)
{
  size_t i;

  if (a->name_len != b->name_len)
    {
      return 0;
    }

  for (i = 0; i < a->name_len; i++)
    {
      unsigned aa = a->name[i], bb = b->name[i];
      if (aa >= 'a' && aa <= 'z')
        {
          aa -= 32;
        }

      if (bb >= 'a' && bb <= 'z')
        {
          bb -= 32;
        }

      if (aa != bb)
        {
          return 0;
        }
    }

  return 1;
}
static LONG NTAPI
fake_query (HANDLE handle, xwn_iosb *io, PVOID buf, ULONG cap, BOOLEAN single,
            PVOID names, ULONG name_len, PULONG index, BOOLEAN restart)
{
  mock_file *f = (mock_file *)handle;
  xtr_win_ea_list one;
  unsigned char *packed = NULL;
  size_t len = 0;
  int rc;

  (void)single;
  (void)names;
  (void)name_len;
  (void)index;
  f->queries++;
  if (restart)
    {
      f->cursor = 0;
    }

  io->information = 0;
  if (!f->current.count)
    {
      return (LONG)0xC0000052UL;
    }

  if (f->cursor == f->current.count)
    {
      return (LONG)0x80000012UL;
    }

  one.items = &f->current.items[f->cursor];
  one.count = 1;
  rc = xtr_win_ea_pack (&one, &packed, &len);
  if (rc != XTR_OK)
    {
      return (LONG)0xC0000001UL;
    }

  if (len > cap)
    {
      free (packed);
      return (LONG)0x80000005UL;
    }

  memcpy (buf, packed, len);
  free (packed);
  io->information = (ULONG_PTR)len;
  f->cursor++;
  return 0;
}
static LONG NTAPI
fake_set (HANDLE handle, xwn_iosb *io, PVOID buf, ULONG size)
{
  mock_file *f = (mock_file *)handle;
  xtr_win_ea_list list, next, copy;
  xtr_win_ea *temps;
  size_t i, count;
  int rc;

  io->information = 0;
  f->sets++;
  if (f->deny_set)
    {
      return (LONG)0xC0000022UL;
    }

  if (xtr_win_ea_parse (buf, (size_t)size, &list) != XTR_OK)
    {
      return (LONG)0xC0000001UL;
    }

  if (list.count != 1U)
    {
      xtr_win_ea_free (&list);
      return (LONG)0xC0000001UL;
    }

  temps = (xtr_win_ea *)calloc (f->current.count + 1U, sizeof (*temps));
  if (!temps)
    {
      xtr_win_ea_free (&list);
      return (LONG)0xC0000017UL;
    }

  count = 0;
  for (i = 0; i < f->current.count; i++)
    {
      if (!equalname (&f->current.items[i], &list.items[0]))
        {
          temps[count++] = f->current.items[i];
        }
    }

  if (list.items[0].value_len)
    {
      temps[count++] = list.items[0];
    }

  next.items = temps;
  next.count = count;
  rc = cl (&next, &copy);
  free (temps);
  xtr_win_ea_free (&list);
  if (rc != XTR_OK)
    {
      return (LONG)0xC0000001UL;
    }

  xtr_win_ea_free (&f->current);
  f->current = copy;
  return 0;
}
HMODULE
GetModuleHandleA (const char *name)
{
  (void)name;
  return (HMODULE)1;
}
FARPROC
GetProcAddress (HMODULE dll, const char *name)
{
  FARPROC generic = NULL;
  xwn_query_fn query = fake_query;
  xwn_set_fn set = fake_set;

  (void)dll;
  if (!strcmp (name, "NtQueryEaFile"))
    {
      if (sizeof (query) == sizeof (generic))
        {
          memcpy (&generic, &query, sizeof (query));
        }
    }
  else if (!strcmp (name, "NtSetEaFile"))
    {
      if (sizeof (set) == sizeof (generic))
        {
          memcpy (&generic, &set, sizeof (set));
        }
    }

  return generic;
}
DWORD
GetFileType (HANDLE handle)
{
  (void)handle;
  return FILE_TYPE_DISK;
}
int
GetFileInformationByHandle (HANDLE h, BY_HANDLE_FILE_INFORMATION *info)
{
  mock_file *f = (mock_file *)h;

  if (!f)
    {
      return 0;
    }

  memset (info, 0, sizeof (*info));
  info->dwVolumeSerialNumber = 0x1234U;
  info->nFileIndexLow = 0xabcdU;
  info->dwFileAttributes = f->reparse ? FILE_ATTRIBUTE_REPARSE_POINT : 0U;
  return 1;
}
/* Other Windows functions occur only in the native executable test. */
static void
item (xtr_win_ea *e, const char *name, unsigned char *v, size_t n)
{
  memset (e, 0, sizeof (*e));
  e->name = (unsigned char *)name;
  e->name_len = strlen (name);
  e->value = v;
  e->value_len = n;
}
int
main (void)
{
  xtr_win_ea e[2], target[2], zero;
  xtr_win_ea_list original, desired, zlist, out;
  unsigned char a[] = { 0, 1, 255, 0 }, b[] = { 21 }, c[] = { 5, 9 },
                owner[16];
  unsigned char badsha[32];
  xtr1_digest dig;
  xtr_extra outer;
  mock_file f;
  FILE *stage, *capt;
  int rc, rb;
  size_t i;

  memset (&f, 0, sizeof (f));
  item (&e[0], "ORIGINAL", a, sizeof (a));
  item (&e[1], "STALE", b, sizeof (b));
  original.items = e;
  original.count = 2;
  CHECK (cl (&original, &f.current) == XTR_OK);
  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1);
    }

  capt = tmpfile ();
  CHECK (capt != NULL);
  if (!capt)
    {
      return 1;
    }

  rc = xtr_win_nt_capture_handle (&f, owner, capt, 0, &dig);
  CHECK (rc == XTR_OK && dig.count == 2U && f.queries == 3U);
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, owner, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  rc = xtr_win_ea_from_manifest (capt, dig.manifest_length, &outer, dig.sha256,
                                 &out);
  CHECK (rc == XTR_OK && out.count == 2U);
  if (rc == XTR_OK)
    {
      xtr_win_ea_free (&out);
    }

  item (&target[0], "ORIGINAL", c, sizeof (c));
  item (&target[1], "NEW", b, sizeof (b));
  desired.items = target;
  desired.count = 2;
  stage = tmpfile ();
  CHECK (stage != NULL);
  if (!stage)
    {
      fclose (capt);
      xtr_win_ea_free (&f.current);
      return 1;
    }

  CHECK (xtr_win_ea_to_manifest (&desired, owner, stage, 0, &dig) == XTR_OK);
  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  memcpy (badsha, dig.sha256, 32);
  badsha[0] ^= 1;
  CHECK (xtr_win_nt_restore_handle (&f, stage, dig.manifest_length, &outer,
                                    badsha, &rb)
         != XTR_OK);
  CHECK (!rb && f.sets == 0U);
  CHECK (xtr_win_nt_restore_handle (&f, stage, dig.manifest_length, &outer,
                                    dig.sha256, &rb)
         == XTR_OK);
  CHECK (!rb && f.sets == 3U && f.current.count == 2U);
  rc = xtr_win_nt_restore_handle (&f, stage, dig.manifest_length, &outer,
                                  dig.sha256, &rb);
  CHECK (rc == XTR_OK && !rb && f.sets == 3U);
  f.reparse = 1;
  CHECK (xtr_win_nt_capture_handle (&f, owner, capt, 0, &dig)
         == XTR_UNSUPPORTED);
  CHECK (xtr_win_nt_restore_handle (&f, stage, dig.manifest_length, &outer,
                                    dig.sha256, &rb)
         == XTR_UNSUPPORTED);
  f.reparse = 0;
  item (&zero, "EMPTY", a, 0);
  zlist.items = &zero;
  zlist.count = 1;
  CHECK (xtr_win_ea_to_manifest (&zlist, owner, capt, 0, &dig) == XTR_OK);
  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  CHECK (xtr_win_nt_restore_handle (&f, capt, dig.manifest_length, &outer,
                                    dig.sha256, &rb)
         == XTR_UNSUPPORTED);
  CHECK (!rb && f.sets == 3U);
  fclose (stage);
  fclose (capt);
  xtr_win_ea_free (&f.current);
  printf ("Windows NT API mocked enumeration+capture+restore: %lu checks; %lu "
          "failed\n",
          checks, failures);
  return failures ? 1 : 0;
}
