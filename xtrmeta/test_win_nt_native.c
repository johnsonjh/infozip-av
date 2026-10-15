/* SPDX-License-Identifier: MIT-0 */
/* Run on real Windows NTFS; Wine may return 77 for unsupported EA syscalls.
 * Operates exclusively on a disposable file beneath the supplied directory.
 * No Zip/UnZip archive-integration claims follow from this test. */
#include "xtrwin_nt.h"
#if defined(_WIN32)
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN 1
# endif /* ifndef WIN32_LEAN_AND_MEAN */
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <windows.h>
typedef struct xwn_iosb_test
{
  union
  {
    LONG status;
    PVOID pointer;
  } u;
  ULONG_PTR information;
} xwn_iosb_test;
typedef LONG (NTAPI *xwn_set_test) (HANDLE, xwn_iosb_test *, PVOID, ULONG);
static int
seed_eas (HANDLE h, const xtr_win_ea_list *set)
{
  HMODULE dll = GetModuleHandleA ("ntdll.dll");
  FARPROC p;
  xwn_set_test fn;
  unsigned char *raw = NULL;
  size_t n = 0;
  xwn_iosb_test io;
  LONG status;

  if (!dll || sizeof (p) != sizeof (fn))
    {
      return XTR_UNSUPPORTED;
    }

  p = GetProcAddress (dll, "NtSetEaFile");
  if (!p)
    {
      return XTR_UNSUPPORTED;
    }

  memcpy (&fn, &p, sizeof (fn));
  if (xtr_win_ea_pack_set (set, &raw, &n) != XTR_OK)
    {
      return XTR_CORRUPT;
    }

  memset (&io, 0, sizeof (io));
  status = fn (h, &io, raw, (ULONG)n);
  free (raw);
  if (status)
    {
      printf ("NtSetEaFile status 0x%08lx\n", (unsigned long)(DWORD)status);
      return XTR_IO;
    }

  return XTR_OK;
}
static void
make_ea (xtr_win_ea *e, const char *name, unsigned char *value, size_t size)
{
  memset (e, 0, sizeof (*e));
  e->name = (unsigned char *)name;
  e->name_len = strlen (name);
  e->value = value;
  e->value_len = size;
}
static int
has_ea (const xtr_win_ea_list *list, const char *name,
        const unsigned char *val, size_t len)
{
  size_t i;

  for (i = 0; i < list->count; i++)
    {
      const xtr_win_ea *v = &list->items[i];
      if (v->name_len == strlen (name) && !memcmp (v->name, name, v->name_len)
          && v->value_len == len && (!len || !memcmp (v->value, val, len)))
        {
          return 1;
        }
    }

  return 0;
}
int
main (int argc, char **argv)
{
  char path[MAX_PATH + 1];
  HANDLE h = INVALID_HANDLE_VALUE;
  xtr_win_ea entries[2], desired[2], empty;
  xtr_win_ea_list initial, want, out, zeros;
  unsigned char binary[] = { 0, 255, 13, 10, 1 };
  unsigned char updated[] = { 9, 0, 3, 255 };
  unsigned char oldv = 17, one = 42, owner[16], badsha[32];
  xtr1_digest dig, dig2;
  xtr_extra outer;
  xtr_u64 n;
  FILE *stage = NULL, *capture = NULL, *empty_stage = NULL;
  int rc = 1, r, rollback = 0, is_wine, created = 0;
  size_t i;

  if (argc != 2)
    {
      fprintf (stderr,
               "usage: test_win_nt_native.exe C:\\writable-directory\n");
      return 2;
    }

  if (strlen (argv[1]) > MAX_PATH - 18U)
    {
      fprintf (stderr, "path too long\n");
      return 2;
    }

  is_wine = GetProcAddress (GetModuleHandleA ("ntdll.dll"), "wine_get_version")
            != NULL;
  if (!GetTempFileNameA (argv[1], "XWE", 0, path))
    {
      fprintf (stderr, "failed to create disposable file: %lu\n",
               (unsigned long)GetLastError ());
      return 1;
    }

  created = 1;
  h = CreateFileA (path,
                   FILE_READ_EA | FILE_WRITE_EA | GENERIC_READ | GENERIC_WRITE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, "CreateFile failed: %lu\n",
               (unsigned long)GetLastError ());
      goto done;
    }

  make_ea (&entries[0], "XTRODATA", binary, sizeof (binary));
  make_ea (&entries[1], "XTROSTALE", &oldv, 1);
  initial.items = entries;
  initial.count = 2;
  r = seed_eas (h, &initial);
  if (r != XTR_OK)
    {
      if (is_wine)
        {
          puts ("SKIP: Wine does not provide native NT EA writes");
          rc = 77;
        }
      else
        {
          puts ("FAIL: native NT EA setup");
        }

      goto done;
    }

  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1);
    }

  make_ea (&desired[0], "XTRODATA", updated, sizeof (updated));
  make_ea (&desired[1], "XTRONEW", &one, 1);
  want.items = desired;
  want.count = 2;
  stage = tmpfile ();
  if (!stage)
    {
      puts ("FAIL: tmpfile");
      goto done;
    }

  if (xtr_win_ea_to_manifest (&want, owner, stage, 0, &dig) != XTR_OK)
    {
      puts ("FAIL: write manifest");
      goto done;
    }

  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, owner, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  n = dig.manifest_length;
  memcpy (badsha, dig.sha256, 32);
  badsha[0] ^= 0x80;
  r = xtr_win_nt_restore_handle (h, stage, n, &outer, badsha, &rollback);
  if (r == XTR_OK || rollback)
    {
      puts ("FAIL: invalid SHA was accepted or altered state");
      goto done;
    }

  r = xtr_win_nt_restore_handle (h, stage, n, &outer, dig.sha256, &rollback);
  if (r != XTR_OK || rollback)
    {
      printf ("FAIL: restore returned %d rollback %d\n", r, rollback);
      goto done;
    }

  capture = tmpfile ();
  if (!capture)
    {
      puts ("FAIL: capture staging");
      goto done;
    }

  r = xtr_win_nt_capture_handle (h, owner, capture, 0, &dig2);
  if (r != XTR_OK)
    {
      printf ("FAIL: capture returned %d\n", r);
      goto done;
    }

  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, owner, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.count = dig2.count;
  outer.manifest_len = dig2.manifest_length;
  outer.crc32 = dig2.crc32;
  r = xtr_win_ea_from_manifest (capture, dig2.manifest_length, &outer,
                                dig2.sha256, &out);
  if (r != XTR_OK)
    {
      puts ("FAIL: decode recaptured EAs");
      goto done;
    }

  r = (out.count == 2 && has_ea (&out, "XTRODATA", updated, sizeof (updated))
       && has_ea (&out, "XTRONEW", &one, 1));
  xtr_win_ea_free (&out);
  if (!r)
    {
      puts ("FAIL: exact replacement or stale-EA removal");
      goto done;
    }

  make_ea (&empty, "XTROEMPTY", binary, 0);
  zeros.items = &empty;
  zeros.count = 1;
  empty_stage = tmpfile ();
  if (!empty_stage)
    {
      goto done;
    }

  if (xtr_win_ea_to_manifest (&zeros, owner, empty_stage, 0, &dig) != XTR_OK)
    {
      goto done;
    }

  outer.count = dig.count;
  outer.manifest_len = dig.manifest_length;
  outer.crc32 = dig.crc32;
  r = xtr_win_nt_restore_handle (h, empty_stage, dig.manifest_length, &outer,
                                 dig.sha256, &rollback);
  if (r != XTR_UNSUPPORTED || rollback)
    {
      puts ("FAIL: empty native EA should be rejected before mutation");
      goto done;
    }

  puts ("PASS: native NT EA handle capture, SHA refusal, exact replace, stale "
        "deletion and readback; NATIVE WINDOWS");
  rc = 0;
done:
  if (empty_stage)
    {
      fclose (empty_stage);
    }

  if (capture)
    {
      fclose (capture);
    }

  if (stage)
    {
      fclose (stage);
    }

  if (h != INVALID_HANDLE_VALUE)
    {
      CloseHandle (h);
    }

  if (created)
    {
      DeleteFileA (path);
    }

  return rc;
}
#else  /* if defined( _WIN32 ) */
int
main (void)
{
  return 77;
}
#endif /* if defined( _WIN32 ) */
