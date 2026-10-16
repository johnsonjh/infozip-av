/* SPDX-License-Identifier: MIT-0 */
/* User-owned disposable-file NT EA capability/ABI probe.
 * A Wine PASS means Wine implemented the tested ABI on this backing FS;
 * it is not evidence of native NTFS behavior. Exit 77 on unsupported API.
 * No archive transport or application of restored manifests occurs here. */
#include "xtrwin_ea.h"
#if defined(_WIN32)
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif /* ifndef WIN32_LEAN_AND_MEAN */
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <windows.h>
/* Declaring the user-mode signatures avoids requiring the NT kernel DDK. */
typedef struct xwe_iosb
{
  union
  {
    LONG status;
    PVOID pointer;
  } u;
  ULONG_PTR information;
} xwe_iosb;
typedef LONG (NTAPI *xwe_set_fn) (HANDLE, xwe_iosb *, PVOID, ULONG);
typedef LONG (NTAPI *xwe_query_fn) (HANDLE, xwe_iosb *, PVOID, ULONG, BOOLEAN,
                                    PVOID, ULONG, PULONG, BOOLEAN);
# define XWE_NO_EAS ((LONG)0xC0000052UL)
# define XWE_UNSUPPORTED ((LONG)0xC000004FUL)
# define XWE_NOT_IMPLEMENTED ((LONG)0xC0000002UL)
static void
print_status (const char *what, LONG st)
{
  printf ("%s: NTSTATUS 0x%08lx\n", what, (unsigned long)(DWORD)st);
}
int
main (int argc, char **argv)
{
  HMODULE ntdll;
  xwe_set_fn fn_set;
  xwe_query_fn fn_query;
  FARPROC proc;
  xwe_iosb io;
  HANDLE h = INVALID_HANDLE_VALUE;
  char path[MAX_PATH + 1];
  xtr_win_ea ea[2];
  xtr_win_ea_list set, list;
  unsigned char data[5] = { 0, 13, 1, 255, 45 };
  unsigned char one = 0x5a;
  unsigned char result[131072];
  unsigned char *raw = NULL;
  size_t len = 0;
  LONG status;
  UINT n;
  size_t i;
  int found_binary = 0, found_small = 0, is_wine = 0;
  int rc = 1, created = 0;

  if (argc != 2)
    {
      fprintf (stderr,
               "usage: test_win_ea_native.exe C:\\\\writable-directory\n");
      return 2;
    }

  if (strlen (argv[1]) > MAX_PATH - 18U)
    {
      fprintf (stderr, "path too long\n");
      return 2;
    }

  ntdll = GetModuleHandleA ("ntdll.dll");
  if (!ntdll)
    {
      printf ("SKIP: ntdll.dll missing\n");
      return 77;
    }

  is_wine = GetProcAddress (ntdll, "wine_get_version") != NULL;
  /* GetProcAddress returns FARPROC, not a prototype-compatible NT API
   * pointer. Copy its pointer representation under the Windows ABI rather
   * than casting incompatible function pointers (-Wcast-function-type).
   * Never copy if the function-pointer sizes differ. */
  if (sizeof (fn_set) != sizeof (proc) || sizeof (fn_query) != sizeof (proc))
    {
      fprintf (stderr, "FAIL: unsupported function-pointer representation\n");
      return 1;
    }

  proc = GetProcAddress (ntdll, "NtSetEaFile");
  if (!proc)
    {
      puts ("SKIP: NtSetEaFile entrypoint missing");
      return 77;
    }

  memcpy (&fn_set, &proc, sizeof (fn_set));
  proc = GetProcAddress (ntdll, "NtQueryEaFile");
  if (!proc)
    {
      puts ("SKIP: NtQueryEaFile entrypoint missing");
      return 77;
    }

  memcpy (&fn_query, &proc, sizeof (fn_query));
  n = GetTempFileNameA (argv[1], "XWE", 0, path);
  if (!n)
    {
      fprintf (stderr, "FAIL: cannot create test file, Win32 error %lu\n",
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
      fprintf (stderr, "FAIL: CreateFile: %lu\n",
               (unsigned long)GetLastError ());
      goto cleanup;
    }

  memset (ea, 0, sizeof (ea));
  ea[0].name = (unsigned char *)"XTROPROBE";
  ea[0].name_len = 9;
  ea[0].value = data;
  ea[0].value_len = sizeof (data);
  ea[1].name = (unsigned char *)"XTROSMALL";
  ea[1].name_len = 9;
  ea[1].value = &one;
  ea[1].value_len = 1;
  set.items = ea;
  set.count = 2;
  if (xtr_win_ea_pack_set (&set, &raw, &len) != XTR_OK)
    {
      fprintf (stderr, "FAIL: pack\n");
      goto cleanup;
    }

  memset (&io, 0, sizeof (io));
  status = fn_set (h, &io, raw, (ULONG)len);
  if (status == XWE_UNSUPPORTED || status == XWE_NOT_IMPLEMENTED
      || status == (LONG)0xC0000010UL || status == (LONG)0xC00000BBUL
      || (is_wine && status == (LONG)0xC0000022UL))
    {
      print_status ("SKIP: native EA set unsupported", status);
      rc = 77;
      goto cleanup;
    }

  if (status != 0)
    {
      print_status ("FAIL: native EA set", status);
      goto cleanup;
    }

  memset (&io, 0, sizeof (io));
  status = fn_query (h, &io, result, sizeof (result), (BOOLEAN)0, NULL, 0,
                     NULL, (BOOLEAN)1);
  if (status == XWE_UNSUPPORTED || status == XWE_NOT_IMPLEMENTED
      || status == (LONG)0xC0000010UL || status == (LONG)0xC00000BBUL
      || (is_wine && status == (LONG)0xC0000022UL))
    {
      print_status ("SKIP: native EA query unsupported", status);
      rc = 77;
      goto cleanup;
    }

  if (status != 0)
    {
      print_status ("FAIL: native EA query", status);
      goto cleanup;
    }

  if (io.information > sizeof (result) || io.information == 0)
    {
      fprintf (stderr, "FAIL: native EA invalid byte count\n");
      goto cleanup;
    }

  if (xtr_win_ea_parse (result, (size_t)io.information, &list) != XTR_OK)
    {
      fprintf (stderr, "FAIL: query returned malformed EA chain\n");
      goto cleanup;
    }

  for (i = 0; i < list.count; i++)
    {
      if (list.items[i].name_len == 9
          && !memcmp (list.items[i].name, "XTROPROBE", 9)
          && list.items[i].value_len == sizeof (data)
          && !memcmp (list.items[i].value, data, sizeof (data)))
        {
          found_binary = 1;
        }

      if (list.items[i].name_len == 9
          && !memcmp (list.items[i].name, "XTROSMALL", 9)
          && list.items[i].value_len == 1 && list.items[i].value[0] == one)
        {
          found_small = 1;
        }
    }

  if (list.count == 2 && found_binary && found_small)
    {
      printf ("PASS: NATIVE NT EA read/write; two EA records, binary and "
              "one-byte values\n");
      rc = 0;
    }
  else
    {
      fprintf (stderr, "FAIL: native EA round-trip mismatch\n");
    }

  xtr_win_ea_free (&list);
cleanup:
  free (raw);
  if (h != INVALID_HANDLE_VALUE)
    {
      CloseHandle (h);
    }

  if (created && !DeleteFileA (path))
    {
      fprintf (stderr, "FAIL: cannot remove temporary test file: %s\n", path);
      rc = 1;
    }

  return rc;
}
#else /* if defined( _WIN32 ) */
# include <stdio.h>
int
main (void)
{
  puts ("SKIP: Windows NT EA APIs unavailable");
  return 77;
}
#endif /* if defined( _WIN32 ) */
