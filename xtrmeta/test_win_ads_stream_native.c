/* SPDX-License-Identifier: MIT-0 */
/* Real NTFS, disposable file, verifies byte-exact streaming beyond 64 KiB. */
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN 1
#endif /* ifndef WIN32_LEAN_AND_MEAN */
#include "xtrwin_ads_stream.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
typedef struct test_state
{
  unsigned long consumed;
  unsigned long length;
  int bad;
} test_state;
static int
on_chunk (void *ctx, const unsigned char *bytes, size_t n)
{
  test_state *s = (test_state *)ctx;
  size_t i;

  for (i = 0; i < n; i++)
    {
      if (bytes[i] != (unsigned char)((s->consumed + i) * 31UL + 7UL))
        {
          s->bad = 1;
        }
    }

  s->consumed += (unsigned long)n;
  return s->bad;
}
static int
create_stream (const wchar_t *path, unsigned long len)
{
  HANDLE h
      = CreateFileW (path, GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  unsigned char buf[4096];
  unsigned long pos = 0;
  DWORD got;
  unsigned i, n;

  if (h == INVALID_HANDLE_VALUE)
    {
      return 0;
    }

  while (pos < len)
    {
      n = (unsigned)((len - pos) > sizeof (buf) ? sizeof (buf) : (len - pos));
      for (i = 0; i < n; i++)
        {
          buf[i] = (unsigned char)((pos + i) * 31UL + 7UL);
        }

      if (!WriteFile (h, buf, n, &got, NULL) || got != n)
        {
          CloseHandle (h);
          return 0;
        }

      pos += n;
    }
  CloseHandle (h);
  return 1;
}
int
main (void)
{
  wchar_t temp[MAX_PATH + 1], path[MAX_PATH + 1], stream[MAX_PATH + 40];
  unsigned short raw[] = { ':', 0x96ea, ':', '$', 'D', 'A', 'T', 'A' };
  xtr_ads_name name;
  HANDLE pinned = INVALID_HANDLE_VALUE;
  test_state state;
  DWORD dirlen;
  int rc = 1;

  dirlen = GetCurrentDirectoryW (MAX_PATH, temp);
  if (!dirlen || dirlen >= MAX_PATH
      || !GetTempFileNameW (temp, L"ads", 0, path))
    {
      return 1;
    }

  if (wcslen (path) + 10U >= sizeof (stream) / sizeof (stream[0]))
    {
      goto cleanup;
    }

  wcscpy (stream, path);
  wcscat (stream, L":\x96ea:$DATA");
  if (!create_stream (stream, 2097152UL))
    {
      fprintf (stderr, "SKIP: named streams unavailable on test filesystem\n");
      rc = 77;
      goto cleanup;
    }

  pinned
      = CreateFileW (path, FILE_READ_ATTRIBUTES,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (pinned == INVALID_HANDLE_VALUE
      || xtr_ads_parse_stream (raw, sizeof (raw) / sizeof (raw[0]), &name)
             != XTR_ADS_OK)
    {
      goto cleanup;
    }

  memset (&state, 0, sizeof (state));
  if (xtr_win_ads_read_stream (pinned, &name, 0, 2097152UL, on_chunk, &state)
          != 0
      || state.bad || state.consumed != 2097152UL)
    {
      fprintf (stderr, "FAIL: ADS streaming integrity or identity\n");
      goto cleanup;
    }

  memset (&state, 0, sizeof (state));
  if (xtr_win_ads_read_stream (pinned, &name, 0, 2097151UL, on_chunk, &state)
      == 0)
    {
      fprintf (stderr, "FAIL: mismatched stream size accepted\n");
      goto cleanup;
    }

  printf ("PASS: NATIVE WINDOWS ADS streaming; Unicode stream; 2 MiB byte "
          "exact; size mismatch rejected\n");
  rc = 0;
cleanup:
  if (pinned != INVALID_HANDLE_VALUE)
    {
      CloseHandle (pinned);
    }

  DeleteFileW (path);
  return rc;
}
