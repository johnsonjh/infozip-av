/* SPDX-License-Identifier: MIT-0 */
/* Native Windows disposable-file stream enumeration acceptance. */
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN 1
#endif /* ifndef WIN32_LEAN_AND_MEAN */
#include "xtrwin_ads_native.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
typedef struct state
{
  unsigned found, unicode, wrong;
} state;
static int
visit (void *ctx, const xtr_ads_name *n, unsigned long hi, unsigned long lo)
{
  state *s = (state *)ctx;

  if (n->utf8_len == 4U && !memcmp (n->utf8, "memo", 4U))
    {
      if (hi || lo != 131072UL)
        {
          s->wrong++;
        }

      s->found++;
    }
  else if (n->utf8_len == 3U && n->utf8[0] == 0xe9U && n->utf8[1] == 0x9bU
           && n->utf8[2] == 0xaaU)
    {
      if (hi || lo != 5UL)
        {
          s->wrong++;
        }

      s->unicode++;
    }
  else
    {
      s->wrong++;
    }

  return 0;
}
int
main (void)
{
  wchar_t path[MAX_PATH + 1], stream[MAX_PATH + 30], directory[MAX_PATH + 1];
  unsigned char block[4096];
  unsigned i;
  DWORD got = 0, n;
  HANDLE h = INVALID_HANDLE_VALUE, v = INVALID_HANDLE_VALUE;
  static const char payload[] = "hello";
  state s;
  int rc = 1, test;

  memset (&s, 0, sizeof (s));
  n = GetCurrentDirectoryW (MAX_PATH, directory);
  if (!n || n >= MAX_PATH || !GetTempFileNameW (directory, L"xas", 0, path))
    {
      fprintf (stderr, "FAIL: temporary path\n");
      return 1;
    }

  if (wcslen (path) + 12U >= sizeof (stream) / sizeof (stream[0]))
    {
      goto done;
    }

  wcscpy (stream, path);
  wcscat (stream, L":memo:$DATA");
  v = CreateFileW (stream, GENERIC_WRITE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (v == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, "SKIP: NTFS named stream creation unsupported (%lu)\n",
               (unsigned long)GetLastError ());
      rc = 77;
      goto done;
    }

  memset (block, 0xa5, sizeof (block));
  for (i = 0; i < 32U; i++)
    {
      if (!WriteFile (v, block, sizeof (block), &got, NULL)
          || got != sizeof (block))
        {
          goto done;
        }
    }

  CloseHandle (v);
  v = INVALID_HANDLE_VALUE;
  wcscpy (stream, path);
  wcscat (stream, L":\x96EA:$DATA");
  v = CreateFileW (stream, GENERIC_WRITE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (v == INVALID_HANDLE_VALUE)
    {
      goto done;
    }

  if (!WriteFile (v, payload, 5U, &got, NULL) || got != 5U)
    {
      goto done;
    }

  CloseHandle (v);
  v = INVALID_HANDLE_VALUE;
  h = CreateFileW (path, FILE_READ_ATTRIBUTES,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE)
    {
      goto done;
    }

  test = xtr_win_ads_enumerate_handle (h, visit, &s);
  if (test == 2)
    {
      fprintf (stderr, "SKIP: stream enumeration unsupported\n");
      rc = 77;
      goto done;
    }

  if (test != 0 || s.found != 1U || s.unicode != 1U || s.wrong)
    {
      fprintf (stderr,
               "FAIL: enumeration rc=%d found=%u unicode=%u wrong=%u\n", test,
               s.found, s.unicode, s.wrong);
      goto done;
    }

  printf ("PASS: NATIVE WINDOWS ADS enumeration; 2 named $DATA streams; 128 "
          "KiB and Unicode\n");
  rc = 0;
done:
  if (v != INVALID_HANDLE_VALUE)
    {
      CloseHandle (v);
    }

  if (h != INVALID_HANDLE_VALUE)
    {
      CloseHandle (h);
    }

  DeleteFileW (path);
  return rc;
}
