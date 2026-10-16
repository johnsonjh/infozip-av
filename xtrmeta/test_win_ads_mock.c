/* SPDX-License-Identifier: MIT-0 */
#define _WIN32 1
#include "mock_ads_win/windows.h"
#include "xtrwin_ads_native.h"
#include <stdio.h>
#include <string.h>
static unsigned count, failed, steps, mode, found;
#define C(x)                                                                  \
  do                                                                          \
    {                                                                         \
      count++;                                                                \
      if (!(x))                                                               \
        {                                                                     \
          failed++;                                                           \
          fprintf (stderr, "fail line %d\n", __LINE__);                       \
        }                                                                     \
    }                                                                         \
  while (0)
int
GetFileInformationByHandle (HANDLE h, BY_HANDLE_FILE_INFORMATION *out)
{
  memset (out, 0, sizeof (*out));
  out->dwVolumeSerialNumber = 42;
  out->nFileIndexLow = mode == 3U && h == (HANDLE)2 ? 10U : 9U;
  if (mode == 4U)
    {
      out->dwFileAttributes = FILE_ATTRIBUTE_REPARSE_POINT;
    }

  return 1;
}
DWORD
GetFinalPathNameByHandleW (HANDLE h, wchar_t *out, DWORD n, DWORD flags)
{
  static const wchar_t path[] = L"\\\\?\\C:\\tmp\\owner.dat";
  unsigned size = (unsigned)(sizeof (path) / sizeof (path[0]) - 1U);

  (void)h;
  (void)flags;
  if (!out)
    {
      return (DWORD)(size + 1U);
    }

  if (n <= size)
    {
      return (DWORD)size;
    }

  memcpy (out, path, sizeof (path));
  return (DWORD)size;
}
HANDLE
CreateFileW (const wchar_t *p, DWORD rights, DWORD share, void *sec,
             DWORD action, DWORD flags, HANDLE tmpl)
{
  (void)p;
  (void)rights;
  (void)share;
  (void)sec;
  (void)action;
  (void)flags;
  (void)tmpl;
  return (HANDLE)2;
}
static void
set (WIN32_FIND_STREAM_DATA *out, const wchar_t *name)
{
  memset (out, 0, sizeof (*out));
  wcscpy (out->cStreamName, name);
  out->StreamSize.LowPart = 5;
}
HANDLE
FindFirstStreamW (const wchar_t *path, int info, void *data, DWORD flags)
{
  (void)path;
  (void)info;
  (void)flags;
  steps = 0;
  if (mode == 5U)
    {
      return INVALID_HANDLE_VALUE;
    }

  set ((WIN32_FIND_STREAM_DATA *)data, L"::$DATA");
  return (HANDLE)3;
}
int
FindNextStreamW (HANDLE h, void *data)
{
  (void)h;
  steps++;
  if (steps > 1)
    {
      return 0;
    }

  if (mode == 2U)
    {
      set ((WIN32_FIND_STREAM_DATA *)data, L":x:$INDEX_ALLOCATION");
    }
  else
    {
      set ((WIN32_FIND_STREAM_DATA *)data, L":memo:$DATA");
    }

  return 1;
}
int
FindClose (HANDLE h)
{
  (void)h;
  return 1;
}
int
CloseHandle (HANDLE h)
{
  (void)h;
  return 1;
}
DWORD
GetLastError (void)
{
  return mode == 5U ? ERROR_NOT_SUPPORTED : ERROR_HANDLE_EOF;
}
static int
visit (void *ctx, const xtr_ads_name *name, unsigned long hi, unsigned long lo)
{
  (void)ctx;
  if (hi != 0UL || lo != 5UL || name->utf8_len != 4U
      || memcmp (name->utf8, "memo", 4U))
    {
      return 1;
    }

  found++;
  return 0;
}
int
main (void)
{
  mode = 0;
  found = 0;
  C (xtr_win_ads_enumerate_handle ((HANDLE)1, visit, NULL) == 0);
  C (found == 1U);
  mode = 2;
  found = 0;
  C (xtr_win_ads_enumerate_handle ((HANDLE)1, visit, NULL) == 3);
  C (found == 0U);
  mode = 3;
  C (xtr_win_ads_enumerate_handle ((HANDLE)1, visit, NULL) == 1);
  mode = 4;
  C (xtr_win_ads_enumerate_handle ((HANDLE)1, visit, NULL) == 1);
  mode = 5;
  C (xtr_win_ads_enumerate_handle ((HANDLE)1, visit, NULL) == 2);
  printf ("Windows ADS native enumeration mock: %u checks, %u failures\n",
          count, failed);
  return failed ? 1 : 0;
}
