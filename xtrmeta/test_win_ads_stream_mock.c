/* SPDX-License-Identifier: MIT-0 */
#define _WIN32 1
#include "mock_ads_win/windows.h"
#include "xtrwin_ads_stream.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
static unsigned checks, failures, mode, calls, closed, reads;
static unsigned long position;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          failures++;                                                         \
          fprintf (stderr, "fail line %d\n", __LINE__);                       \
        }                                                                     \
    }                                                                         \
  while (0)
static const wchar_t base[] = L"\\\\?\\C:\\temporary\\owner.bin";
int
GetFileInformationByHandle (HANDLE h, BY_HANDLE_FILE_INFORMATION *out)
{
  memset (out, 0, sizeof (*out));
  out->dwVolumeSerialNumber = 123;
  out->nFileIndexLow = mode == 1U && h == (HANDLE)2 ? 88U : 77U;
  if (mode == 2U && h == (HANDLE)3)
    {
      out->dwFileAttributes = FILE_ATTRIBUTE_REPARSE_POINT;
    }

  if (mode == 7U && h == (HANDLE)1 && reads)
    {
      out->nFileIndexLow = 99U;
    }

  return 1;
}
DWORD
GetFinalPathNameByHandleW (HANDLE h, wchar_t *out, DWORD cap, DWORD flags)
{
  DWORD len = (DWORD)(sizeof (base) / sizeof (base[0]) - 1U);

  (void)h;
  (void)flags;
  if (!out)
    {
      return len + 1U;
    }

  if (cap <= len)
    {
      return len + 1U;
    }

  memcpy (out, base, sizeof (base));
  return len;
}
HANDLE
CreateFileW (const wchar_t *name, DWORD access, DWORD share, void *sa,
             DWORD disp, DWORD flags, HANDLE template)
{
  (void)share;
  (void)sa;
  (void)template;
  calls++;
  if (disp != OPEN_EXISTING || !(flags & FILE_FLAG_OPEN_REPARSE_POINT))
    {
      return INVALID_HANDLE_VALUE;
    }

  if (calls == 1U)
    {
      if (wcscmp (name, base) || access != FILE_READ_ATTRIBUTES
          || !(flags & FILE_FLAG_BACKUP_SEMANTICS))
        {
          return INVALID_HANDLE_VALUE;
        }

      return (HANDLE)2;
    }

  if (calls == 2U)
    {
      if (wcscmp (name, L"\\\\?\\C:\\temporary\\owner.bin:memo:$DATA")
          || access != GENERIC_READ)
        {
          return INVALID_HANDLE_VALUE;
        }

      return (HANDLE)3;
    }

  return INVALID_HANDLE_VALUE;
}
int
GetFileSizeEx (HANDLE h, LARGE_INTEGER *size)
{
  (void)h;
  size->HighPart = 0;
  size->LowPart = mode == 3U ? 131073UL : 131072UL;
  size->QuadPart = (long)size->LowPart;
  return 1;
}
int
ReadFile (HANDLE h, void *buffer, DWORD want, DWORD *got, void *overlapped)
{
  size_t i;

  (void)h;
  (void)overlapped;
  reads++;
  if (mode == 4U && reads == 3U)
    {
      return 0;
    }

  if (mode == 5U && reads == 3U)
    {
      *got = 0;
      return 1;
    }

  if (position >= 131072UL)
    {
      if (mode == 6U)
        {
          ((unsigned char *)buffer)[0] = 1;
          *got = 1;
          return 1;
        }

      *got = 0;
      return 1;
    }

  if (want > 131072UL - position)
    {
      want = 131072UL - position;
    }

  for (i = 0; i < (size_t)want; i++)
    {
      ((unsigned char *)buffer)[i]
          = (unsigned char)((position + i) * 31UL + 7UL);
    }

  position += want;
  *got = want;
  return 1;
}
int
CloseHandle (HANDLE h)
{
  (void)h;
  closed++;
  return 1;
}
static int
collect (void *ctx, const unsigned char *buffer, size_t len)
{
  size_t i;
  unsigned long *at = (unsigned long *)ctx;

  if (mode == 8U)
    {
      return 1;
    }

  for (i = 0; i < len; i++)
    {
      if (buffer[i] != (unsigned char)((*at + i) * 31UL + 7UL))
        {
          return 1;
        }
    }

  *at += (unsigned long)len;
  return 0;
}
static void
reset (unsigned value)
{
  mode = value;
  calls = 0;
  closed = 0;
  reads = 0;
  position = 0;
}
int
main (void)
{
  unsigned short sample[]
      = { ':', 'm', 'e', 'm', 'o', ':', '$', 'D', 'A', 'T', 'A' };
  xtr_ads_name name;
  unsigned long consumed = 0;

  CHECK (xtr_ads_parse_stream (sample, sizeof (sample) / sizeof (sample[0]),
                               &name)
         == XTR_ADS_OK);
  reset (0);
  consumed = 0;
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         == 0);
  CHECK (consumed == 131072UL && position == 131072UL);
  CHECK (closed == 2U && calls == 2U);
  reset (1);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (2);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (3);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (4);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (5);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (6);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (7);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (8);
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         != 0);
  reset (0);
  name.utf8[0] = 'X';
  CHECK (xtr_win_ads_read_stream ((HANDLE)1, &name, 0, 131072UL, collect,
                                  &consumed)
         == 2);
  CHECK (calls == 0U);
  printf ("Windows ADS native stream mock: %u checks, %u failures\n", checks,
          failures);
  return failures ? 1 : 0;
}
