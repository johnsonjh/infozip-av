/* SPDX-License-Identifier: MIT-0 */
/* Host simulation for W3C2A ADS creation; never certifies real NTFS. */
#define _WIN32 1
#include "xtrwin_ads_write.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, failed;
#define CHECK(e)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(e))                                                               \
        {                                                                     \
          failed++;                                                           \
          fprintf (stderr, "fail line %d\n", __LINE__);                       \
        }                                                                     \
    }                                                                         \
  while (0)
static unsigned char store[2U * 1024U * 1024U];
static unsigned long length, pos;
static int exists, fail_write, fail_delete, delete_count, create_count;
static HANDLE h_owner = (HANDLE)1, h_base = (HANDLE)2, h_stream = (HANDLE)3;
static unsigned long owner_id = 123UL;
int
GetFileInformationByHandle (HANDLE h, BY_HANDLE_FILE_INFORMATION *info)
{
  if (h != h_owner && h != h_base && h != h_stream)
    {
      return 0;
    }

  memset (info, 0, sizeof (*info));
  info->nFileIndexLow = owner_id;
  info->dwVolumeSerialNumber = 5U;
  return 1;
}
DWORD
GetFinalPathNameByHandleW (HANDLE h, wchar_t *p, DWORD len, DWORD flags)
{
  static const wchar_t path[] = L"C:\\owner.bin";
  DWORD n = (DWORD)(sizeof (path) / sizeof (path[0]) - 1U);

  (void)flags;
  if (h != h_owner)
    {
      return 0;
    }

  if (!p)
    {
      return n + 1U;
    }

  if (len < n + 1U)
    {
      return n + 1U;
    }

  memcpy (p, path, (n + 1U) * sizeof (*p));
  return n;
}
HANDLE
CreateFileW (const wchar_t *p, DWORD rights, DWORD share, void *sec,
             DWORD disp, DWORD attrs, HANDLE template_file)
{
  (void)rights;
  (void)share;
  (void)sec;
  (void)attrs;
  (void)template_file;
  if (disp == OPEN_EXISTING && wcscmp (p, L"C:\\owner.bin") == 0)
    {
      return h_base;
    }

  if (disp == CREATE_NEW && wcsstr (p, L":$DATA") != NULL)
    {
      create_count++;
      if (exists)
        {
          return INVALID_HANDLE_VALUE;
        }

      exists = 1;
      length = 0;
      pos = 0;
      return h_stream;
    }

  return INVALID_HANDLE_VALUE;
}
int
CloseHandle (HANDLE h)
{
  return h == h_base || h == h_stream;
}
int
WriteFile (HANDLE h, const void *p, DWORD n, DWORD *written, void *async)
{
  (void)async;
  if (h != h_stream || fail_write || length + n > sizeof (store))
    {
      return 0;
    }

  memcpy (store + length, p, n);
  length += n;
  pos = length;
  *written = n;
  return 1;
}
int
ReadFile (HANDLE h, void *p, DWORD n, DWORD *got, void *async)
{
  (void)async;
  if (h != h_stream)
    {
      return 0;
    }

  if (n > length - pos)
    {
      n = (DWORD)(length - pos);
    }

  if (n)
    {
      memcpy (p, store + pos, n);
    }

  pos += n;
  *got = n;
  return 1;
}
int
FlushFileBuffers (HANDLE h)
{
  return h == h_stream;
}
int
GetFileSizeEx (HANDLE h, LARGE_INTEGER *s)
{
  if (h != h_stream)
    {
      return 0;
    }

  s->QuadPart = (long)length;
  s->HighPart = 0;
  s->LowPart = length;
  return 1;
}
int
SetFilePointerEx (HANDLE h, LARGE_INTEGER off, LARGE_INTEGER *newpos,
                  DWORD origin)
{
  (void)newpos;
  (void)origin;
  if (h != h_stream || off.QuadPart)
    {
      return 0;
    }

  pos = 0;
  return 1;
}
int
DeleteFileW (const wchar_t *p)
{
  if (!p || fail_delete || !exists)
    {
      return 0;
    }

  delete_count++;
  exists = 0;
  length = 0;
  return 1;
}
static FILE *
stagefile (size_t n)
{
  FILE *f = tmpfile ();
  size_t i;

  if (!f)
    {
      return NULL;
    }

  for (i = 0; i < n; i++)
    {
      if (fputc ((int)(i * 29U + 11U) & 255, f) == EOF)
        {
          fclose (f);
          return NULL;
        }
    }

  if (fflush (f) || fseek (f, 0, SEEK_SET))
    {
      fclose (f);
      return NULL;
    }

  return f;
}
int
main (void)
{
  unsigned short raw[]
      = { ':', 's', 'n', 'o', 'w', 0x96ea, ':', '$', 'D', 'A', 'T', 'A' };
  xtr_ads_name name;
  FILE *f;
  int unclean = 0;

  CHECK (xtr_ads_parse_stream (raw, 12, &name) == XTR_ADS_OK);
  f = stagefile (65537U);
  CHECK (f != NULL);
  if (!f)
    {
      return 1;
    }

  CHECK (xtr_win_ads_create_stream (h_owner, &name, f, 65537UL, &unclean)
         == 0);
  CHECK (!unclean && exists && length == 65537UL);
  CHECK (xtr_win_ads_create_stream (h_owner, &name, f, 65537UL, &unclean)
         == 2);
  CHECK (exists && length == 65537UL && delete_count == 0);
  exists = 0;
  length = 0;
  fail_write = 1;
  CHECK (xtr_win_ads_create_stream (h_owner, &name, f, 65537UL, &unclean)
         == 1);
  CHECK (!exists && !unclean && delete_count == 1);
  fail_delete = 1;
  CHECK (xtr_win_ads_create_stream (h_owner, &name, f, 65537UL, &unclean)
         == 1);
  CHECK (exists && unclean);
  fclose (f);
  printf ("Windows ADS create mock: %u checks, %u failed\n", checks, failed);
  return failed != 0;
}
