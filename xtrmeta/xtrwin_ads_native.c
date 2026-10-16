/* SPDX-License-Identifier: MIT-0 */
/* Windows NTFS alternate $DATA stream enumeration by pinned owner identity.
 * Does not capture bytes, emit archives, or write streams. */
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN 1
#endif /* ifndef WIN32_LEAN_AND_MEAN */
#include "xtrwin_ads_native.h"
#include <stdlib.h>
#include <string.h>
#include <windows.h>
static int
xas_same (const BY_HANDLE_FILE_INFORMATION *a,
          const BY_HANDLE_FILE_INFORMATION *b)
{
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber
         && a->nFileIndexHigh == b->nFileIndexHigh
         && a->nFileIndexLow == b->nFileIndexLow
         && !(a->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
         && !(b->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
int
xtr_win_ads_enumerate_handle (HANDLE pinned, xtr_ads_visit_cb visit, void *ctx)
{
  BY_HANDLE_FILE_INFORMATION first, second;
  WIN32_FIND_STREAM_DATA stream;
  wchar_t *path = NULL;
  HANDLE opened = INVALID_HANDLE_VALUE, find = INVALID_HANDLE_VALUE;
  DWORD need, err;
  size_t length, i;
  unsigned count = 0;
  int rc = 1, kind;

  if (!pinned || pinned == INVALID_HANDLE_VALUE || !visit
      || !GetFileInformationByHandle (pinned, &first)
      || (first.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
      return 1;
    }

  need = GetFinalPathNameByHandleW (pinned, NULL, 0,
                                    FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (need < 4U || need > 32767U)
    {
      return 1;
    }

  path = (wchar_t *)calloc ((size_t)need + 1U, sizeof (wchar_t));
  if (!path)
    {
      return 1;
    }

  {
    DWORD written = GetFinalPathNameByHandleW (
        pinned, path, need + 1U, FILE_NAME_OPENED | VOLUME_NAME_DOS);
    /* Probe returns length INCLUDING NUL; success excludes NUL. */
    if (!written || written >= need + 1U)
      {
        goto done;
      }
  }
  opened = CreateFileW (
      path, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
      NULL);
  if (opened == INVALID_HANDLE_VALUE
      || !GetFileInformationByHandle (opened, &second)
      || !xas_same (&first, &second))
    {
      goto done;
    }

  find = FindFirstStreamW (path, FindStreamInfoStandard, &stream, 0);
  if (find == INVALID_HANDLE_VALUE)
    {
      err = GetLastError ();
      if (err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_SUPPORTED
          || err == ERROR_CALL_NOT_IMPLEMENTED)
        {
          rc = 2;
        }

      goto done;
    }

  do
    {
      unsigned short units[MAX_PATH + 36];
      xtr_ads_name name;
      for (length = 0; length < (size_t)(MAX_PATH + 36); length++)
        {
          if (!stream.cStreamName[length])
            {
              break;
            }
        }

      if (length == (size_t)(MAX_PATH + 36))
        {
          rc = 3;
          goto done;
        }

      for (i = 0; i < length; i++)
        {
          units[i] = (unsigned short)stream.cStreamName[i];
        }

      kind = xtr_ads_parse_stream (units, length, &name);
      if (kind == XTR_ADS_DEFAULT)
        {
          continue;
        }

      if (kind != XTR_ADS_OK)
        {
          rc = 3;
          goto done;
        }

      if (stream.StreamSize.QuadPart < 0 || count++ >= 1024U)
        {
          rc = 3;
          goto done;
        }

      if (visit (ctx, &name, (unsigned long)stream.StreamSize.HighPart,
                 (unsigned long)stream.StreamSize.LowPart))
        {
          goto done;
        }
    }
  while (FindNextStreamW (find, &stream));
  err = GetLastError ();
  if (err != ERROR_HANDLE_EOF && err != ERROR_NO_MORE_FILES)
    {
      goto done;
    }

  if (!GetFileInformationByHandle (pinned, &second)
      || !xas_same (&first, &second))
    {
      goto done;
    }

  rc = 0;
done:
  if (find != INVALID_HANDLE_VALUE)
    {
      FindClose (find);
    }

  if (opened != INVALID_HANDLE_VALUE)
    {
      CloseHandle (opened);
    }

  free (path);
  return rc;
}
