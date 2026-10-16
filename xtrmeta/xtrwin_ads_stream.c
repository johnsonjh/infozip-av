/* SPDX-License-Identifier: MIT-0 */
/* Byte-accurate, bounded-memory NTFS $DATA read from a pinned owner.
 * A transient pathname is checked against the original handle; no reparse
 * point may substitute the owner. Archive publication MUST independently
 * authenticate the full Xtro manifest and member payload. */
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN 1
#endif /* ifndef WIN32_LEAN_AND_MEAN */
#include "xtrwin_ads_stream.h"
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#define XAS_READ_CHUNK 16384U
static int
xas_id_equal (const BY_HANDLE_FILE_INFORMATION *a,
              const BY_HANDLE_FILE_INFORMATION *b)
{
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber
         && a->nFileIndexHigh == b->nFileIndexHigh
         && a->nFileIndexLow == b->nFileIndexLow
         && !(a->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
         && !(b->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
/* Reject API callers' unvalidated or tampered names. */
static int
xas_name_ok (const xtr_ads_name *n)
{
  unsigned short raw[XTR_ADS_MAX_NAME + 8U];
  xtr_ads_name normalized;
  static const unsigned short suffix[6] = { ':', '$', 'D', 'A', 'T', 'A' };
  size_t i, rawlen;

  if (!n || !n->utf16_len || n->utf16_len > XTR_ADS_MAX_NAME
      || n->utf8_len > XTR_ADS_MAX_UTF8)
    {
      return 0;
    }

  rawlen = n->utf16_len + 7U;
  raw[0] = ':';
  for (i = 0; i < n->utf16_len; i++)
    {
      raw[i + 1U] = n->utf16[i];
    }

  for (i = 0; i < 6U; i++)
    {
      raw[1U + n->utf16_len + i] = suffix[i];
    }

  if (xtr_ads_parse_stream (raw, rawlen, &normalized) != XTR_ADS_OK)
    {
      return 0;
    }

  return normalized.utf16_len == n->utf16_len
         && normalized.utf8_len == n->utf8_len
         && memcmp (normalized.utf16, n->utf16,
                    n->utf16_len * sizeof (unsigned short))
                == 0
         && memcmp (normalized.utf8, n->utf8, n->utf8_len) == 0;
}
int
xtr_win_ads_read_stream (HANDLE pinned, const xtr_ads_name *name,
                         unsigned long high, unsigned long low,
                         xtr_ads_bytes_cb consumer, void *ctx)
{
  BY_HANDLE_FILE_INFORMATION first, openedinfo, after;
  wchar_t *path = NULL, *stream_path = NULL;
  HANDLE base = INVALID_HANDLE_VALUE, stream = INVALID_HANDLE_VALUE;
  unsigned char chunk[XAS_READ_CHUNK];
  LARGE_INTEGER size;
  DWORD count, done;
  size_t start, tail, i;
  unsigned long hi = high, lo = low;
  int rc = 1;

  if (!name || !xas_name_ok (name))
    {
      return 2;
    }

  if (!pinned || pinned == INVALID_HANDLE_VALUE || !consumer
      || high > 0xffffffffUL || low > 0xffffffffUL
      || !GetFileInformationByHandle (pinned, &first)
      || (first.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
      return 1;
    }

  count = GetFinalPathNameByHandleW (pinned, NULL, 0,
                                     FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (count < 4U || count > 32767U)
    {
      return 1;
    }

  path = (wchar_t *)calloc ((size_t)count + 1U, sizeof (wchar_t));
  if (!path)
    {
      return 1;
    }

  done = GetFinalPathNameByHandleW (pinned, path, count + 1U,
                                    FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (!done || done >= count + 1U)
    {
      goto cleanup;
    }

  base = CreateFileW (
      path, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
      NULL);
  if (base == INVALID_HANDLE_VALUE
      || !GetFileInformationByHandle (base, &openedinfo)
      || !xas_id_equal (&first, &openedinfo))
    {
      goto cleanup;
    }

  start = (size_t)done;
  tail = name->utf16_len + 7U;
  if (start > 32767U - tail
      || start > (((size_t)-1) / sizeof (wchar_t)) - tail - 1U)
    {
      goto cleanup;
    }

  stream_path = (wchar_t *)malloc ((start + tail + 1U) * sizeof (wchar_t));
  if (!stream_path)
    {
      goto cleanup;
    }

  memcpy (stream_path, path, start * sizeof (wchar_t));
  stream_path[start++] = L':';
  for (i = 0; i < name->utf16_len; i++)
    {
      stream_path[start++] = (wchar_t)name->utf16[i];
    }

  stream_path[start++] = L':';
  stream_path[start++] = L'$';
  stream_path[start++] = L'D';
  stream_path[start++] = L'A';
  stream_path[start++] = L'T';
  stream_path[start++] = L'A';
  stream_path[start] = 0;
  stream
      = CreateFileW (stream_path, GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (stream == INVALID_HANDLE_VALUE
      || !GetFileInformationByHandle (stream, &after)
      || !xas_id_equal (&first, &after) || !GetFileSizeEx (stream, &size)
      || size.QuadPart < 0 || (unsigned long)size.HighPart != high
      || (unsigned long)size.LowPart != low)
    {
      goto cleanup;
    }

  while (hi || lo)
    {
      DWORD want = hi || lo > XAS_READ_CHUNK ? XAS_READ_CHUNK : (DWORD)lo;
      DWORD n = 0;
      if (!ReadFile (stream, chunk, want, &n, NULL) || n != want
          || consumer (ctx, chunk, (size_t)n))
        {
          goto cleanup;
        }

      if (lo < (unsigned long)n)
        {
          hi--;
          lo = 0xffffffffUL - ((unsigned long)n - lo) + 1UL;
        }
      else
        {
          lo -= (unsigned long)n;
        }
    }
  /* Prevent accepting a concurrently extended stream or short enumeration. */
  {
    DWORD n = 0;
    if (!ReadFile (stream, chunk, 1U, &n, NULL) || n != 0U)
      {
        goto cleanup;
      }
  }
  if (!GetFileSizeEx (stream, &size) || size.QuadPart < 0
      || (unsigned long)size.HighPart != high
      || (unsigned long)size.LowPart != low
      || !GetFileInformationByHandle (pinned, &after)
      || !xas_id_equal (&first, &after)
      || !GetFileInformationByHandle (base, &after)
      || !xas_id_equal (&first, &after))
    {
      goto cleanup;
    }

  rc = 0;
cleanup:
  if (stream != INVALID_HANDLE_VALUE)
    {
      CloseHandle (stream);
    }

  if (base != INVALID_HANDLE_VALUE)
    {
      CloseHandle (base);
    }

  free (stream_path);
  free (path);
  return rc;
}
