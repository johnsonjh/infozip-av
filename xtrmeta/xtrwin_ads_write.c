/* SPDX-License-Identifier: MIT-0 */
/* Opt-in native NTFS stream creation primitive, strict bounded-memory C89. */
#include "xtrwin_ads_write.h"
#if defined(_WIN32)
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN 1
# endif /* ifndef WIN32_LEAN_AND_MEAN */
# include <stdlib.h>
# include <string.h>
# include <windows.h>
# define XAW_CHUNK 16384U
# define XAW_LIMIT (32UL * 1024UL * 1024UL)
static int
xaw_same (const BY_HANDLE_FILE_INFORMATION *a,
          const BY_HANDLE_FILE_INFORMATION *b)
{
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber
         && a->nFileIndexHigh == b->nFileIndexHigh
         && a->nFileIndexLow == b->nFileIndexLow
         && !(a->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
         && !(b->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
static int
xaw_valid (const xtr_ads_name *n)
{
  unsigned short raw[XTR_ADS_MAX_NAME + 8U];
  xtr_ads_name normalized;
  size_t i;

  if (!n || !n->utf16_len || n->utf16_len > XTR_ADS_MAX_NAME || !n->utf8_len
      || n->utf8_len > XTR_ADS_MAX_UTF8)
    {
      return 0;
    }

  raw[0] = ':';
  for (i = 0; i < n->utf16_len; i++)
    {
      raw[i + 1U] = n->utf16[i];
    }

  raw[1U + n->utf16_len] = ':';
  raw[2U + n->utf16_len] = '$';
  raw[3U + n->utf16_len] = 'D';
  raw[4U + n->utf16_len] = 'A';
  raw[5U + n->utf16_len] = 'T';
  raw[6U + n->utf16_len] = 'A';
  if (xtr_ads_parse_stream (raw, n->utf16_len + 7U, &normalized) != XTR_ADS_OK)
    {
      return 0;
    }

  return normalized.utf8_len == n->utf8_len
         && memcmp (normalized.utf8, n->utf8, n->utf8_len) == 0;
}
int
xtr_win_ads_create_stream_at (HANDLE owner, const xtr_ads_name *name,
                              FILE *stage, long offset, unsigned long size,
                              int *cleanup_failed)
{
  BY_HANDLE_FILE_INFORMATION original, current;
  wchar_t *base = NULL, *streamname = NULL;
  HANDLE base_h = INVALID_HANDLE_VALUE, stream = INVALID_HANDLE_VALUE;
  HANDLE verifybase = INVALID_HANDLE_VALUE;
  unsigned char buf[XAW_CHUNK], back[XAW_CHUNK];
  DWORD needed, written;
  size_t off, i;
  unsigned long remain;
  int rc = 1, created = 0;
  LARGE_INTEGER actual, zero;

  if (cleanup_failed)
    {
      *cleanup_failed = 0;
    }

  if (!cleanup_failed || !xaw_valid (name) || !stage || size > XAW_LIMIT
      || offset < 0 || !owner || owner == INVALID_HANDLE_VALUE
      || !GetFileInformationByHandle (owner, &original)
      || (original.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || (original.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
      return 2;
    }

  needed = GetFinalPathNameByHandleW (owner, NULL, 0,
                                      FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (needed < 4U || needed > 32767U)
    {
      return 1;
    }

  base = (wchar_t *)calloc ((size_t)needed + 1U, sizeof (*base));
  if (!base)
    {
      return 1;
    }

  written = GetFinalPathNameByHandleW (owner, base, needed + 1U,
                                       FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (!written || written >= needed + 1U)
    {
      goto done;
    }

  base_h
      = CreateFileW (base, FILE_READ_ATTRIBUTES,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (base_h == INVALID_HANDLE_VALUE
      || !GetFileInformationByHandle (base_h, &current)
      || !xaw_same (&original, &current))
    {
      goto done;
    }

  off = (size_t)written;
  if (off > 32767U - name->utf16_len - 8U)
    {
      goto done;
    }

  streamname
      = (wchar_t *)calloc (off + name->utf16_len + 8U, sizeof (wchar_t));
  if (!streamname)
    {
      goto done;
    }

  memcpy (streamname, base, off * sizeof (wchar_t));
  streamname[off++] = L':';
  for (i = 0; i < name->utf16_len; i++)
    {
      streamname[off++] = (wchar_t)name->utf16[i];
    }

  streamname[off++] = L':';
  streamname[off++] = L'$';
  streamname[off++] = L'D';
  streamname[off++] = L'A';
  streamname[off++] = L'T';
  streamname[off++] = L'A';
  streamname[off] = 0;
  /* CREATE_NEW must not clobber an existing stream. OPEN_REPARSE_POINT
   * keeps the final-component behavior explicit for this named stream. */
  stream = CreateFileW (streamname, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (stream == INVALID_HANDLE_VALUE)
    {
      rc = 2;
      goto done;
    }

  created = 1;
  if (!GetFileInformationByHandle (stream, &current)
      || !xaw_same (&original, &current)
      || fseek (stage, offset, SEEK_SET) != 0)
    {
      goto done;
    }

  remain = size;
  while (remain)
    {
      DWORD n = (DWORD)(remain > XAW_CHUNK ? XAW_CHUNK : remain), put = 0;
      if (fread (buf, 1, n, stage) != (size_t)n
          || !WriteFile (stream, buf, n, &put, NULL) || put != n)
        {
          goto done;
        }

      remain -= (unsigned long)n;
    }
  zero.QuadPart = 0;
  if (!FlushFileBuffers (stream) || !GetFileSizeEx (stream, &actual)
      || actual.QuadPart < 0 || (unsigned long)actual.HighPart != 0UL
      || (unsigned long)actual.LowPart != size
      || !SetFilePointerEx (stream, zero, NULL, FILE_BEGIN))
    {
      goto done;
    }

  if (fseek (stage, offset, SEEK_SET) != 0)
    {
      goto done;
    }

  remain = size;
  while (remain)
    {
      DWORD n = (DWORD)(remain > XAW_CHUNK ? XAW_CHUNK : remain), got = 0;
      if (fread (buf, 1, n, stage) != (size_t)n
          || !ReadFile (stream, back, n, &got, NULL) || got != n
          || memcmp (buf, back, n))
        {
          goto done;
        }

      remain -= (unsigned long)n;
    }
  {
    DWORD got = 0;
    if (!ReadFile (stream, back, 1U, &got, NULL) || got != 0U
        || !GetFileInformationByHandle (owner, &current)
        || !xaw_same (&original, &current))
      {
        goto done;
      }
  }
  rc = 0;
done:
  if (stream != INVALID_HANDLE_VALUE)
    {
      CloseHandle (stream);
    }

  if (rc && created)
    {
      /* A renamed/replaced pathname may identify a different owner.
       * Reopen the base pathname immediately before cleanup. */
      verifybase = CreateFileW (
          base, FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
      if (verifybase == INVALID_HANDLE_VALUE
          || !GetFileInformationByHandle (verifybase, &current)
          || !xaw_same (&original, &current) || !DeleteFileW (streamname))
        {
          *cleanup_failed = 1;
        }

      if (verifybase != INVALID_HANDLE_VALUE)
        {
          CloseHandle (verifybase);
        }
    }

  if (base_h != INVALID_HANDLE_VALUE)
    {
      CloseHandle (base_h);
    }

  free (streamname);
  free (base);
  return rc;
}
int
xtr_win_ads_create_stream (HANDLE owner, const xtr_ads_name *name, FILE *stage,
                           unsigned long size, int *cleanup_failed)
{
  return xtr_win_ads_create_stream_at (owner, name, stage, 0L, size,
                                       cleanup_failed);
}
#else  /* if defined( _WIN32 ) */
typedef int xtr_win_ads_write_disabled_translation_unit;
#endif /* if defined( _WIN32 ) */
