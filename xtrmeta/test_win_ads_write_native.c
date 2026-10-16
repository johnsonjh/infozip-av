/* SPDX-License-Identifier: MIT-0 */
/* Disposable native NTFS ADS create/readback test. Real Windows required. */
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN 1
#endif /* ifndef WIN32_LEAN_AND_MEAN */
#include "xtrwin_ads_stream.h"
#include "xtrwin_ads_write.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
typedef struct verify
{
  unsigned long pos;
  int bad;
} verify;
static int
compare (void *ctx, const unsigned char *buf, size_t n)
{
  verify *v = (verify *)ctx;
  size_t i;

  for (i = 0; i < n; i++)
    {
      if (buf[i]
          != (unsigned char)(((v->pos + (unsigned long)i) * 23UL + 3UL)
                             & 255UL))
        {
          v->bad = 1;
        }
    }

  v->pos += (unsigned long)n;
  return v->bad;
}
static int
fill (FILE *f, unsigned long length)
{
  unsigned char bytes[8192];
  unsigned long off = 0;
  size_t i, n;

  while (off < length)
    {
      n = (size_t)((length - off) > sizeof (bytes) ? sizeof (bytes)
                                                   : (length - off));
      for (i = 0; i < n; i++)
        {
          bytes[i] = (unsigned char)(((off + i) * 23UL + 3UL) & 255UL);
        }

      if (fwrite (bytes, 1, n, f) != n)
        {
          return 0;
        }

      off += (unsigned long)n;
    }
  return fflush (f) == 0 && fseek (f, 0, SEEK_SET) == 0;
}
int
main (void)
{
  wchar_t cwd[MAX_PATH + 1], ownername[MAX_PATH + 1];
  unsigned short raw[] = { ':', 0x96ea, ':', '$', 'D', 'A', 'T', 'A' };
  xtr_ads_name name;
  HANDLE owner = INVALID_HANDLE_VALUE;
  FILE *stage = NULL, *short_stage = NULL;
  verify check;
  int rc = 1, incomplete = 0;
  DWORD cwdlen;

  cwdlen = GetCurrentDirectoryW (MAX_PATH, cwd);
  if (!cwdlen || cwdlen >= MAX_PATH
      || !GetTempFileNameW (cwd, L"ads", 0, ownername))
    {
      return 1;
    }

  owner = CreateFileW (
      ownername, GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  stage = tmpfile ();
  short_stage = tmpfile ();
  if (owner == INVALID_HANDLE_VALUE || !stage || !short_stage
      || xtr_ads_parse_stream (raw, sizeof (raw) / sizeof (raw[0]), &name)
             != XTR_ADS_OK
      || !fill (stage, 2097152UL))
    {
      goto done;
    }

  rc = xtr_win_ads_create_stream (owner, &name, stage, 2097152UL, &incomplete);
  if (rc)
    {
      if (!incomplete && rc == 2)
        {
          puts (
              "SKIP: NTFS named ADS creation unavailable on this filesystem");
          rc = 77;
        }
      else
        {
          fprintf (stderr, "FAIL: ADS creation returned %d, cleanup=%d\n", rc,
                   incomplete);
        }

      goto done;
    }

  memset (&check, 0, sizeof (check));
  if (xtr_win_ads_read_stream (owner, &name, 0, 2097152UL, compare, &check)
          != 0
      || check.bad || check.pos != 2097152UL)
    {
      puts ("FAIL: ADS byte comparison");
      rc = 1;
      goto done;
    }

  if (xtr_win_ads_create_stream (owner, &name, stage, 2097152UL, &incomplete)
          != 2
      || incomplete)
    {
      puts ("FAIL: existing stream overwritten or deletion attempted");
      rc = 1;
      goto done;
    }

  puts ("PASS: NATIVE WINDOWS W3C2A Unicode ADS create; 2 MiB verified; "
        "existing stream protected");
  rc = 0;
done:
  if (owner != INVALID_HANDLE_VALUE)
    {
      CloseHandle (owner);
    }

  if (stage)
    {
      fclose (stage);
    }

  if (short_stage)
    {
      fclose (short_stage);
    }

  DeleteFileW (ownername);
  return rc;
}
