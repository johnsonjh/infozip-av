/* SPDX-License-Identifier: MIT-0 */
/* Native NTFS adapter for bounded ADS snapshot/reconcile/rollback.
 * Only supports ordinary non-reparse FILE handles. Cannot promise atomic
 * publication across multiple NTFS streams; failures are reported. */
#include "xtrwin_ads_restore.h"
#if defined(_WIN32)
# include "xtrwin_ads_native.h"
# include "xtrwin_ads_stream.h"
# include "xtrwin_ads_write.h"
# include <limits.h>
# include <stdlib.h>
# include <string.h>
# define XAR_MAX 128U
# define XAR_BYTES (32UL * 1024UL * 1024UL)
typedef struct xar_ctx
{
  HANDLE owner;
  FILE *backup;
  xtr_win_ads_inventory *inventory;
  unsigned long total, active;
  int failed;
} xar_ctx;
static int
xar_same (const BY_HANDLE_FILE_INFORMATION *a,
          const BY_HANDLE_FILE_INFORMATION *b)
{
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber
         && a->nFileIndexHigh == b->nFileIndexHigh
         && a->nFileIndexLow == b->nFileIndexLow
         && !(a->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
         && !(b->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
static int
xar_name_equal (void *unused, const xtr_ads_name *a, const xtr_ads_name *b)
{
  (void)unused;
  return CompareStringOrdinal ((LPCWCH)a->utf16, (int)a->utf16_len,
                               (LPCWCH)b->utf16, (int)b->utf16_len, TRUE)
         == CSTR_EQUAL;
}
static int
xar_save (void *context, const unsigned char *data, size_t count)
{
  xar_ctx *x = (xar_ctx *)context;

  if (count > XAR_BYTES - x->total
      || fwrite (data, 1, count, x->backup) != count)
    {
      return 1;
    }

  x->total += (unsigned long)count;
  x->active += (unsigned long)count;
  return 0;
}
static int
xar_visit (void *context, const xtr_ads_name *name, unsigned long hi,
           unsigned long lo)
{
  xar_ctx *x = (xar_ctx *)context;
  xtr_win_ads_part *part;
  unsigned i;
  long pos;

  if (hi || x->inventory->count >= XAR_MAX || lo > XAR_BYTES - x->total
      || (pos = ftell (x->backup)) < 0 || lo > (unsigned long)LONG_MAX
      || (unsigned long)pos > (unsigned long)LONG_MAX - lo)
    {
      return 1;
    }

  for (i = 0; i < x->inventory->count; i++)
    {
      if (xar_name_equal (NULL, &x->inventory->items[i].name, name))
        {
          return 1;
        }
    }

  part = &x->inventory->items[x->inventory->count];
  part->name = *name;
  part->offset = pos;
  part->length = lo;
  x->active = 0;
  if (xtr_win_ads_read_stream (x->owner, name, hi, lo, xar_save, x)
      || x->active != lo)
    {
      return 1;
    }

  x->inventory->count++;
  return 0;
}
static int
xar_snapshot (void *context, FILE *output, xtr_win_ads_inventory *inventory)
{
  xar_ctx x;
  xar_ctx *parent = (xar_ctx *)context;
  int rc;

  memset (inventory, 0, sizeof (*inventory));
  inventory->items
      = (xtr_win_ads_part *)calloc (XAR_MAX, sizeof (*inventory->items));
  if (!inventory->items)
    {
      return XTR_LIMIT;
    }

  memset (&x, 0, sizeof (x));
  x.owner = parent->owner;
  x.backup = output;
  x.inventory = inventory;
  if (fseek (output, 0, SEEK_END) != 0)
    {
      rc = 1;
    }
  else
    {
      rc = xtr_win_ads_enumerate_handle (parent->owner, xar_visit, &x);
    }

  if (rc || fflush (output) != 0)
    {
      xtr_win_ads_inventory_free (inventory);
      return XTR_IO;
    }

  return XTR_OK;
}
static wchar_t *
xar_path (HANDLE owner, const xtr_ads_name *name)
{
  wchar_t *base = NULL, *path = NULL;
  HANDLE h = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION a, b;
  DWORD needed, written;
  size_t off, i;

  if (!GetFileInformationByHandle (owner, &a)
      || (a.dwFileAttributes
          & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
    {
      return NULL;
    }

  needed = GetFinalPathNameByHandleW (owner, NULL, 0,
                                      FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (needed < 4U || needed > 32767U)
    {
      return NULL;
    }

  base = (wchar_t *)calloc ((size_t)needed + 1U, sizeof (wchar_t));
  if (!base)
    {
      return NULL;
    }

  written = GetFinalPathNameByHandleW (owner, base, needed + 1U,
                                       FILE_NAME_OPENED | VOLUME_NAME_DOS);
  if (!written || written >= needed + 1U
      || (size_t)written > 32767U - name->utf16_len - 8U)
    {
      goto done;
    }

  h = CreateFileW (base, FILE_READ_ATTRIBUTES,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE || !GetFileInformationByHandle (h, &b)
      || !xar_same (&a, &b))
    {
      goto done;
    }

  off = (size_t)written;
  path = (wchar_t *)calloc (off + name->utf16_len + 8U, sizeof (wchar_t));
  if (!path)
    {
      goto done;
    }

  memcpy (path, base, off * sizeof (wchar_t));
  path[off++] = L':';
  for (i = 0; i < name->utf16_len; i++)
    {
      path[off++] = (wchar_t)name->utf16[i];
    }

  path[off++] = L':';
  path[off++] = L'$';
  path[off++] = L'D';
  path[off++] = L'A';
  path[off++] = L'T';
  path[off++] = L'A';
  path[off] = 0;
done:
  if (h != INVALID_HANDLE_VALUE)
    {
      CloseHandle (h);
    }

  free (base);
  return path;
}
static int
xar_remove (void *context, const xtr_ads_name *name)
{
  xar_ctx *x = (xar_ctx *)context;
  wchar_t *path = xar_path (x->owner, name);
  int ok = 0;

  if (path)
    {
      ok = DeleteFileW (path) != 0;
      free (path);
    }

  return ok ? XTR_OK : XTR_IO;
}
static int
xar_put (void *context, const xtr_ads_name *name, FILE *stage, long off,
         unsigned long length)
{
  xar_ctx *x = (xar_ctx *)context;
  wchar_t *path = xar_path (x->owner, name);
  int cleanup_failed = 0, rc;

  if (!path)
    {
      return XTR_IO;
    }

  /* Remove before CREATE_NEW. A failed following create triggers rollback
   * from the complete private pre-mutation snapshot. */
  if (!DeleteFileW (path))
    {
      DWORD why = GetLastError ();
      if (why != ERROR_FILE_NOT_FOUND && why != ERROR_PATH_NOT_FOUND)
        {
          free (path);
          return XTR_IO;
        }
    }

  free (path);
  rc = xtr_win_ads_create_stream_at (x->owner, name, stage, off, length,
                                     &cleanup_failed);
  return rc == 0 && !cleanup_failed ? XTR_OK : XTR_IO;
}
int
xtr_win_ads_restore_exact (HANDLE owner, const xtr_win_ads_part *parts,
                           unsigned count, FILE *verified_stage,
                           FILE *secure_backup, int *rollback_failed)
{
  xar_ctx ctx;
  xtr_win_ads_ops ops;
  BY_HANDLE_FILE_INFORMATION info;

  if (rollback_failed)
    {
      *rollback_failed = 0;
    }

  if (!owner || owner == INVALID_HANDLE_VALUE || !verified_stage
      || !secure_backup || !rollback_failed
      || !GetFileInformationByHandle (owner, &info)
      || (info.dwFileAttributes
          & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
    {
      return XTR_UNSUPPORTED;
    }

  memset (&ctx, 0, sizeof (ctx));
  ctx.owner = owner;
  memset (&ops, 0, sizeof (ops));
  ops.context = &ctx;
  ops.snapshot = xar_snapshot;
  ops.put = xar_put;
  ops.remove = xar_remove;
  ops.equal_name = xar_name_equal;
  return xtr_win_ads_apply_exact (&ops, parts, count, verified_stage,
                                  secure_backup, rollback_failed);
}
#else  /* if defined( _WIN32 ) */
typedef int xtr_win_ads_restore_disabled_translation_unit;
#endif /* if defined( _WIN32 ) */
