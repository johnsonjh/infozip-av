/* SPDX-License-Identifier: MIT-0 */
/* Windows user-mode native NT EA backend. Strict C89 syntax, MinGW-compatible.
 * Only NT EAs, not alternate streams, ACLs, SACLs or security descriptors.
 * Native operations use the caller's pinned, non-reparse HANDLE. */
#include "xtrwin_nt.h"
#if defined(_WIN32)
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN 1
# endif /* ifndef WIN32_LEAN_AND_MEAN */
# include "xtrwin_txn.h"
# include <stdlib.h>
# include <string.h>
# include <windows.h>

# include "xtrwin_nt_abi.h"
typedef struct xwn_context
{
  HANDLE handle;
  xwn_query_fn query;
  xwn_set_fn set;
  BY_HANDLE_FILE_INFORMATION identity;
} xwn_context;
# define XWN_NO_EAS ((LONG)0xC0000052UL)
# define XWN_BUF_SMALL ((LONG)0xC0000023UL)
# define XWN_BUF_OVERFLOW ((LONG)0x80000005UL)
# define XWN_INFO_LENGTH ((LONG)0xC0000004UL)
# define XWN_NO_MORE_EAS ((LONG)0x80000012UL)
# define XWN_LIMIT (1024UL * 1024UL)

static int
xwn_same (const BY_HANDLE_FILE_INFORMATION *a,
          const BY_HANDLE_FILE_INFORMATION *b)
{
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber
         && a->nFileIndexHigh == b->nFileIndexHigh
         && a->nFileIndexLow == b->nFileIndexLow
         && !((b->dwFileAttributes) & FILE_ATTRIBUTE_REPARSE_POINT);
}
static int
xwn_identity (xwn_context *x)
{
  BY_HANDLE_FILE_INFORMATION current;

  if (!GetFileInformationByHandle (x->handle, &current))
    {
      return XTR_IO;
    }

  return xwn_same (&x->identity, &current) ? XTR_OK : XTR_UNSUPPORTED;
}
static int
xwn_begin (HANDLE h, xwn_context *ctx, int writing)
{
  HMODULE dll;
  FARPROC entry;

  memset (ctx, 0, sizeof (*ctx));
  ctx->handle = h;
  if (!h || h == INVALID_HANDLE_VALUE || GetFileType (h) != FILE_TYPE_DISK
      || !GetFileInformationByHandle (h, &ctx->identity)
      || (ctx->identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
      return XTR_UNSUPPORTED;
    }

  dll = GetModuleHandleA ("ntdll.dll");
  if (!dll)
    {
      return XTR_UNSUPPORTED;
    }

  if (sizeof (entry) != sizeof (ctx->query)
      || sizeof (entry) != sizeof (ctx->set))
    {
      return XTR_UNSUPPORTED;
    }

  entry = GetProcAddress (dll, "NtQueryEaFile");
  if (!entry)
    {
      return XTR_UNSUPPORTED;
    }

  memcpy (&ctx->query, &entry, sizeof (entry));
  if (writing)
    {
      entry = GetProcAddress (dll, "NtSetEaFile");
      if (!entry)
        {
          return XTR_UNSUPPORTED;
        }

      memcpy (&ctx->set, &entry, sizeof (entry));
    }

  return XTR_OK;
}
/* Native queries can return STATUS_SUCCESS with just the records that
 * fit in a buffer. Do NOT assume one successful call is a complete EA set:
 * explicitly exhaust the enumeration with RestartScan=FALSE. A continued
 * enumeration, even on a filesystem with far more than 1 MiB of EAs, must
 * terminate within the declared adapter limits; otherwise fail closed. */
static int
xwn_snapshot (void *v, xtr_win_ea_list *output)
{
  xwn_context *x = (xwn_context *)v;
  unsigned char *buf;
  size_t aggregate = 0;
  unsigned calls = 0;
  xwn_iosb io;
  LONG status;
  int rc = XTR_OK;

  memset (output, 0, sizeof (*output));
  if (xwn_identity (x) != XTR_OK)
    {
      return XTR_UNSUPPORTED;
    }

  buf = (unsigned char *)malloc ((size_t)XWN_LIMIT);
  if (!buf)
    {
      return XTR_LIMIT;
    }

  for (;;)
    {
      xtr_win_ea_list chunk;
      xtr_win_ea *larger;
      memset (&chunk, 0, sizeof (chunk));
      memset (&io, 0, sizeof (io));
      status = x->query (x->handle, &io, buf, (ULONG)XWN_LIMIT, (BOOLEAN)0,
                         NULL, 0, NULL, (BOOLEAN)(calls == 0U));
      if (status == XWN_NO_EAS || status == XWN_NO_MORE_EAS)
        {
          /* NO_EAS_ON_FILE is legitimate before any records only. */
          if (status == XWN_NO_EAS && calls > 0U)
            {
              rc = XTR_IO;
            }

          break;
        }

      if (status == XWN_BUF_SMALL || status == XWN_BUF_OVERFLOW
          || status == XWN_INFO_LENGTH)
        {
          rc = XTR_LIMIT;
          break;
        }

      if (status != 0)
        {
          rc = XTR_IO;
          break;
        }

      if (io.information == 0 || io.information > (ULONG_PTR)XWN_LIMIT
          || io.information > (ULONG_PTR)(XWN_LIMIT - aggregate))
        {
          rc = XTR_LIMIT;
          break;
        }

      /* A malicious or nonconforming driver must not cause an unbounded
       * loop by repeatedly returning zero or duplicate entries. */
      if (calls++ >= 1024U)
        {
          rc = XTR_LIMIT;
          break;
        }

      rc = xtr_win_ea_parse (buf, (size_t)io.information, &chunk);
      if (rc != XTR_OK)
        {
          break;
        }

      if (chunk.count == 0U || chunk.count > 1024U - output->count)
        {
          xtr_win_ea_free (&chunk);
          rc = XTR_LIMIT;
          break;
        }

      larger = (xtr_win_ea *)realloc (
          output->items, (output->count + chunk.count) * sizeof (*larger));
      if (!larger)
        {
          xtr_win_ea_free (&chunk);
          rc = XTR_LIMIT;
          break;
        }

      output->items = larger;
      memcpy (output->items + output->count, chunk.items,
              chunk.count * sizeof (*larger));
      output->count += chunk.count;
      /* Names and values have transferred ownership to output. */
      free (chunk.items);
      aggregate += (size_t)io.information;
    }

  free (buf);
  if (rc == XTR_OK)
    {
      /* Run the W1 global validator across ALL chunks, so case-folding
       * collisions and aggregate native buffer limits cannot be missed. */
      unsigned char *flat = NULL;
      size_t n = 0;
      rc = xtr_win_ea_pack (output, &flat, &n);
      free (flat);
      if (rc == XTR_OK)
        {
          rc = xwn_identity (x);
        }
    }

  if (rc != XTR_OK)
    {
      xtr_win_ea_free (output);
    }

  return rc;
}
static int
xwn_change (void *v, const xtr_win_ea *ea, int deletion)
{
  xwn_context *x = (xwn_context *)v;
  xtr_win_ea item;
  xtr_win_ea_list one;
  unsigned char *buf = NULL;
  size_t n = 0;
  xwn_iosb io;
  LONG status;
  int rc;

  if (xwn_identity (x) != XTR_OK)
    {
      return XTR_UNSUPPORTED;
    }

  item = *ea;
  if (deletion)
    {
      item.flags = 0;
      item.value_len = 0;
      item.value = NULL;
    }

  one.items = &item;
  one.count = 1;
  rc = deletion ? xtr_win_ea_pack (&one, &buf, &n)
                : xtr_win_ea_pack_set (&one, &buf, &n);
  if (rc != XTR_OK)
    {
      return rc;
    }

  if (n > (size_t)0xffffffffUL)
    {
      free (buf);
      return XTR_LIMIT;
    }

  memset (&io, 0, sizeof (io));
  status = x->set (x->handle, &io, buf, (ULONG)n);
  free (buf);
  if (status != 0)
    {
      return XTR_IO;
    }

  return xwn_identity (x);
}
int
xtr_win_nt_snapshot_handle (void *handle, xtr_win_ea_list *output)
{
  xwn_context x;
  int rc;

  if (!output)
    {
      return XTR_CORRUPT;
    }

  memset (output, 0, sizeof (*output));
  rc = xwn_begin ((HANDLE)handle, &x, 0);
  if (rc != XTR_OK)
    {
      return rc;
    }

  return xwn_snapshot (&x, output);
}
int
xtr_win_nt_capture_handle (void *handle, const unsigned char owner[16],
                           FILE *stage, int encrypted, xtr1_digest *digest)
{
  xwn_context x;
  xtr_win_ea_list list;
  int rc;

  if (!owner || !stage || !digest)
    {
      return XTR_CORRUPT;
    }

  rc = xwn_begin ((HANDLE)handle, &x, 0);
  if (rc != XTR_OK)
    {
      return rc;
    }

  memset (&list, 0, sizeof (list));
  rc = xwn_snapshot (&x, &list);
  if (rc == XTR_OK)
    {
      rc = xtr_win_ea_to_manifest (&list, owner, stage, encrypted, digest);
    }

  xtr_win_ea_free (&list);
  return rc;
}
int
xtr_win_nt_apply_list (void *handle, const xtr_win_ea_list *desired,
                       int *rollback_failed)
{
  xwn_context x;
  xtr_win_ea_ops ops;
  int rc;

  if (rollback_failed)
    {
      *rollback_failed = 0;
    }

  if (!desired || !rollback_failed)
    {
      return XTR_CORRUPT;
    }

  rc = xwn_begin ((HANDLE)handle, &x, 1);
  if (rc != XTR_OK)
    {
      return rc;
    }

  ops.context = &x;
  ops.snapshot = xwn_snapshot;
  ops.change = xwn_change;
  return xtr_win_ea_apply_exact (&ops, desired, rollback_failed);
}
int
xtr_win_nt_restore_handle (void *handle, FILE *stage, xtr_u64 encoded,
                           const xtr_extra *outer, const unsigned char *sha,
                           int *rollback_failed)
{
  xwn_context x;
  xtr_win_ea_ops ops;
  xtr_win_ea_list list;
  int rc;

  if (rollback_failed)
    {
      *rollback_failed = 0;
    }

  if (!stage || !outer || !rollback_failed)
    {
      return XTR_CORRUPT;
    }

  /* Authentication, SHA, TLVs and limits are checked before any writes.
   * A foreign origin is never mapped to Windows EAs by name alone. */
  memset (&list, 0, sizeof (list));
  rc = xtr_win_ea_from_manifest (stage, encoded, outer, sha, &list);
  if (rc != XTR_OK)
    {
      return rc;
    }

  rc = xwn_begin ((HANDLE)handle, &x, 1);
  if (rc == XTR_OK)
    {
      ops.context = &x;
      ops.snapshot = xwn_snapshot;
      ops.change = xwn_change;
      rc = xtr_win_ea_apply_exact (&ops, &list, rollback_failed);
    }

  xtr_win_ea_free (&list);
  return rc;
}
#else  /* if defined( _WIN32 ) */
typedef int xtr_win_nt_disabled_translation_unit;
#endif /* if defined( _WIN32 ) */
