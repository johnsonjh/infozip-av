/* SPDX-License-Identifier: MIT-0 */
/* Host-driven W2B2A contract test; no native Windows filesystem semantics. */
#define XTR_WIN_TEST_STAGE 1
#define XTR_WIN_NATIVE 1
#define WIN32 1
#define _WIN32 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char uch;
typedef long zoff_t;
typedef struct min_info
{
  zoff_t offset;
  unsigned long compr_size, crc, diskstart;
  unsigned compression_method;
  unsigned char *xtr_central;
  char *xtr_source_name;
  unsigned xtr_central_len;
  void *xtr_restore_handle;
  unsigned char xtr_companion;
  unsigned long uncompr_size;
  unsigned encrypted, fwkcs_md5;
  unsigned aes_strength, aes_version, aes_iterations;
} min_info;
int xtr_unzip_xattrs = 1;
int xtr_unzip_streams = 0;
#include "../unzip60/xtrunzip_win.c"
#include "xtrwin_ads_record.h"
static unsigned tests, failures, restorations, ads_restorations;
static int reparse, changed, dir_changed;
static unsigned mock_link_count = 1;
static unsigned overwrite_truncations, overwrite_fd_opens, overwrite_fd_closes;
static int overwrite_setend_fail, overwrite_fd_fail;
static int overwrite_eas_intact = 1, overwrite_ads_intact = 1;
static unsigned char mockzip[4096];
static unsigned long mockpos;
#define CHECK(q)                                                              \
  do                                                                          \
    {                                                                         \
      tests++;                                                                \
      if (!(q))                                                               \
        {                                                                     \
          failures++;                                                         \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #q);               \
        }                                                                     \
    }                                                                         \
  while (0)
/* Reject attribute bits as the real Win32 ReOpenFile API does. The old
 * mock ignored attrs and falsely accepted FILE_ATTRIBUTE_NORMAL. */
static unsigned reopen_bad_flags, reopen_good_flags;
HANDLE
ReOpenFile (HANDLE orig, DWORD rights, DWORD shares, DWORD attrs)
{
  (void)rights;
  (void)shares;
  if (attrs != 0U)
    {
      reopen_bad_flags++;
      return INVALID_HANDLE_VALUE;
    }

  reopen_good_flags++;
  return orig;
}
int
GetFileSizeEx (HANDLE h, LARGE_INTEGER *size)
{
  (void)h;
  size->QuadPart = (LONGLONG)sizeof (mockzip);
  return 1;
}
int
SetFilePointerEx (HANDLE h, LARGE_INTEGER at, LARGE_INTEGER *out, DWORD method)
{
  (void)h;
  (void)out;
  if (method != FILE_BEGIN || at.QuadPart < 0
      || at.QuadPart > (LONGLONG)sizeof (mockzip))
    {
      return 0;
    }

  mockpos = (unsigned long)at.QuadPart;
  return 1;
}
int
SetEndOfFile (HANDLE h)
{
  (void)h;
  if (overwrite_setend_fail)
    {
      return 0;
    }

  overwrite_truncations++;
  /* Truncating ONLY the unnamed stream retains simulated EAs and ADS.
   * The original unlink/recreate extraction path did not do this. */
  return 1;
}
int
_open_osfhandle (intptr_t h, int flags)
{
  (void)h;
  (void)flags;
  if (overwrite_fd_fail)
    {
      return -1;
    }

  overwrite_fd_opens++;
  return 99;
}
FILE *
_fdopen (int fd, const char *mode)
{
  if (fd != 99 || !mode || mode[0] != 'w')
    {
      return NULL;
    }

  return tmpfile ();
}
int
_close (int fd)
{
  if (fd == 99)
    {
      overwrite_fd_closes++;
    }

  return 0;
}
int
ReadFile (HANDLE h, void *buf, DWORD len, DWORD *n, void *overlap)
{
  (void)h;
  (void)overlap;
  if (len > sizeof (mockzip) - mockpos)
    {
      return 0;
    }

  memcpy (buf, mockzip + mockpos, len);
  mockpos += len;
  *n = len;
  return 1;
}
HANDLE
GetCurrentProcess (void) { return (HANDLE)1; }
int
DuplicateHandle (HANDLE a, HANDLE b, HANDLE c, HANDLE *out, DWORD access,
                 int inherit, DWORD option)
{
  (void)a;
  (void)c;
  (void)access;
  (void)inherit;
  (void)option;
  *out = b;
  return 1;
}
DWORD
GetFullPathNameA (const char *in, DWORD cap, char *out, char **file)
{
  const char *prefix = "C:\\work\\";
  size_t n = strlen (prefix) + strlen (in);

  (void)file;
  if (n + 1 > cap)
    {
      return (DWORD)(n + 1);
    }

  strcpy (out, prefix);
  strcat (out, in);
  return (DWORD)n;
}
static unsigned wide_opens, ansi_opens;
UINT
GetACP (void)
{
  return 1252U;
}
int
MultiByteToWideChar (unsigned int cp, DWORD flags, const char *src, int len,
                     wchar_t *out, int cap)
{
  int i = 0;

  (void)cp;
  (void)flags;
  if (len != -1)
    {
      return 0;
    }

  while (src[i])
    {
      if ((unsigned char)src[i] > (wchar_t)127)
        {
          return 0;
        }

      i++;
    }
  if (!out)
    {
      return i + 1;
    }

  if (cap < i + 1)
    {
      return 0;
    }

  for (i = 0; src[i]; i++)
    {
      out[i] = (wchar_t)(unsigned char)src[i];
    }

  out[i] = 0;
  return i + 1;
}
int
WideCharToMultiByte (unsigned int cp, DWORD flags, const wchar_t *src, int len,
                     char *out, int cap, const char *def, int *subst)
{
  int i = 0;

  (void)cp;
  (void)flags;
  (void)def;
  if (len != -1)
    {
      return 0;
    }

  while (src[i])
    {
      if (src[i] > (wchar_t)127)
        {
          return 0;
        }

      i++;
    }
  if (!out)
    {
      return i + 1;
    }

  if (cap < i + 1)
    {
      return 0;
    }

  for (i = 0; src[i]; i++)
    {
      out[i] = (char)src[i];
    }

  out[i] = 0;
  if (subst)
    {
      *subst = 0;
    }

  return i + 1;
}
DWORD
GetFullPathNameW (const wchar_t *in, DWORD cap, wchar_t *out, wchar_t **file)
{
  static const wchar_t prefix[] = L"C:\\work\\";
  size_t j, k = 0;

  (void)file;
  while (prefix[k])
    {
      k++;
    }
  for (j = 0; in[j]; j++)
    {
      ;
    }

  if (k + j + 1U > cap)
    {
      return (DWORD)(k + j + 1U);
    }

  memcpy (out, prefix, k * sizeof (*out));
  memcpy (out + k, in, (j + 1U) * sizeof (*out));
  return (DWORD)(k + j);
}
HANDLE
CreateFileW (const wchar_t *name, DWORD rights, DWORD share, void *sec,
             DWORD disp, DWORD flags, HANDLE tmpl)
{
  char out[1024];
  size_t i = 0;

  while (name[i] && i + 1U < sizeof (out))
    {
      if (name[i] > (wchar_t)127)
        {
          return INVALID_HANDLE_VALUE;
        }

      out[i] = (char)name[i];
      i++;
    }
  out[i] = 0;
  wide_opens++;
  return CreateFileA (out, rights, share, sec, disp, flags, tmpl);
}
HANDLE
CreateFileA (const char *name, DWORD rights, DWORD share, void *sec,
             DWORD disp, DWORD flags, HANDLE tmpl)
{
  (void)rights;
  (void)share;
  (void)sec;
  (void)disp;
  (void)flags;
  (void)tmpl;
  ansi_opens++;
  return (
      HANDLE)(unsigned long)((strstr (name, "owner.dat") != NULL)
                                 ? (changed ? 3 : 2)
                             : (strstr (name, "dir") != NULL && dir_changed)
                                 ? 5
                                 : 4);
}
int
CloseHandle (HANDLE h)
{
  (void)h;
  return 1;
}
int
DeleteFileA (const char *p)
{
  (void)p;
  return 1;
}
int
RemoveDirectoryA (const char *p)
{
  (void)p;
  return 1;
}
int
GetFileInformationByHandle (HANDLE h, BY_HANDLE_FILE_INFORMATION *out)
{
  memset (out, 0, sizeof (*out));
  out->dwVolumeSerialNumber = 0x12;
  out->nNumberOfLinks = mock_link_count;
  out->nFileIndexLow
      = (h == (HANDLE)(unsigned long)3 || h == (HANDLE)(unsigned long)5)
            ? 0x22
            : 0x21;
  out->dwFileAttributes
      = (h == (HANDLE)(unsigned long)4 || h == (HANDLE)(unsigned long)5)
            ? FILE_ATTRIBUTE_DIRECTORY
            : ((h == (HANDLE)(unsigned long)2 && reparse)
                   ? FILE_ATTRIBUTE_REPARSE_POINT
                   : 0);
  return 1;
}
long
_get_osfhandle (int fd)
{
  (void)fd;
  return 2;
}
int
_fileno (FILE *f)
{
  (void)f;
  return 5;
}
int
xtr_win_nt_snapshot_handle (void *h, xtr_win_ea_list *out)
{
  (void)h;
  memset (out, 0, sizeof (*out));
  return XTR_OK;
}
int
xtr_win_nt_apply_list (void *h, const xtr_win_ea_list *list, int *rollback)
{
  (void)h;
  *rollback = 0;
  if (list->count != 1U || list->items[0].name_len != 8U
      || memcmp (list->items[0].name, "XTRODATA", 8)
      || list->items[0].value_len != 4U
      || memcmp (list->items[0].value, "data", 4))
    {
      return XTR_CORRUPT;
    }

  restorations++;
  return XTR_OK;
}
int
xtr_win_ads_restore_exact (HANDLE owner, const xtr_win_ads_part *parts,
                           unsigned count, FILE *verified_stage,
                           FILE *secure_backup, int *rollback_failed)
{
  unsigned char buf[3];

  (void)owner;
  (void)secure_backup;
  *rollback_failed = 0;
  if (count != 1U || parts[0].length != 3UL
      || fseek (verified_stage, parts[0].offset, SEEK_SET) != 0
      || fread (buf, 1, 3, verified_stage) != 3U || memcmp (buf, "ADS", 3))
    {
      return XTR_CORRUPT;
    }

  ads_restorations++;
  return XTR_OK;
}
int
xtr_win_nt_restore_handle (void *h, FILE *stage, xtr_u64 size,
                           const xtr_extra *e, const unsigned char *sha,
                           int *rollback)
{
  xtr_win_ea_list out;
  int rc;

  (void)h;
  *rollback = 0;
  rc = xtr_win_ea_from_manifest (stage, size, e, sha, &out);
  if (rc == XTR_OK)
    {
      if (out.count != 1 || out.items[0].name_len != 8
          || memcmp (out.items[0].name, "XTRODATA", 8)
          || out.items[0].value_len != 4
          || memcmp (out.items[0].value, "data", 4))
        {
          rc = XTR_CORRUPT;
        }

      xtr_win_ea_free (&out);
    }

  if (rc == XTR_OK)
    {
      restorations++;
    }

  return rc;
}
static void
fixture (unsigned char *cen, size_t *cn, unsigned char *loc, size_t *ln)
{
  unsigned char owner[16] = { 1 };
  unsigned char name[] = "XTRODATA", value[] = "data";
  xtr_win_ea ea;
  xtr_win_ea_list list;
  xtr1_digest digest;
  xtr_extra extra;
  FILE *f = tmpfile ();
  size_t used;
  unsigned char body[512];

  CHECK (f != NULL);
  memset (&ea, 0, sizeof (ea));
  ea.name = name;
  ea.name_len = 8;
  ea.value = value;
  ea.value_len = 4;
  list.items = &ea;
  list.count = 1;
  CHECK (xtr_win_ea_to_manifest (&list, owner, f, 0, &digest) == XTR_OK);
  CHECK (digest.manifest_length.lo < sizeof (body));
  CHECK (fread (body, 1, (size_t)digest.manifest_length.lo, f)
         == (size_t)digest.manifest_length.lo);
  memset (&extra, 0, sizeof (extra));
  extra.mode = XTR_V1_INLINE;
  memcpy (extra.owner, owner, 16);
  extra.count = digest.count;
  extra.manifest_len = digest.manifest_length;
  extra.crc32 = digest.crc32;
  CHECK (xtr1_extra_encode (cen + 4, 1000, &extra, 1, body,
                            (size_t)digest.manifest_length.lo, NULL, &used)
         == XTR_OK);
  cen[0] = 0x54;
  cen[1] = 0x58;
  cen[2] = (unsigned char)used;
  cen[3] = (unsigned char)(used >> 8);
  *cn = used + 4;
  CHECK (xtr1_extra_encode (loc + 4, 1000, &extra, 0, NULL, 0, NULL, &used)
         == XTR_OK);
  loc[0] = 0x54;
  loc[1] = 0x58;
  loc[2] = (unsigned char)used;
  loc[3] = (unsigned char)(used >> 8);
  *ln = used + 4;
  fclose (f);
}

/* W3C2B/C: verify UnZip class selection against an actual ADS-only XTMD. */
typedef struct test_ads_input
{
  const unsigned char *data;
  size_t len, at;
} test_ads_input;
static size_t
test_ads_read (void *v, unsigned char *out, size_t n)
{
  test_ads_input *t = (test_ads_input *)v;

  if (n > t->len - t->at)
    {
      n = t->len - t->at;
    }

  if (n)
    {
      memcpy (out, t->data + t->at, n);
    }

  t->at += n;
  return n;
}
static int
test_ads_write (void *v, const unsigned char *p, size_t n)
{
  return fwrite (p, 1, n, (FILE *)v) == n ? 0 : 1;
}
static void
test_ads_selection (void)
{
  static const unsigned char owner[16] = { 1, 2, 3 };
  static const unsigned char payload[] = { 'A', 'D', 'S' };
  static const unsigned short raw[]
      = { ':', 0x96ea, ':', '$', 'D', 'A', 'T', 'A' };
  xtr_ads_name name;
  xtr1_source source;
  xtr1_digest digest;
  xtr1_policy policy;
  xtr1_sink sink;
  xtr_extra outer;
  xtr_u64 length;
  test_ads_input input;
  FILE *f = tmpfile ();
  unsigned before_ea = restorations, before_ads = ads_restorations;
  unsigned char native[22];

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  CHECK (xtr_ads_parse_stream (raw, 8U, &name) == XTR_ADS_OK);
  memset (&source, 0, sizeof (source));
  input.data = payload;
  input.len = 3;
  input.at = 0;
  length.lo = 3;
  length.hi = 0;
  CHECK (xtr_ads_record_source (&name, length, test_ads_read, &input, &source,
                                native)
         == XTR_OK);
  memset (&policy, 0, sizeof (policy));
  policy.max_records = 1024U;
  policy.max_field = 1024UL * 1024UL;
  policy.max_manifest.lo = 32UL * 1024UL * 1024UL;
  sink.context = f;
  sink.write = test_ads_write;
  CHECK (xtr1_write_manifest (owner, &source, 1U, 0, &policy, &sink, &digest)
         == XTR_OK);
  memset (&outer, 0, sizeof (outer));
  outer.mode = XTR_V1_COMPANION;
  memcpy (outer.owner, owner, 16);
  outer.count = digest.count;
  outer.manifest_len = digest.manifest_length;
  outer.crc32 = digest.crc32;
  xtr_unzip_xattrs = 0;
  xtr_unzip_streams = 1;
  CHECK (xtr_apply_win_metadata ((HANDLE)2, f, digest.manifest_length, &outer,
                                 digest.sha256, 0)
         == 0);
  CHECK (ads_restorations == before_ads + 1U && restorations == before_ea);
  xtr_unzip_xattrs = 1;
  xtr_unzip_streams = 0;
  CHECK (xtr_apply_win_metadata ((HANDLE)2, f, digest.manifest_length, &outer,
                                 digest.sha256, 0)
         == 0);
  CHECK (ads_restorations == before_ads + 1U && restorations == before_ea);
  xtr_unzip_xattrs = 1;
  xtr_unzip_streams = 1;
  CHECK (xtr_apply_win_metadata ((HANDLE)2, f, digest.manifest_length, &outer,
                                 digest.sha256, 0)
         == 0);
  CHECK (ads_restorations == before_ads + 2U && restorations == before_ea);
  xtr_unzip_xattrs = 1;
  xtr_unzip_streams = 0;
  fclose (f);
}

/* W2B2B: simulate central registration and successfully decrypted decoded
 * ZIP companion bytes. The parser and Xtro checksum code remain real. */
static void
companion_test (int encrypted, int mismatch, int corrupt, int directory)
{
  unsigned char owner[16] = { 1 }, cen[1000], loc[1000];
  unsigned char name[] = "XTRODATA", value[] = "data";
  xtr_win_ea ea;
  xtr_win_ea_list list;
  xtr_extra extra;
  xtr1_digest dig;
  FILE *f = tmpfile ();
  unsigned char payload[1024];
  size_t size, cn, ln;
  char member[52];
  min_info in, cp;
  FILE *dummy = tmpfile ();
  unsigned before = restorations;

  CHECK (f != NULL && dummy != NULL);
  memset (&ea, 0, sizeof (ea));
  ea.name = name;
  ea.name_len = 8;
  ea.value = value;
  ea.value_len = 4;
  list.items = &ea;
  list.count = 1;
  CHECK (xtr_win_ea_to_manifest (&list, owner, f, encrypted, &dig) == XTR_OK);
  CHECK (fseek (f, 0, SEEK_END) == 0);
  size = (size_t)ftell (f);
  CHECK (size < sizeof (payload));
  CHECK (fseek (f, 0, SEEK_SET) == 0);
  CHECK (fread (payload, 1, size, f) == size);
  fclose (f);
  memset (&extra, 0, sizeof (extra));
  extra.mode = XTR_V1_COMPANION;
  extra.flags = encrypted ? XTR_V1_ENCRYPTED : 0;
  memcpy (extra.owner, owner, 16);
  if (!encrypted)
    {
      extra.count = dig.count;
      extra.manifest_len = dig.manifest_length;
      extra.crc32 = dig.crc32;
    }

  CHECK (xtr1_extra_encode (cen + 4, sizeof (cen) - 4, &extra, 1, NULL, 0,
                            encrypted ? NULL : dig.sha256, &cn)
         == XTR_OK);
  cen[0] = 0x54;
  cen[1] = 0x58;
  cen[2] = (unsigned char)cn;
  cen[3] = (unsigned char)(cn >> 8);
  cn += 4;
  CHECK (xtr1_extra_encode (loc + 4, sizeof (loc) - 4, &extra, 0, NULL, 0,
                            NULL, &ln)
         == XTR_OK);
  loc[0] = 0x54;
  loc[1] = 0x58;
  loc[2] = (unsigned char)ln;
  loc[3] = (unsigned char)(ln >> 8);
  ln += 4;
  CHECK (xtr1_companion_name (owner, member) == XTR_OK);
  memset (&in, 0, sizeof (in));
  memset (&cp, 0, sizeof (cp));
  in.encrypted = (unsigned)encrypted;
  cp.encrypted = (unsigned)(encrypted && !mismatch);
  cp.uncompr_size = (unsigned long)size;
  CHECK (xtr_note_central (&in, cen, (unsigned)cn,
                           directory ? "dir/" : "owner.dat")
         == 0);
  CHECK (xtr_note_central (&cp, NULL, 0, member) == 0);
  if (directory)
    {
      CHECK (xtr_directory_created (&in, "dir/") == 0);
    }
  else
    {
      CHECK (xtr_pin_output (&in, dummy) == 0);
      CHECK (xtr_defer_owner (&in, loc, (unsigned)ln, "owner.dat") == 0);
    }

  CHECK (xtr_stage_begin (&cp, member) == 0);
  if (corrupt)
    {
      payload[20] ^= 0x80;
    }

  CHECK (fwrite (payload, 1, size, xtr_stage_file (member)) == size);
  CHECK (xtr_stage_end (&cp, member) == 0);
  xtr_stage_verified (member);
  CHECK ((xtr_apply_pending (0) == 0) == (!mismatch && !corrupt));
  if (directory)
    {
      CHECK (restorations == before);
      if (!mismatch && !corrupt)
        {
          CHECK (xtr_apply_directories () == 0);
        }
    }

  CHECK (restorations == before + (unsigned)(!mismatch && !corrupt));
  xtr_cleanup_block (&in, 1);
  xtr_cleanup_block (&cp, 1);
  xtr_release_registry ();
  fclose (dummy);
}

int
main (void)
{
  unsigned char cen[2048], loc[2048];
  size_t cn, ln;
  FILE *dummy;
  min_info info;

  fixture (cen, &cn, loc, &ln);
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, cen, (unsigned)cn, "owner.dat") == 0);
  dummy = tmpfile ();
  CHECK (dummy != NULL);
  CHECK (xtr_pin_output (&info, dummy) == 0);
  CHECK (xtr_restore_verified (&info, loc, (unsigned)ln, "owner.dat") == 0);
  CHECK (restorations == 1);
  xtr_cleanup_block (&info, 1);
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, cen, (unsigned)cn, "owner.dat") == 0);
  CHECK (xtr_pin_output (&info, dummy) == 0);
  loc[4 + 8] ^= 0x8;
  CHECK (xtr_restore_verified (&info, loc, (unsigned)ln, "owner.dat") != 0);
  loc[4 + 8] ^= 0x8;
  CHECK (restorations == 1);
  xtr_cleanup_block (&info, 1);
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, cen, (unsigned)cn, "owner.dat") == 0);
  CHECK (xtr_pin_output (&info, dummy) == 0);
  reparse = 1;
  CHECK (xtr_restore_verified (&info, loc, (unsigned)ln, "owner.dat") != 0);
  reparse = 0;
  xtr_cleanup_block (&info, 1);
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, cen, (unsigned)cn, "owner.dat") == 0);
  CHECK (xtr_pin_output (&info, dummy) == 0);
  changed = 1;
  CHECK (xtr_restore_verified (&info, loc, (unsigned)ln, "owner.dat") != 0);
  changed = 0;
  xtr_cleanup_block (&info, 1);
  /* Native directory local-header preflight: independent re-open must
   * check both the original name and the local XTRO extra field. */
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, cen, (unsigned)cn, "dir/") == 0);
  memset (mockzip, 0, sizeof (mockzip));
  memcpy (mockzip, "PK\003\004", 4);
  mockzip[26] = 4;
  mockzip[28] = (unsigned char)ln;
  mockzip[29] = (unsigned char)(ln >> 8);
  memcpy (mockzip + 30, "dir/", 4);
  memcpy (mockzip + 34, loc, ln);
  CHECK (xtr_directory_preflight (&info, 8, 0) == 0);
  CHECK (reopen_bad_flags == 0U);
  CHECK (reopen_good_flags == 1U);
  mockzip[34 + 4 + 8] ^= 0x40;
  CHECK (xtr_directory_preflight (&info, 8, 0) != 0);
  mockzip[34 + 4 + 8] ^= 0x40;
  CHECK (xtr_directory_created (&info, "dir/") == 0);
  CHECK (xtr_apply_pending (0) == 0);
  CHECK (restorations == 1); /* files first, directories afterward */
  dir_changed = 1;
  CHECK (xtr_apply_directories () != 0);
  CHECK (restorations == 1);
  dir_changed = 0;
  CHECK (xtr_apply_directories () == 0);
  CHECK (restorations == 2);
  xtr_cleanup_block (&info, 1);
  xtr_release_registry ();
  memset (&info, 0, sizeof (info));
  CHECK (
      xtr_note_central (&info, NULL, 0,
                        "__XTRO_ZIP__/x/00000000000000000000000000000001.xtm")
      == 0);
  xtr_release_registry ();
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, cen, (unsigned)cn, "owner.dat") == 0);
  CHECK (xtr_directory_preflight (&info, 0, 0) != 0);
  xtr_cleanup_block (&info, 1);
  memset (&info, 0, sizeof (info));
  CHECK (xtr_note_central (&info, NULL, 0, "ordinary.dat") == 0);
  CHECK (info.xtr_central == NULL);
  fclose (dummy);
  test_ads_selection ();
  companion_test (0, 0, 0, 0);
  companion_test (1, 0, 0, 0);
  companion_test (1, 1, 0, 0);
  companion_test (1, 0, 1, 0);
  companion_test (0, 0, 0, 1);
  companion_test (0, 0, 1, 1);
  /* Association constraints must fail before any native write. */
  {
    const char *m = "__XTRO_ZIP__/x/01000000000000000000000000000000.xtm";
    min_info c, d;
    memset (&c, 0, sizeof (c));
    memset (&d, 0, sizeof (d));
    CHECK (xtr_note_central (&c, NULL, 0, m) == 0);
    CHECK (xtr_note_central (&d, NULL, 0, m) != 0); /* duplicate ID */
    xtr_release_registry ();
    memset (&c, 0, sizeof (c));
    c.uncompr_size = XTR_WIN_STAGE_MAX + 1UL;
    CHECK (xtr_note_central (&c, NULL, 0, m) != 0); /* quota */
    xtr_release_registry ();
    memset (&c, 0, sizeof (c));
    CHECK (xtr_note_central (&c, NULL, 0, m) == 0);
    CHECK (xtr_apply_pending (0) != 0); /* orphan */
    CHECK (xtr_apply_pending (1) == 0); /* unrelated selected owner */
    xtr_release_registry ();
  }
  {
    HANDLE w;
    const char lossy[] = "\xff.dat";
    unsigned before = wide_opens;
    w = xtr_open_verified_path ("owner.dat");
    CHECK (w == (HANDLE)(unsigned long)2);
    CHECK (wide_opens > before);
    if (w != INVALID_HANDLE_VALUE)
      {
        CloseHandle (w);
      }

    CHECK (xtr_open_verified_path (lossy) == INVALID_HANDLE_VALUE);
    {
      wchar_t *wname = xtr_widen_exact_acp ("owner.dat");
      CHECK (wname != NULL);
      free (wname);
    }
  }
  /* A streams-only overwrite must never delete EAs and an EA-only
   * overwrite must never delete named streams. Reparse-point rejection
   * must precede truncation or ownership transfer of the HANDLE. */
  {
    FILE *out;
    unsigned before = overwrite_truncations;
    xtr_unzip_streams = 1;
    xtr_unzip_xattrs = 0;
    out = xtr_win_open_existing_output ("owner.dat", 0);
    CHECK (out != NULL);
    CHECK (overwrite_truncations == before + 1U);
    CHECK (overwrite_eas_intact && overwrite_ads_intact);
    if (out)
      {
        fclose (out);
      }

    /* Both restore classes disabled: preserve existing file identity,
     * EA and ADS exactly as when one class is selected. */
    xtr_unzip_streams = 0;
    xtr_unzip_xattrs = 0;
    before = overwrite_truncations;
    out = xtr_win_open_existing_output ("owner.dat", 0);
    CHECK (out != NULL);
    CHECK (overwrite_truncations == before + 1U);
    CHECK (overwrite_eas_intact && overwrite_ads_intact);
    if (out)
      {
        fclose (out);
      }

    xtr_unzip_streams = 0;
    xtr_unzip_xattrs = 1;
    out = xtr_win_open_existing_output ("owner.dat", 1);
    CHECK (out != NULL);
    CHECK (overwrite_eas_intact && overwrite_ads_intact);
    if (out)
      {
        fclose (out);
      }

    reparse = 1;
    before = overwrite_truncations;
    out = xtr_win_open_existing_output ("owner.dat", 0);
    CHECK (out == NULL);
    CHECK (overwrite_truncations == before);
    reparse = 0;
    mock_link_count = 2;
    out = xtr_win_open_existing_output ("owner.dat", 0);
    CHECK (out == NULL);
    CHECK (overwrite_truncations == before);
    mock_link_count = 1;
    overwrite_setend_fail = 1;
    out = xtr_win_open_existing_output ("owner.dat", 0);
    CHECK (out == NULL);
    CHECK (overwrite_truncations == before);
    overwrite_setend_fail = 0;
    overwrite_fd_fail = 1;
    out = xtr_win_open_existing_output ("owner.dat", 0);
    CHECK (out == NULL);
    CHECK (overwrite_truncations == before + 1U);
    overwrite_fd_fail = 0;
    CHECK (overwrite_fd_opens >= 2U);
    CHECK (overwrite_fd_closes == 0U);
    xtr_unzip_xattrs = 1;
    xtr_unzip_streams = 0;
  }
  printf ("Windows UnZip W2B2C1 integration mock: %u checks; %u failed\n",
          tests, failures);
  return failures ? 1 : 0;
}
