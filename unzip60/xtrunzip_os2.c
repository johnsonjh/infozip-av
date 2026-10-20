/* SPDX-License-Identifier: MIT-0 */
/* Native OS/2 Xtro V1 restore adapter. No kLIBC, private temp files, or
 * native metadata writes before the selected archive passes verification. */
#if defined(XTR_OS2_NATIVE) && !defined(SFX) && !defined(DLL)
# include "../xtrmeta/xtros2_decode.h"
# include "../xtrmeta/xtros2_memory.h"
# include "../xtrmeta/xtros2_nls.h"
# include <fcntl.h>
# include <io.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/stat.h>
# define XTR_OS2_STAGE_LIMIT (32UL * 1024UL * 1024UL + 36UL)
# define XTR_OS2_TOTAL_LIMIT (128UL * 1024UL * 1024UL)
# define XTR_OS2_MAX_OWNERS 65536UL
extern int iz_os2_xtr_stage_native (const char *, const unsigned char *,
                                    size_t);
extern int iz_os2_link_safe_path (const char *);
extern int iz_os2_xtr_ea_complete (int);
static int xtr_restore_rejected;
static int xtr_exit_hook;
typedef struct xtr_pending_restore
{
  struct xtr_pending_restore *next;
  unsigned char id[16], sha[32];
  xtr_extra outer;
  unsigned owner_crypto, companion_crypto, owner_strength, companion_strength;
  unsigned long owner_iterations, companion_iterations;
  int companion_fwkcs, is_dir;
  int has_owner, has_companion, owner_verified, companion_verified;
  int fd;
  char *output_name;
  xtr_os2_memory stage;
} xtr_pending_restore;
static xtr_pending_restore *xtr_pending_head, *xtr_active;
static unsigned long xtr_reserved, xtr_advertised, xtr_registry_count;
static unsigned
xtr_transport (const min_info *in)
{
# ifndef NO_AES
  if (in->aes_strength)
    {
      if (in->aes_version == 1U)
        {
          return 2U;
        }

      if (in->aes_version == 2U)
        {
          return 3U;
        }

      if (in->aes_version == 3U)
        {
          return 4U;
        }

      return 5U;
    }

# endif /* ifndef NO_AES */
  return in->encrypted ? 1U : 0U;
}
static xtr_pending_restore *
xtr_lookup (const unsigned char id[16], int create)
{
  xtr_pending_restore *p;

  for (p = xtr_pending_head; p; p = p->next)
    {
      if (!memcmp (p->id, id, 16))
        {
          return p;
        }
    }

  if (!create || xtr_registry_count >= XTR_OS2_MAX_OWNERS)
    {
      return NULL;
    }

  p = (xtr_pending_restore *)calloc (1, sizeof (*p));
  if (!p)
    {
      return NULL;
    }

  memcpy (p->id, id, 16);
  p->fd = -1;
  xtr_os2_memory_init (&p->stage, XTR_OS2_STAGE_LIMIT);
  p->next = xtr_pending_head;
  xtr_pending_head = p;
  xtr_registry_count++;
  return p;
}
static int
xtr_id_from_name (const char *name, unsigned char id[16])
{
  unsigned i;

  if (!name || strlen (name) != 51U || strncmp (name, "__XTRO_ZIP__/x/", 15)
      || strcmp (name + 47, ".xtm"))
    {
      return 1;
    }

  for (i = 0; i < 16; i++)
    {
      unsigned a, b;
      char x = name[15 + 2 * i], y = name[16 + 2 * i];
      a = x >= '0' && x <= '9'   ? (unsigned)(x - '0')
          : x >= 'a' && x <= 'f' ? (unsigned)(x - 'a' + 10)
                                 : 16U;
      b = y >= '0' && y <= '9'   ? (unsigned)(y - '0')
          : y >= 'a' && y <= 'f' ? (unsigned)(y - 'a' + 10)
                                 : 16U;
      if (a > 15U || b > 15U)
        {
          return 1;
        }

      id[i] = (unsigned char)((a << 4) | b);
    }

  return xtr1_companion_matches (id, name, strlen (name)) != XTR_OK;
}
static void
xtr_release_registry (void)
{
  xtr_pending_restore *p = xtr_pending_head, *next;

  while (p)
    {
      next = p->next;
      if (p->fd >= 0)
        {
          close (p->fd);
        }

      xtr_os2_memory_free (&p->stage);
      free (p->output_name);
      free (p);
      p = next;
    }
  xtr_pending_head = xtr_active = NULL;
  xtr_registry_count = xtr_reserved = xtr_advertised = 0;
}
static int
xtr_locate (const unsigned char *s, size_t n, const unsigned char **value,
            size_t *len)
{
  size_t i = 0;

  *value = NULL;
  *len = 0;
  while (i < n)
    {
      unsigned id, sz;
      if (!s || n - i < 4)
        {
          return XTR_CORRUPT;
        }

      id = (unsigned)s[i] | ((unsigned)s[i + 1] << 8);
      sz = (unsigned)s[i + 2] | ((unsigned)s[i + 3] << 8);
      i += 4;
      if (sz > n - i)
        {
          return XTR_CORRUPT;
        }

      if (id == XTR_V1_EXTRA_ID)
        {
          if (*value)
            {
              return XTR_CORRUPT;
            }

          *value = s + i;
          *len = sz;
        }

      i += sz;
    }
  return XTR_OK;
}
static int
xtr_note_central (min_info *in, const uch *ef, unsigned len, const char *name)
{
  const unsigned char *v;
  size_t n;
  unsigned char id[16], sha[32];
  xtr_extra e;
  xtr_pending_restore *p;

  in->xtr_central = NULL;
  in->xtr_source_name = NULL;
  in->xtr_central_len = 0;
  in->xtr_restore_fd = -1;
  in->xtr_companion = 0;
  if (xtr_locate (ef, len, &v, &n) != XTR_OK)
    {
      goto fail;
    }

  if (!strncmp (name, "__XTRO_ZIP__/", 13))
    {
      unsigned long size;
      if (v || xtr_id_from_name (name, id))
        {
          goto fail;
        }

      if (in->uncompr_size > XTR_OS2_STAGE_LIMIT
          || in->uncompr_size > XTR_OS2_TOTAL_LIMIT - xtr_advertised)
        {
          goto fail;
        }

      size = (unsigned long)in->uncompr_size;
      p = xtr_lookup (id, 1);
      if (!p || p->has_companion)
        {
          goto fail;
        }

      p->has_companion = 1;
      p->companion_crypto = xtr_transport (in);
      p->companion_fwkcs = in->fwkcs_md5;
# ifndef NO_AES
      p->companion_strength = in->aes_strength;
      p->companion_iterations = in->aes_iterations;
# endif /* ifndef NO_AES */
      xtr_advertised += size;
      in->xtr_companion = 1;
      in->textmode = 0;
      return 0;
    }

  if (!v)
    {
      return 0;
    }

  if (xtr1_extra_decode (v, n, 1, &e, sha) != XTR_OK)
    {
      goto fail;
    }

  in->xtr_central = (unsigned char *)malloc (n);
  if (!in->xtr_central)
    {
      goto fail;
    }

  memcpy (in->xtr_central, v, n);
  in->xtr_central_len = (unsigned)n;
  if (name[0] && name[strlen (name) - 1] == '/')
    {
      in->xtr_source_name = (char *)malloc (strlen (name) + 1U);
      if (!in->xtr_source_name)
        {
          goto fail;
        }

      strcpy (in->xtr_source_name, name);
    }

  if (e.mode == XTR_V1_COMPANION)
    {
      p = xtr_lookup (e.owner, 1);
      if (!p || p->has_owner)
        {
          goto fail;
        }

      p->has_owner = 1;
      p->outer = e;
      memcpy (p->sha, sha, 32);
      p->owner_crypto = xtr_transport (in);
# ifndef NO_AES
      p->owner_strength = in->aes_strength;
      p->owner_iterations = in->aes_iterations;
# endif /* ifndef NO_AES */
    }

  return 0;

fail:
  fprintf (stderr, "unzip: invalid OS/2 Xtro metadata: %s\n", name);
  free (in->xtr_central);
  free (in->xtr_source_name);
  in->xtr_central = NULL;
  in->xtr_source_name = NULL;
  xtr_restore_rejected = 1;
  return 1;
}
static void
xtr_cleanup_block (min_info *entries, unsigned n)
{
  unsigned i;

  for (i = 0; i < n; i++)
    {
      if (entries[i].xtr_restore_fd >= 0)
        {
          close (entries[i].xtr_restore_fd);
        }

      entries[i].xtr_restore_fd = -1;
      free (entries[i].xtr_central);
      free (entries[i].xtr_source_name);
      entries[i].xtr_central = NULL;
      entries[i].xtr_source_name = NULL;
      entries[i].xtr_central_len = 0;
    }
}
static int
xtr_pin_output (min_info *info, FILE *out)
{
  struct stat st;
  int fd;

  if (!info->xtr_central)
    {
      return 0;
    }

  if (!out)
    {
      return 1;
    }

  fd = dup (fileno (out));
  if (fd < 0)
    {
      return 1;
    }

  if (fstat (fd, &st) != 0 || (st.st_mode & S_IFMT) != S_IFREG)
    {
      close (fd);
      return 1;
    }

  info->xtr_restore_fd = fd;
  return 0;
}
/* OS/2 lacks openat(O_NOFOLLOW). Native link-EA path checks are repeated
 * immediately prior to any metadata write; we do not claim race immunity
 * against an independently malicious concurrent filesystem actor. */
static int
xtr_output_ok (const char *path, int directory)
{
  struct stat st;
  size_t n;
  char name[260];

  if (!path || !iz_os2_link_safe_path (path))
    {
      return 0;
    }

  n = strlen (path);
  if (!n || n >= sizeof (name))
    {
      return 0;
    }

  memcpy (name, path, n + 1);
  if (directory && n && (name[n - 1] == '/' || name[n - 1] == '\\'))
    {
      name[n - 1] = '\0';
    }

  if (stat (name, &st) != 0)
    {
      return 0;
    }

  return directory ? ((st.st_mode & S_IFMT) == S_IFDIR)
                   : ((st.st_mode & S_IFMT) == S_IFREG);
}
/* Local headers for directory entries are not otherwise parsed by UnZip.
 * Seek/restore the archive handle with strict offset and field bounds. */
static int
xtr_directory_preflight (min_info *info, int fd, zoff_t extra)
{
  unsigned char h[30], *ef = NULL, *name = NULL;
  const unsigned char *loc;
  size_t ln;
  long save, at;
  unsigned fn, sz;
  xtr_extra e;
  int bad = 1;

  if (!info || !info->xtr_central || !info->xtr_source_name || info->encrypted
      || info->diskstart || info->compression_method || info->compr_size
      || info->uncompr_size || info->crc || info->offset < 0 || extra < 0)
    {
      return 1;
    }

  save = lseek (fd, 0L, SEEK_CUR);
  if (save < 0 || info->offset > 0x7fffffffL - extra)
    {
      return 1;
    }

  at = (long)(info->offset + extra);
  if (lseek (fd, at, SEEK_SET) < 0 || read (fd, h, 30) != 30)
    {
      goto done;
    }

  if (memcmp (h, "PK\003\004", 4) != 0 || (h[6] & 9U) || h[8] || h[9]
      || memcmp (h + 14, "\0\0\0\0\0\0\0\0\0\0\0\0", 12) != 0)
    {
      goto done;
    }

  fn = (unsigned)h[26] | ((unsigned)h[27] << 8);
  sz = (unsigned)h[28] | ((unsigned)h[29] << 8);
  if (!fn || fn != strlen (info->xtr_source_name))
    {
      goto done;
    }

  name = (unsigned char *)malloc (fn);
  ef = (unsigned char *)malloc (sz ? sz : 1);
  if (!name || !ef || read (fd, name, fn) != (int)fn
      || memcmp (name, info->xtr_source_name, fn) != 0
      || read (fd, ef, sz) != (int)sz
      || xtr_locate (ef, sz, &loc, &ln) != XTR_OK || !loc
      || xtr1_check_headers (loc, ln, info->xtr_central, info->xtr_central_len,
                             &e, NULL)
             != XTR_OK)
    {
      goto done;
    }

  bad = 0;
done:
  free (name);
  free (ef);
  if (lseek (fd, save, SEEK_SET) != save)
    {
      return 1;
    }

  return bad;
}
static int
xtr_save_name (xtr_pending_restore *p, const char *name, int dir)
{
  if (!p || p->owner_verified || !xtr_output_ok (name, dir))
    {
      return 1;
    }

  p->output_name = (char *)malloc (strlen (name) + 1U);
  if (!p->output_name)
    {
      return 1;
    }

  strcpy (p->output_name, name);
  p->is_dir = dir;
  p->owner_verified = 1;
  return 0;
}
static int
xtr_set_inline (min_info *info, const char *name, const xtr_extra *outer,
                const unsigned char *manifest, size_t n, int dir)
{
  xtr_pending_restore *p;

  if (outer->manifest_len.hi || outer->manifest_len.lo != n
      || n > XTR_OS2_TOTAL_LIMIT - xtr_reserved)
    {
      return 1;
    }

  p = xtr_lookup (outer->owner, 1);
  if (!p || p->has_owner || p->has_companion)
    {
      return 1;
    }

  if (xtr_save_name (p, name, dir))
    {
      return 1;
    }

  if (xtr_os2_memory_write (&p->stage, manifest, n))
    {
      return 1;
    }

  p->has_owner = p->has_companion = p->companion_verified = 1;
  p->outer = *outer;
  xtr_reserved += (unsigned long)n;
  return 0;
}
static int
xtr_directory_created (min_info *info, const char *name)
{
  xtr_extra e;
  xtr_pending_restore *p;

  if (!info || !info->xtr_central)
    {
      return 0;
    }

  if (xtr1_extra_decode (info->xtr_central, info->xtr_central_len, 1, &e, NULL)
      != XTR_OK)
    {
      return 1;
    }

  if (e.mode == XTR_V1_INLINE)
    {
      return xtr_set_inline (info, name, &e, info->xtr_central + 40,
                             info->xtr_central_len - 40U, 1);
    }

  p = xtr_lookup (e.owner, 0);
  return !p || !p->has_owner || xtr_save_name (p, name, 1);
}
static int
xtr_restore_verified (min_info *info, const uch *local, unsigned len,
                      const char *name)
{
  const unsigned char *v;
  size_t n;
  xtr_extra e;
  int rc;

  if (!info->xtr_central)
    {
      return 0;
    }

  rc = xtr_locate (local, len, &v, &n);
  if (rc || !v
      || xtr1_check_headers (v, n, info->xtr_central, info->xtr_central_len,
                             &e, NULL)
             != XTR_OK
      || e.mode != XTR_V1_INLINE || info->xtr_restore_fd < 0)
    {
      return 1;
    }

  rc = xtr_set_inline (info, name, &e, info->xtr_central + 40,
                       info->xtr_central_len - 40U, 0);
  close (info->xtr_restore_fd);
  info->xtr_restore_fd = -1;
  return rc;
}
static int
xtr_stage_begin (min_info *info, const char *name)
{
  unsigned char id[16];
  xtr_pending_restore *p;
  unsigned long bytes;

  if (!info->xtr_companion || xtr_active || xtr_id_from_name (name, id)
      || info->uncompr_size > XTR_OS2_STAGE_LIMIT
      || info->uncompr_size > XTR_OS2_TOTAL_LIMIT - xtr_reserved)
    {
      return 1;
    }

  bytes = (unsigned long)info->uncompr_size;
  p = xtr_lookup (id, 0);
  if (!p || !p->has_companion || p->stage.length)
    {
      return 1;
    }

  xtr_reserved += bytes;
  xtr_active = p;
  return 0;
}
static FILE *
xtr_stage_file (const char *name)
{
  unsigned char id[16];

  if (!xtr_active || xtr_id_from_name (name, id)
      || memcmp (id, xtr_active->id, 16))
    {
      return NULL;
    }

  /* Sentinel: fileio.c intercepts every byte before any C-runtime write. */
  return stdout;
}
int
xtr_os2_stage_write (const unsigned char *b, size_t n)
{
  if (!xtr_active)
    {
      return 1;
    }

  return xtr_os2_memory_write (&xtr_active->stage, b, n) ? 1 : 0;
}
static int
xtr_stage_end (min_info *info, const char *name)
{
  unsigned char id[16];
  int bad;

  if (!xtr_active || xtr_id_from_name (name, id)
      || memcmp (id, xtr_active->id, 16))
    {
      return 1;
    }

  bad = xtr_active->stage.length != (size_t)info->uncompr_size;
  xtr_os2_memory_rewind (&xtr_active->stage);
  xtr_active = NULL;
  return bad;
}
static void
xtr_stage_verified (const char *name)
{
  unsigned char id[16];
  xtr_pending_restore *p;

  if (xtr_id_from_name (name, id))
    {
      return;
    }

  p = xtr_lookup (id, 0);
  if (p)
    {
      p->companion_verified = 1;
    }
}
static int
xtr_defer_owner (min_info *info, const uch *local, unsigned len,
                 const char *name)
{
  const unsigned char *v;
  size_t n;
  xtr_extra e;
  xtr_pending_restore *p;
  int fd = info->xtr_restore_fd;

  info->xtr_restore_fd = -1;
  if (fd < 0 || xtr_locate (local, len, &v, &n) != XTR_OK || !v
      || xtr1_check_headers (v, n, info->xtr_central, info->xtr_central_len,
                             &e, NULL)
             != XTR_OK
      || e.mode != XTR_V1_COMPANION)
    {
      if (fd >= 0)
        {
          close (fd);
        }

      return 1;
    }

  p = xtr_lookup (e.owner, 0);
  if (!p || !p->has_owner || xtr_save_name (p, name, 0))
    {
      close (fd);
      return 1;
    }

  p->fd = fd;
  return 0;
}
static int
xtr_apply_pending (int selective)
{
  xtr_pending_restore *p;
  unsigned char *native = NULL;
  size_t native_len = 0;
  int rc;

  for (p = xtr_pending_head; p; p = p->next)
    {
      if (selective && !p->has_owner)
        {
          continue;
        }

      if (!p->has_owner || !p->has_companion || !p->companion_verified
          || p->owner_crypto > 4U || p->companion_crypto > 4U
          || (p->is_dir && p->owner_crypto != 0U)
          || !((p->owner_crypto == p->companion_crypto
                && p->owner_strength == p->companion_strength
                && p->owner_iterations == p->companion_iterations)
               || (p->is_dir && p->owner_crypto == 0U
                   && p->companion_crypto != 0U
                   && (p->outer.flags & XTR_V1_ENCRYPTED)))
          || ((p->outer.flags & XTR_V1_ENCRYPTED) != 0)
                 != (p->companion_crypto != 0)
          || (p->companion_crypto != 0 && p->companion_fwkcs))
        {
          fprintf (stderr, "unzip: OS/2 Xtro owner/companion mismatch\n");
          return 1;
        }

      if (!p->owner_verified)
        {
          continue;
        }

      if (!xtr_output_ok (p->output_name, p->is_dir))
        {
          return 1;
        }

      if (p->stage.length > XTR_OS2_STAGE_LIMIT)
        {
          return 1;
        }

      rc = xtr_os2_decode_manifest (
          p->stage.bytes, p->stage.length, &p->outer,
          (p->outer.flags & XTR_V1_ENCRYPTED || p->outer.mode == XTR_V1_INLINE)
              ? NULL
              : p->sha,
          xtr_os2_ea_native_equal, NULL, &native, &native_len);
      if (rc != XTR_OK)
        {
          fprintf (stderr, "unzip: OS/2 Xtro manifest invalid (%d)\n", rc);
          return 1;
        }

      /* Store verified EA bytes; the OS/2 adapter merges with 0x0009
       * before performing any filesystem changes. */
      rc = iz_os2_xtr_stage_native (p->output_name, native, native_len);
      if (native)
        {
          xtr_os2_memory_wipe (native, native_len);
          free (native);
        }

      native = NULL;
      native_len = 0U;
      if (rc != PK_OK)
        {
          return 1;
        }
    }

  return 0;
}
static int
xtr_apply_directories (void)
{
  return 0;
}
#endif /* if defined( XTR_OS2_NATIVE ) && !defined( SFX ) && !defined( DLL )  \
        */
