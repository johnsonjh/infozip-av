/* SPDX-License-Identifier: MIT-0 */
/* OS/2 Open Watcom native Xtro V1 Zip capture. All metadata stays in memory
 * until ordinary Zip compression/encryption writes the companion. */
#include "zip.h"
#undef local
#include "../xtrmeta/xtros2_ea.h"
#include "../xtrmeta/xtros2_memory.h"
#include "../xtrmeta/xtros2_native.h"
#include "../xtrmeta/xtros2_nls.h"
#include "../xtrmeta/xtrv1.h"
#define local static
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "os2/os2link.h"
#ifndef NO_AES
# include "wzaes.h"
#endif /* ifndef NO_AES */

extern int xtr_zip_xattrs;
extern int fwkcs_md5;
#define OS2_STAGE_MAX (32UL * 1024UL * 1024UL + 36UL)
#define OS2_STAGE_FD 0x7fef

typedef struct xtr_os2_pending
{
  struct xtr_os2_pending *next;
  char member[52], source[64];
  xtr_os2_memory data;
  unsigned aes_version;
} xtr_os2_pending;
static xtr_os2_pending *head, *tail, *active;
static int registered;
static unsigned long ticket;

static void
clear_pending (void)
{
  xtr_os2_pending *p = head, *next;

  while (p)
    {
      next = p->next;
      xtr_os2_memory_free (&p->data);
      free (p);
      p = next;
    }
  head = tail = active = NULL;
}
static int
reserve_id (unsigned char id[16])
{
  struct zlist far *z;
  xtr_os2_pending *p;
  unsigned tries;

  for (tries = 0; tries < 16U; tries++)
    {
      unsigned i, at;
#ifndef NO_AES
      if (!iz_aes_entropy (id, 16U))
        {
          return 1;
        }

#else /* ifndef NO_AES */
      return 1;

#endif /* ifndef NO_AES */
      for (i = 0; i < 16U; i++)
        {
          if (id[i])
            {
              break;
            }
        }

      if (i == 16U)
        {
          continue;
        }

      for (p = head; p; p = p->next)
        {
          char name[52];
          if (xtr1_companion_name (id, name) == XTR_OK
              && !strcmp (name, p->member))
            {
              break;
            }
        }

      if (p)
        {
          continue;
        }

      for (z = zfiles; z; z = z->nxt)
        {
          const unsigned char *field = (const unsigned char *)z->cextra;
          for (at = 0; field && at + 4U <= z->cext;)
            {
              unsigned n
                  = (unsigned)field[at + 2U] | ((unsigned)field[at + 3U] << 8);
              if (n > z->cext - at - 4U)
                {
                  return 1;
                }

              if (field[at] == 0x54 && field[at + 1U] == 0x58 && n >= 40U
                  && !memcmp (field + at + 4U, "XTRO", 4U)
                  && !memcmp (field + at + 12U, id, 16U))
                {
                  break;
                }

              at += n + 4U;
            }

          if (at + 4U <= z->cext)
            {
              break;
            }
        }

      if (!z)
        {
          return 0;
        }
    }

  return 1;
}
static int
append_extra (struct zlist far *z, const unsigned char *payload, size_t len,
              int central)
{
  unsigned old = central ? z->cext : z->ext;
  char *original = central ? z->cextra : z->extra;
  unsigned at = 0;
  char *newbuf;

  while (at < old)
    {
      unsigned tag, n;
      if (old - at < 4U)
        {
          return ZE_FORM;
        }

      tag = (unsigned)(unsigned char)original[at]
            | ((unsigned)(unsigned char)original[at + 1U] << 8);
      n = (unsigned)(unsigned char)original[at + 2U]
          | ((unsigned)(unsigned char)original[at + 3U] << 8);
      if (n > old - at - 4U || tag == XTR_V1_EXTRA_ID)
        {
          return ZE_FORM;
        }

      at += n + 4U;
    }
  if (len > 65531U || old > 65535U - len - 4U)
    {
      return ZE_BIG;
    }

  newbuf = (char *)malloc (old + len + 4U);
  if (!newbuf)
    {
      return ZE_MEM;
    }

  if (old)
    {
      memcpy (newbuf, original, old);
    }

  newbuf[old] = 0x54;
  newbuf[old + 1] = 0x58;
  newbuf[old + 2] = (char)(len & 255U);
  newbuf[old + 3] = (char)((len >> 8) & 255U);
  memcpy (newbuf + old + 4U, payload, len);
  if (central)
    {
      if (z->cextra != z->extra)
        {
          free (z->cextra);
        }

      z->cextra = newbuf;
      z->cext = (ush)(old + len + 4U);
    }
  else
    {
      free (z->extra);
      z->extra = newbuf;
      z->ext = (ush)(old + len + 4U);
    }

  return ZE_OK;
}
static void
default_policy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = 65536UL;
  p->max_field = 65536UL;
  p->max_manifest.lo = OS2_STAGE_MAX;
}
int
xtr_zip_is_stage (const char *path, const char *member)
{
  xtr_os2_pending *p;

  for (p = head; p; p = p->next)
    {
      if (path && member && !strcmp (p->source, path)
          && !strcmp (p->member, member))
        {
          return 1;
        }
    }

  return 0;
}
int
xtr_os2_stage_stat (const char *name, ulg *attr, long *length, iztimes *t)
{
  xtr_os2_pending *p;

  for (p = head; p; p = p->next)
    {
      if (name && !strcmp (name, p->source))
        {
          if (attr)
            {
              *attr = ((ulg)S_IFREG << 16);
            }

          if (length)
            {
              *length = (long)p->data.length;
            }

          if (t)
            {
              memset (t, 0, sizeof (*t));
            }

          return 1;
        }
    }

  return 0;
}
int
xtr_os2_stage_open (const char *name, int flags)
{
  xtr_os2_pending *p;

  for (p = head; p; p = p->next)
    {
      if (name && !strcmp (name, p->source))
        {
          if (active)
            {
              return -1;
            }

          active = p;
          xtr_os2_memory_rewind (&p->data);
          return OS2_STAGE_FD;
        }
    }

  return open (name, flags);
}
int
xtr_os2_stage_read (int fd, void *buf, unsigned n)
{
  if (fd == OS2_STAGE_FD)
    {
      if (!active)
        {
          return -1;
        }

      return (int)xtr_os2_memory_read (&active->data, (unsigned char *)buf, n);
    }

  return read (fd, buf, n);
}
int
xtr_os2_stage_close (int fd)
{
  if (fd == OS2_STAGE_FD)
    {
      if (!active)
        {
          return -1;
        }

      active = NULL;
      return 0;
    }

  return close (fd);
}
int
xtr_zip_capture (struct zlist far *z, int isdir, int issym, int encrypted,
                 int original_fd)
{
  unsigned char *native = NULL, id[16], locbuf[128], *central = NULL;
  xtr_os2_ea_item *items = NULL;
  xtr_os2_ea_source *sources = NULL;
  xtr1_source *flat = NULL;
  xtr1_digest digest;
  xtr_extra outer;
  xtr1_policy policy;
  xtr1_sink sink;
  xtr_os2_pending *p = NULL;
  size_t natlen = 0, count = 0U, actual = 0U, i, ln = 0U, cn = 0U;
  int rc = ZE_TEMP;
  char resolved[1024];
  const char *sourcepath = z->name;

  (void)isdir;
  (void)original_fd;
  if (!xtr_zip_xattrs || xtr_zip_is_stage (z->name, z->iname))
    {
      return ZE_OK;
    }

  if (!z->name || !z->iname || !strcmp (z->name, "-")
      || !strncmp (z->iname, "__XTRO_ZIP__/", 13))
    {
      return ZE_PARMS;
    }

  if (encrypted && fwkcs_md5)
    {
      return ZE_PARMS;
    }

  /* A kLIBC link is an ordinary native file.  Native Open Watcom Dos*
   * functions do not interpret its SYMLINK EA. -y retains that file. */
  if (!issym)
    {
      if (iz_os2_link_resolve (z->name, resolved, sizeof (resolved), 1))
        {
          return ZE_OPEN;
        }

      sourcepath = resolved;
    }

  rc = xtr_os2_query_native_eas (sourcepath, &native, &natlen);
  if (rc == 1)
    {
      return ZE_OK;
    }

  if (rc != 0)
    {
      return ZE_OPEN;
    }

  if (xtr_os2_ea_parse_ex (native, natlen, NULL, 0, &count,
                           xtr_os2_ea_native_equal, NULL)
      != XTR_OS2_EA_OK)
    {
      rc = ZE_FORM;
      goto done;
    }

  if (!count)
    {
      rc = ZE_OK;
      goto done;
    }

  /* A full 64 KiB field on the stack leaves too little headroom under LX. */
  central = (unsigned char *)malloc (65535U);
  if (!central)
    {
      rc = ZE_MEM;
      goto done;
    }

  if (count > (size_t)-1 / sizeof (*items))
    {
      goto done;
    }

  items = (xtr_os2_ea_item *)malloc (count * sizeof (*items));
  sources = (xtr_os2_ea_source *)calloc (count, sizeof (*sources));
  flat = (xtr1_source *)calloc (count, sizeof (*flat));
  if (!items || !sources || !flat)
    {
      rc = ZE_MEM;
      goto done;
    }

  if (xtr_os2_ea_parse_ex (native, natlen, items, count, &actual,
                           xtr_os2_ea_native_equal, NULL)
          != XTR_OS2_EA_OK
      || actual != count)
    {
      rc = ZE_FORM;
      goto done;
    }

  qsort (items, count, sizeof (*items), xtr_os2_ea_item_compare);
  for (i = 0; i < count; i++)
    {
      if (xtr_os2_ea_source_init (&sources[i], &items[i]) != XTR_OS2_EA_OK)
        {
          rc = ZE_FORM;
          goto done;
        }

      flat[i] = sources[i].source;
    }

  if (reserve_id (id))
    {
      rc = ZE_TEMP;
      goto done;
    }

  p = (xtr_os2_pending *)calloc (1, sizeof (*p));
  if (!p)
    {
      rc = ZE_MEM;
      goto done;
    }

  xtr_os2_memory_init (&p->data, OS2_STAGE_MAX);
  sink.context = &p->data;
  sink.write = xtr_os2_memory_write;
  default_policy (&policy);
  if (xtr1_write_manifest (id, flat, count, encrypted, &policy, &sink, &digest)
      != XTR_OK)
    {
      rc = ZE_TEMP;
      goto done;
    }

  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, id, 16U);
  outer.mode = XTR_V1_COMPANION;
  outer.flags = encrypted ? XTR_V1_ENCRYPTED : 0;
  if (!encrypted)
    {
      outer.count = digest.count;
      outer.manifest_len = digest.manifest_length;
      outer.crc32 = digest.crc32;
    }

  /* Never inline confidential values; inline unencrypted only when both
   * the central field and original local extra fields can accommodate. */
  if (!encrypted && digest.manifest_length.hi == 0
      && digest.manifest_length.lo + 44UL <= 65535UL - z->cext)
    {
      outer.mode = XTR_V1_INLINE;
      if (xtr1_extra_encode (locbuf, sizeof (locbuf), &outer, 0, NULL, 0, NULL,
                             &ln)
              != XTR_OK
          || xtr1_extra_encode (central, 65535U, &outer, 1, p->data.bytes,
                                p->data.length, NULL, &cn)
                 != XTR_OK)
        {
          rc = ZE_FORM;
          goto done;
        }
    }
  else
    {
      if (xtr1_extra_encode (locbuf, sizeof (locbuf), &outer, 0, NULL, 0, NULL,
                             &ln)
              != XTR_OK
          || xtr1_extra_encode (central, 65535U, &outer, 1, NULL, 0,
                                encrypted ? NULL : digest.sha256, &cn)
                 != XTR_OK)
        {
          rc = ZE_FORM;
          goto done;
        }

      if (xtr1_companion_name (id, p->member) != XTR_OK)
        {
          rc = ZE_FORM;
          goto done;
        }

      /* Pseudo-path identifies an in-process memory buffer ONLY. */
      ++ticket;
      if (ticket == 0UL || ticket > 999999UL)
        {
          rc = ZE_TEMP;
          goto done;
        }

      sprintf (p->source, "@XTRO-MEM-%06lu", ticket);
    }

  /* The initial local and central extra fields may alias the same heap
   * block. Clone/replace the central field first, otherwise replacing
   * the local field can leave z->cextra pointing into freed storage. */
  if ((rc = append_extra (z, central, cn, 1)) != ZE_OK)
    {
      goto done;
    }

  if ((rc = append_extra (z, locbuf, ln, 0)) != ZE_OK)
    {
      goto done;
    }

  if (outer.mode == XTR_V1_COMPANION)
    {
      if (!registered)
        {
          if (atexit (clear_pending) != 0)
            {
              rc = ZE_TEMP;
              goto done;
            }

          registered = 1;
        }

      if (tail)
        {
          tail->next = p;
        }
      else
        {
          head = p;
        }

      tail = p;
      p = NULL;
    }

  rc = ZE_OK;
done:
  if (central)
    {
      xtr_os2_memory_wipe (central, 65535U);
      free (central);
    }

  if (native)
    {
      xtr_os2_memory_wipe (native, natlen);
      free (native);
    }

  free (items);
  free (sources);
  free (flat);
  if (p)
    {
      xtr_os2_memory_free (&p->data);
      free (p);
    }

  return rc;
}
void
xtr_zip_owner_complete (const struct zlist far *z)
{
  xtr_os2_pending *p;
  unsigned at;
  const unsigned char *e = (const unsigned char *)z->cextra;

  if (!e)
    {
      return;
    }

  for (p = head; p; p = p->next)
    {
      unsigned char id[16];
      for (at = 0; at + 4U <= z->cext;)
        {
          unsigned n = (unsigned)e[at + 2U] | ((unsigned)e[at + 3U] << 8);
          if (n > z->cext - at - 4U)
            {
              break;
            }

          if (e[at] == 0x54 && e[at + 1U] == 0x58 && n >= 40U
              && !memcmp (e + at + 4U, "XTRO", 4))
            {
              memcpy (id, e + at + 12U, 16U);
              if (xtr1_companion_matches (id, p->member, strlen (p->member))
                  == XTR_OK)
                {
                  unsigned step;
                  p->aes_version = 0;
                  for (step = 0; step + 4U <= z->cext;)
                    {
                      unsigned sz = (unsigned)e[step + 2U]
                                    | ((unsigned)e[step + 3U] << 8);
                      if (sz > z->cext - step - 4U)
                        {
                          break;
                        }

                      if (e[step] == 1 && e[step + 1U] == 0x99 && sz >= 7U)
                        {
                          p->aes_version = (unsigned)e[step + 4U];
                        }

                      step += sz + 4U;
                    }

                  return;
                }
            }

          at += 4U + n;
        }
    }
}
unsigned
xtr_zip_stage_aes_version (void)
{
  return head ? head->aes_version : 0U;
}
int
xtr_zip_next_companion (char source[64], char member[52])
{
  if (!head)
    {
      return 0;
    }

  strcpy (source, head->source);
  strcpy (member, head->member);
  return 1;
}
void
xtr_zip_companion_done (void)
{
  xtr_os2_pending *p = head;

  if (!p)
    {
      return;
    }

  head = p->next;
  if (!head)
    {
      tail = NULL;
    }

  if (active == p)
    {
      active = NULL;
    }

  xtr_os2_memory_free (&p->data);
  free (p);
}
