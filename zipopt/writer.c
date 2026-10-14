/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* zipopt ZIP member/header rebuilder w/seekable-output */

#ifndef _FILE_OFFSET_BITS
# define _FILE_OFFSET_BITS 64
#endif /* ifndef _FILE_OFFSET_BITS */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
# define _POSIX_C_SOURCE 200809L
#endif /* if !defined( _POSIX_C_SOURCE ) */

#include "writer.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
# include <io.h>
# include "win32_port.h"
# define unlink _unlink
# define close _close
# define fdopen _fdopen
# define mkstemp iz_win_mkstemp
# define link(a,b) iz_win_publish_noreplace((a),(b))
typedef int zo_sigmask_t;
#else
# include <unistd.h>
typedef sigset_t zo_sigmask_t;
#endif

/*
 * The only work done in the interrupt handler is async-signal-safe:
 * unlink the (already named) work file and terminate.  All other temporary
 * streams are tmpfile() objects, automatically unlinked by the OS.
 * Block handled signals while modifying the pathname to avoid observing
 * an incomplete or freed allocation from a handler. Windows currently only
 * performs synchronous normal/error cleanup (no POSIX signal handler).
 */

static const char *volatile zo_interrupt_path;

static int
zo_signal_mask (int block, zo_sigmask_t *previous)
{
#ifdef _WIN32
  /* Native Win32 has no POSIX signal mask. Normal/error cleanup still
   * removes the exclusive temporary; publication remains fail-closed. */
  (void)block;
  (void)previous;
  return 1;
#else
  sigset_t set;

  if (sigemptyset (&set) != 0 || sigaddset (&set, SIGINT) != 0
      || sigaddset (&set, SIGTERM) != 0 || sigaddset (&set, SIGHUP) != 0
      || sigaddset (&set, SIGQUIT) != 0)
    {
      return 0;
    }

  return sigprocmask (block ? SIG_BLOCK : SIG_SETMASK, block ? &set : previous,
                      block ? previous : NULL)
         == 0;
#endif
}

#ifndef _WIN32
static void
zo_interrupt (int signo)
{
  const char *path = zo_interrupt_path;

  if (path)
    {
      (void)unlink (path);
    }

  _exit (128 + signo);
}

#endif /* !_WIN32 */
int
zo_writer_install_interrupts (void)
{
#ifdef _WIN32
  return 1;
#else
  struct sigaction action, old;
  int signals[4];
  unsigned i;

  signals[0] = SIGINT;
  signals[1] = SIGTERM;
  signals[2] = SIGHUP;
  signals[3] = SIGQUIT;
  memset (&action, 0, sizeof (action));
  action.sa_handler = zo_interrupt;

  if (sigemptyset (&action.sa_mask) != 0)
    {
      return 0;
    }

  for (i = 0; i < 4; i++)
    {
      if (sigaction (signals[i], NULL, &old) != 0)
        {
          return 0;
        }

      /* Preserve ignored signals, as specified by POSIX. */
      if (old.sa_handler == SIG_IGN)
        {
          continue;
        }

      if (sigaction (signals[i], &action, NULL) != 0)
        {
          return 0;
        }
    }

  return 1;
#endif
}

#define ZO32MAX 0xffffffffUL
#define ZO64MAX ((zo_u64) - 1)

static unsigned
zo_u16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static int
zo_write (zo_writer *w, const void *v, size_t n)
{
  if (w->failed || fwrite (v, 1, n, w->stream) != n)
    {
      w->failed = 1;

      return 0;
    }

  return 1;
}

static int
zo_w16 (zo_writer *w, unsigned u)
{
  unsigned char b[2];

  b[0] = (unsigned char)u;
  b[1] = (unsigned char)(u >> 8);

  return zo_write (w, b, 2);
}

static int
zo_w32 (zo_writer *w, zo_u64 u)
{
  unsigned char b[4];
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      b[i] = (unsigned char)u;
      u >>= 8;
    }

  return zo_write (w, b, 4);
}

static int
zo_w64 (zo_writer *w, zo_u64 u)
{
  unsigned char b[8];
  unsigned i;

  for (i = 0; i < 8; i++)
    {
      b[i] = (unsigned char)u;
      u >>= 8;
    }

  return zo_write (w, b, 8);
}

static int
zo_tell (zo_writer *w, zo_u64 *v)
{
#ifdef _WIN32
  __int64 off = _ftelli64 (w->stream);
#else
  off_t off = ftello (w->stream);
#endif

  if (off < 0)
    {
      w->failed = 1;
      return 0;
    }

  *v = (zo_u64)off;

  return 1;
}

static int
zo_copy (zo_writer *w, FILE *src, zo_u64 n)
{
  unsigned char buf[32768];

  while (n)
    {
      size_t want = (n > sizeof (buf)) ? sizeof (buf) : (size_t)n;

      if (fread (buf, 1, want, src) != want || !zo_write (w, buf, want))
        {
          return 0;
        }

      n -= (zo_u64)want;
    }

  return 1;
}

static int
zo_seekin (FILE *f, zo_u64 off)
{
  if (off > (ZO64MAX >> 1))
    {
      return 0;
    }
#ifdef _WIN32
  return _fseeki64 (f, (__int64)off, SEEK_SET) == 0;
#else
  if ((zo_u64)(off_t)off != off)
    return 0;
  return fseeko (f, (off_t)off, SEEK_SET) == 0;
#endif
}

static int
zo_copy_src (zo_writer *w, zo_u64 off, zo_u64 n)
{
  if (!zo_seekin (w->source->fp, off))
    {
      return 0;
    }

  return zo_copy (w, w->source->fp, n);
}

static unsigned
zo_need_version (unsigned method)
{
  if (method <= 6)
    {
      return 10;
    }

  switch (method)
    {
    case 8:
    case 10:
    case 93:
    case 95:
      return 20;

    case 9:
      return 21;

    case 12:
      return 46;

    case 14:
    case 98:
      return 63;

    default:
      return 63;
    }
}

/*
 * Strict preflight has already checked types and lengths. Rebuild safely;
 * always strip input ZIP64 and FWKCS; regenerate ZIP64 from new sizes.
 */

static int
zo_extras_without_rewritten (const unsigned char *src, unsigned n,
                             unsigned char **out, unsigned *outn)
{
  unsigned i = 0, used = 0, len, typ;
  unsigned char *buf;

  buf = (unsigned char *)malloc ((size_t)n + 32);
  if (!buf)
    {
      return 0;
    }

  while (i < n)
    {
      if (n - i < 4)
        {
          free (buf);
          return 0;
        }

      typ = zo_u16 (src + i);
      len = zo_u16 (src + i + 2);

      if (len > n - i - 4)
        {
          free (buf);

          return 0;
        }

      if (typ != 1 && typ != 0x4b46U)
        {
          memcpy (buf + used, src + i, (size_t)len + 4U);
          used += len + 4;
        }

      i += len + 4;
    }

  *out = buf;
  *outn = used;

  return 1;
}

static int
zo_read_extras (zo_archive *a, zo_u64 at, unsigned n, unsigned char **p,
                unsigned *plen)
{
  unsigned char *raw = NULL;
  int ok;

  if (n)
    {
      raw = (unsigned char *)malloc (n);

      if (!raw)
        {
          return 0;
        }

      if (!zo_archive_at (a, at, raw, n))
        {
          free (raw);

          return 0;
        }
    }

  ok = zo_extras_without_rewritten (raw, n, p, plen);
  free (raw);

  return ok;
}

int
zo_writer_begin (zo_writer *w, zo_archive *a, const char *dst)
{
  size_t n;
  int fd;
#ifndef _WIN32
  struct stat st;
#endif
  zo_sigmask_t previous;

  memset (w, 0, sizeof (*w));

  if (!a || !dst || !dst[0])
    {
      return 0;
    }

#ifdef _WIN32
  if (GetFileAttributesA (dst) != INVALID_FILE_ATTRIBUTES)
#else
  if (lstat (dst, &st) == 0)
#endif
    {
      return 0;
    }

  n = strlen (dst);

  if (n > ((size_t)-1) - 32)
    {
      return 0;
    }

  if (!zo_signal_mask (1, &previous))
    {
      return 0;
    }

  w->temporary = (char *)malloc (n + 24);
  w->destination = (char *)malloc (n + 1);

  if (!w->temporary || !w->destination)
    {
      zo_signal_mask (0, &previous);

      return 0;
    }

  strcpy (w->destination, dst);
  memcpy (w->temporary, dst, n);
  strcpy (w->temporary + n, ".zipopt-XXXXXX");

  /* Register the fully constructed pathname before creating the file. */
  zo_interrupt_path = w->temporary;
  fd = mkstemp (w->temporary);

  if (fd < 0)
    {
      zo_signal_mask (0, &previous);

      return 0;
    }

  w->stream = fdopen (fd, "wb+");

  if (!w->stream)
    {
      close (fd);
      unlink (w->temporary);
      zo_signal_mask (0, &previous);

      return 0;
    }

  w->entries = (zo_outentry *)calloc ((size_t)(a->count ? a->count : 1),
                                      sizeof (*w->entries));
  if (!w->entries)
    {
      zo_signal_mask (0, &previous);

      return 0;
    }

  w->source = a;

  if (!zo_signal_mask (0, &previous))
    {
      return 0;
    }

  return 1;
}

int
zo_writer_add (zo_writer *w, zo_u64 idx, FILE *payload, unsigned method,
               unsigned flags, zo_u64 csize)
{
  zo_entry *e;
  zo_outentry *o;
  unsigned char *extra = NULL;
  unsigned nx = 0, ver;
  int z64;
  zo_u64 off;

  if (!w || !w->source || idx >= w->source->count || w->failed)
    {
      return 0;
    }

  e = &w->source->entries[(size_t)idx];
  o = &w->entries[(size_t)idx];

  if (!zo_tell (w, &off))
    {
      return 0;
    }

  o->local_off = off;
  o->usize = e->usize;
  o->csize = csize;
  o->method = method;
  o->flags = flags;
  o->version = ver = zo_need_version (method);
  z64 = e->usize >= ZO32MAX || csize >= ZO32MAX;

  /*
   * The central directory needs ZIP64 when this local record begins
   * beyond 4 GiB, even if both member sizes fit in 32 bits.  Keep
   * local and central extraction versions consistent.  Offset-only
   * ZIP64 never requires a ZIP64 size extra in the local header.
   */

  if ((z64 || off >= ZO32MAX) && ver < 45)
    {
      o->version = ver = 45;
    }

  if (!zo_read_extras (w->source, e->local_offset + 30 + e->name_len,
                       e->local_extra_len, &extra, &nx))
    {
      return 0;
    }

  if (z64 && nx > 65535 - 20)
    {
      free (extra);

      return 0;
    }

  if (!zo_w32 (w, 0x04034b50UL) || !zo_w16 (w, ver) || !zo_w16 (w, flags & ~8U)
      || !zo_w16 (w, method))
    {
      goto fail;
    }

  {
    unsigned char stamp[4];

    if (!zo_archive_at (w->source, e->local_offset + 10, stamp, 4)
        || !zo_write (w, stamp, 4))
      {
        goto fail;
      }
  }

  if (!zo_w32 (w, e->crc) || !zo_w32 (w, csize >= ZO32MAX ? ZO32MAX : csize)
      || !zo_w32 (w, e->usize >= ZO32MAX ? ZO32MAX : e->usize)
      || !zo_w16 (w, e->name_len) || !zo_w16 (w, nx + (z64 ? 20 : 0))
      || !zo_write (w, e->name, e->name_len) || !zo_write (w, extra, nx))
    {
      goto fail;
    }

  if (z64
      && (!zo_w16 (w, 1) || !zo_w16 (w, 16) || !zo_w64 (w, e->usize)
          || !zo_w64 (w, csize)))
    {
      goto fail;
    }

  free (extra);

  if (payload)
    {
      rewind (payload);

      if (!zo_copy (w, payload, csize))
        {
          return 0;
        }
    }
  else if (!zo_copy_src (w, e->data_offset, csize))
    {
      return 0;
    }

  return 1;

fail:
  free (extra);

  return 0;
}

int
zo_writer_complete (zo_writer *w)
{
  zo_u64 i, cd, cdend, now, z64end;
  zo_archive *a;
  zo_entry *e;
  zo_outentry *o;
  unsigned char cen[46];
  unsigned char *extra;
  unsigned nx, need;
  unsigned z64, zsz, zcs, zoff, ver, made;

  if (!w || !w->source || w->failed)
    {
      return 0;
    }

  a = w->source;

  if (!zo_tell (w, &cd))
    {
      return 0;
    }

  for (i = 0; i < a->count; i++)
    {
      e = &a->entries[(size_t)i];
      o = &w->entries[(size_t)i];

      if (!zo_archive_at (a, e->central_offset, cen, 46))
        {
          return 0;
        }

      if (!zo_read_extras (a, e->central_offset + 46 + e->name_len,
                           e->central_extra_len, &extra, &nx))
        {
          return 0;
        }

      zsz = o->usize >= ZO32MAX;
      zcs = o->csize >= ZO32MAX;
      zoff = o->local_off >= ZO32MAX;
      z64 = zsz || zcs || zoff;
      need = (zsz ? 8 : 0) + (zcs ? 8 : 0) + (zoff ? 8 : 0);

      if (nx > 65535U - (z64 ? 4U + need : 0U)
                    - (o->has_md5 ? 23U : 0U))
        {
          free (extra);
          return 0;
        }

      ver = o->version;

      if (z64 && ver < 45)
        {
          ver = 45;
        }

      made = (zo_u16 (cen + 4) & 0xff00U)
             | ((zo_u16 (cen + 4) & 255U) < ver ? ver
                                                : (zo_u16 (cen + 4) & 255U));
      if (!zo_w32 (w, 0x02014b50UL) || !zo_w16 (w, made) || !zo_w16 (w, ver)
          || !zo_w16 (w, o->flags & ~8U) || !zo_w16 (w, o->method))
        {
          goto fail;
        }

      if (!zo_write (w, cen + 12, 4) || !zo_w32 (w, e->crc)
          || !zo_w32 (w, zcs ? ZO32MAX : o->csize)
          || !zo_w32 (w, zsz ? ZO32MAX : o->usize) || !zo_w16 (w, e->name_len)
          || !zo_w16 (w, nx + (z64 ? 4 + need : 0)
                             + (o->has_md5 ? 23U : 0U))
          || !zo_w16 (w, e->central_comment_len) || !zo_w16 (w, 0)
          || !zo_write (w, cen + 36, 6)
          || !zo_w32 (w, zoff ? ZO32MAX : o->local_off)
          || !zo_write (w, e->name, e->name_len) || !zo_write (w, extra, nx))
        {
          goto fail;
        }

      if (z64)
        {
          if (!zo_w16 (w, 1) || !zo_w16 (w, need))
            {
              goto fail;
            }

          if (zsz && !zo_w64 (w, o->usize))
            {
              goto fail;
            }

          if (zcs && !zo_w64 (w, o->csize))
            {
              goto fail;
            }

          if (zoff && !zo_w64 (w, o->local_off))
            {
              goto fail;
            }
        }

      if (o->has_md5)
        {
          if (!zo_w16 (w, 0x4b46U) || !zo_w16 (w, 19U)
              || !zo_write (w, "MD5", 3)
              || !zo_write (w, o->md5, 16))
            {
              goto fail;
            }
        }

      free (extra);

      if (!zo_copy_src (
              w, e->central_offset + 46 + e->name_len + e->central_extra_len,
              (zo_u64)e->central_comment_len))
        {
          return 0;
        }

      continue;

    fail:
      free (extra);

      return 0;
    }

  if (!zo_tell (w, &cdend))
    {
      return 0;
    }

  /* ZIP64 EOCD when any EOCD legacy field would overflow. */
  z64 = (a->count >= 65535 || cd >= ZO32MAX || cdend - cd >= ZO32MAX);

  for (i = 0; i < a->count; i++)
    {
      o = &w->entries[(size_t)i];

      if (o->usize >= ZO32MAX || o->csize >= ZO32MAX
          || o->local_off >= ZO32MAX)
        {
          z64 = 1;
        }
    }

  if (z64)
    {
      if (!zo_tell (w, &z64end) || !zo_w32 (w, 0x06064b50UL) || !zo_w64 (w, 44)
          || !zo_w16 (w, 45) || !zo_w16 (w, 45) || !zo_w32 (w, 0)
          || !zo_w32 (w, 0) || !zo_w64 (w, a->count) || !zo_w64 (w, a->count)
          || !zo_w64 (w, cdend - cd) || !zo_w64 (w, cd)
          || !zo_w32 (w, 0x07064b50UL) || !zo_w32 (w, 0) || !zo_w64 (w, z64end)
          || !zo_w32 (w, 1))
        {
          return 0;
        }
    }

  if (!zo_w32 (w, 0x06054b50UL) || !zo_w16 (w, 0) || !zo_w16 (w, 0)
      || !zo_w16 (w, a->count >= 65535 ? 65535 : (unsigned)a->count)
      || !zo_w16 (w, a->count >= 65535 ? 65535 : (unsigned)a->count)
      || !zo_w32 (w, cdend - cd >= ZO32MAX ? ZO32MAX : cdend - cd)
      || !zo_w32 (w, cd >= ZO32MAX ? ZO32MAX : cd)
      || !zo_w16 (w, a->archive_comment_len))
    {
      return 0;
    }

  if (!zo_copy_src (w, a->eocd_offset + 22, (zo_u64)a->archive_comment_len))
    {
      return 0;
    }

  if (fflush (w->stream) != 0)
    {
      return 0;
    }

  if (!zo_tell (w, &now))
    {
      return 0;
    }

  (void)now;

  return 1;
}

int
zo_writer_publish (zo_writer *w)
{
  zo_sigmask_t previous;
  int ok;

  if (!w || !w->stream || w->failed)
    {
      return 0;
    }

  if (fclose (w->stream) != 0)
    {
      w->stream = NULL;
      return 0;
    }

  w->stream = NULL;

  if (!zo_signal_mask (1, &previous))
    {
      return 0;
    }

  /* Both POSIX hardlink and Win32 CreateHardLinkA fail if output exists. */
  ok = link (w->temporary, w->destination) == 0;

  if (ok)
    {
      (void)unlink (w->temporary);
    }

  zo_interrupt_path = NULL;

  if (!zo_signal_mask (0, &previous))
    {
      return 0;
    }

  return ok;
}

void
zo_writer_abort (zo_writer *w)
{
  zo_sigmask_t previous;
  int blocked;

  if (!w)
    {
      return;
    }

  blocked = zo_signal_mask (1, &previous);

  /* This path also handles partial zo_writer_begin() failures. */
  zo_interrupt_path = NULL;

  if (w->stream)
    {
      fclose (w->stream);
    }

  if (w->temporary)
    {
      unlink (w->temporary);
    }

  free (w->temporary);
  free (w->destination);
  free (w->entries);
  memset (w, 0, sizeof (*w));

  if (blocked)
    {
      (void)zo_signal_mask (0, &previous);
    }
}
