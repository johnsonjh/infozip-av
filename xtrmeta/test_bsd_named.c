/* SPDX-License-Identifier: MIT-0 */
/* Linux-hosted FreeBSD 15 named-stream ABI integration, not a FreeBSD test. */
#define _GNU_SOURCE 1
#include "xtrbsd.h"
#include "xtrsha.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define N 32
#define CHECK(cond)                                                           \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(cond))                                                            \
        {                                                                     \
          fprintf (stderr, "check failed at %d: %s\n", __LINE__, #cond);      \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)
static char directory[160];
static int checks, failures;
typedef struct item
{
  char name[256];
  unsigned char *buf;
  size_t n;
} item;
static item items[N];
static size_t nitems;
static int switch_on_open;
static item *
lookup (const char *name)
{
  size_t i;

  for (i = 0; i < nitems; i++)
    {
      if (!strcmp (items[i].name, name))
        {
          return &items[i];
        }
    }

  return NULL;
}
static int
put (const char *name, const unsigned char *b, size_t len)
{
  item *p = lookup (name);
  unsigned char *next;

  if (!p)
    {
      if (nitems == N)
        {
          return -1;
        }

      p = &items[nitems++];
      strcpy (p->name, name);
    }

  next = (unsigned char *)malloc (len ? len : 1U);
  if (!next)
    {
      return -1;
    }

  if (len)
    {
      memcpy (next, b, len);
    }

  free (p->buf);
  p->buf = next;
  p->n = len;
  return 0;
}
ssize_t
extattr_list_fd (int fd, int ns, void *out, size_t len)
{
  size_t i, sz = 0;
  unsigned char *p = (unsigned char *)out;

  if (fd != 7 || ns != 1)
    {
      errno = EBADF;
      return -1;
    }

  for (i = 0; i < nitems; i++)
    {
      sz += strlen (items[i].name) + 1U;
    }

  if (!out)
    {
      return (ssize_t)sz;
    }

  if (len < sz)
    {
      errno = ERANGE;
      return -1;
    }

  for (i = 0; i < nitems; i++)
    {
      size_t n = strlen (items[i].name);
      *p++ = (unsigned char)n;
      memcpy (p, items[i].name, n);
      p += n;
    }

  return (ssize_t)sz;
}
ssize_t
extattr_get_fd (int fd, int ns, const char *name, void *out, size_t len)
{
  item *p = lookup (name);

  if (fd != 7 || ns != 1 || !p)
    {
      errno = ENOENT;
      return -1;
    }

  if (!out)
    {
      return (ssize_t)p->n;
    }

  if (len < p->n)
    {
      errno = ERANGE;
      return -1;
    }

  if (p->n)
    {
      memcpy (out, p->buf, p->n);
    }

  return (ssize_t)p->n;
}
ssize_t
extattr_set_fd (int fd, int ns, const char *name, const void *val, size_t len)
{
  if (fd != 7 || ns != 1 || put (name, (const unsigned char *)val, len))
    {
      errno = EIO;
      return -1;
    }

  return (ssize_t)len;
}
int
extattr_delete_fd (int fd, int ns, const char *name)
{
  size_t i;

  if (fd != 7 || ns != 1)
    {
      return -1;
    }

  for (i = 0; i < nitems; i++)
    {
      if (!strcmp (items[i].name, name))
        {
          free (items[i].buf);
          if (i + 1 < nitems)
            {
              memmove (items + i, items + i + 1,
                       (nitems - i - 1) * sizeof (*items));
            }

          nitems--;
          memset (items + nitems, 0, sizeof (*items));
          return 0;
        }
    }

  errno = ENOENT;
  return -1;
}
int
xtr_test_named_enabled (int fd)
{
  return fd == 7 ? 1 : -1;
}
int
xtr_test_named_has (int fd)
{
  DIR *d;
  struct dirent *e;
  int has = 0;

  if (fd != 7)
    {
      return -1;
    }

  d = opendir (directory);
  if (!d)
    {
      return -1;
    }

  while ((e = readdir (d)) != NULL)
    {
      if (strcmp (e->d_name, ".") && strcmp (e->d_name, ".."))
        {
          has = 1;
          break;
        }
    }
  closedir (d);
  return has;
}
int
xtr_test_named_directory (int fd)
{
  if (fd != 7)
    {
      errno = EBADF;
      return -1;
    }

  return open (directory, O_RDONLY | O_DIRECTORY);
}
int
xtr_test_named_open (int fd, const char *name, int flags, mode_t mode)
{
  int d, rv;

  if (fd != 7 || strchr (name, '/'))
    {
      errno = EBADF;
      return -1;
    }

  d = open (directory, O_RDONLY | O_DIRECTORY);
  if (d < 0)
    {
      return -1;
    }

  if (!strcmp (name, "swapped") && (flags & O_ACCMODE) == O_RDONLY
      && switch_on_open)
    {
      switch_on_open++;
      if (switch_on_open == 3)
        {
          int out;
          if (renameat (d, "swapped", d, "old-swapped") != 0)
            {
              close (d);
              return -1;
            }

          out = openat (d, "swapped", O_WRONLY | O_CREAT | O_EXCL, 0600);
          if (out < 0 || write (out, "SAME", 4) != 4)
            {
              if (out >= 0)
                {
                  close (out);
                }

              close (d);
              return -1;
            }

          close (out);
        }
    }

  rv = openat (d, name, flags, mode);
  close (d);
  return rv;
}
int
xtr_test_named_unlink (int fd, const char *name)
{
  return unlinkat (fd, name, 0);
}
static void
clear_all (void)
{
  DIR *d = opendir (directory);
  struct dirent *e;
  size_t i;

  if (d)
    {
      while ((e = readdir (d)) != NULL)
        {
          if (strcmp (e->d_name, ".") && strcmp (e->d_name, ".."))
            {
              int fd = dirfd (d);
              unlinkat (fd, e->d_name, 0);
            }
        }
      closedir (d);
    }

  for (i = 0; i < nitems; i++)
    {
      free (items[i].buf);
    }

  memset (items, 0, sizeof (items));
  nitems = 0;
}
static int
setstream (const char *name, const unsigned char *data, size_t len, int mode)
{
  int fd = xtr_test_named_open (7, name, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  size_t done = 0;

  if (fd < 0)
    {
      return -1;
    }

  while (done < len)
    {
      ssize_t n = write (fd, data + done, len - done);
      if (n <= 0)
        {
          close (fd);
          return -1;
        }

      done += (size_t)n;
    }
  if (fchmod (fd, (mode_t)mode))
    {
      close (fd);
      return -1;
    }

  return close (fd);
}
static int
settimes (const char *name, time_t at, time_t mt)
{
  struct timespec ts[2];
  int fd = xtr_test_named_open (7, name, O_RDONLY, 0), rc;

  if (fd < 0)
    {
      return -1;
    }

  ts[0].tv_sec = at;
  ts[0].tv_nsec = 123456789L;
  ts[1].tv_sec = mt;
  ts[1].tv_nsec = 987654321L;
  rc = futimens (fd, ts);
  if (close (fd) != 0)
    {
      rc = -1;
    }

  return rc;
}
static int
checktimes (const char *name, time_t at, time_t mt)
{
  int fd = xtr_test_named_open (7, name, O_RDONLY, 0), ok = 0;
  struct stat st;

  if (fd < 0)
    {
      return 0;
    }

  if (fstat (fd, &st) == 0 && st.st_atim.tv_sec == at
      && st.st_atim.tv_nsec == 123456789L && st.st_mtim.tv_sec == mt
      && st.st_mtim.tv_nsec == 987654321L)
    {
      ok = 1;
    }

  close (fd);
  return ok;
}
static int
verifystream (const char *name, const unsigned char *data, size_t len,
              int mode)
{
  int fd = xtr_test_named_open (7, name, O_RDONLY, 0), rc = 1;
  struct stat st;
  unsigned char buf[4096];
  size_t off = 0;

  if (fd < 0)
    {
      return 0;
    }

  if (fstat (fd, &st) != 0 || (size_t)st.st_size != len
      || (unsigned)(st.st_mode & 07777) != (unsigned)mode)
    {
      goto done;
    }

  while (off < len)
    {
      size_t want = len - off;
      ssize_t n;
      if (want > sizeof (buf))
        {
          want = sizeof (buf);
        }

      n = read (fd, buf, want);
      if (n <= 0 || memcmp (buf, data + off, (size_t)n))
        {
          goto done;
        }

      off += (size_t)n;
    }
  if (read (fd, buf, 1) != 0)
    {
      goto done;
    }

  rc = 2;
done:
  close (fd);
  return rc == 2;
}
static void
scenario (int encrypted)
{
  unsigned char owner[16], val[] = { 1, 0, 255, 2 }, *big;
  xtr1_digest dig;
  xtr_extra e;
  xtr_u64 length;
  FILE *f = tmpfile ();
  int rc;
  unsigned i;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  clear_all ();
  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1);
    }

  big = (unsigned char *)malloc (2U * 1024U * 1024U + 17U);
  CHECK (big != NULL);
  if (!big)
    {
      fclose (f);
      return;
    }

  for (i = 0; i < 2U * 1024U * 1024U + 17U; i++)
    {
      big[i] = (unsigned char)((i * 17U + 23U) & 255U);
    }

  CHECK (put ("shared", val, sizeof (val)) == 0);
  CHECK (put ("ordinary", NULL, 0) == 0);
  CHECK (setstream ("shared", big, 2U * 1024U * 1024U + 17U, 0640) == 0);
  CHECK (setstream ("other", val, sizeof (val), 0600) == 0);
  CHECK (setstream ("empty", NULL, 0, 0644) == 0);
  CHECK (settimes ("shared", (time_t)1234000000, (time_t)1235000000) == 0);
  rc = xtr_bsd_capture_fd (7, owner, f, encrypted, &dig);
  CHECK (rc == XTR_OK && dig.count == 5U);
  if (rc)
    {
      free (big);
      fclose (f);
      return;
    }

  memset (&e, 0, sizeof (e));
  memcpy (e.owner, owner, 16);
  e.mode = 2;
  if (encrypted)
    {
      e.flags = 1;
    }
  else
    {
      e.count = dig.count;
      e.crc32 = dig.crc32;
      e.manifest_len = dig.manifest_length;
    }

  length = dig.manifest_length;
  if (encrypted)
    {
      length.lo += 36U;
    }

  CHECK (put ("stale", val, sizeof (val)) == 0);
  CHECK (put ("shared", NULL, 0) == 0);
  CHECK (setstream ("shared", val, sizeof (val), 0600) == 0);
  CHECK (setstream ("stale", val, sizeof (val), 0600) == 0);
  rc = xtr_bsd_restore_fd (7, f, length, &e, encrypted ? NULL : dig.sha256);
  CHECK (rc == XTR_OK);
  CHECK (lookup ("shared") && lookup ("shared")->n == sizeof (val)
         && !memcmp (lookup ("shared")->buf, val, sizeof (val)));
  CHECK (lookup ("ordinary") && lookup ("ordinary")->n == 0);
  CHECK (!lookup ("stale"));
  CHECK (checktimes ("shared", (time_t)1234000000, (time_t)1235000000));
  CHECK (verifystream ("shared", big, 2U * 1024U * 1024U + 17U, 0640));
  CHECK (verifystream ("other", val, sizeof (val), 0600));
  CHECK (verifystream ("empty", NULL, 0, 0644));
  {
    int fd = xtr_test_named_open (7, "stale", O_RDONLY, 0);
    CHECK (fd < 0);
    if (fd >= 0)
      {
        close (fd);
      }
  }
#ifdef XTR_TEST_HOOKS
  /* Verify both classes of attributes roll back after a native write
   * failure midway through restoring an otherwise valid manifest. */
  CHECK (put ("stale", val, sizeof (val)) == 0);
  CHECK (setstream ("shared", val, sizeof (val), 0600) == 0);
  CHECK (settimes ("shared", (time_t)1234000000, (time_t)1235000000) == 0);
  xtr_bsd_test_fail_after (2);
  rc = xtr_bsd_restore_fd (7, f, length, &e, encrypted ? NULL : dig.sha256);
  CHECK (rc == XTR_IO);
  CHECK (lookup ("stale") && lookup ("stale")->n == sizeof (val));
  CHECK (checktimes ("shared", (time_t)1234000000, (time_t)1235000000));
  CHECK (verifystream ("shared", val, sizeof (val), 0600));
#endif /* ifdef XTR_TEST_HOOKS */
  free (big);
  fclose (f);
}
static void
corrupt_test (void)
{
  unsigned char owner[16];
  xtr1_digest dig;
  xtr_extra e;
  xtr_u64 length;
  FILE *f = tmpfile ();
  unsigned char buf[1024];
  int rc;
  unsigned i;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  clear_all ();
  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1);
    }

  CHECK (setstream ("safe", (const unsigned char *)"DATA", 4, 0644) == 0);
  rc = xtr_bsd_capture_fd (7, owner, f, 0, &dig);
  CHECK (rc == XTR_OK);
  memset (&e, 0, sizeof (e));
  memcpy (e.owner, owner, 16);
  e.mode = 2;
  e.count = dig.count;
  e.crc32 = dig.crc32;
  e.manifest_len = dig.manifest_length;
  length = dig.manifest_length;
  CHECK (fseek (f, 45, SEEK_SET) == 0);
  CHECK (fread (buf, 1, 1, f) == 1);
  CHECK (fseek (f, 45, SEEK_SET) == 0);
  buf[0] ^= 0x80;
  CHECK (fwrite (buf, 1, 1, f) == 1);
  CHECK (fflush (f) == 0);
  rc = xtr_bsd_restore_fd (7, f, length, &e, dig.sha256);
  CHECK (rc != XTR_OK);
  CHECK (verifystream ("safe", (const unsigned char *)"DATA", 4, 0644));
  fclose (f);
}

/* Decode a cu70-style 22-byte native TLV (mode only, no times). */
typedef struct old_value
{
  const unsigned char *bytes;
  size_t len, pos;
} old_value;
static size_t
old_read (void *ctx, unsigned char *out, size_t want)
{
  old_value *v = (old_value *)ctx;
  size_t n = v->len - v->pos;

  if (n > want)
    {
      n = want;
    }

  if (n)
    {
      memcpy (out, v->bytes + v->pos, n);
    }

  v->pos += n;
  return n;
}
static int
old_write (void *ctx, const unsigned char *data, size_t n)
{
  return fwrite (data, 1, n, (FILE *)ctx) == n ? 0 : 1;
}
/* An internally consistent CRC/SHA cannot make malformed time TLVs
 * eligible for native application. Verify rejection before any writes. */
static void
time_corrupt_test (void)
{
  unsigned char owner[16], *buf;
  xtr1_digest digest;
  xtr_extra outer;
  xtr_u64 len;
  xtr_sha256 hash;
  FILE *f = tmpfile ();
  size_t n;
  int rc;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  clear_all ();
  memset (owner, 3, sizeof (owner));
  CHECK (setstream ("safe", (const unsigned char *)"DATA", 4, 0600) == 0);
  rc = xtr_bsd_capture_fd (7, owner, f, 0, &digest);
  CHECK (rc == XTR_OK);
  if (rc)
    {
      fclose (f);
      return;
    }

  len = digest.manifest_length;
  CHECK (len.hi == 0 && len.lo < 1024U);
  n = (size_t)len.lo;
  buf = (unsigned char *)malloc (n);
  CHECK (buf != NULL);
  if (!buf)
    {
      fclose (f);
      return;
    }

  rewind (f);
  CHECK (fread (buf, 1, n, f) == n);
  /* Header 36, record 28, namespace 4, name 'safe' 4,
   * first timestamp TLV header 8, seconds 8, then nanoseconds. */
  CHECK (n > 114U);
  if (n > 114U)
    {
      memset (buf + 110, 255, 4);
      rewind (f);
      CHECK (fwrite (buf, 1, n, f) == n && fflush (f) == 0);
      memset (&outer, 0, sizeof (outer));
      memcpy (outer.owner, owner, 16);
      outer.mode = 2;
      outer.count = 1;
      outer.manifest_len = len;
      outer.crc32 = xtr_crc32_update (0, buf, n);
      xtr_sha256_init (&hash);
      xtr_sha256_update (&hash, buf, n);
      xtr_sha256_final (&hash, digest.sha256);
      rc = xtr_bsd_restore_fd (7, f, len, &outer, digest.sha256);
      CHECK (rc == XTR_CORRUPT);
      CHECK (verifystream ("safe", (const unsigned char *)"DATA", 4, 0600));
    }

  free (buf);
  fclose (f);
}
static void
old_format_test (void)
{
  unsigned char owner[16], native[22] = { 1, 0, 0, 0, 2, 0, 0, 0,    3, 0, 2,
                                          0, 0, 0, 4, 0, 0, 0, 0xa4, 1, 0, 0 };
  static const unsigned char val[3] = { 0, 255, 7 };
  xtr1_source item;
  xtr1_sink sink;
  xtr1_policy pol;
  xtr1_digest digest;
  xtr_extra outer;
  old_value value;
  FILE *f = tmpfile ();
  int rc;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  clear_all ();
  memset (owner, 7, sizeof (owner));
  memset (&item, 0, sizeof (item));
  item.record.type = 2;
  item.record.origin = 2;
  item.record.encoding = 0;
  item.record.ns_len = 4;
  item.record.name_len = 6;
  item.record.native_len = 22;
  item.record.value_len.lo = 3;
  item.ns = (const unsigned char *)"user";
  item.name = (const unsigned char *)"legacy";
  item.native = native;
  value.bytes = val;
  value.len = sizeof (val);
  value.pos = 0;
  item.read_value = old_read;
  item.value_context = &value;
  memset (&pol, 0, sizeof (pol));
  pol.max_records = 1024;
  pol.max_field = 1024 * 1024;
  pol.max_manifest.lo = 32UL * 1024UL * 1024UL;
  sink.context = f;
  sink.write = old_write;
  rc = xtr1_write_manifest (owner, &item, 1, 0, &pol, &sink, &digest);
  CHECK (rc == XTR_OK);
  if (rc == XTR_OK)
    {
      memset (&outer, 0, sizeof (outer));
      memcpy (outer.owner, owner, 16);
      outer.mode = 2;
      outer.count = digest.count;
      outer.crc32 = digest.crc32;
      outer.manifest_len = digest.manifest_length;
      rc = xtr_bsd_restore_fd (7, f, digest.manifest_length, &outer,
                               digest.sha256);
      CHECK (rc == XTR_OK);
      CHECK (verifystream ("legacy", val, sizeof (val), 0644));
    }

  fclose (f);
}
static void
name_race_test (void)
{
  unsigned char owner[16];
  xtr1_digest dig;
  FILE *f = tmpfile ();
  int rc;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  clear_all ();
  memset (owner, 1, sizeof (owner));
  CHECK (setstream ("swapped", (const unsigned char *)"SAME", 4, 0600) == 0);
  switch_on_open = 1;
  rc = xtr_bsd_capture_fd (7, owner, f, 0, &dig);
  switch_on_open = 0;
  CHECK (rc == XTR_IO); /* name now points to another inode */
  clear_all ();
  fclose (f);
}
static void
symlink_test (void)
{
  char victim[220], linkpath[220];
  unsigned char owner[16];
  unsigned char check[5];
  xtr1_digest dig;
  FILE *f = tmpfile ();
  int v, rc;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  clear_all ();
  memset (owner, 1, sizeof (owner));
  CHECK (strlen (directory) < 180U);
  sprintf (victim, "%s/victim", directory);
  sprintf (linkpath, "%s/link", directory);
  v = open (victim, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  CHECK (v >= 0);
  if (v < 0)
    {
      fclose (f);
      return;
    }

  CHECK (write (v, "SAFE", 4) == 4);
  CHECK (close (v) == 0);
  CHECK (symlink ("victim", linkpath) == 0);
  rc = xtr_bsd_capture_fd (7, owner, f, 0, &dig);
  CHECK (rc != XTR_OK); /* the stream is a symlink, never follow it */
  v = open (victim, O_RDONLY);
  CHECK (v >= 0);
  if (v >= 0)
    {
      CHECK (read (v, check, 4) == 4 && !memcmp (check, "SAFE", 4));
      CHECK (close (v) == 0);
    }

  CHECK (unlink (linkpath) == 0);
  CHECK (unlink (victim) == 0);
  fclose (f);
}
int
main (void)
{
  strcpy (directory, "/tmp/xtro-named-XXXXXX");
  if (!mkdtemp (directory))
    {
      perror ("mkdtemp");
      return 1;
    }

  scenario (0);
  scenario (1);
  corrupt_test ();
  symlink_test ();
  name_race_test ();
  old_format_test ();
  time_corrupt_test ();
  clear_all ();
  if (rmdir (directory))
    {
      perror ("rmdir");
    }

  printf ("FreeBSD 15 named stream emulation: %d checks, %d failures\n",
          checks, failures);
  return failures ? 1 : 0;
}
