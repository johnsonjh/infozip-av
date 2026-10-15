/* SPDX-License-Identifier: MIT-0 */
/* Traditional FreeBSD/NetBSD user extattr(2), plus FreeBSD 15's
 * file-like O_NAMEDATTR namespace. Never conflate aliases or same-name
 * distinct attributes. Supplied Zip/UnZip owner FDs are retained.
 * Native writes occur AFTER complete structural/cryptographic validation.
 * Rollback is best effort; this API does not promise filesystem atomicity. */
#include "xtrbsd.h"
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(XTR_BSD_TEST)
# include <sys/types.h>
# if defined(XTR_BSD_TEST)
#  define EXTATTR_NAMESPACE_USER 1
extern ssize_t extattr_list_fd (int, int, void *, size_t);
extern ssize_t extattr_get_fd (int, int, const char *, void *, size_t);
#  if defined(XTR_BSD_TEST_NETBSD)
extern int extattr_set_fd (int, int, const char *, const void *, size_t);
#  else  /* if defined( XTR_BSD_TEST_NETBSD ) */
extern ssize_t extattr_set_fd (int, int, const char *, const void *, size_t);
#  endif /* if defined( XTR_BSD_TEST_NETBSD ) */
extern int extattr_delete_fd (int, int, const char *);
# else /* if defined( XTR_BSD_TEST ) */
#  include <sys/extattr.h>
# endif /* if defined( XTR_BSD_TEST ) */
# include <errno.h>
# include <fcntl.h>
# include <limits.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
/* FreeBSD 15's stream namespace is separate from extattr(2), although
 * individual entries can alias on ZFS. The mock ABI has no kernel headers. */
# if (defined(__FreeBSD__) && defined(O_NAMEDATTR)                             \
     && defined(_PC_NAMEDATTR_ENABLED) && defined(_PC_HAS_NAMEDATTR))         \
    || defined(XTR_BSD_TEST_NAMED)
#  define XB_NAMED 1
#  include <dirent.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  if defined(XTR_BSD_TEST_NAMED)
extern int xtr_test_named_enabled (int);
extern int xtr_test_named_has (int);
extern int xtr_test_named_directory (int);
extern int xtr_test_named_open (int, const char *, int, mode_t);
extern int xtr_test_named_unlink (int, const char *);
#   define xb_nenabled(f) xtr_test_named_enabled (f)
#   define xb_nhas(f) xtr_test_named_has (f)
#   define xb_ndir(f) xtr_test_named_directory (f)
#   define xb_nopen(f, n, flags, mode)                                           \
  xtr_test_named_open (f, n, (flags) | XB_NOPEN_FLAGS, mode)
#   define xb_nunlink(f, n) xtr_test_named_unlink (f, n)
#  else /* if defined( XTR_BSD_TEST_NAMED ) */
#   define xb_nenabled(f) fpathconf ((f), _PC_NAMEDATTR_ENABLED)
#   define xb_nhas(f) fpathconf ((f), _PC_HAS_NAMEDATTR)
#   define xb_ndir(f) openat ((f), ".", O_RDONLY | O_NAMEDATTR, 0)
#   define xb_nopen(f, n, flags, mode)                                           \
  openat ((f), (n), (flags) | O_NAMEDATTR | XB_NOPEN_FLAGS, (mode))
#   define xb_nunlink(f, n) unlinkat ((f), (n), 0)
#  endif /* if defined( XTR_BSD_TEST_NAMED ) */
# endif /* if ( defined( __FreeBSD__ ) && defined( O_NAMEDATTR ) && defined(   \
          _PC_NAMEDATTR_ENABLED ) && defined( _PC_HAS_NAMEDATTR )) ||         \
          defined( XTR_BSD_TEST_NAMED ) */
/* Attribute names never follow symlinks. Some filesystems do not allow
 * symlink objects in their named-attribute directory, but mocks and other
 * backends can; reject rather than operating on an external target. */
# ifdef XB_NAMED
#  ifndef O_NOFOLLOW
#   error "Named-stream restoration requires O_NOFOLLOW"
#  endif /* ifndef O_NOFOLLOW */
#  define XB_NOPEN_FLAGS O_NOFOLLOW
#  ifdef O_CLOEXEC
#   undef XB_NOPEN_FLAGS
#   define XB_NOPEN_FLAGS (O_NOFOLLOW | O_CLOEXEC)
#  endif /* ifdef O_CLOEXEC */
# endif /* ifdef XB_NAMED */
# define XB_MAX_LIST (1024UL * 1024UL)
# define XB_MAX_VALUE (1024UL * 1024UL)
# define XB_MAX_MANIFEST (32UL * 1024UL * 1024UL)
# define XB_MAX_RECORDS 1024UL
# if defined(__NetBSD__) || defined(XTR_BSD_TEST_NETBSD)
#  define XB_ORIGIN 3U
#  define XB_IFACE 4U
#  define XB_SET_SUCCESS(r, n) ((r) == 0)
# else /* if defined( __NetBSD__ ) || defined( XTR_BSD_TEST_NETBSD ) */
#  define XB_ORIGIN 2U
#  define XB_IFACE 2U
#  define XB_SET_SUCCESS(r, n) ((r) >= 0 && (size_t)(r) == (n))
# endif /* if defined( __NetBSD__ ) || defined( XTR_BSD_TEST_NETBSD ) */

typedef struct xb_attr
{
  char *name;
  unsigned char *data;
  size_t size, pos;
  unsigned char native[62];
  unsigned type, mode;
  int stream_fd;
# ifdef XB_NAMED
  xtr_sha256 captured_hash;
  dev_t captured_dev;
  ino_t captured_ino;
  struct timespec stamp[2];
# endif /* ifdef XB_NAMED */
} xb_attr;
static const unsigned char xb_user[] = "user";
static void
xb_free (xb_attr *a, size_t count)
{
  size_t i;

  if (!a)
    {
      return;
    }

  for (i = 0; i < count; i++)
    {
# ifdef XB_NAMED
      if (a[i].type == 2U && a[i].stream_fd >= 0)
        {
          close (a[i].stream_fd);
        }

# endif /* ifdef XB_NAMED */
      free (a[i].name);
      free (a[i].data);
    }

  free (a);
}
static xtr_u64
xb_u64 (size_t n)
{
  xtr_u64 v;

  v.lo = ((unsigned long)n) & 0xffffffffUL;
  v.hi = ((unsigned long)n) >> 16 >> 16;
  return v;
}
static void
xb_policy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = XB_MAX_RECORDS;
  p->max_field = XB_MAX_VALUE;
  p->max_manifest = xb_u64 (XB_MAX_MANIFEST);
}
static int
xb_cmp (const void *a, const void *b)
{
  const xb_attr *x = (const xb_attr *)a, *y = (const xb_attr *)b;

  if (x->type != y->type)
    {
      return x->type < y->type ? -1 : 1;
    }

  return strcmp (x->name, y->name);
}
static int
xb_set (int fd, const char *name, const unsigned char *data, size_t size)
{
# if defined(__NetBSD__) || defined(XTR_BSD_TEST_NETBSD)
  int rv = extattr_set_fd (fd, EXTATTR_NAMESPACE_USER, name, data, size);
# else  /* if defined( __NetBSD__ ) || defined( XTR_BSD_TEST_NETBSD ) */
  ssize_t rv = extattr_set_fd (fd, EXTATTR_NAMESPACE_USER, name, data, size);
# endif /* if defined( __NetBSD__ ) || defined( XTR_BSD_TEST_NETBSD ) */
  return XB_SET_SUCCESS (rv, size) ? 0 : -1;
}
/* A second list read must fit exactly; no silently truncated buffer. */
static int
xb_list (int fd, unsigned char **out, size_t *length)
{
  ssize_t n, got;
  unsigned char *p;

  *out = NULL;
  *length = 0;
  n = extattr_list_fd (fd, EXTATTR_NAMESPACE_USER, NULL, 0);
  if (n < 0)
    {
      return XTR_IO;
    }

  if ((unsigned long)n > XB_MAX_LIST)
    {
      return XTR_LIMIT;
    }

  p = (unsigned char *)malloc (n ? (size_t)n : 1U);
  if (!p)
    {
      return XTR_LIMIT;
    }

  got = extattr_list_fd (fd, EXTATTR_NAMESPACE_USER, p, (size_t)n);
  if (got < 0)
    {
      free (p);
      return XTR_IO;
    }

  if (got != n)
    {
      free (p);
      return XTR_IO;
    }

  *out = p;
  *length = (size_t)n;
  return XTR_OK;
}
/* Entire length-prefixed name enumeration is checked before any native
 * operation; names cannot have embedded NUL and must not repeat. */
static int
xb_names (const unsigned char *p, size_t length, size_t *count)
{
  size_t at = 0, n = 0, i;

  while (at < length)
    {
      size_t len = (size_t)p[at++], start = at;
      if (len == 0 || len > length - at || memchr (p + at, 0, len))
        {
          return XTR_CORRUPT;
        }

      at += len;
      n++;
      if (n > XB_MAX_RECORDS)
        {
          return XTR_LIMIT;
        }

      /* Reject exact duplicate native names irrespective of list order. */
      for (i = 0; i < start - 1U;)
        {
          size_t other = (size_t)p[i++];
          if (other == len && !memcmp (p + i, p + start, len))
            {
              return XTR_CORRUPT;
            }

          i += other;
        }
    }
  *count = n;
  return XTR_OK;
}
# ifdef XB_NAMED
/* File-like attributes are enumerated through the associated attribute
 * directory. Every open names a single component and the supplied owner fd
 * is never replaced by a pathname lookup. Native per-stream metadata is
 * preserved as a mode TLV; ownership/timestamps require a later increment. */
/* V1 time TLVs store signed two's-complement seconds in 64 bits,
 * followed by nanoseconds. Implement the conversion without long long,
 * signed overflow, host byte-order assumptions, or non-C89 arithmetic. */
static void
xb_put32 (unsigned char *p, unsigned long n)
{
  unsigned i;

  for (i = 0; i < 4U; i++)
    {
      p[i] = (unsigned char)(n & 255UL);
      n >>= 8;
    }
}
static int
xb_stamp_put (unsigned char *p, const struct timespec *ts)
{
  time_t n = ts->tv_sec;
  int neg = n < (time_t)0;
  unsigned i;

  if (ts->tv_nsec < 0 || ts->tv_nsec > 999999999L)
    {
      return XTR_UNSUPPORTED;
    }

  if (neg)
    {
      n = -(n + (time_t)1);
    }

  for (i = 0; i < 8U; i++)
    {
      unsigned part = (unsigned)(n % (time_t)256);
      p[i] = (unsigned char)(neg ? (255U - part) : part);
      n /= (time_t)256;
    }

  if (n != (time_t)0 || ((!neg && (p[7] & 128U)) || (neg && !(p[7] & 128U))))
    {
      return XTR_UNSUPPORTED;
    }

  xb_put32 (p + 8, (unsigned long)ts->tv_nsec);
  return XTR_OK;
}
static int
xb_stamp_get (struct timespec *ts, const unsigned char *p)
{
  unsigned i, bits = (unsigned)(sizeof (time_t) * CHAR_BIT);
  int neg = (p[7] & 128U) != 0;
  time_t max = 0, n = 0;
  unsigned long ns = (unsigned long)p[8] | ((unsigned long)p[9] << 8)
                     | ((unsigned long)p[10] << 16)
                     | ((unsigned long)p[11] << 24);

  if (ns > 999999999UL || bits < 16U || bits > 64U)
    {
      return XTR_UNSUPPORTED;
    }

  /* The signed-i64 wire format cannot represent >2^63-1, including on
   * a host with unsigned time_t. Negative times require signed time_t. */
  if (neg && (time_t)-1 > (time_t)0)
    {
      return XTR_UNSUPPORTED;
    }

  for (i = 0; i < bits - 1U; i++)
    {
      max = max * (time_t)2 + (time_t)1;
    }

  for (i = 8U; i != 0U;)
    {
      unsigned digit;
      i--;
      digit = neg ? (255U - (unsigned)p[i]) : (unsigned)p[i];
      if (n > (max - (time_t)digit) / (time_t)256)
        {
          return XTR_UNSUPPORTED;
        }

      n = n * (time_t)256 + (time_t)digit;
    }

  ts->tv_sec = neg ? (-n - (time_t)1) : n;
  ts->tv_nsec = (long)ns;
  return XTR_OK;
}
static int
xb_collect_named (int fd, xb_attr **entries, size_t *count,
                  size_t traditional_total)
{
  DIR *directory = NULL;
  struct dirent *ent;
  xb_attr *a = *entries;
  size_t n = *count, total = traditional_total;
  int dfd, err = XTR_OK;
  long enabled = xb_nenabled (fd), has;

  if (enabled == 0)
    {
      return XTR_OK;
    }

  if (enabled < 0)
    {
      return XTR_IO;
    }

  has = xb_nhas (fd);
  if (has < 0)
    {
      return XTR_IO;
    }

  if (has == 0)
    {
      return XTR_OK; /* Do not create an empty attribute directory. */
    }

  dfd = xb_ndir (fd);
  if (dfd < 0)
    {
      return XTR_IO;
    }

  directory = fdopendir (dfd);
  if (!directory)
    {
      close (dfd);
      return XTR_IO;
    }

  errno = 0;
  while ((ent = readdir (directory)) != NULL)
    {
      size_t len;
      int vfd;
      struct stat st;
      xb_attr *v, *next;
      if (!strcmp (ent->d_name, ".") || !strcmp (ent->d_name, ".."))
        {
          continue;
        }

      len = strlen (ent->d_name);
      if (!len || len > 255U || strchr (ent->d_name, '/'))
        {
          err = XTR_UNSUPPORTED;
          break;
        }

      if (n >= XB_MAX_RECORDS)
        {
          err = XTR_LIMIT;
          break;
        }

      vfd = xb_nopen (fd, ent->d_name, O_RDONLY, 0);
      if (vfd < 0)
        {
          err = XTR_IO;
          break;
        }

      if (fstat (vfd, &st) != 0 || !S_ISREG (st.st_mode) || st.st_size < 0
          || st.st_size > (off_t)(XB_MAX_MANIFEST - total))
        {
          close (vfd);
          err = XTR_LIMIT;
          break;
        }

      next = (xb_attr *)realloc (a, (n + 1U) * sizeof (*a));
      if (!next)
        {
          close (vfd);
          err = XTR_LIMIT;
          break;
        }

      a = next;
      memset (&a[n], 0, sizeof (a[n]));
      v = &a[n];
      v->stream_fd = vfd;
      v->type = 2U;
      v->name = (char *)malloc (len + 1U);
      if (!v->name)
        {
          close (vfd);
          v->stream_fd = -1;
          err = XTR_LIMIT;
          break;
        }

      memcpy (v->name, ent->d_name, len + 1U);
      v->size = (size_t)st.st_size;
      v->mode = (unsigned)(st.st_mode & 07777);
      v->captured_dev = st.st_dev;
      v->captured_ino = st.st_ino;
      v->stamp[0] = st.st_atim;
      v->stamp[1] = st.st_mtim;
      xtr_sha256_init (&v->captured_hash);
      total += v->size;
      n++;
      errno = 0;
    }
  if (errno && err == XTR_OK)
    {
      err = XTR_IO;
    }

  closedir (directory);
  *entries = a;
  *count = n;
  return err;
}
static int
xb_clear_named (int fd)
{
  DIR *directory;
  struct dirent *ent;
  char **names;
  size_t n = 0, i;
  int dfd, rc = XTR_OK;
  long enabled = xb_nenabled (fd), has;

  if (enabled == 0)
    {
      return XTR_OK;
    }

  if (enabled < 0)
    {
      return XTR_IO;
    }

  has = xb_nhas (fd);
  if (has < 0)
    {
      return XTR_IO;
    }

  if (has == 0)
    {
      return XTR_OK;
    }

  dfd = xb_ndir (fd);
  if (dfd < 0)
    {
      return XTR_IO;
    }

  directory = fdopendir (dfd);
  if (!directory)
    {
      close (dfd);
      return XTR_IO;
    }

  names = (char **)calloc (XB_MAX_RECORDS, sizeof (char *));
  if (!names)
    {
      closedir (directory);
      return XTR_LIMIT;
    }

  errno = 0;
  while ((ent = readdir (directory)) != NULL)
    {
      size_t len;
      if (!strcmp (ent->d_name, ".") || !strcmp (ent->d_name, ".."))
        {
          continue;
        }

      len = strlen (ent->d_name);
      if (n == XB_MAX_RECORDS)
        {
          rc = XTR_LIMIT;
          break;
        }

      if (len == 0 || len > 255U || strchr (ent->d_name, '/'))
        {
          rc = XTR_UNSUPPORTED;
          break;
        }

      names[n] = (char *)malloc (len + 1U);
      if (!names[n])
        {
          rc = XTR_LIMIT;
          break;
        }

      memcpy (names[n], ent->d_name, len + 1U);
      n++;
      errno = 0;
    }
  if (errno && rc == XTR_OK)
    {
      rc = XTR_IO;
    }

  if (rc == XTR_OK)
    {
      for (i = 0; i < n; i++)
        {
          if (xb_nunlink (dfd, names[i]) != 0 && errno != ENOENT)
            {
              rc = XTR_IO;
              break;
            }
        }
    }

  closedir (directory);
  for (i = 0; i < n; i++)
    {
      free (names[i]);
    }

  free (names);
  return rc;
}
static int
xb_write_named (int fd, const char *name, int mode, int source_fd,
                const unsigned char *data, size_t length,
                const struct timespec stamp[2])
{
  unsigned char buf[4096];
  size_t left = length;
  int to, rc = 0;

  to = xb_nopen (fd, name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (to < 0)
    {
      return -1;
    }

  {
    struct stat st;
    if (fstat (to, &st) != 0 || !S_ISREG (st.st_mode))
      {
        rc = -1;
      }
  }
  if (!rc && source_fd >= 0 && lseek (source_fd, 0, SEEK_SET) < 0)
    {
      rc = -1;
    }

  while (left && !rc)
    {
      size_t want = left < sizeof (buf) ? left : sizeof (buf), at = 0;
      ssize_t got;
      const unsigned char *src = data;
      if (source_fd >= 0)
        {
          got = read (source_fd, buf, want);
          if (got <= 0)
            {
              rc = -1;
              break;
            }

          want = (size_t)got;
          src = buf;
        }

      while (at < want)
        {
          ssize_t put = write (to, src + at, want - at);
          if (put <= 0)
            {
              rc = -1;
              break;
            }

          at += (size_t)put;
        }
      if (!rc)
        {
          left -= want;
          if (data)
            {
              data += want;
            }
        }
    }
  if (!rc && fchmod (to, (mode_t)(mode & 07777)) != 0)
    {
      rc = -1;
    }

  if (!rc && futimens (to, stamp) != 0)
    {
      rc = -1;
    }

  if (close (to) != 0)
    {
      rc = -1;
    }

  return rc;
}
# endif /* ifdef XB_NAMED */
/* Snapshot values.  Cap total memory and detect changed enumeration. */
static int
xb_snapshot (int fd, xb_attr **out, size_t *count)
{
  unsigned char *names = NULL, *again = NULL;
  size_t n = 0, n2 = 0, items = 0, at = 0, used = 0, total = 0, i;
  xb_attr *a = NULL;
  int rc;

  *out = NULL;
  *count = 0;
  rc = xb_list (fd, &names, &n);
  if (rc)
    {
      return rc;
    }

  rc = xb_names (names, n, &items);
  if (rc)
    {
      goto done;
    }

  a = (xb_attr *)calloc (items ? items : 1U, sizeof (*a));
  if (!a)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  while (at < n)
    {
      size_t len = names[at++];
      ssize_t size, got;
      xb_attr *v = &a[used++];
      /* Count the partially initialized entry so every error path frees
       * its name/value allocation as well as completed entries. */
      v->type = 1U;
      v->name = (char *)malloc (len + 1U);
      if (!v->name)
        {
          rc = XTR_LIMIT;
          goto done;
        }

      memcpy (v->name, names + at, len);
      v->name[len] = 0;
      at += len;
      size = extattr_get_fd (fd, EXTATTR_NAMESPACE_USER, v->name, NULL, 0);
      if (size < 0)
        {
          rc = XTR_IO;
          goto done;
        }

      if ((unsigned long)size > XB_MAX_VALUE
          || (size_t)size > XB_MAX_MANIFEST - total)
        {
          rc = XTR_LIMIT;
          goto done;
        }

      v->size = (size_t)size;
      v->data = (unsigned char *)malloc (v->size ? v->size : 1U);
      if (!v->data)
        {
          rc = XTR_LIMIT;
          goto done;
        }

      got = extattr_get_fd (fd, EXTATTR_NAMESPACE_USER, v->name, v->data,
                            v->size);
      if (got < 0 || (size_t)got != v->size)
        {
          rc = XTR_IO;
          goto done;
        }

      total += v->size;
    }
  rc = xb_list (fd, &again, &n2);
  if (rc)
    {
      goto done;
    }

  if (n != n2 || (n && memcmp (names, again, n)))
    {
      rc = XTR_IO;
      goto done;
    }

# ifdef XB_NAMED
  rc = xb_collect_named (fd, &a, &items, total);
  if (rc)
    {
      goto done;
    }

# endif /* ifdef XB_NAMED */
  qsort (a, items, sizeof (*a), xb_cmp);
  for (i = 1; i < items; i++)
    {
      if (a[i - 1].type == a[i].type && !strcmp (a[i - 1].name, a[i].name))
        {
          rc = XTR_CORRUPT;
          goto done;
        }
    }

  *out = a;
  *count = items;
  a = NULL;
  rc = XTR_OK;
done:
  xb_free (a, items);
  free (names);
  free (again);
  return rc;
}
static size_t
xb_value_read (void *arg, unsigned char *out, size_t want)
{
  xb_attr *a = (xb_attr *)arg;
  size_t n = a->size - a->pos;

  if (n > want)
    {
      n = want;
    }

# ifdef XB_NAMED
  if (a->type == 2U)
    {
      ssize_t got = read (a->stream_fd, out, n);
      if (got <= 0)
        {
          return 0;
        }

      xtr_sha256_update (&a->captured_hash, out, (size_t)got);
      a->pos += (size_t)got;
      return (size_t)got;
    }

# endif /* ifdef XB_NAMED */
  if (n)
    {
      memcpy (out, a->data + a->pos, n);
    }

  a->pos += n;
  return n;
}
static int
xb_file_write (void *arg, const unsigned char *in, size_t n)
{
  return fwrite (in, 1, n, (FILE *)arg) == n ? 0 : 1;
}
static size_t
xb_file_read (void *arg, unsigned char *out, size_t want)
{
  return fread (out, 1, want, (FILE *)arg);
}
int
xtr_bsd_capture_fd (int fd, const unsigned char owner[16], FILE *stage,
                    int encrypted, xtr1_digest *digest)
{
  xb_attr *a = NULL;
  xtr1_source *sources = NULL;
  xtr1_policy pol;
  xtr1_sink sink;
  size_t n = 0, i;
  int rc;

  if (fd < 0 || !owner || !stage || !digest
      || (encrypted != 0 && encrypted != 1))
    {
      return XTR_CORRUPT;
    }

  rc = xb_snapshot (fd, &a, &n);
  if (rc)
    {
      return rc;
    }

  sources = (xtr1_source *)calloc (n ? n : 1U, sizeof (*sources));
  if (!sources)
    {
      xb_free (a, n);
      return XTR_LIMIT;
    }

  for (i = 0; i < n; i++)
    {
      xtr1_source *v = &sources[i];
      xb_attr *attr = &a[i];
      attr->native[0] = 1;
      attr->native[1] = 0;
      attr->native[2] = 0;
      attr->native[3] = 0;
      attr->native[4] = 2;
      attr->native[5] = 0;
      attr->native[6] = 0;
      attr->native[7] = 0;
      attr->native[8] = XB_IFACE;
      attr->native[9] = 0;
      v->record.type = 1;
      v->record.origin = XB_ORIGIN;
# ifdef XB_NAMED
      if (attr->type == 2U)
        {
          attr->native[8] = 3; /* FreeBSD named streams */
          attr->native[10] = 2;
          attr->native[11] = 0;
          attr->native[12] = 0;
          attr->native[13] = 0;
          attr->native[14] = 4;
          attr->native[15] = 0;
          attr->native[16] = 0;
          attr->native[17] = 0;
          attr->native[18] = (unsigned char)attr->mode;
          attr->native[19] = (unsigned char)(attr->mode >> 8);
          attr->native[20] = 0;
          attr->native[21] = 0;
          /* TLV 6 and 7: atime and mtime. Existing 22-byte manifests
           * remain readable; no new on-disk record type is introduced. */
          attr->native[22] = 6;
          attr->native[26] = 12;
          attr->native[42] = 7;
          attr->native[46] = 12;
          if (xb_stamp_put (attr->native + 30, &attr->stamp[0]) != XTR_OK
              || xb_stamp_put (attr->native + 50, &attr->stamp[1]) != XTR_OK)
            {
              free (sources);
              xb_free (a, n);
              return XTR_UNSUPPORTED;
            }

          v->record.type = 2U;
          v->record.origin = 2U;
        }

# endif /* ifdef XB_NAMED */
      v->record.encoding = 0;
      v->record.ns_len = 4;
      v->record.name_len = (unsigned long)strlen (attr->name);
      v->record.native_len = attr->type == 2U ? 62UL : 10UL;
      v->record.value_len = xb_u64 (attr->size);
      v->ns = xb_user;
      v->name = (const unsigned char *)attr->name;
      v->native = attr->native;
      v->read_value = xb_value_read;
      v->value_context = attr;
    }

  xb_policy (&pol);
  sink.write = xb_file_write;
  sink.context = stage;
  if (fseek (stage, 0, SEEK_SET))
    {
      rc = XTR_IO;
    }
  else
    {
      rc = xtr1_write_manifest (owner, sources, n, encrypted, &pol, &sink,
                                digest);
    }

# ifdef XB_NAMED
  /* Catch same-size/mode changes during the snapshot before publishing the
   * staged manifest. The stream itself remains bounded and never buffered. */
  if (rc == XTR_OK)
    {
      for (i = 0; i < n; i++)
        {
          if (a[i].type == 2U)
            {
              unsigned char original[32], current[32], buf[4096];
              xtr_sha256 verify;
              size_t remaining = a[i].size;
              struct stat st;
              int current_fd = -1;
              xtr_sha256_final (&a[i].captured_hash, original);
              xtr_sha256_init (&verify);
              if (lseek (a[i].stream_fd, 0, SEEK_SET) < 0)
                {
                  rc = XTR_IO;
                  break;
                }

              while (remaining)
                {
                  size_t want
                      = remaining < sizeof (buf) ? remaining : sizeof (buf);
                  ssize_t got = read (a[i].stream_fd, buf, want);
                  if (got <= 0)
                    {
                      rc = XTR_IO;
                      break;
                    }

                  xtr_sha256_update (&verify, buf, (size_t)got);
                  remaining -= (size_t)got;
                }
              if (rc)
                {
                  break;
                }

              xtr_sha256_final (&verify, current);
              if (memcmp (original, current, 32)
                  || fstat (a[i].stream_fd, &st) != 0
                  || st.st_dev != a[i].captured_dev
                  || st.st_ino != a[i].captured_ino
                  || st.st_size != (off_t)a[i].size
                  || st.st_mtim.tv_sec != a[i].stamp[1].tv_sec
                  || st.st_mtim.tv_nsec != a[i].stamp[1].tv_nsec
                  || (unsigned)(st.st_mode & 07777) != a[i].mode)
                {
                  rc = XTR_IO;
                  break;
                }

              /* Reading the pinned inode is not sufficient: a concurrent
               * rename could replace the name with a different object. Verify
               * the descriptor still identifies the file currently under that
               * name. */
              current_fd = xb_nopen (fd, a[i].name, O_RDONLY, 0);
              if (current_fd < 0)
                {
                  rc = XTR_IO;
                  break;
                }

              if (fstat (current_fd, &st) != 0
                  || st.st_dev != a[i].captured_dev
                  || st.st_ino != a[i].captured_ino
                  || st.st_size != (off_t)a[i].size
                  || st.st_mtim.tv_sec != a[i].stamp[1].tv_sec
                  || st.st_mtim.tv_nsec != a[i].stamp[1].tv_nsec
                  || (unsigned)(st.st_mode & 07777) != a[i].mode)
                {
                  rc = XTR_IO;
                }

              if (close (current_fd) != 0)
                {
                  rc = XTR_IO;
                }

              if (rc)
                {
                  break;
                }
            }
        }
    }

# endif /* ifdef XB_NAMED */
  if (rc == XTR_OK && (fflush (stage) || fseek (stage, 0, SEEK_SET)))
    {
      rc = XTR_IO;
    }

  free (sources);
  xb_free (a, n);
  return rc;
}
/* Metadata callbacks validate names, native TLVs and exact origin BEFORE
 * restoring. No system namespace, no cross-BSD implicit name conversion. */
typedef struct xb_restore
{
  int fd, dry, error, have;
  xtr_record rec;
  char *name;
  unsigned char *value;
  size_t at_name, at_value;
  unsigned mode;
  int stream_fd, have_times;
# ifdef XB_NAMED
  struct timespec stamp[2];
# endif /* ifdef XB_NAMED */
} xb_restore;
# ifdef XTR_TEST_HOOKS
static long xb_fail_after = -1;
void
xtr_bsd_test_fail_after (long writes)
{
  xb_fail_after = writes;
}
# endif /* ifdef XTR_TEST_HOOKS */
static int
xb_flush (xb_restore *r)
{
  if (!r->have)
    {
      return 0;
    }

  if (r->at_name != (size_t)r->rec.name_len
      || r->at_value != (size_t)r->rec.value_len.lo || !r->name || !r->at_name
      || memchr (r->name, 0, r->at_name))
    {
      r->error = XTR_CORRUPT;
      return 1;
    }

  r->name[r->at_name] = '\0';
# ifdef XB_NAMED
  if (r->rec.type == 2U
      && (strchr (r->name, '/') || !strcmp (r->name, ".")
          || !strcmp (r->name, "..")))
    {
      r->error = XTR_CORRUPT;
      return 1;
    }

# endif /* ifdef XB_NAMED */
# ifdef XTR_TEST_HOOKS
  if (!r->dry && xb_fail_after == 0)
    {
      xb_fail_after = -1;
      errno = EIO;
      r->error = XTR_IO;
      return 1;
    }

  if (!r->dry && xb_fail_after > 0)
    {
      xb_fail_after--;
    }

# endif /* ifdef XTR_TEST_HOOKS */
# ifdef XB_NAMED
  if (r->rec.type == 2U)
    {
      if (r->stream_fd >= 0)
        {
          if (r->dry == 2)
            {
              unsigned char b;
              if (read (r->stream_fd, &b, 1) != 0)
                {
                  r->error = XTR_CORRUPT;
                  return 1;
                }
            }

          if (r->dry == 0 && fchmod (r->stream_fd, (mode_t)r->mode) != 0)
            {
              r->error = XTR_IO;
              return 1;
            }

          /* Apply times after verification reads, otherwise those reads
           * can modify atime immediately after the restore. */
          if (r->dry == 2 && r->have_times)
            {
              struct stat st;
              if (futimens (r->stream_fd, r->stamp) != 0)
                {
                  r->error = XTR_IO;
                  return 1;
                }

              /* On filesystems that round timestamp precision, a
               * successful futimens() is not proof of an exact restore. */
              if (fstat (r->stream_fd, &st) != 0
                  || st.st_atim.tv_sec != r->stamp[0].tv_sec
                  || st.st_atim.tv_nsec != r->stamp[0].tv_nsec
                  || st.st_mtim.tv_sec != r->stamp[1].tv_sec
                  || st.st_mtim.tv_nsec != r->stamp[1].tv_nsec)
                {
                  r->error = XTR_UNSUPPORTED;
                  return 1;
                }
            }

          if (close (r->stream_fd) != 0)
            {
              r->stream_fd = -1;
              r->error = XTR_IO;
              return 1;
            }

          r->stream_fd = -1;
        }
    }
  else
# endif /* ifdef XB_NAMED */
    if (r->rec.type == 1U)
      {
        if (r->dry == 2)
          {
            ssize_t got = extattr_get_fd (r->fd, EXTATTR_NAMESPACE_USER,
                                          r->name, NULL, 0);
            unsigned char *actual;
            if (got < 0 || (size_t)got != r->at_value)
              {
                r->error = XTR_UNSUPPORTED;
                return 1;
              }

            actual = (unsigned char *)malloc (r->at_value ? r->at_value : 1U);
            if (!actual)
              {
                r->error = XTR_LIMIT;
                return 1;
              }

            got = extattr_get_fd (r->fd, EXTATTR_NAMESPACE_USER, r->name,
                                  actual, r->at_value);
            if (got < 0 || (size_t)got != r->at_value
                || (r->at_value && memcmp (actual, r->value, r->at_value)))
              {
                free (actual);
                r->error = XTR_UNSUPPORTED;
                return 1;
              }

            free (actual);
          }
        else if (r->dry == 0 && xb_set (r->fd, r->name, r->value, r->at_value))
          {
            r->error = XTR_IO;
            return 1;
          }
      }

  free (r->name);
  free (r->value);
  r->name = NULL;
  r->value = NULL;
  r->have = 0;
  return 0;
}
static int
xb_begin (void *ctx, const xtr_record *rec)
{
  xb_restore *r = (xb_restore *)ctx;

  if (xb_flush (r))
    {
      return 1;
    }

  if (rec->encoding != 0U || rec->ns_len != 4UL || !rec->name_len
      || rec->name_len > 255UL || rec->value_len.hi
      || rec->value_len.lo > XB_MAX_MANIFEST)
    {
      r->error = XTR_UNSUPPORTED;
      return 1;
    }

  if (rec->type == 1U)
    {
      if (rec->origin != XB_ORIGIN || rec->native_len != 10UL
          || rec->value_len.lo > XB_MAX_VALUE)
        {
          r->error = XTR_UNSUPPORTED;
          return 1;
        }
    }
  else if (rec->type == 2U)
    {
# ifdef XB_NAMED
      if (rec->origin != 2U
          || (rec->native_len != 22UL && rec->native_len != 62UL))
        {
          r->error = XTR_UNSUPPORTED;
          return 1;
        }

# else /* ifdef XB_NAMED */
      r->error = XTR_UNSUPPORTED;
      return 1;

# endif /* ifdef XB_NAMED */
    }
  else
    {
      r->error = XTR_UNSUPPORTED;
      return 1;
    }

  r->name = (char *)malloc ((size_t)rec->name_len + 1U);
  if (rec->type == 1U)
    {
      r->value = (unsigned char *)malloc (
          rec->value_len.lo ? (size_t)rec->value_len.lo : 1U);
    }

  if (!r->name || (rec->type == 1U && !r->value))
    {
      r->error = XTR_LIMIT;
      return 1;
    }

  r->rec = *rec;
  r->at_name = r->at_value = 0;
  r->have = 1;
  r->stream_fd = -1;
  r->have_times = 0;
  r->mode = 0;
  return 0;
}
static int
xb_data (void *ctx, const xtr_record *rec, unsigned field,
         const unsigned char *data, size_t size)
{
  xb_restore *r = (xb_restore *)ctx;
  static const unsigned char expected[10]
      = { 1, 0, 0, 0, 2, 0, 0, 0, XB_IFACE, 0 };

  (void)rec;
  if (!r->have)
    {
      return 1;
    }

  switch (field)
    {
    case 0:
      if (size != 4 || memcmp (data, "user", 4))
        {
          goto unsupported;
        }

      break;

    case 1:
      if (size > (size_t)r->rec.name_len - r->at_name)
        {
          goto corrupt;
        }

      memcpy (r->name + r->at_name, data, size);
      r->at_name += size;
      break;

    case 2:
      if (r->rec.type == 1U)
        {
          if (size != 10 || memcmp (data, expected, 10))
            {
              goto unsupported;
            }
        }
      else
        {
# ifdef XB_NAMED
          static const unsigned char named[10]
              = { 1, 0, 0, 0, 2, 0, 0, 0, 3, 0 };
          if ((size != 22U && size != 62U) || memcmp (data, named, 10)
              || memcmp (data + 10, "\002\000\000\000\004\000\000\000", 8)
              || data[20] || data[21] || (data[19] & 0xf0U))
            {
              goto unsupported;
            }

          r->mode = (unsigned)data[18] | ((unsigned)data[19] << 8);
          if (size == 62U)
            {
              static const unsigned char atag[8] = { 6, 0, 0, 0, 12, 0, 0, 0 };
              static const unsigned char mtag[8] = { 7, 0, 0, 0, 12, 0, 0, 0 };
              if (memcmp (data + 22, atag, 8) || memcmp (data + 42, mtag, 8)
                  || xb_stamp_get (&r->stamp[0], data + 30) != XTR_OK
                  || xb_stamp_get (&r->stamp[1], data + 50) != XTR_OK)
                {
                  goto unsupported;
                }

              r->have_times = 1;
            }

          if (r->at_name != (size_t)r->rec.name_len)
            {
              goto corrupt;
            }

          r->name[r->at_name] = '\0';
          /* Validate *before* O_CREAT/O_TRUNC, not on record flush. */
          if (!r->name[0] || strchr (r->name, '/') || !strcmp (r->name, ".")
              || !strcmp (r->name, ".."))
            {
              goto corrupt;
            }

          if (!r->dry)
            {
              struct stat st;
              r->stream_fd = xb_nopen (r->fd, r->name,
                                       O_WRONLY | O_CREAT | O_TRUNC, 0600);
              if (r->stream_fd < 0)
                {
                  r->error = XTR_IO;
                  return 1;
                }

              if (fstat (r->stream_fd, &st) != 0 || !S_ISREG (st.st_mode))
                {
                  r->error = XTR_UNSUPPORTED;
                  return 1;
                }
            }
          else if (r->dry == 2)
            {
              r->stream_fd = xb_nopen (r->fd, r->name, O_RDONLY, 0);
              if (r->stream_fd < 0)
                {
                  r->error = XTR_UNSUPPORTED;
                  return 1;
                }

              {
                struct stat st;
                if (fstat (r->stream_fd, &st) != 0 || !S_ISREG (st.st_mode)
                    || (unsigned)(st.st_mode & 07777) != r->mode)
                  {
                    r->error = XTR_UNSUPPORTED;
                    return 1;
                  }
              }
            }

# else  /* ifdef XB_NAMED */
          goto unsupported;
# endif /* ifdef XB_NAMED */
        }

      break;

    case 3:
      if (size > (size_t)r->rec.value_len.lo - r->at_value)
        {
          goto corrupt;
        }

# ifdef XB_NAMED
      if (r->rec.type == 2U)
        {
          if (r->dry == 0)
            {
              size_t pos = 0;
              while (pos < size)
                {
                  ssize_t n = write (r->stream_fd, data + pos, size - pos);
                  if (n <= 0)
                    {
                      r->error = XTR_IO;
                      return 1;
                    }

                  pos += (size_t)n;
                }
            }
          else if (r->dry == 2)
            {
              unsigned char buf[4096];
              size_t pos = 0;
              while (pos < size)
                {
                  size_t want = size - pos;
                  ssize_t n;
                  if (want > sizeof (buf))
                    {
                      want = sizeof (buf);
                    }

                  n = read (r->stream_fd, buf, want);
                  if (n <= 0 || memcmp (buf, data + pos, (size_t)n))
                    {
                      r->error = XTR_UNSUPPORTED;
                      return 1;
                    }

                  pos += (size_t)n;
                }
            }
        }
      else
# endif /* ifdef XB_NAMED */
        memcpy (r->value + r->at_value, data, size);
      r->at_value += size;
      break;

    default:
      goto corrupt;
    }
  return 0;

unsupported:
  r->error = XTR_UNSUPPORTED;
  return 1;

corrupt:
  r->error = XTR_CORRUPT;
  return 1;
}
static int
xb_clear (int fd)
{
  unsigned char *names = NULL;
  size_t n = 0, at = 0, count;
  int rc;

# ifdef XB_NAMED
  rc = xb_clear_named (fd);
  if (rc)
    {
      return rc;
    }

# endif /* ifdef XB_NAMED */
  rc = xb_list (fd, &names, &n);
  if (rc)
    {
      return rc;
    }

  rc = xb_names (names, n, &count);
  if (rc)
    {
      free (names);
      return rc;
    }

  while (at < n)
    {
      size_t len = names[at++];
      char name[256];
      memcpy (name, names + at, len);
      name[len] = 0;
      at += len;
      if (extattr_delete_fd (fd, EXTATTR_NAMESPACE_USER, name) != 0)
        {
          free (names);
          return XTR_IO;
        }
    }
  free (names);
  return XTR_OK;
}
static int
xb_rollback (int fd, xb_attr *snapshot, size_t n)
{
  size_t i;
  int rc = xb_clear (fd);

  for (i = 0; i < n; i++)
    {
# ifdef XB_NAMED
      if (snapshot[i].type == 2U)
        {
          if (xb_write_named (fd, snapshot[i].name, (int)snapshot[i].mode,
                              snapshot[i].stream_fd, NULL, snapshot[i].size,
                              snapshot[i].stamp))
            {
              rc = XTR_IO;
            }
        }
      else
# endif /* ifdef XB_NAMED */
        if (xb_set (fd, snapshot[i].name, snapshot[i].data, snapshot[i].size))
          {
            rc = XTR_IO;
          }
    }

  return rc;
}
int
xtr_bsd_restore_fd (int fd, FILE *stage, xtr_u64 encoded_size,
                    const xtr_extra *outer, const unsigned char *sha32)
{
  xtr_reader reader;
  xtr1_policy pol;
  xtr1_digest digest;
  xtr_manifest manifest;
  xb_restore restore;
  xb_attr *prior = NULL;
  size_t prior_count = 0;
  int rc, pass, rb;

  if (fd < 0 || !stage || !outer)
    {
      return XTR_CORRUPT;
    }

  xb_policy (&pol);
  memset (&reader, 0, sizeof (reader));
  reader.context = stage;
  reader.read = xb_file_read;
  if (fseek (stage, 0, SEEK_SET))
    {
      return XTR_IO;
    }

  rc = xtr1_check_manifest (&reader, encoded_size, outer, sha32, &pol,
                            &digest);
  if (rc)
    {
      return rc;
    }

  if (!digest.schema_supported)
    {
      return XTR_UNSUPPORTED;
    }

  for (pass = 0; pass < 3; pass++)
    {
      if (pass == 1)
        {
          rc = xb_snapshot (fd, &prior, &prior_count);
          if (rc)
            {
              return rc;
            }

          rc = xb_clear (fd);
          if (rc)
            {
              rb = xb_rollback (fd, prior, prior_count);
              xb_free (prior, prior_count);
              return rb ? XTR_IO : rc;
            }
        }

      memset (&restore, 0, sizeof (restore));
      restore.fd = fd;
      restore.dry = (pass == 0 ? 1 : pass == 1 ? 0 : 2);
      restore.stream_fd = -1;
      reader.sink_context = &restore;
      reader.begin = xb_begin;
      reader.data = xb_data;
      reader.max_records = pol.max_records;
      reader.max_field = pol.max_field;
      reader.max_total = pol.max_manifest;
      if (fseek (stage, 0, SEEK_SET))
        {
          rc = XTR_IO;
        }
      else
        {
          rc = xtr_parse_manifest (&reader, digest.manifest_length, &manifest);
        }

      if (!rc && xb_flush (&restore))
        {
          rc = restore.error ? restore.error : XTR_IO;
        }

      if (rc == XTR_IO && restore.error)
        {
          rc = restore.error;
        }

# ifdef XB_NAMED
      if (restore.stream_fd >= 0)
        {
          close (restore.stream_fd);
        }

# endif /* ifdef XB_NAMED */
      free (restore.name);
      free (restore.value);
      if (rc)
        {
          if (pass >= 1)
            {
              rb = xb_rollback (fd, prior, prior_count);
              xb_free (prior, prior_count);
              if (rb)
                {
                  return XTR_IO;
                }
            }

          return rc;
        }
    }

  xb_free (prior, prior_count);
  return XTR_OK;
}
#endif /* if defined( __FreeBSD__ ) || defined( __NetBSD__ ) || defined(      \
          XTR_BSD_TEST ) */
