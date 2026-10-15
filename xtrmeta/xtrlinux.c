/* SPDX-License-Identifier: MIT-0 */
/* Linux filesystem adapter for the Xtro-ZIP V1 portable metadata core.
 * No ZIP parser, no filesystem paths, no native writes prior to validation. */
#include "xtrlinux.h"
#ifdef __linux__
# include <errno.h>
# include <limits.h>
# include <stdlib.h>
# include <string.h>
# include <sys/types.h>
# include <sys/xattr.h>
# define XL_MAX_NAMES (1024U * 1024U)
# define XL_MAX_RECORDS 1024U
# define XL_MAX_VALUE (1024U * 1024U)
# define XL_MAX_MANIFEST (32UL * 1024UL * 1024UL)

typedef struct xl_attr
{
  char *name;
  unsigned char *value;
  size_t length, at;
  unsigned char native[10];
  xtr1_source source;
} xl_attr;
static const unsigned char xl_ns[] = "user";
static int
xl_cmp (const void *va, const void *vb)
{
  const xl_attr *a = (const xl_attr *)va, *b = (const xl_attr *)vb;

  return strcmp (a->name, b->name);
}
static size_t
xl_read_value (void *ctx, unsigned char *out, size_t want)
{
  xl_attr *a = (xl_attr *)ctx;
  size_t n = a->length - a->at;

  if (n > want)
    {
      n = want;
    }

  if (n)
    {
      memcpy (out, a->value + a->at, n);
    }

  a->at += n;
  return n;
}
static int
xl_write_file (void *ctx, const unsigned char *data, size_t len)
{
  return fwrite (data, 1, len, (FILE *)ctx) == len ? 0 : 1;
}
static size_t
xl_read_file (void *ctx, unsigned char *data, size_t want)
{
  return fread (data, 1, want, (FILE *)ctx);
}
static xtr_u64
xl_size (size_t n)
{
  xtr_u64 z;

  z.lo = ((unsigned long)n) & 0xffffffffUL;
  z.hi = ((unsigned long)n) >> 16 >> 16;
  return z;
}
static void
xl_policy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = XL_MAX_RECORDS;
  p->max_field = XL_MAX_VALUE;
  p->max_manifest = xl_size (XL_MAX_MANIFEST);
}
static void
xl_release (xl_attr *a, size_t n)
{
  size_t i;

  if (!a)
    {
      return;
    }

  for (i = 0; i < n; i++)
    {
      free (a[i].name);
      free (a[i].value);
    }

  free (a);
}
int
xtr_linux_capture_fd (int fd, const unsigned char owner[16], FILE *stage,
                      int encrypted, xtr1_digest *digest)
{
  char *names = NULL;
  ssize_t nn, nread;
  size_t at = 0, count = 0, i, used = 0;
  xl_attr *a = NULL;
  xtr1_source *source = NULL;
  xtr1_policy policy;
  xtr1_sink sink;
  int rc = XTR_IO;

  if (fd < 0 || !stage || !digest || !owner
      || (encrypted != 0 && encrypted != 1))
    {
      return XTR_CORRUPT;
    }

  xl_policy (&policy);
  nn = flistxattr (fd, NULL, 0);
  if (nn < 0)
    {
      return XTR_IO;
    }

  if ((unsigned long)nn > XL_MAX_NAMES)
    {
      return XTR_LIMIT;
    }

  names = (char *)malloc (nn ? (size_t)nn : 1U);
  if (!names)
    {
      return XTR_LIMIT;
    }

  nread = flistxattr (fd, names, (size_t)nn);
  if (nread < 0)
    {
      rc = XTR_IO;
      goto done;
    }

  if (nread > nn)
    {
      rc = XTR_CORRUPT;
      goto done;
    }

  nn = nread;
  while (at < (size_t)nn)
    {
      size_t n = at;
      while (n < (size_t)nn && names[n])
        {
          n++;
        }
      if (n == (size_t)nn || n == at)
        {
          rc = XTR_CORRUPT;
          goto done;
        }

      if (n - at > 5U && !memcmp (names + at, "user.", 5U))
        {
          count++;
        }

      at = n + 1;
    }
  if (count > XL_MAX_RECORDS)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  a = (xl_attr *)calloc (count ? count : 1U, sizeof (*a));
  source = (xtr1_source *)calloc (count ? count : 1U, sizeof (*source));
  if (!a || !source)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  at = 0;
  while (at < (size_t)nn)
    {
      size_t n = at, sz;
      ssize_t got;
      while (names[n])
        {
          n++;
        }
      sz = n - at;
      if (sz > 5U && !memcmp (names + at, "user.", 5U))
        {
          xl_attr *v = &a[used++];
          v->name = (char *)malloc (sz + 1U);
          if (!v->name)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          memcpy (v->name, names + at, sz + 1U);
          got = fgetxattr (fd, v->name, NULL, 0);
          if (got < 0)
            {
              rc = XTR_IO;
              goto done;
            }

          if ((unsigned long)got > XL_MAX_VALUE)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          v->length = (size_t)got;
          v->value = (unsigned char *)malloc (v->length ? v->length : 1U);
          if (!v->value)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          got = fgetxattr (fd, v->name, v->value, v->length);
          if (got < 0 || (size_t)got != v->length)
            {
              rc = XTR_IO;
              goto done;
            }

          /* Mandatory native interface TLV: tag=1, length=2, interface=1. */
          v->native[0] = 1;
          v->native[1] = 0;
          v->native[2] = v->native[3] = 0;
          v->native[4] = 2;
          v->native[5] = v->native[6] = v->native[7] = 0;
          v->native[8] = 1;
          v->native[9] = 0;
        }

      at = n + 1;
    }
  qsort (a, count, sizeof (*a), xl_cmp);
  for (i = 0; i < count; i++)
    {
      a[i].source.record.type = 1;
      a[i].source.record.origin = 1;
      a[i].source.record.encoding = 0;
      a[i].source.record.ns_len = 4;
      a[i].source.record.name_len = (unsigned long)strlen (a[i].name);
      a[i].source.record.native_len = 10;
      a[i].source.record.value_len = xl_size (a[i].length);
      a[i].source.ns = xl_ns;
      a[i].source.name = (const unsigned char *)a[i].name;
      a[i].source.native = a[i].native;
      a[i].source.value_context = &a[i];
      a[i].source.read_value = xl_read_value;
      source[i] = a[i].source;
    }

  sink.write = xl_write_file;
  sink.context = stage;
  if (fseek (stage, 0, SEEK_SET) != 0)
    {
      rc = XTR_IO;
      goto done;
    }

  rc = xtr1_write_manifest (owner, source, count, encrypted, &policy, &sink,
                            digest);
  if (rc == XTR_OK && (fflush (stage) || fseek (stage, 0, SEEK_SET)))
    {
      rc = XTR_IO;
    }

done:
  free (names);
  free (source);
  xl_release (a, count);
  return rc;
}
/* Verified-only native application. Store a complete attribute value before
 * calling fsetxattr. This can fail partway due to filesystem policies; callers
 * must report the failure, never claim a successful metadata round trip. */
typedef struct xl_restore
{
  int fd, error, have, dry_run;
  xtr_record r;
  unsigned char *name, *val;
  size_t name_at, val_at;
} xl_restore;
# ifdef XTR_TEST_HOOKS
static long xl_test_fail_after = -1;
# endif /* ifdef XTR_TEST_HOOKS */
static int
xl_flush (xl_restore *x)
{
  if (!x->have)
    {
      return 0;
    }

  if (x->name_at != (size_t)x->r.name_len
      || x->val_at != (size_t)x->r.value_len.lo || !x->name
      || memchr (x->name, 0, x->name_at) || x->name_at < 6
      || memcmp (x->name, "user.", 5))
    {
      x->error = XTR_UNSUPPORTED;
      return 1;
    }

  x->name[x->name_at] = 0;
# ifdef XTR_TEST_HOOKS
  if (!x->dry_run && xl_test_fail_after == 0)
    {
      xl_test_fail_after = -1;
      errno = EIO;
      x->error = XTR_IO;
      return 1;
    }

  if (!x->dry_run && xl_test_fail_after > 0)
    {
      xl_test_fail_after--;
    }

# endif /* ifdef XTR_TEST_HOOKS */
  if (!x->dry_run
      && fsetxattr (x->fd, (const char *)x->name, x->val, x->val_at, 0) != 0)
    {
      x->error = XTR_IO;
      return 1;
    }

  free (x->name);
  free (x->val);
  x->name = x->val = NULL;
  x->have = 0;
  return 0;
}
static int
xl_begin (void *p, const xtr_record *r)
{
  xl_restore *x = (xl_restore *)p;

  if (xl_flush (x))
    {
      if (!x->error)
        {
          x->error = XTR_IO;
        }

      return 1;
    }

  if (r->type != 1 || r->origin != 1 || r->encoding != 0 || r->ns_len != 4
      || r->name_len > 255U || r->name_len < 6U || r->value_len.hi
      || r->value_len.lo > XL_MAX_VALUE)
    {
      x->error = XTR_UNSUPPORTED;
      return 1;
    }

  x->name = (unsigned char *)malloc ((size_t)r->name_len + 1U);
  x->val = (unsigned char *)malloc (r->value_len.lo ? (size_t)r->value_len.lo
                                                    : 1U);
  if (!x->name || !x->val)
    {
      x->error = XTR_LIMIT;
      return 1;
    }

  x->r = *r;
  x->name_at = 0;
  x->val_at = 0;
  x->have = 1;
  return 0;
}
static int
xl_data (void *p, const xtr_record *r, unsigned field,
         const unsigned char *data, size_t n)
{
  xl_restore *x = (xl_restore *)p;

  (void)r;
  if (!x->have)
    {
      return 1;
    }

  if (field == 0)
    {
      if (n != 4 || memcmp (data, "user", 4))
        {
          x->error = XTR_UNSUPPORTED;
          return 1;
        }
    }
  else if (field == 1)
    {
      if (n > (size_t)x->r.name_len - x->name_at)
        {
          x->error = XTR_CORRUPT;
          return 1;
        }

      memcpy (x->name + x->name_at, data, n);
      x->name_at += n;
    }
  else if (field == 2)
    {
      static const unsigned char native[10] = { 1, 0, 0, 0, 2, 0, 0, 0, 1, 0 };
      if (n != 10 || memcmp (data, native, 10))
        {
          x->error = XTR_UNSUPPORTED;
          return 1;
        }
    }
  else if (field == 3)
    {
      if (n > (size_t)x->r.value_len.lo - x->val_at)
        {
          x->error = XTR_CORRUPT;
          return 1;
        }

      memcpy (x->val + x->val_at, data, n);
      x->val_at += n;
    }
  else
    {
      return 1;
    }

  return 0;
}
/* Snapshot eligible destination attributes before an exact replacement.
 * Do not begin native writes unless the entire prior set can be saved within
 * the same bounded resource policy as an input manifest.  This is a
 * best-effort rollback on write errors, not a filesystem transaction: other
 * writers and permission changes cannot be rolled back atomically. */
static int
xl_snapshot_fd (int fd, xl_attr **saved, size_t *count)
{
  char *names = NULL;
  ssize_t n, got;
  size_t at = 0, total = 0, used = 0, capacity = 0;
  xl_attr *items = NULL;
  int rc = XTR_IO;

  *saved = NULL;
  *count = 0;
  n = flistxattr (fd, NULL, 0);
  if (n < 0)
    {
      return XTR_IO;
    }

  if ((unsigned long)n > XL_MAX_NAMES)
    {
      return XTR_LIMIT;
    }

  names = (char *)malloc (n ? (size_t)n : 1U);
  if (!names)
    {
      return XTR_LIMIT;
    }

  got = flistxattr (fd, names, (size_t)n);
  if (got < 0)
    {
      goto done;
    }

  if (got > n)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  n = got;
  while (at < (size_t)n)
    {
      size_t end = at;
      while (end < (size_t)n && names[end])
        {
          end++;
        }
      if (end == (size_t)n || end == at)
        {
          rc = XTR_CORRUPT;
          goto done;
        }

      if (end - at >= 6U && !memcmp (names + at, "user.", 5U))
        {
          capacity++;
        }

      at = end + 1U;
    }
  if (capacity > XL_MAX_RECORDS)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  items = (xl_attr *)calloc (capacity ? capacity : 1U, sizeof (*items));
  if (!items)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  at = 0;
  while (at < (size_t)n)
    {
      size_t end = at, namelen;
      ssize_t valuelen, actual;
      while (end < (size_t)n && names[end])
        {
          end++;
        }
      namelen = end - at;
      if (namelen >= 6U && !memcmp (names + at, "user.", 5U))
        {
          xl_attr *a = &items[used];
          if (namelen > 255U)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          a->name = (char *)malloc (namelen + 1U);
          if (!a->name)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          memcpy (a->name, names + at, namelen);
          a->name[namelen] = 0;
          valuelen = fgetxattr (fd, a->name, NULL, 0);
          if (valuelen < 0)
            {
              rc = XTR_IO;
              goto done;
            }

          if ((unsigned long)valuelen > XL_MAX_VALUE
              || (size_t)valuelen > XL_MAX_MANIFEST - total)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          a->value
              = (unsigned char *)malloc (valuelen ? (size_t)valuelen : 1U);
          if (!a->value)
            {
              rc = XTR_LIMIT;
              goto done;
            }

          actual = fgetxattr (fd, a->name, a->value, (size_t)valuelen);
          if (actual != valuelen)
            {
              rc = XTR_IO;
              goto done;
            }

          a->length = (size_t)actual;
          total += a->length;
          used++;
        }

      at = end + 1U;
    }
  /* Reject concurrent changes detectable through a changed names list.
   * The kernel does not offer an atomic snapshot, so this is not a lock. */
  {
    ssize_t again = flistxattr (fd, NULL, 0);
    char *second;
    if (again < 0 || again != n)
      {
        rc = XTR_IO;
        goto done;
      }

    second = (char *)malloc (n ? (size_t)n : 1U);
    if (!second)
      {
        rc = XTR_LIMIT;
        goto done;
      }

    again = flistxattr (fd, second, (size_t)n);
    if (again != n || (n > 0 && memcmp (names, second, (size_t)n)))
      {
        free (second);
        rc = XTR_IO;
        goto done;
      }

    free (second);
  }
  *saved = items;
  *count = used;
  items = NULL;
  rc = XTR_OK;
done:
  xl_release (items, capacity);
  free (names);
  return rc;
}

/* Clear only user.*. Other namespaces are never modified, even during
 * rollback. May fail after removing some attributes: caller must report it. */
static int
xl_clear_user_fd (int fd)
{
  char *names = NULL;
  ssize_t n, got;
  size_t at = 0;
  int rc = XTR_IO;

  n = flistxattr (fd, NULL, 0);
  if (n < 0)
    {
      return XTR_IO;
    }

  if ((unsigned long)n > XL_MAX_NAMES)
    {
      return XTR_LIMIT;
    }

  names = (char *)malloc (n ? (size_t)n : 1U);
  if (!names)
    {
      return XTR_LIMIT;
    }

  got = flistxattr (fd, names, (size_t)n);
  if (got < 0)
    {
      goto done;
    }

  if (got > n)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  n = got;
  while (at < (size_t)n)
    {
      size_t end = at;
      while (end < (size_t)n && names[end])
        {
          end++;
        }
      if (end == (size_t)n || end == at)
        {
          rc = XTR_CORRUPT;
          goto done;
        }

      if (end - at >= 6U && !memcmp (names + at, "user.", 5U)
          && fremovexattr (fd, names + at) != 0)
        {
          rc = XTR_IO;
          goto done;
        }

      at = end + 1U;
    }
  rc = XTR_OK;
done:
  free (names);
  return rc;
}

static int
xl_rollback_fd (int fd, xl_attr *saved, size_t count)
{
  size_t i;
  int rc = xl_clear_user_fd (fd);

  /* Retry all the old values even if the clear encountered an error. */
  for (i = 0; i < count; i++)
    {
      if (fsetxattr (fd, saved[i].name, saved[i].value, saved[i].length, 0)
          != 0)
        {
          rc = XTR_IO;
        }
    }

  return rc;
}

# ifdef XTR_TEST_HOOKS
void
xtr_linux_test_fail_after (long writes)
{
  xl_test_fail_after = writes;
}
# endif /* ifdef XTR_TEST_HOOKS */

int
xtr_linux_restore_fd (int fd, FILE *stage, xtr_u64 encoded,
                      const xtr_extra *outer, const unsigned char *sha32)
{
  xtr_reader rd;
  xtr1_digest digest;
  xtr1_policy pol;
  xtr_manifest manifest;
  xl_restore x;
  int rc, rollback_result;
  xl_attr *saved = NULL;
  size_t saved_count = 0;

  if (fd < 0 || !stage || !outer)
    {
      return XTR_CORRUPT;
    }

  xl_policy (&pol);
  memset (&rd, 0, sizeof (rd));
  rd.context = stage;
  rd.read = xl_read_file;
  if (fseek (stage, 0, SEEK_SET))
    {
      return XTR_IO;
    }

  rc = xtr1_check_manifest (&rd, encoded, outer, sha32, &pol, &digest);
  if (rc)
    {
      return rc;
    }

  if (!digest.schema_supported)
    {
      return XTR_UNSUPPORTED;
    }

  /* Pass 1 verifies ALL native-name/namespace/flag constraints before
   * applying ANY attribute. This prevents malicious-but-checksummed
   * manifests from causing a partial restore due to a late bad record. */
  {
    int pass;
    for (pass = 0; pass < 2; pass++)
      {
        if (pass == 1)
          {
            rc = xl_snapshot_fd (fd, &saved, &saved_count);
            if (rc)
              {
                return rc;
              }

            rc = xl_clear_user_fd (fd);
            if (rc)
              {
                rollback_result = xl_rollback_fd (fd, saved, saved_count);
                xl_release (saved, saved_count);
                return rollback_result ? XTR_IO : rc;
              }
          }

        memset (&x, 0, sizeof (x));
        x.fd = fd;
        x.dry_run = (pass == 0);
        rd.sink_context = &x;
        rd.begin = xl_begin;
        rd.data = xl_data;
        rd.max_records = pol.max_records;
        rd.max_field = pol.max_field;
        rd.max_total = pol.max_manifest;
        if (fseek (stage, 0, SEEK_SET))
          {
            return XTR_IO;
          }

        rc = xtr_parse_manifest (&rd, digest.manifest_length, &manifest);
        if (!rc && xl_flush (&x))
          {
            rc = x.error ? x.error : XTR_IO;
          }

        if (rc == XTR_IO && x.error)
          {
            rc = x.error;
          }

        free (x.name);
        free (x.val);
        if (rc)
          {
            if (pass == 1)
              {
                rollback_result = xl_rollback_fd (fd, saved, saved_count);
                xl_release (saved, saved_count);
                if (rollback_result)
                  {
                    return XTR_IO;
                  }
              }

            return rc;
          }
      }
  }
  xl_release (saved, saved_count);
  return XTR_OK;
}
#endif /* __linux__ */
