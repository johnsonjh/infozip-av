/* SPDX-License-Identifier: MIT-0 */
/* A native-API contract test, NOT a claim of BSD execution. */
#include "xtrbsd.h"
#include "xtrsha.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define FMAX 32
#define VMAX 1048576UL
typedef struct field
{
  char name[256];
  unsigned char *bytes;
  size_t n;
} field;
static field fields[FMAX];
static size_t nf;
static int checks, failed, fail_set, duplicate_list, wrong_read, bad_list;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #x);               \
          failed++;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)
static void
reset (void)
{
  size_t i;

  for (i = 0; i < nf; i++)
    {
      free (fields[i].bytes);
    }

  memset (fields, 0, sizeof (fields));
  nf = 0;
  fail_set = 0;
  duplicate_list = 0;
  wrong_read = 0;
  bad_list = 0;
}
static field *
find (const char *name)
{
  size_t i;

  for (i = 0; i < nf; i++)
    {
      if (!strcmp (name, fields[i].name))
        {
          return &fields[i];
        }
    }

  return NULL;
}
static int
store (const char *name, const unsigned char *data, size_t size)
{
  field *f = find (name);
  unsigned char *p;

  if (!f)
    {
      if (nf == FMAX)
        {
          return -1;
        }

      f = &fields[nf++];
      strcpy (f->name, name);
    }

  p = (unsigned char *)malloc (size ? size : 1);
  if (!p)
    {
      return -1;
    }

  if (size)
    {
      memcpy (p, data, size);
    }

  free (f->bytes);
  f->bytes = p;
  f->n = size;
  return 0;
}
ssize_t
extattr_list_fd (int fd, int ns, void *out, size_t len)
{
  size_t i, at = 0, need = 0;
  unsigned char *p = (unsigned char *)out;

  if (fd != 7 || ns != 1)
    {
      errno = EBADF;
      return -1;
    }

  for (i = 0; i < nf; i++)
    {
      need += strlen (fields[i].name) + 1U;
    }

  if (duplicate_list && nf)
    {
      need += strlen (fields[0].name) + 1U;
    }

  if (!out)
    {
      return (ssize_t)need;
    }

  if (len < need)
    {
      errno = ERANGE;
      return -1;
    }

  for (i = 0; i < nf + (duplicate_list && nf ? 1U : 0U); i++)
    {
      const char *name = fields[i % nf].name;
      size_t n = strlen (name);
      p[at++] = (unsigned char)n;
      memcpy (p + at, name, n);
      at += n;
    }

  if (bad_list && need)
    {
      p[0] = (unsigned char)(bad_list == 1 ? 0 : 255);
    }

  return (ssize_t)need;
}
ssize_t
extattr_get_fd (int fd, int ns, const char *name, void *out, size_t len)
{
  field *f = find (name);

  if (fd != 7 || ns != 1 || !f)
    {
      errno = ENOENT;
      return -1;
    }

  if (!out)
    {
      return (ssize_t)f->n;
    }

  if (wrong_read)
    {
      return (ssize_t)(f->n ? f->n - 1U : 1U);
    }

  if (len < f->n)
    {
      errno = ERANGE;
      return -1;
    }

  if (f->n)
    {
      memcpy (out, f->bytes, f->n);
    }

  return (ssize_t)f->n;
}
#if defined(XTR_BSD_TEST_NETBSD)
int
extattr_set_fd (int fd, int ns, const char *name, const void *data, size_t n)
{
#else  /* if defined( XTR_BSD_TEST_NETBSD ) */
ssize_t
extattr_set_fd (int fd, int ns, const char *name, const void *data, size_t n)
{
#endif /* if defined( XTR_BSD_TEST_NETBSD ) */
  if (fd != 7 || ns != 1 || fail_set)
    {
      errno = EIO;
      return -1;
    }

  if (store (name, (const unsigned char *)data, n))
    {
      errno = ENOMEM;
      return -1;
    }

#if defined(XTR_BSD_TEST_NETBSD)
  return 0;

#else /* if defined( XTR_BSD_TEST_NETBSD ) */
  return (ssize_t)n;

#endif /* if defined( XTR_BSD_TEST_NETBSD ) */
}
int
extattr_delete_fd (int fd, int ns, const char *name)
{
  size_t i;

  if (fd != 7 || ns != 1)
    {
      errno = EBADF;
      return -1;
    }

  for (i = 0; i < nf; i++)
    {
      if (!strcmp (fields[i].name, name))
        {
          free (fields[i].bytes);
          if (i + 1U < nf)
            {
              memmove (&fields[i], &fields[i + 1U],
                       (nf - i - 1U) * sizeof (fields[i]));
            }

          memset (&fields[--nf], 0, sizeof (fields[nf]));
          return 0;
        }
    }

  errno = ENOENT;
  return -1;
}
static void
init_owner (unsigned char o[16])
{
  unsigned i;

  for (i = 0; i < 16; i++)
    {
      o[i] = (unsigned char)(i + 1U);
    }
}
static xtr_extra
envelope (const unsigned char owner[16], const xtr1_digest *d, int encrypt)
{
  xtr_extra e;

  memset (&e, 0, sizeof (e));
  memcpy (e.owner, owner, 16);
  e.mode = 2;
  if (encrypt)
    {
      e.flags = 1;
    }
  else
    {
      e.count = d->count;
      e.manifest_len = d->manifest_length;
      e.crc32 = d->crc32;
    }

  return e;
}
static void
round_trip (int encrypt, int failure_test)
{
  unsigned char owner[16], a[] = { 0, 1, 2, 3, 255 }, b[] = { 4, 0, 5, 6 };
  unsigned char c[] = { 88, 89 }, *big;
  xtr1_digest dig;
  xtr_extra extra;
  xtr_u64 encoded;
  FILE *f = tmpfile ();
  int rc;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  reset ();
  init_owner (owner);
  CHECK (store ("zeta", a, sizeof (a)) == 0);
  CHECK (store ("empty", NULL, 0) == 0);
  CHECK (store ("alpha", b, sizeof (b)) == 0);
  big = (unsigned char *)malloc (70000U);
  CHECK (big != NULL);
  if (!big)
    {
      fclose (f);
      return;
    }

  memset (big, 0xa5, 70000U);
  CHECK (store ("large", big, 70000U) == 0);
  free (big);
  rc = xtr_bsd_capture_fd (7, owner, f, encrypt, &dig);
  CHECK (rc == XTR_OK && dig.count == 4U);
  if (rc)
    {
      fclose (f);
      return;
    }

  extra = envelope (owner, &dig, encrypt);
  encoded = dig.manifest_length;
  if (encrypt)
    {
      encoded.lo += 36U;
    }

  CHECK (store ("stale", c, sizeof (c)) == 0);
  CHECK (store ("alpha", c, sizeof (c)) == 0);
  /* Encrypted metadata's digest belongs inside private payload. */
  rc = xtr_bsd_restore_fd (7, f, encoded, &extra, encrypt ? NULL : dig.sha256);
  CHECK (rc == XTR_OK);
  CHECK (!find ("stale"));
  CHECK (find ("empty") && find ("empty")->n == 0);
  CHECK (find ("alpha") && find ("alpha")->n == sizeof (b)
         && !memcmp (find ("alpha")->bytes, b, sizeof (b)));
  CHECK (find ("large") && find ("large")->n == 70000U
         && find ("large")->bytes[69999] == 0xa5);
  if (failure_test)
    {
      CHECK (store ("stale", c, sizeof (c)) == 0);
      CHECK (store ("alpha", c, sizeof (c)) == 0);
      xtr_bsd_test_fail_after (1);
      rc = xtr_bsd_restore_fd (7, f, encoded, &extra,
                               encrypt ? NULL : dig.sha256);
      CHECK (rc == XTR_IO);
      CHECK (find ("stale") && find ("stale")->n == sizeof (c));
      CHECK (find ("alpha") && find ("alpha")->n == sizeof (c)
             && !memcmp (find ("alpha")->bytes, c, sizeof (c)));
    }

  fclose (f);
}
static void
bad_inputs (void)
{
  unsigned char owner[16], sample[] = { 12, 33 }, *saved;
  xtr1_digest dig;
  xtr_extra e;
  xtr_u64 len;
  FILE *f = tmpfile ();
  int rc;

  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  reset ();
  init_owner (owner);
  CHECK (store ("safe", sample, sizeof (sample)) == 0);
  rc = xtr_bsd_capture_fd (7, owner, f, 0, &dig);
  CHECK (rc == XTR_OK);
  if (rc)
    {
      fclose (f);
      return;
    }

  e = envelope (owner, &dig, 0);
  len = dig.manifest_length;
  /* Wrong origin native data is preserve-only, never implicitly mapped. */
  saved = (unsigned char *)malloc ((size_t)len.lo);
  CHECK (saved != NULL);
  if (saved)
    {
      CHECK (fread (saved, 1, (size_t)len.lo, f) == (size_t)len.lo);
      saved[36U + 4U] = 0xff;
      CHECK (fseek (f, 0, SEEK_SET) == 0);
      CHECK (fwrite (saved, 1, (size_t)len.lo, f) == (size_t)len.lo);
      CHECK (fflush (f) == 0);
      rc = xtr_bsd_restore_fd (7, f, len, &e, dig.sha256);
      CHECK (rc != XTR_OK);
      CHECK (find ("safe") && find ("safe")->n == sizeof (sample));
      /* Recalculate both integrity values: a correctly checksummed but
       * cross-platform schema must still never write native BSD EAs. */
      {
        xtr_sha256 sha;
        saved[36U + 4U] = (unsigned char)99;
        e.crc32 = xtr_crc32_update (0, saved, (size_t)len.lo);
        xtr_sha256_init (&sha);
        xtr_sha256_update (&sha, saved, (size_t)len.lo);
        xtr_sha256_final (&sha, dig.sha256);
        CHECK (fseek (f, 0, SEEK_SET) == 0);
        CHECK (fwrite (saved, 1, (size_t)len.lo, f) == (size_t)len.lo);
        CHECK (fflush (f) == 0);
        rc = xtr_bsd_restore_fd (7, f, len, &e, dig.sha256);
        CHECK (rc == XTR_UNSUPPORTED);
        CHECK (find ("safe") && find ("safe")->n == sizeof (sample));
      }
      free (saved);
    }

  fclose (f);
  f = tmpfile ();
  CHECK (f != NULL);
  if (!f)
    {
      return;
    }

  duplicate_list = 1;
  CHECK (xtr_bsd_capture_fd (7, owner, f, 0, &dig) == XTR_CORRUPT);
  duplicate_list = 0;
  wrong_read = 1;
  CHECK (xtr_bsd_capture_fd (7, owner, f, 0, &dig) == XTR_IO);
  wrong_read = 0;
  bad_list = 1;
  CHECK (xtr_bsd_capture_fd (7, owner, f, 0, &dig) == XTR_CORRUPT);
  bad_list = 2;
  CHECK (xtr_bsd_capture_fd (7, owner, f, 0, &dig) == XTR_CORRUPT);
  bad_list = 0;
  fclose (f);
}
int
main (void)
{
  round_trip (0, 1);
  round_trip (1, 1);
  bad_inputs ();
  reset ();
#if defined(XTR_BSD_TEST_NETBSD)
  printf ("NetBSD extattr API emulation: %d checks, %d failures\n", checks,
          failed);
#else  /* if defined( XTR_BSD_TEST_NETBSD ) */
  printf ("FreeBSD extattr API emulation: %d checks, %d failures\n", checks,
          failed);
#endif /* if defined( XTR_BSD_TEST_NETBSD ) */
  return failed ? 1 : 0;
}
