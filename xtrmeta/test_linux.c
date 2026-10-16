/* SPDX-License-Identifier: MIT-0 */
/* Actual Linux f*xattr round-trip and corrupted-manifest no-write tests. */
#define _XOPEN_SOURCE 700
#include "xtrlinux.h"
#ifdef __linux__
# include <errno.h>
# include <fcntl.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/xattr.h>
# include <unistd.h>
static int checks = 0, errors = 0;
# define T(c)                                                                 \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(c))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL %s:%d %s (errno=%d)\n", __FILE__, __LINE__,  \
                   #c, errno);                                                \
          errors++;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)
static int
tempfile (char name[64])
{
  int fd;

  strcpy (name, "/dev/shm/xtro-linux-m2-XXXXXX");
  fd = mkstemp (name);
  if (fd >= 0)
    {
      unlink (name);
    }

  return fd;
}
static xtr_u64
sz (size_t n)
{
  xtr_u64 r;

  r.lo = (unsigned long)n & 0xffffffffUL;
  r.hi = (unsigned long)n >> 16 >> 16;
  return r;
}
static int
attrs_equal (int a, int b, const char *name)
{
  unsigned char x[65536], y[65536];
  ssize_t n = fgetxattr (a, name, x, sizeof (x)),
          m = fgetxattr (b, name, y, sizeof (y));

  return n >= 0 && n == m && !memcmp (x, y, (size_t)n);
}
static void
roundtrip (int encrypted)
{
  int a, b, c, d;
  char path[64];
  FILE *stream = tmpfile ();
  unsigned char owner[16], sha[32], l[128], cen[128];
  unsigned char *large = (unsigned char *)malloc (60000U);
  unsigned char *medium = (unsigned char *)malloc (14000U);
  unsigned char bytes[9] = { 0, 255, 1, 0, 0x7f, 14, 3, 251, 20 };
  xtr1_digest digest;
  xtr_extra outer, decoded;
  size_t ll, cl, n, i;
  int rc;

  a = tempfile (path);
  b = tempfile (path);
  c = tempfile (path);
  d = tempfile (path);
  T (a >= 0 && b >= 0 && c >= 0 && d >= 0 && stream != NULL && large != NULL
     && medium != NULL);
  if (a < 0 || b < 0 || c < 0 || d < 0 || !stream || !large || !medium)
    {
      goto cleanup;
    }

  for (i = 0; i < 16; i++)
    {
      owner[i] = (unsigned char)(i + 1U);
    }

  for (i = 0; i < 60000U; i++)
    {
      large[i] = (unsigned char)((i * 73U + i / 3U) & 255U);
    }

  for (i = 0; i < 14000U; i++)
    {
      medium[i] = (unsigned char)((i * 3U + 91U) & 255U);
    }

  T (fsetxattr (a, "user.xtro_large", large, 60000, 0) == 0);
  T (fsetxattr (a, "user.xtro_medium", medium, 14000, 0) == 0);
  T (fsetxattr (a, "user.xtro_empty", "", 0, 0) == 0);
  T (fsetxattr (a, "user.xtro_binary", bytes, sizeof (bytes), 0) == 0);
  rc = xtr_linux_capture_fd (a, owner, stream, encrypted, &digest);
  T (rc == XTR_OK);
  T (digest.count == 4U);
  T (digest.manifest_length.hi == 0 && digest.manifest_length.lo > 65535UL);
  memset (&outer, 0, sizeof (outer));
  memcpy (outer.owner, owner, 16);
  outer.mode = XTR_V1_COMPANION;
  outer.flags = encrypted ? 1U : 0U;
  if (!encrypted)
    {
      outer.count = digest.count;
      outer.manifest_len = digest.manifest_length;
      outer.crc32 = digest.crc32;
    }

  T (xtr1_extra_encode (l, sizeof (l), &outer, 0, NULL, 0, NULL, &ll)
     == XTR_OK);
  T (xtr1_extra_encode (cen, sizeof (cen), &outer, 1, NULL, 0,
                        encrypted ? NULL : digest.sha256, &cl)
     == XTR_OK);
  T (xtr1_check_headers (l, ll, cen, cl, &decoded, sha) == XTR_OK);
  T (fseek (stream, 0, SEEK_END) == 0);
  n = (size_t)ftell (stream);
  T (n > 65535U);
  T (n == (size_t)digest.manifest_length.lo + (encrypted ? 36U : 0U));
  T (fsetxattr (b, "user.old_stale", "old", 3U, 0) == 0);
  T (fsetxattr (b, "user.xtro_binary", "old-value", 9U, 0) == 0);
  T (xtr_linux_restore_fd (b, stream, sz (n), &decoded, encrypted ? NULL : sha)
     == XTR_OK);
  {
    ssize_t v = fgetxattr (b, "user.old_stale", NULL, 0);
    T (v == -1 && errno == ENODATA);
  }
  /* Repeating a successful exact replace must be idempotent. */
  T (xtr_linux_restore_fd (b, stream, sz (n), &decoded, encrypted ? NULL : sha)
     == XTR_OK);
# ifdef XTR_TEST_HOOKS
  T (fsetxattr (d, "user.keep", "keep", 4U, 0) == 0);
  T (fsetxattr (d, "user.xtro_binary", "previous", 8U, 0) == 0);
  xtr_linux_test_fail_after (1);
  T (xtr_linux_restore_fd (d, stream, sz (n), &decoded, encrypted ? NULL : sha)
     == XTR_IO);
  {
    char v[16];
    ssize_t m = fgetxattr (d, "user.keep", v, sizeof (v));
    T (m == 4 && !memcmp (v, "keep", 4));
    m = fgetxattr (d, "user.xtro_binary", v, sizeof (v));
    T (m == 8 && !memcmp (v, "previous", 8));
  }
  {
    ssize_t m = fgetxattr (d, "user.xtro_large", NULL, 0);
    T (m == -1 && errno == ENODATA);
  }
# endif /* ifdef XTR_TEST_HOOKS */
  T (attrs_equal (a, b, "user.xtro_large"));
  T (attrs_equal (a, b, "user.xtro_medium"));
  T (attrs_equal (a, b, "user.xtro_empty"));
  T (attrs_equal (a, b, "user.xtro_binary"));
  T (fseek (stream, 72, SEEK_SET) == 0);
  {
    int byte = fgetc (stream);
    T (byte != EOF);
    T (fseek (stream, 72, SEEK_SET) == 0);
    T (fputc (byte ^ 1, stream) != EOF);
    T (fflush (stream) == 0);
  }
  T (xtr_linux_restore_fd (c, stream, sz (n), &decoded, encrypted ? NULL : sha)
     == XTR_CORRUPT);
  {
    ssize_t v = fgetxattr (c, "user.xtro_large", NULL, 0);
    T (v == -1 && errno == ENODATA);
  }
  if (!encrypted)
    {
      unsigned char *payload;
      T (fseek (stream, 72, SEEK_SET) == 0);
      {
        int byte = fgetc (stream);
        T (byte != EOF);
        T (fseek (stream, 72, SEEK_SET) == 0);
        T (fputc (byte ^ 1, stream) != EOF);
        T (fflush (stream) == 0);
      }
      /* Create a CORRECTLY SHA-256/CRC32-resigned manifest whose last
       * attribute has an unsupported native namespace. The first records
       * are otherwise valid. No native writes are permitted during the
       * upfront semantic validation pass. */
      payload = (unsigned char *)malloc (n);
      if (payload)
        {
          size_t j;
          int found = 0;
          xtr_sha256 sh;
          T (fseek (stream, 0, SEEK_SET) == 0);
          T (fread (payload, 1, n, stream) == n);
          for (j = 0; j + 16U < n; j++)
            {
              if (!memcmp (payload + j, "user.xtro_medium", 16U))
                {
                  payload[j] = 'z';
                  found = 1;
                  break;
                }
            }

          T (found);
          if (found)
            {
              decoded.crc32 = xtr_crc32_update (0, payload, n);
              xtr_sha256_init (&sh);
              xtr_sha256_update (&sh, payload, n);
              xtr_sha256_final (&sh, sha);
              T (fseek (stream, 0, SEEK_SET) == 0);
              T (fwrite (payload, 1, n, stream) == n);
              T (fflush (stream) == 0);
              T (xtr_linux_restore_fd (c, stream, sz (n), &decoded, sha)
                 == XTR_UNSUPPORTED);
              {
                ssize_t v = fgetxattr (c, "user.xtro_binary", NULL, 0);
                T (v == -1 && errno == ENODATA);
              }
            }

          free (payload);
        }
      else
        {
          T (0);
        }
    }

cleanup:
  if (a >= 0)
    {
      close (a);
    }

  if (b >= 0)
    {
      close (b);
    }

  if (c >= 0)
    {
      close (c);
    }

  if (d >= 0)
    {
      close (d);
    }

  if (stream)
    {
      fclose (stream);
    }

  free (large);
  free (medium);
}
int
main (void)
{
  roundtrip (0);
  roundtrip (1);
  printf ("Linux native metadata tests: %d assertions, %d failures\n", checks,
          errors);
  return errors ? 1 : 0;
}
#else  /* ifdef __linux__ */
int
main (void)
{
  return 0;
}
#endif /* ifdef __linux__ */
