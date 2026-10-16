/* SPDX-License-Identifier: MIT-0 */
/* Linux-hosted BSD integration test shim, NEVER linked in a production
 * FreeBSD or NetBSD build. Maps user.<name> to traditional BSD user EAs. */

#ifndef XTR_BSD_TEST
# error This is a Linux-hosted TEST shim only
#endif /* ifndef XTR_BSD_TEST */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif /* ifndef _GNU_SOURCE */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define XS_MAX_NAMES (1024UL * 1024UL)
#define XS_PREFIX "user."

static int
xs_name (const char *in, char *out, size_t capacity)
{
  size_t n;

  if (!in || (n = strlen (in)) == 0 || n > 255U || n + 6U > capacity)
    {
      errno = EINVAL;
      return -1;
    }

  memcpy (out, XS_PREFIX, 5U);
  memcpy (out + 5U, in, n + 1U);
  return 0;
}

ssize_t
extattr_list_fd (int fd, int ns, void *out, size_t length)
{
  ssize_t got;
  char *names;
  size_t pos = 0, used = 0, need = 0, n;
  unsigned char *dst = (unsigned char *)out;

  if (ns != 1)
    {
      errno = EINVAL;
      return -1;
    }

  got = flistxattr (fd, NULL, 0);
  if (got < 0 || (unsigned long)got > XS_MAX_NAMES)
    {
      if (got >= 0)
        {
          errno = E2BIG;
        }

      return -1;
    }

  names = (char *)malloc (got ? (size_t)got : 1U);
  if (!names)
    {
      errno = ENOMEM;
      return -1;
    }

  if (flistxattr (fd, names, (size_t)got) != got)
    {
      free (names);
      errno = EIO;
      return -1;
    }

  while (pos < (size_t)got)
    {
      n = strlen (names + pos);
      if (n == 0 || n + pos >= (size_t)got)
        {
          free (names);
          errno = EIO;
          return -1;
        }

      if (n > 5U && !memcmp (names + pos, XS_PREFIX, 5U))
        {
          if (n - 5U > 255U)
            {
              free (names);
              errno = E2BIG;
              return -1;
            }

          need += n - 5U + 1U;
          if (out && need <= length)
            {
              dst[used++] = (unsigned char)(n - 5U);
              memcpy (dst + used, names + pos + 5U, n - 5U);
              used += n - 5U;
            }
        }

      pos += n + 1U;
    }
  free (names);
  if (out && need > length)
    {
      errno = ERANGE;
      return -1;
    }

  return (ssize_t)need;
}

ssize_t
extattr_get_fd (int fd, int ns, const char *name, void *out, size_t len)
{
  char key[264];

  if (ns != 1 || xs_name (name, key, sizeof (key)))
    {
      return -1;
    }

  return fgetxattr (fd, key, out, len);
}

#if defined(XTR_BSD_TEST_NETBSD)
int
extattr_set_fd (int fd, int ns, const char *name, const void *in, size_t n)
{
#else  /* if defined( XTR_BSD_TEST_NETBSD ) */
ssize_t
extattr_set_fd (int fd, int ns, const char *name, const void *in, size_t n)
{
#endif /* if defined( XTR_BSD_TEST_NETBSD ) */
  char key[264];
  if (ns != 1 || xs_name (name, key, sizeof (key)))
    {
      return -1;
    }

  if (fsetxattr (fd, key, in, n, 0))
    {
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
  char key[264];

  if (ns != 1 || xs_name (name, key, sizeof (key)))
    {
      return -1;
    }

  return fremovexattr (fd, key);
}
