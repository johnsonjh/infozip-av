/* SPDX-License-Identifier: MIT-0 */
/* On-target FreeBSD 15 named attribute tool. No non-FreeBSD code paths. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__FreeBSD__) && defined(O_NAMEDATTR)                              \
    && defined(_PC_NAMEDATTR_ENABLED) && defined(_PC_HAS_NAMEDATTR)

static int
transfer (int from, int to)
{
  unsigned char buf[8192];
  ssize_t n;

  while ((n = read (from, buf, sizeof (buf))) > 0)
    {
      ssize_t at = 0;
      while (at < n)
        {
          ssize_t k = write (to, buf + at, (size_t)(n - at));
          if (k <= 0)
            {
              return 1;
            }

          at += k;
        }
    }
  return n < 0;
}

int
main (int argc, char **argv)
{
  int fd, a, rc = 1;
  long enabled, has;

  if (argc < 3)
    {
      fprintf (stderr, "usage: tool cap|has|put|get|mode|times|settimes "
                       "pathname [attribute]\n");
      return 2;
    }

  fd = open (argv[2], O_RDONLY);
  if (fd < 0)
    {
      perror ("owner open");
      return 2;
    }

  enabled = fpathconf (fd, _PC_NAMEDATTR_ENABLED);
  has = fpathconf (fd, _PC_HAS_NAMEDATTR);
  if (!strcmp (argv[1], "cap"))
    {
      printf ("%ld %ld\n", enabled, has);
      rc = 0;
      goto done;
    }

  if (!strcmp (argv[1], "has"))
    {
      printf ("%ld\n", has);
      rc = 0;
      goto done;
    }

  if (argc < 4)
    {
      fprintf (stderr, "missing attribute name\n");
      goto done;
    }

  if (strlen (argv[3]) == 0 || strlen (argv[3]) > 255U || strchr (argv[3], '/')
      || !strcmp (argv[3], ".") || !strcmp (argv[3], ".."))
    {
      goto done;
    }

  if (!strcmp (argv[1], "put"))
    {
      unsigned long mode = 0600;
      if (argc == 5)
        {
          char *end;
          mode = strtoul (argv[4], &end, 8);
          if (*end || mode > 07777U)
            {
              goto done;
            }
        }

      a = openat (fd, argv[3], O_NAMEDATTR | O_WRONLY | O_CREAT | O_TRUNC,
                  0600);
      if (a < 0)
        {
          perror ("named put open");
          goto done;
        }

      if (transfer (STDIN_FILENO, a))
        {
          perror ("named put write");
          close (a);
          goto done;
        }

      if (fchmod (a, (mode_t)mode))
        {
          perror ("named chmod");
          close (a);
          goto done;
        }

      rc = close (a) != 0;
    }
  else if (!strcmp (argv[1], "get"))
    {
      a = openat (fd, argv[3], O_NAMEDATTR | O_RDONLY, 0);
      if (a < 0)
        {
          perror ("named get open");
          goto done;
        }

      rc = transfer (a, STDOUT_FILENO);
      close (a);
    }
  else if (!strcmp (argv[1], "settimes"))
    {
      struct timespec ts[2];
      char *end;
      long atsec, mtsec;
      if (argc != 6)
        {
          goto done;
        }

      errno = 0;
      atsec = strtol (argv[4], &end, 10);
      if (errno || *end)
        {
          goto done;
        }

      errno = 0;
      mtsec = strtol (argv[5], &end, 10);
      if (errno || *end)
        {
          goto done;
        }

      ts[0].tv_sec = (time_t)atsec;
      ts[0].tv_nsec = 123456789L;
      ts[1].tv_sec = (time_t)mtsec;
      ts[1].tv_nsec = 987654321L;
      a = openat (fd, argv[3], O_NAMEDATTR | O_RDONLY, 0);
      if (a < 0)
        {
          goto done;
        }

      rc = futimens (a, ts) != 0;
      if (close (a) != 0)
        {
          rc = 1;
        }
    }
  else if (!strcmp (argv[1], "times"))
    {
      struct stat st;
      a = openat (fd, argv[3], O_NAMEDATTR | O_RDONLY, 0);
      if (a < 0)
        {
          goto done;
        }

      if (fstat (a, &st) == 0)
        {
          printf ("%ld %ld %ld %ld\n", (long)st.st_atim.tv_sec,
                  (long)st.st_atim.tv_nsec, (long)st.st_mtim.tv_sec,
                  (long)st.st_mtim.tv_nsec);
          rc = 0;
        }

      close (a);
    }
  else if (!strcmp (argv[1], "mode"))
    {
      struct stat st;
      a = openat (fd, argv[3], O_NAMEDATTR | O_RDONLY, 0);
      if (a < 0)
        {
          perror ("named mode open");
          goto done;
        }

      if (!fstat (a, &st))
        {
          printf ("%04o\n", (unsigned)(st.st_mode & 07777));
          rc = 0;
        }

      close (a);
    }

done:
  close (fd);
  return rc;
}

#else  /* if defined( __FreeBSD__ ) && defined( O_NAMEDATTR ) && defined(     \
          _PC_NAMEDATTR_ENABLED ) && defined( _PC_HAS_NAMEDATTR ) */
int
main (void)
{
  fprintf (stderr, "FreeBSD 15 O_NAMEDATTR API is unavailable\n");
  return 77;
}
#endif /* if defined( __FreeBSD__ ) && defined( O_NAMEDATTR ) && defined(     \
          _PC_NAMEDATTR_ENABLED ) && defined( _PC_HAS_NAMEDATTR ) */
