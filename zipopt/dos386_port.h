/* SPDX-License-Identifier: MIT-0. */

#ifndef IZ_DOS386_PORT_H
# define IZ_DOS386_PORT_H
# ifndef __DJGPP__
#  error DJGPP only
# endif /* ifndef __DJGPP__ */

# include <fcntl.h>
# include <stdio.h>
# include <sys/stat.h>
# include <unistd.h>

/*
 * DOS/FAT cannot atomically install a hard link. DJGPP link() copies and
 * rename() REPLACES an existing destination. Use O_EXCL to avoid clobber.
 * The copy is not atomic: power loss can leave an incomplete new file.
 */

static int
iz_dos386_publish_noreplace (const char *src, const char *dst)
{
  unsigned char buf[16384];
  FILE *in, *out;
  int fd, ok = 1;
  size_t n;

  in = fopen (src, "rb");

  if (!in)
    {
      return -1;
    }

  fd = open (dst, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0666);

  if (fd < 0)
    {
      fclose (in);
      return -1;
    }

  out = fdopen (fd, "wb");

  if (!out)
    {
      close (fd);
      fclose (in);
      unlink (dst);
      return -1;
    }

  while ((n = fread (buf, 1, sizeof (buf), in)) != 0)
    {
      if (fwrite (buf, 1, n, out) != n)
        {
          ok = 0;
          break;
        }
    }

  if (ferror (in))
    {
      ok = 0;
    }

  if (fclose (in) != 0)
    {
      ok = 0;
    }

  if (fclose (out) != 0)
    {
      ok = 0;
    }

  if (!ok)
    {
      unlink (dst);
      return -1;
    }

  return 0;
}

#endif /* ifndef IZ_DOS386_PORT_H */
