/*
 * SPDX-License-Identifier: MIT-0.
 * DOS16 has no filesystem hard links. Publish using an exclusive create
 * followed by a verified copy. This is not crash-atomic on FAT.
 */

#ifndef IZ_ZD_DOS16_PORT_H
# define IZ_ZD_DOS16_PORT_H

# include <errno.h>
# include <fcntl.h>
# include <io.h>
# include <stdio.h>
# include <sys/stat.h>

    static int
iz_dos16_publish_noreplace (const char *src, const char *dst)
{
  char buf[4096];
  FILE *in, *out;
  int fd, ok;
  size_t got;

  in = fopen (src, "rb");

  if (!in)
    {
      return -1;
    }

  fd = open (dst, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, S_IREAD | S_IWRITE);

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

  ok = 1;

  while ((got = fread (buf, 1, sizeof buf, in)) != 0)
    {
      if (fwrite (buf, 1, got, out) != got)
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

#endif /* ifndef IZ_ZD_DOS16_PORT_H */
