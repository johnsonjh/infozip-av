/* Ensure that ZipOpt releases the output writer before reopening the ZIP
 * for validation, and never publishes an unsealed output.  SPDX: MIT-0. */

#include "../archive.h"
#include "../writer.h"

#include <stdio.h>
#include <string.h>

static const unsigned char empty_zip[22] = {
  0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

int
main (void)
{
  const char *input = "build/zipopt-seal-source.zip";
  const char *output = "build/zipopt-seal-published.zip";
  zo_archive original, checked;
  zo_writer w;
  FILE *f;
  size_t written;
  int close_rc;
  int ok = 0;

  memset (&original, 0, sizeof (original));
  memset (&checked, 0, sizeof (checked));
  memset (&w, 0, sizeof (w));
  (void)remove (input);
  (void)remove (output);

  f = fopen (input, "wb");
  if (!f)
    goto done;
  written = fwrite (empty_zip, 1, sizeof (empty_zip), f);
  close_rc = fclose (f);
  if (written != sizeof (empty_zip) || close_rc != 0)
    {
      goto done;
    }

  if (!zo_archive_open (&original, input))
    goto done;
  if (!zo_writer_begin (&w, &original, output))
    goto done;

  /* No publication before completion and sealing. */
  if (zo_writer_seal (&w) || zo_writer_publish (&w))
    goto done;
  if (!zo_writer_complete (&w) || !zo_writer_seal (&w)
      || w.stream != NULL || !w.sealed || zo_writer_seal (&w))
    goto done;
  /* Reopening the output is now legal even on file-sharing OSes. */
  if (!zo_archive_open (&checked, w.temporary))
    goto done;
  if (checked.count != 0)
    goto done;
  zo_archive_close (&checked);
  if (!zo_writer_publish (&w))
    goto done;
  if (!zo_archive_open (&checked, output) || checked.count != 0)
    goto done;
  zo_archive_close (&checked);
  /* Existing output is protected against replacement. */
  {
    zo_writer another;
    memset (&another, 0, sizeof (another));
    if (zo_writer_begin (&another, &original, output))
      {
        zo_writer_abort (&another);
        goto done;
      }
    zo_writer_abort (&another);
  }

  ok = 1;

done:
  zo_archive_close (&checked);
  zo_writer_abort (&w);
  zo_archive_close (&original);
  (void)remove (input);
  (void)remove (output);
  puts (ok ? "zipopt writer sealing: PASS" : "zipopt writer sealing: FAIL");
  return ok ? 0 : 1;
}
