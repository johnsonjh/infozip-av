/* MIT-0. Standalone C89 verifier for independent ZIP byte fixtures. */
#include "xtrv1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct source
{
  FILE *file;
} source;
static size_t
file_read (void *p, unsigned char *b, size_t n)
{
  return fread (b, 1, n, ((source *)p)->file);
}
static int
load (const char *path, unsigned char *b, size_t cap, size_t *n)
{
  FILE *f = fopen (path, "rb");

  if (!f)
    {
      return 0;
    }

  *n = fread (b, 1, cap, f);
  if (ferror (f) || !feof (f))
    {
      int c = fgetc (f);
      if (c != EOF)
        {
          fclose (f);
          return 0;
        }
    }

  if (fclose (f))
    {
      return 0;
    }

  return 1;
}
int
main (int argc, char **argv)
{
  unsigned char local[65535], central[65535], sha[32];
  size_t ll, cl;
  xtr_extra ex;
  xtr1_policy policy;
  xtr1_digest dig;
  xtr_reader r;
  xtr_u64 size;
  source s;
  long n;
  int rc;

  if (argc != 4)
    {
      return 2;
    }

  if (!load (argv[2], local, sizeof (local), &ll)
      || !load (argv[3], central, sizeof (central), &cl))
    {
      return 3;
    }

  rc = xtr1_check_headers (local, ll, central, cl, &ex, sha);
  if (rc)
    {
      fprintf (stderr, "extra mismatch %d\n", rc);
      return 4;
    }

  s.file = fopen (argv[1], "rb");
  if (!s.file)
    {
      return 5;
    }

  if (fseek (s.file, 0, SEEK_END) || (n = ftell (s.file)) < 0
      || fseek (s.file, 0, SEEK_SET))
    {
      fclose (s.file);
      return 5;
    }

  /* Test-only verifier supports files fitting into a C89 long. */
  size.lo = (unsigned long)n & 0xffffffffUL;
  size.hi = ((unsigned long)n) >> 16 >> 16;
  memset (&policy, 0, sizeof (policy));
  policy.max_records = 100000;
  policy.max_field = 1024UL * 1024UL;
  policy.max_manifest.lo = 0xffffffffUL;
  policy.max_manifest.hi = 0x1UL;
  memset (&r, 0, sizeof (r));
  r.read = file_read;
  r.context = &s;
  rc = xtr1_check_manifest (&r, size, &ex, ex.flags ? NULL : sha, &policy,
                            &dig);
  fclose (s.file);
  if (rc || !dig.schema_supported)
    {
      fprintf (stderr, "manifest invalid %d\n", rc);
      return 6;
    }

  printf ("verified count=%lu crc=%08lx sha=", dig.count, dig.crc32);
  {
    unsigned i;
    for (i = 0; i < 32; i++)
      {
        printf ("%02x", dig.sha256[i]);
      }
  }
  printf ("\n");
  return 0;
}
