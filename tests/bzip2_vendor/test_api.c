/* libbzip2 public API smoke: C89, no compiler extensions required. */
#include <bzlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 1123456UL
#define ZIPMAX (N * 2UL + 1000UL)

static int
roundtrip (int level, int small)
{
  char *in = (char *)malloc (N);
  char *enc = (char *)malloc (ZIPMAX);
  char *dec = (char *)malloc (N);
  unsigned int enc_len, dec_len;
  unsigned long i;
  int rc;

  if (in == NULL || enc == NULL || dec == NULL)
    {
      return 1;
    }

  for (i = 0; i < N; ++i)
    {
      in[i] = (char)((i * 29UL + i / 37UL) & 255UL);
    }

  enc_len = (unsigned int)ZIPMAX;
  rc = BZ2_bzBuffToBuffCompress (enc, &enc_len, in, (unsigned int)N, level, 0,
                                 30);
  if (rc != BZ_OK)
    {
      return 2;
    }

  dec_len = (unsigned int)N;
  rc = BZ2_bzBuffToBuffDecompress (dec, &dec_len, enc, enc_len, small, 0);
  if (rc != BZ_OK || dec_len != (unsigned int)N || memcmp (in, dec, N))
    {
      return 3;
    }

  /* A truncated stream must not be accepted as a complete stream. */
  dec_len = (unsigned int)N;
  rc = BZ2_bzBuffToBuffDecompress (dec, &dec_len, enc, enc_len - 1U, small, 0);
  if (rc == BZ_OK)
    {
      return 4;
    }

  free (dec);
  free (enc);
  free (in);
  return 0;
}

static int
stream_test (void)
{
  bz_stream s;
  int rc;

  memset (&s, 0, sizeof (s));
  rc = BZ2_bzCompressInit (&s, 1, 0, 30);
  if (rc != BZ_OK)
    {
      return 1;
    }

  rc = BZ2_bzCompressEnd (&s);
  if (rc != BZ_OK)
    {
      return 2;
    }

  memset (&s, 0, sizeof (s));
  rc = BZ2_bzDecompressInit (&s, 0, 1);
  if (rc != BZ_OK)
    {
      return 3;
    }

  rc = BZ2_bzDecompressEnd (&s);
  return rc == BZ_OK ? 0 : 4;
}

static int
file_test (void)
{
  FILE *f;
  BZFILE *b;
  int err, count, close_err;
  char result[6];

  f = tmpfile ();
  if (f == NULL)
    {
      return 1;
    }

  b = BZ2_bzWriteOpen (&err, f, 1, 0, 30);
  if (err != BZ_OK || b == NULL)
    {
      return 2;
    }

  BZ2_bzWrite (&err, b, "hello", 5);
  if (err != BZ_OK)
    {
      return 3;
    }

  BZ2_bzWriteClose (&close_err, b, 0, NULL, NULL);
  if (close_err != BZ_OK)
    {
      return 4;
    }

  rewind (f);
  b = BZ2_bzReadOpen (&err, f, 0, 0, NULL, 0);
  if (err != BZ_OK || b == NULL)
    {
      return 5;
    }

  count = BZ2_bzRead (&err, b, result, 5);
  if (count != 5 || memcmp (result, "hello", 5))
    {
      return 6;
    }

  BZ2_bzReadClose (&err, b);
  fclose (f);
  return err == BZ_OK ? 0 : 7;
}

int
main (void)
{
  int level, small, rc;

  if (strncmp (BZ2_bzlibVersion (), "1.0.8", 5))
    {
      return 1;
    }

  if (stream_test ())
    {
      return 2;
    }

  if (file_test ())
    {
      return 3;
    }

  for (level = 1; level <= 9; level++)
    {
      for (small = 0; small <= 1; small++)
        {
          rc = roundtrip (level, small);
          if (rc)
            {
              fprintf (stderr, "level %d small %d returned %d\n", level, small,
                       rc);
              return 4;
            }
        }
    }

  puts ("libbzip2 full API 1.0.8: PASS");
  return 0;
}
