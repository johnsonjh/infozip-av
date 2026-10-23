/* SPDX-License-Identifier: MIT-0 */
/* Test the production comparison helpers without linking the full codec set.
 * Linker section GC drops the unused ZipOpt CLI and its decoder references. */
#define main zo_unused_program_main_for_comparison_test
#include "../zipopt.c"
#undef main

/* The record comparison helper depends only on this archive read primitive. */
int
zo_archive_at (zo_archive *a, zo_u64 off, void *out, size_t n)
{
  if (!a || !a->fp || off > (zo_u64)LONG_MAX
      || fseek (a->fp, (long)off, SEEK_SET) != 0)
    return 0;
  return fread (out, 1, n, a->fp) == n;
}

static FILE *
zo_test_file (const unsigned char *p, size_t n)
{
  FILE *f = tmpfile ();
  if (!f || fwrite (p, 1, n, f) != n || fflush (f) != 0)
    {
      if (f)
        fclose (f);
      return NULL;
    }
  return f;
}

#define CHECK(x) do { if (!(x)) { \
  fprintf (stderr, "output compare test failed at line %d: %s\n", \
           __LINE__, #x); return 1; } } while (0)

int
main (void)
{
  unsigned char a_bytes[32789], b_bytes[32789];
  zo_archive a_archive, b_archive;
  zo_u64 where;
  FILE *a, *b;
  size_t i;

  for (i = 0; i < sizeof (a_bytes); i++)
    a_bytes[i] = (unsigned char)(i * 31U);
  memcpy (b_bytes, a_bytes, sizeof (b_bytes));
  a = zo_test_file (a_bytes, sizeof (a_bytes));
  b = zo_test_file (b_bytes, sizeof (b_bytes));
  CHECK (a && b);
  CHECK (zo_equal (a, b, &where) == ZO_COMPARE_EQUAL);
  a_archive.fp = a;
  b_archive.fp = b;
  CHECK (zo_equal_records (&a_archive, 2, &b_archive, 2,
                           sizeof (a_bytes) - 2U, &where)
         == ZO_COMPARE_EQUAL);
  fclose (b);

  b_bytes[32772] ^= 1U;
  b = zo_test_file (b_bytes, sizeof (b_bytes));
  CHECK (b);
  b_archive.fp = b;
  CHECK (zo_equal (a, b, &where) == ZO_COMPARE_BYTES && where == 32772U);
  CHECK (zo_equal_records (&a_archive, 2, &b_archive, 2,
                           sizeof (a_bytes) - 2U, &where)
         == ZO_COMPARE_BYTES && where == 32770U);
  fclose (b);

  b = zo_test_file (a_bytes, 32775U);
  CHECK (b);
  b_archive.fp = b;
  CHECK (zo_equal (a, b, &where) == ZO_COMPARE_SIZE && where == 32775U);
  CHECK (zo_equal_records (&a_archive, 0, &b_archive, 0,
                           sizeof (a_bytes), &where)
         == ZO_COMPARE_RIGHT_IO && where == 32768U);

  fclose (a);
  fclose (b);
  puts ("zipopt output comparison helpers: PASS");
  return 0;
}
