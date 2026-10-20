/* MIT-0. Transport/encryption/FWKCS/rewrite safety gates, C89. */
#include "xtrv1.h"
#include <stdio.h>
#include <string.h>
static int errs = 0, checks = 0;
#define C(z)                                                                  \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(z))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #z);               \
          errs++;                                                             \
        }                                                                     \
    }                                                                         \
  while (0)
static void
test_crypto (void)
{
  xtr_extra e;
  unsigned m;

  memset (&e, 0, sizeof (e));
  memset (e.owner, 0x3a, 16);
  for (m = 0; m <= 4U; m++)
    {
      e.mode = 2;
      e.flags = (m != 0U);
      C (xtr1_check_member_policy (&e, m, m, 1, m >= 2, 0, 0) == XTR_OK);
      C (xtr1_check_member_policy (&e, m, m, 0, 1, 0, 0) == XTR_IO);
      if (m >= 2U)
        {
          C (xtr1_check_member_policy (&e, m, m, 1, 0, 0, 0) == XTR_IO);
          C (xtr1_crypto_check (m, m, 0, 1) == XTR_IO);
        }

      C (xtr1_check_member_policy (&e, m, (m + 1U) % 5U, 1, 1, 0, 0)
         == XTR_CORRUPT);
      if (m != 0U)
        {
          C (xtr1_check_member_policy (&e, m, m, 1, 1, 1, 0) == XTR_CORRUPT);
          C (xtr1_check_member_policy (&e, m, m, 1, 1, 0, 1)
             == XTR_UNSUPPORTED);
        }
      else
        {
          C (xtr1_check_member_policy (&e, 0, 0, 1, 0, 1, 1) == XTR_OK);
        }
    }

  /* Cleartext directory owner, encrypted metadata companion only. */
  e.mode = 2;
  e.flags = 1;
  C (xtr1_check_member_policy_dir (&e, 0, 3, 1, 1, 1, 0, 0) == XTR_OK);
  C (xtr1_check_member_policy_dir (&e, 0, 3, 0, 1, 1, 0, 0) == XTR_CORRUPT);
  C (xtr1_check_member_policy_dir (&e, 0, 3, 1, 1, 0, 0, 0) == XTR_IO);
  C (xtr1_check_member_policy_dir (&e, 0, 3, 1, 0, 1, 0, 0) == XTR_IO);
  C (xtr1_check_member_policy_dir (&e, 0, 3, 1, 1, 1, 1, 0) == XTR_CORRUPT);
  C (xtr1_check_member_policy_dir (&e, 0, 3, 1, 1, 1, 0, 1) == XTR_UNSUPPORTED);
  C (xtr1_check_member_policy_dir (&e, 1, 3, 1, 1, 1, 0, 0) == XTR_CORRUPT);
  C (xtr1_check_member_policy_dir (&e, 3, 3, 1, 1, 1, 0, 0) == XTR_CORRUPT);
  e.flags = 0;
  C (xtr1_check_member_policy_dir (&e, 0, 3, 1, 1, 1, 0, 0) == XTR_CORRUPT);
  e.flags = 1;
  C (xtr1_check_member_policy (&e, 0, 3, 1, 1, 0, 0) == XTR_CORRUPT);
  e.mode = 1;
  e.flags = 0;
  C (xtr1_check_member_policy (&e, 0, 0, 1, 0, 0, 1) == XTR_OK);
  C (xtr1_check_member_policy (&e, 1, 1, 1, 0, 0, 0) == XTR_UNSUPPORTED);
  C (xtr1_check_member_policy (&e, 0, 0, 1, 0, 1, 0) == XTR_UNSUPPORTED);
  memset (e.owner, 0, 16);
  C (xtr1_check_member_policy (&e, 0, 0, 1, 0, 0, 0) == XTR_CORRUPT);
}
static void
test_rewrite (void)
{
  unsigned char a[16], b[16];
  xtr1_rewrite_entry r[4];

  memset (a, 1, 16);
  memset (b, 2, 16);
  memset (r, 0, sizeof (r));
  r[0].operation = XTR1_RETAIN;
  r[0].old_mode = 2;
  r[0].new_mode = 2;
  r[0].old_owner = a;
  r[0].new_owner = a;
  r[1] = r[0];
  r[1].operation = XTR1_RENAME;
  r[2] = r[0];
  r[2].operation = XTR1_REPLACE;
  r[2].new_owner = b;
  r[2].manifest_rebuilt = 1;
  r[3] = r[0];
  r[3].operation = XTR1_CLONE;
  r[3].new_owner = b;
  r[3].manifest_rebuilt = 1;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_OK);
  r[0].new_owner = b;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_CORRUPT);
  r[0].new_owner = a;
  r[1].new_mode = 1;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_CORRUPT);
  r[1].new_mode = 2;
  r[2].new_owner = a;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_CORRUPT);
  r[2].new_owner = b;
  r[3].manifest_rebuilt = 0;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_CORRUPT);
  r[3].manifest_rebuilt = 1;
  r[3].new_owner = a;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_CORRUPT);
  r[3].new_owner = b;
  r[0].operation = XTR1_DELETE;
  r[0].new_mode = 0;
  r[0].new_owner = NULL;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_OK);
  r[0].new_mode = 2;
  r[0].new_owner = a;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_CORRUPT);
  r[0].new_mode = 0;
  r[0].new_owner = NULL;
  r[2].new_mode = 0;
  r[2].new_owner = NULL;
  r[2].manifest_rebuilt = 0;
  C (xtr1_check_rewrite_decisions (r, 4) == XTR_OK);
  C (xtr1_check_rewrite_decisions (NULL, 1) == XTR_CORRUPT);
}
static void
test_zero_owner (void)
{
  xtr1_policy p;
  xtr1_sink sink;
  xtr1_digest d;
  unsigned char zero[16];

  memset (&p, 0, sizeof (p));
  p.max_records = 10;
  p.max_field = 1024;
  p.max_manifest.lo = 1024;
  memset (zero, 0, 16);
  memset (&sink, 0, sizeof (sink));
  /* Valid callback pointer is needed before testing the zero owner. */
  C (xtr1_write_manifest (zero, NULL, 0, 0, &p, &sink, &d) == XTR_CORRUPT);
}
int
main (void)
{
  test_crypto ();
  test_rewrite ();
  test_zero_owner ();
  printf ("policy/rewrite tests: %d assertions, %d failures\n", checks, errs);
  return errs != 0;
}
