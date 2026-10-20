/* SPDX-License-Identifier: MIT-0 */
#include "xtros2_ea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void
put32 (unsigned char *p, unsigned long x)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      p[i] = (unsigned char)(x >> (i * 8));
    }
}
static void
require (int yes, const char *msg)
{
  if (!yes)
    {
      fprintf (stderr, "FAIL: %s\n", msg);
      exit (1);
    }
}
/* Deliberately simulated non-ASCII OS/2 NLS equivalence: native builds
 * use DosMapCase, never this test callback. */
static int
mock_nls (const unsigned char *a, size_t na, const unsigned char *b, size_t nb,
          void *ctx)
{
  size_t i;

  if (ctx)
    {
      return -1;
    }

  if (na != nb)
    {
      return 0;
    }

  for (i = 0; i < na; i++)
    {
      unsigned x = a[i], y = b[i];
      if (x == 0x81U)
        {
          x = 0x80U;
        }

      if (y == 0x81U)
        {
          y = 0x80U;
        }

      if (x != y)
        {
          return 0;
        }
    }

  return 1;
}
int
main (void)
{
  unsigned char raw[128], bad[128],
      sym[] = { 0xfd, 0xff, 4, 0, 't', 'e', 's', 't' };
  xtr_os2_ea_item a[2], b[2];
  xtr_os2_ea_source s;
  size_t n;
  int rc;

  memset (raw, 0, sizeof (raw));
  put32 (raw, 24);
  put32 (raw + 4, 0);
  raw[8] = 0x80;
  raw[9] = 7;
  raw[10] = 8;
  raw[12] = 'S';
  raw[13] = 'Y';
  memcpy (raw + 12, "SYMLINK", 7);
  memcpy (raw + 20, sym, 8);
  /* 4 outer + 8 header + 7 name + 1 NUL + 8 value = 28 */
  put32 (raw, 28);
  rc = xtr_os2_ea_parse (raw, 28, a, 2, &n);
  require (rc == XTR_OS2_EA_OK && n == 1 && a[0].flags == 0x80U, "valid list");
  require (xtr_os2_ea_source_init (&s, &a[0]) == XTR_OS2_EA_OK, "source init");
  require (s.source.record.origin == 8U && s.tlv[8] == 10 && s.tlv[10] == 10
               && s.tlv[18] == 0x80U,
           "V1 native TLVs");
  b[0] = a[0];
  require (xtr_os2_ea_reconcile (a, 1, b, 1) == XTR_OS2_EA_OK,
           "equal metadata");
  b[0].flags = 0;
  require (xtr_os2_ea_reconcile (a, 1, b, 1) == XTR_OS2_EA_CONFLICT,
           "flag conflict");
  b[0] = a[0];
  b[0].value_len = 7;
  require (xtr_os2_ea_reconcile (a, 1, b, 1) == XTR_OS2_EA_BAD,
           "malformed symlink");
  memcpy (bad, raw, 28);
  bad[20] = 0;
  require (xtr_os2_ea_parse (bad, 28, a, 2, &n) == XTR_OS2_EA_BAD,
           "bad SYMLINK type");
  memcpy (bad, raw, 28);
  bad[12] = 's';
  bad[13] = 'y';
  require (xtr_os2_ea_parse (bad, 28, a, 2, &n) == XTR_OS2_EA_OK,
           "case insensitive name");
  require (xtr_os2_ea_parse (raw, 27, a, 2, &n) == XTR_OS2_EA_BAD,
           "bad cbList");
  /* Native NLS can alias non-ASCII names which bytewise comparison misses.
   * Bad/missing NLS service must fail closed, before writing EAs. */
  {
    static const unsigned char n1[] = { 0x80 }, n2[] = { 0x81 };
    static const unsigned char v1[] = { 1 }, v2[] = { 2 };
    a[0].name = n1;
    a[0].name_len = 1;
    a[0].value = v1;
    a[0].value_len = 1;
    a[0].flags = 0;
    b[0].name = n2;
    b[0].name_len = 1;
    b[0].value = v2;
    b[0].value_len = 1;
    b[0].flags = 0;
    require (xtr_os2_ea_reconcile (a, 1, b, 1) == XTR_OS2_EA_OK,
             "bytewise ASCII fallback does not invent NLS aliases");
    require (xtr_os2_ea_reconcile_ex (a, 1, b, 1, mock_nls, NULL)
                 == XTR_OS2_EA_CONFLICT,
             "native codepage detects alias conflict");
    require (xtr_os2_ea_reconcile_ex (a, 1, b, 1, mock_nls, (void *)a)
                 == XTR_OS2_EA_BAD,
             "failed NLS mapping denies native restore");
  }
  /* The structural validator checks a complete list with two records:
   * first record's next offset is nonzero and final record terminates. */
  memcpy (raw + 28, raw + 4, 24);
  put32 (raw, 52);
  put32 (raw + 4, 24);
  put32 (raw + 28, 0);
  raw[36] = 's';
  raw[37] = 'y';
  require (xtr_os2_ea_parse (raw, 52, a, 2, &n) == XTR_OS2_EA_BAD,
           "duplicate names differing only in case");
  /* One record only; malformed next offset must not walk outside list. */
  memcpy (bad, raw, 28);
  put32 (bad, 28);
  put32 (bad + 4, 8);
  require (xtr_os2_ea_parse (bad, 28, a, 2, &n) == XTR_OS2_EA_BAD,
           "overlapping FEA2 next offset");
  put32 (bad + 4, 32);
  require (xtr_os2_ea_parse (bad, 28, a, 2, &n) == XTR_OS2_EA_BAD,
           "oversized FEA2 next offset");
  /* Verify byte-exact native partitioning: the SYMLINK EA is isolated,
   * ordinary EAs remain in a separate valid list, and the original is
   * untouched. This is the basis for deferred native link activation. */
  {
    xtr_os2_ea_partition parts;
    static const unsigned char ordinary_name[] = { 'A', 'A', 'A' };
    static const unsigned char ordinary_value[] = { 0x11, 0x22, 0x33 };
    unsigned char original[49];
    memset (raw, 0, sizeof (raw));
    put32 (raw, 49);
    put32 (raw + 4, 20);
    raw[9] = 3;
    raw[10] = 3;
    memcpy (raw + 12, ordinary_name, 3);
    memcpy (raw + 16, ordinary_value, 3);
    /* The second FEA2 starts at offset 24, not 28. */
    put32 (raw + 24, 0);
    raw[28] = 0x80;
    raw[29] = 7;
    raw[30] = 8;
    memcpy (raw + 32, "SYMLINK", 7);
    memcpy (raw + 40, sym, 8);
    memcpy (original, raw, 49);
    require (xtr_os2_ea_partition_list (raw, 49, &parts, NULL, NULL) == 0,
             "partition mixed EA list");
    require (parts.ordinary != NULL && parts.symlink != NULL
                 && parts.ordinary_len == 19U && parts.symlink_len == 28U,
             "split list sizes");
    require (xtr_os2_ea_parse (parts.ordinary, parts.ordinary_len, a, 2, &n)
                     == 0
                 && n == 1 && a[0].name_len == 3U
                 && memcmp (a[0].value, ordinary_value, 3) == 0,
             "ordinary EA preserved");
    require (xtr_os2_ea_parse (parts.symlink, parts.symlink_len, a, 2, &n) == 0
                 && n == 1 && a[0].flags == 0x80 && a[0].value_len == 8
                 && memcmp (a[0].value, sym, 8) == 0,
             "deferred link EA preserved");
    require (memcmp (raw, original, 49) == 0, "split never mutates its input");
    xtr_os2_ea_partition_free (&parts);
    require (parts.ordinary == NULL && parts.symlink == NULL,
             "partition allocations released");
    raw[40] = 0;
    require (xtr_os2_ea_partition_list (raw, 49, &parts, NULL, NULL)
                     == XTR_OS2_EA_BAD
                 && !parts.ordinary && !parts.symlink,
             "malformed symlink fails closed before any ordinary writes");
  }
  puts ("OS/2 EA parser, NLS conflict, V1 TLV unit tests: PASS");
  return 0;
}
