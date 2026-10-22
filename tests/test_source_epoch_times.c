/* SPDX-License-Identifier: MIT-0 */

/* Small independently compilable C89 tests for all encoded time formats. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define XTR_SDE_NEED_DOS 1
#define XTR_SDE_NEED_EXTRAS 1
#include "../xtrmeta/source_epoch.h"
#include "../xtrmeta/source_epoch_times.h"

static void
test_parser (void)
{
  unsigned long value;

  assert (xtr_source_epoch_parse ("315532800", &value)
          && value == 315532800UL);
  assert (xtr_source_epoch_parse ("0002147483647", &value)
          && value == 2147483647UL);
  assert (!xtr_source_epoch_parse ("", &value));
  assert (!xtr_source_epoch_parse ("-315532800", &value));
  assert (!xtr_source_epoch_parse ("+315532800", &value));
  assert (!xtr_source_epoch_parse ("315532800 ", &value));
  assert (!xtr_source_epoch_parse (" 315532800", &value));
  assert (!xtr_source_epoch_parse ("315532799", &value));
  assert (!xtr_source_epoch_parse ("2147483648", &value));
  assert (!xtr_source_epoch_parse ("9999999999999999999999999999", &value));
  assert (!xtr_source_epoch_parse ("315532800;touch /tmp/no", &value));
}

static void
test_dos (void)
{
  unsigned char late[4] = { 0xff, 0xff, 0xff, 0xff };
  unsigned char early[4] = { 0, 0, 0, 0 };
  unsigned long cutoff = xtr_sde_dos (946684801UL);

  assert (cutoff == 0x28210000UL); /* UTC 2000-01-01 00:00:00 */
  xtr_sde_clip_dos (late, cutoff);
  assert (xtr_sde_u32 (late) == cutoff);
  xtr_sde_clip_dos (early, cutoff);
  assert (xtr_sde_u32 (early) == 0UL);
  assert (xtr_sde_dos (315532801UL) == 0x00210000UL);
}

static void
test_extras (void)
{
  unsigned char ut[] = { 0x55, 0x54, 13, 0, 7,    0xff, 0xff, 0xff, 0xff,
                         1,    0,    0,  0, 0xff, 0xff, 0xff, 0xff };
  unsigned char central_ut[] = { 0x55, 0x54, 5, 0, 7, 0xff, 0xff, 0xff, 0xff };
  unsigned char ux[]
      = { 0x55, 0x58, 8, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned char ntfs[36];
  unsigned char vendor[] = { 0x23, 0x45, 4, 0, 1, 2, 3, 4 };
  unsigned char vendor_saved[sizeof (vendor)];
  unsigned long hi, lo;
  unsigned i;

  assert (xtr_sde_clip_extras (ut, sizeof (ut), 946684801UL));
  assert (xtr_sde_u32 (ut + 5) == 946684801UL);
  assert (xtr_sde_u32 (ut + 9) == 1UL);
  assert (xtr_sde_u32 (ut + 13) == 946684801UL);
  assert (xtr_sde_clip_extras (central_ut, sizeof (central_ut), 946684801UL));
  assert (xtr_sde_u32 (central_ut + 5) == 946684801UL);
  assert (xtr_sde_clip_extras (ux, sizeof (ux), 946684801UL));
  assert (xtr_sde_u32 (ux + 4) == 946684801UL);
  assert (xtr_sde_u32 (ux + 8) == 946684801UL);
  memset (ntfs, 0, sizeof (ntfs));
  ntfs[0] = 0x0a;
  ntfs[2] = 32; /* data length 32 */
  ntfs[8] = 1;
  ntfs[10] = 24; /* tag 1: three 64-bit timestamps */
  for (i = 12; i < sizeof (ntfs); i++)
    {
      ntfs[i] = 255;
    }

  assert (xtr_sde_clip_extras (ntfs, sizeof (ntfs), 946684801UL));
  xtr_sde_filetime_cutoff (946684801UL, &hi, &lo);
  assert (hi == 0x01bf53ebUL && lo == 0x2605d680UL);
  for (i = 0; i < 3; i++)
    {
      assert (xtr_sde_u32 (ntfs + 12 + i * 8) == lo);
      assert (xtr_sde_u32 (ntfs + 16 + i * 8) == hi);
    }

  memcpy (vendor_saved, vendor, sizeof (vendor));
  assert (xtr_sde_clip_extras (vendor, sizeof (vendor), 946684801UL));
  assert (memcmp (vendor, vendor_saved, sizeof (vendor)) == 0);
}

int
main (void)
{
  test_parser ();
  test_dos ();
  test_extras ();
  puts ("SOURCE_DATE_EPOCH timestamp C89 vectors: PASS");
  return 0;
}
