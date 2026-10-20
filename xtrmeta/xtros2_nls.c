/* SPDX-License-Identifier: MIT-0 */
/* Native OS/2 EA name identity: the active country/codepage,
 * not ASCII-only. */
#define INCL_DOSNLS
#include "xtros2_ea.h"
#include <os2.h>
#include <string.h>
int
xtr_os2_ea_native_equal (const unsigned char *a, size_t na,
                         const unsigned char *b, size_t nb, void *unused)
{
  COUNTRYCODE country;
  char ca[256], cb[256];

  (void)unused;
  if (na != nb)
    {
      return 0;
    }

  if (na > 255U || (!a && na) || (!b && nb))
    {
      return -1;
    }

  if (!na)
    {
      return 1;
    }

  memcpy (ca, a, na);
  memcpy (cb, b, nb);
  country.country = 0;
  country.codepage = 0;
  if (DosMapCase ((ULONG)na, &country, ca) != 0)
    {
      return -1;
    }

  if (DosMapCase ((ULONG)nb, &country, cb) != 0)
    {
      return -1;
    }

  return memcmp (ca, cb, na) == 0;
}
