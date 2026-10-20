/* SPDX-License-Identifier: MIT-0 */
/* Host test of the real native EA enumerator with deterministic Dos* shims. */
#include "../xtrmeta/xtros2_ea.h"
#include "../xtrmeta/xtros2_native.h"
#include "os2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int
xtr_os2_ea_native_equal (const unsigned char *a, size_t na,
                         const unsigned char *b, size_t nb, void *ctx)
{
  size_t i;

  (void)ctx;
  if (na != nb)
    {
      return 0;
    }

  for (i = 0; i < na; i++)
    {
      unsigned x = a[i], y = b[i];
      if (x >= 'a' && x <= 'z')
        {
          x -= 32;
        }

      if (y >= 'a' && y <= 'z')
        {
          y -= 32;
        }

      if (x != y)
        {
          return 0;
        }
    }

  return 1;
}
static int mode;
static unsigned calls;
static char last[300];
static unsigned char fixture[64];
static size_t fixture_len;
static int
fail (const char *msg)
{
  fprintf (stderr, "os2 native query: %s\n", msg);
  return 1;
}
APIRET
DosQueryPathInfo (PSZ path, ULONG level, PVOID out, ULONG len)
{
  if (strlen (path) >= sizeof (last))
    {
      return 5;
    }

  strcpy (last, path);
  calls++;
  if (mode == 1)
    {
      return ERROR_EAS_NOT_SUPPORTED;
    }

  if (mode == 2)
    {
      return 5U;
    }

  if (level == FIL_QUERYEASIZE)
    {
      FILESTATUS4 *s = (FILESTATUS4 *)out;
      if (len < sizeof (*s))
        {
          return 5U;
        }

      memset (s, 0, sizeof (*s));
      s->cbList = fixture_len;
      return NO_ERROR;
    }

  if (level == FIL_QUERYEASFROMLIST)
    {
      EAOP2 *a = (EAOP2 *)out;
      if (len < sizeof (*a) || !a->fpGEA2List || !a->fpFEA2List
          || a->fpFEA2List->cbList < fixture_len)
        {
          return 5U;
        }

      if (mode == 3)
        {
          a->fpFEA2List->cbList = 3U;
          return NO_ERROR;
        }

      memcpy (a->fpFEA2List, fixture, fixture_len);
      return NO_ERROR;
    }

  return 5U;
}
APIRET
DosEnumAttribute (ULONG type, PVOID path, ULONG start, PVOID out, ULONG size,
                  ULONG *count, ULONG level)
{
  unsigned char *b = (unsigned char *)out;

  (void)path;
  if (type != ENUMEA_REFTYPE_PATH || start != 1U
      || level != ENUMEA_LEVEL_NO_VALUE || size < 64U)
    {
      return 5U;
    }

  if (mode == 4)
    {
      *count = 0U;
      return NO_ERROR;
    }

  memset (b, 0, 20U);
  b[5] = 4U;
  b[8] = 'T';
  b[9] = 'E';
  b[10] = 'S';
  b[11] = 'T';
  b[12] = 0U;
  *count = 1U;
  return NO_ERROR;
}
int
main (void)
{
  unsigned char *got = NULL;
  size_t length = 0U;
  xtr_os2_ea_item item;
  int i;

  memset (&item, 0, sizeof (item));
  item.flags = 0x80U;
  item.name = (const unsigned char *)"TEST";
  item.name_len = 4U;
  item.value = (const unsigned char *)"\x01\x02\x03";
  item.value_len = 3U;
  {
    unsigned char *tmp = NULL;
    if (xtr_os2_ea_pack_list (&item, 1U, &tmp, &fixture_len, NULL, NULL))
      {
        return fail ("fixture pack");
      }

    if (fixture_len > sizeof (fixture))
      {
        free (tmp);
        return fail ("fixture size");
      }

    memcpy (fixture, tmp, fixture_len);
    free (tmp);
  }
  if (xtr_os2_query_native_eas ("C:\\DIR\\", &got, &length) != 0
      || strcmp (last, "C:\\DIR") || length != fixture_len
      || memcmp (got, fixture, length))
    {
      return fail ("directory capture");
    }

  free (got);
  got = NULL;
  if (xtr_os2_query_native_eas ("C:\\", &got, &length) != 0
      || strcmp (last, "C:\\"))
    {
      return fail ("drive root");
    }

  free (got);
  got = NULL;
  for (i = 1; i <= 4; i++)
    {
      mode = i;
      got = (unsigned char *)1;
      length = 777U;
      if (xtr_os2_query_native_eas ("C:\\DIR", &got, &length)
              != (i == 1 || i == 4 ? 1 : -1)
          || got != NULL || length)
        {
          return fail ("error/no-EA behavior");
        }
    }

  printf ("OS/2 Dos* native EA query shim: PASS (%u calls)\n", calls);
  return 0;
}
