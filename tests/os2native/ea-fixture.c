/* SPDX-License-Identifier: MIT-0 */
/* OS/2 beta-only EA fixture utility. Operate on disposable files ONLY.
 * set PATH EA-NAME FLAGS-HEX VALUE-HEX
 * get PATH EA-NAME
 * check PATH EA-NAME FLAGS-HEX VALUE-HEX
 * flags are 00 or 80; typed EA payload bytes are supplied verbatim. */
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include <os2.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned char data[65536U];
static unsigned char querybuf[65536U];
static int
hval (int c)
{
  if (c >= '0' && c <= '9')
    {
      return c - '0';
    }

  if (c >= 'a' && c <= 'f')
    {
      return c - 'a' + 10;
    }

  if (c >= 'A' && c <= 'F')
    {
      return c - 'A' + 10;
    }

  return -1;
}
static int
fromhex (const char *hex, unsigned char *out, size_t maximum, size_t *used)
{
  size_t n, i;

  n = strlen (hex);
  if ((n & 1U) || n / 2U > maximum)
    {
      return 1;
    }

  for (i = 0; i < n / 2U; i++)
    {
      int a = hval ((unsigned char)hex[2U * i]);
      int b = hval ((unsigned char)hex[2U * i + 1U]);
      if (a < 0 || b < 0)
        {
          return 1;
        }

      out[i] = (unsigned char)((a << 4) | b);
    }

  *used = n / 2U;
  return 0;
}
static int
do_get (const char *path, const char *name, unsigned *flags,
        unsigned char *value, size_t *length)
{
  unsigned char geabuf[512];
  PGEA2LIST names = (PGEA2LIST)geabuf;
  PFEA2LIST list = (PFEA2LIST)querybuf;
  PFEA2 e;
  EAOP2 op;
  size_t n = strlen (name), off;
  APIRET rc;

  if (!n || n > 255U)
    {
      return 1;
    }

  memset (geabuf, 0, sizeof (geabuf));
  names->cbList = (ULONG)(4U + offsetof (GEA2, szName) + n + 1U);
  names->list[0].oNextEntryOffset = 0;
  names->list[0].cbName = (BYTE)n;
  memcpy (names->list[0].szName, name, n + 1U);
  list->cbList = sizeof (querybuf);
  op.fpGEA2List = names;
  op.fpFEA2List = list;
  op.oError = 0;
  rc = DosQueryPathInfo ((PSZ)path, FIL_QUERYEASFROMLIST, &op, sizeof (op));
  if (rc != NO_ERROR)
    {
      fprintf (stderr, "DosQueryPathInfo rc=%lu\n", (unsigned long)rc);
      return 1;
    }

  e = &list->list[0];
  off = 4U + offsetof (FEA2, szName) + (size_t)e->cbName + 1U;
  if (e->cbName != n || list->cbList < off || e->cbValue > list->cbList - off
      || memcmp (e->szName, name, n) != 0)
    {
      return 1;
    }

  *flags = e->fEA;
  *length = e->cbValue;
  memcpy (value, ((const unsigned char *)list) + off, *length);
  return 0;
}
static int
do_set (const char *path, const char *name, unsigned flags,
        const unsigned char *value, size_t length)
{
  PFEA2LIST list = (PFEA2LIST)querybuf;
  PFEA2 e = &list->list[0];
  EAOP2 op;
  size_t n = strlen (name), off;
  APIRET rc;

  if (!n || n > 255U || length > 65535U || (flags != 0 && flags != 0x80U))
    {
      return 1;
    }

  off = 4U + offsetof (FEA2, szName) + n + 1U;
  if (off + length > sizeof (querybuf))
    {
      return 1;
    }

  memset (querybuf, 0, off);
  list->cbList = (ULONG)(off + length);
  e->oNextEntryOffset = 0;
  e->fEA = (BYTE)flags;
  e->cbName = (BYTE)n;
  e->cbValue = (USHORT)length;
  memcpy (e->szName, name, n);
  e->szName[n] = 0;
  if (length)
    {
      memcpy (querybuf + off, value, length);
    }

  op.fpGEA2List = NULL;
  op.fpFEA2List = list;
  op.oError = 0;
  rc = DosSetPathInfo ((PSZ)path, FIL_QUERYEASIZE, &op, sizeof (op), 0);
  if (rc != NO_ERROR)
    {
      fprintf (stderr, "DosSetPathInfo rc=%lu\n", (unsigned long)rc);
      return 1;
    }

  return 0;
}
int
main (int argc, char **argv)
{
  unsigned flags, actual;
  unsigned char expected[65536U];
  size_t length = 0, n = 0, i;

  if (argc < 4)
    {
      fprintf (stderr,
               "usage: ea-fixture set/check PATH NAME FLAGS_HEX VALUE_HEX\n"
               "       ea-fixture get PATH NAME\n");
      return 2;
    }

  if (!strcmp (argv[1], "get"))
    {
      if (argc != 4 || do_get (argv[2], argv[3], &flags, data, &length))
        {
          return 1;
        }

      printf ("flags=%02X length=%lu value=", flags, (unsigned long)length);
      for (i = 0; i < length; i++)
        {
          printf ("%02X", data[i]);
        }

      puts ("");
      return 0;
    }

  if (argc != 6 || strlen (argv[4]) != 2U
      || fromhex (argv[4], expected, 1U, &n) || n != 1U
      || (flags = expected[0]) > 0x80U || (flags != 0U && flags != 0x80U)
      || fromhex (argv[5], expected, sizeof (expected), &n))
    {
      return 2;
    }

  if (!strcmp (argv[1], "set"))
    {
      return do_set (argv[2], argv[3], flags, expected, n);
    }

  if (!strcmp (argv[1], "check"))
    {
      if (do_get (argv[2], argv[3], &actual, data, &length) || actual != flags
          || length != n || memcmp (data, expected, n))
        {
          fprintf (stderr, "EA mismatch: %s/%s\n", argv[2], argv[3]);
          return 1;
        }

      printf ("EA %s matches (%lu bytes)\n", argv[3], (unsigned long)n);
      return 0;
    }

  return 2;
}
