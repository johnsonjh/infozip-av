main(1049): Parsing: 3728 bytes (3728 chars) from stdin as language C
/* SPDX-License-Identifier: MIT-0 */
/* Linux mock exercises THE SAME EA reader and resolver used by Open Watcom.
 * No native OS/2 runtime behavior is claimed by this fixture. */
#include "../zip30/os2/os2link.h"
#include <os2.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* The mock ULONG must use 32 bits, so the native ABI layout is reproduced.
 * Compiling on LP64 requires fixed-width sizes, not host 'unsigned long'. */
static int mock_mode = 0;
static const char *mock_target = "../target";
static int errors = 0;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #x);               \
          errors++;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)
APIRET
DosQueryPathInfo (PSZ path, ULONG level, PVOID data, ULONG length)
{
  EAOP2 *op = (EAOP2 *)data;
  unsigned char *buf = (unsigned char *)op->fpFEA2List;
  size_t n;
  const char *target = mock_target;
  int yes = mock_mode;
  size_t sz;

  (void)length;
  if (level != FIL_QUERYEASFROMLIST)
    {
      return 87;
    }

  if (!strcmp (path, "a"))
    {
      yes = 1;
      target = "b";
    }
  else if (!strcmp (path, "b"))
    {
      yes = 1;
      target = "a";
    }
  else if (!strcmp (path, "dir/link"))
    {
      yes = 1;
      target = "../target";
    }
  else if (!strcmp (path, "dir/link/child"))
    {
      yes = 0;
    }

  /* FEA2LIST: DWORD size, 8-byte fixed header, 7-byte name, NUL, value. */
  n = strlen (target);
  sz = 4U + 8U + 8U + (yes ? 4U + n : 0U);
  if (op->fpFEA2List->cbList < sz)
    {
      return 111U;
    }

  memset (buf, 0, sz);
  buf[0] = (unsigned char)sz;
  buf[1] = (unsigned char)(sz >> 8);
  buf[4 + 4] = 0x80;
  buf[4 + 5] = 7U;
  buf[4 + 6] = (unsigned char)(yes ? 4U + n : 0U);
  memcpy (buf + 4 + 8, "SYMLINK", 8);
  if (yes)
    {
      buf[4 + 8 + 8] = 0xfd;
      buf[4 + 8 + 9] = 0xff;
      buf[4 + 8 + 10] = (unsigned char)n;
      buf[4 + 8 + 11] = (unsigned char)(n >> 8);
      memcpy (buf + 4 + 8 + 12, target, n);
      if (yes == 2)
        {
          buf[4 + 8 + 8] = 1; /* Invalid type */
        }

      if (yes == 3)
        {
          buf[4 + 8 + 12] = 0; /* Embedded NUL */
        }

      if (yes == 4)
        {
          buf[4 + 8 + 10]++; /* Length mismatch */
        }
    }

  return 0;
}
int
main (void)
{
  char output[1024];

  mock_mode = 0;
  CHECK (iz_os2_link_target ("none", output, sizeof (output)) == 0);
  mock_mode = 1;
  CHECK (iz_os2_link_target ("link", output, sizeof (output)) == 1);
  CHECK (!strcmp (output, "../target"));
  CHECK (iz_os2_link_target ("link", output, 3) == -1);
  mock_mode = 2;
  CHECK (iz_os2_link_target ("link", output, sizeof (output)) == -1);
  mock_mode = 3;
  CHECK (iz_os2_link_target ("link", output, sizeof (output)) == -1);
  mock_mode = 4;
  CHECK (iz_os2_link_target ("link", output, sizeof (output)) == -1);
  mock_mode = 0;
  CHECK (iz_os2_link_resolve ("dir/link/child", output, sizeof (output), 1)
         == 0);
  CHECK (!strcmp (output, "dir/../target/child"));
  CHECK (iz_os2_link_resolve ("a", output, sizeof (output), 1) == -1);
  if (errors)
    {
      fprintf (stderr, "%d failures\n", errors);
      return 1;
    }

  puts ("PASS native OS/2 EA mock parser/resolver");
  return 0;
}
