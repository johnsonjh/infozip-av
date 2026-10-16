/* Xtro UTF-8 Win32 path validation; no OS APIs called. MIT-0. */
#include "xtrwin_utf8path.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks = 0, failed = 0;
static void
check (const char *s, int expected, const char *reason)
{
  int got = xtr_win_u8_valid (s);

  checks++;
  if (got != expected)
    {
      fprintf (stderr, "FAIL: %s\n", reason);
      failed++;
    }
}
int
main (void)
{
  static const char *valid[] = { "a",
                                 "hello/a.txt",
                                 "\xc3\xa9.bin",
                                 "\xe9\x9b\xaa.bin",
                                 "\xf0\x9f\xa7\xaa.bin",
                                 "\xf4\x8f\xbf\xbf" };
  static const char *bad[] = { "",
                               "\x80",
                               "\xbf",
                               "\xc0\x80",
                               "\xc1\xbf",
                               "\xe0\x80\x80",
                               "\xed\xa0\x80",
                               "\xed\xbf\xbf",
                               "\xf0\x80\x80\x80",
                               "\xf4\x90\x80\x80",
                               "\xf5\x80\x80\x80",
                               "\xe2\x82",
                               "\xf0\x9f\xa7",
                               "\xc2",
                               "\xe1\x41\x80" };
  unsigned i, j;
  char s[64];

  check (NULL, 0, "null");
  for (i = 0; i < sizeof (valid) / sizeof (valid[0]); i++)
    {
      check (valid[i], 1, "valid");
    }

  for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++)
    {
      check (bad[i], 0, "invalid");
    }

  for (i = 0; i < 30000U; i++)
    {
      unsigned char b = (unsigned char)(i % 128U);
      s[0] = 'x';
      s[1] = (char)(0x80U | b);
      s[2] = 0;
      check (s, 0, "isolated continuation");
    }

  for (j = 1; j <= 4; j++)
    {
      memset (s, 'A', sizeof (s));
      s[sizeof (s) - 1] = 0;
      check (s, 1, "long ASCII");
    }

  printf ("Windows UTF-8 pathname validator: %u checks, %u failed\n", checks,
          failed);
  return failed ? 1 : 0;
}
