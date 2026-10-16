/* Win32 wide command-line converter contract on Linux, strict C89. MIT-0. */
#include "xtrwin_utf8argv.h"
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static int scenario, freed, called;
static wchar_t exe_name[] = { L'u', L'n', L'z', L'i', L'p', 0 };
static wchar_t path_snow[]
    = { L'C', L':', L'/', 0x96ea, L'.', L'z', L'i', L'p', 0 };
static wchar_t path_emoji[]
    = { L'C', L':', L'/', 0xd83e, 0xddea, L'/', 0x96ea, 0 };
static wchar_t invalid[] = { L'x', 0xd800, 0 };
static LPWSTR args[4];
LPWSTR
GetCommandLineW (void) { return L"unzip "; }
LPWSTR *
CommandLineToArgvW (const wchar_t *cmd, int *n)
{
  (void)cmd;
  called++;
  if (scenario == 3)
    {
      return NULL;
    }

  args[0] = exe_name;
  args[1] = path_snow;
  args[2] = (scenario == 2) ? invalid : path_emoji;
  args[3] = NULL;
  *n = 3;
  return args;
}
HLOCAL
LocalFree (HLOCAL a)
{
  if (a != (HLOCAL)args)
    {
      fprintf (stderr, "incorrect LocalFree\n");
      exit (19);
    }

  freed++;
  return NULL;
}
/* Mock WideCharToMultiByte with genuine surrogate-pair validation. */
int
WideCharToMultiByte (UINT cp, DWORD flags, const wchar_t *w, int len,
                     char *out, int cap, const char *unused, BOOL *used)
{
  int i = 0, n = 0;

  (void)unused;
  if (used)
    {
      *used = 0;
    }

  if (cp != CP_UTF8 || flags != WC_ERR_INVALID_CHARS || len != -1)
    {
      return 0;
    }

  while (1)
    {
      unsigned long ch = (unsigned long)w[i++];
      unsigned char b[4];
      int k, j;
      if (!ch)
        {
          if (out)
            {
              if (n >= cap)
                {
                  return 0;
                }

              out[n] = 0;
            }

          return n + 1;
        }

      if (ch >= 0xd800UL && ch <= 0xdbffUL)
        {
          unsigned long lo = (unsigned long)w[i++];
          if (lo < 0xdc00UL || lo > 0xdfffUL)
            {
              return 0;
            }

          ch = 0x10000UL + ((ch - 0xd800UL) << 10) + (lo - 0xdc00UL);
        }
      else if (ch >= 0xdc00UL && ch <= 0xdfffUL)
        {
          return 0;
        }

      if (ch < 0x80UL)
        {
          b[0] = (unsigned char)ch;
          k = 1;
        }
      else if (ch < 0x800UL)
        {
          b[0] = (unsigned char)(0xc0U | (ch >> 6));
          b[1] = (unsigned char)(0x80U | (ch & 63UL));
          k = 2;
        }
      else if (ch < 0x10000UL)
        {
          b[0] = (unsigned char)(0xe0U | (ch >> 12));
          b[1] = (unsigned char)(0x80U | ((ch >> 6) & 63UL));
          b[2] = (unsigned char)(0x80U | (ch & 63UL));
          k = 3;
        }
      else
        {
          b[0] = (unsigned char)(0xf0U | (ch >> 18));
          b[1] = (unsigned char)(0x80U | ((ch >> 12) & 63UL));
          b[2] = (unsigned char)(0x80U | ((ch >> 6) & 63UL));
          b[3] = (unsigned char)(0x80U | (ch & 63UL));
          k = 4;
        }

      for (j = 0; j < k; j++)
        {
          if (out)
            {
              if (n >= cap)
                {
                  return 0;
                }

              out[n] = b[j];
            }

          n++;
        }
    }
}
int
main (void)
{
  int n = 88;
  char **v = NULL;

  if (!xtr_win_utf8_argv (&n, &v) || n != 3 || !v || v[3]
      || strcmp (v[1], "C:/\xe9\x9b\xaa.zip")
      || strcmp (v[2], "C:/\xf0\x9f\xa7\xaa/\xe9\x9b\xaa"))
    {
      return 1;
    }

  xtr_win_utf8_free_argv (n, v);
  if (freed != 1 || called != 1)
    {
      return 2;
    }

  scenario = 2;
  if (xtr_win_utf8_argv (&n, &v) || n != 0 || v != NULL || freed != 2)
    {
      return 3;
    }

  scenario = 3;
  if (xtr_win_utf8_argv (&n, &v) || n != 0 || v != NULL || freed != 2)
    {
      return 4;
    }

  if (xtr_win_utf8_argv (NULL, &v) || xtr_win_utf8_argv (&n, NULL))
    {
      return 5;
    }

  printf ("PASS: Windows UTF-16 command line; 5 checks\n");
  return 0;
}
