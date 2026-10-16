/* Unicode command-line boundary for opt-in console UnZip. MIT-0.
 * Caller's Windows CRT argv is never treated as a reliable Unicode source.
 * Individual strings remain valid until xtr_win_utf8_free_argv(). */
#include "xtrwin_utf8argv.h"
#include <errno.h>
#include <limits.h>
#include <shellapi.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void
xtr_win_utf8_free_argv (int argc, char **argv)
{
  int i;

  if (!argv)
    {
      return;
    }

  for (i = 0; i < argc; i++)
    {
      free (argv[i]);
    }

  free (argv);
}

int
xtr_win_utf8_argv (int *argc, char ***argv)
{
  LPWSTR *wargv;
  char **result;
  int count, i, n;

  if (!argc || !argv)
    {
      errno = EINVAL;
      return 0;
    }

  *argc = 0;
  *argv = NULL;
  count = 0;
  wargv = CommandLineToArgvW (GetCommandLineW (), &count);
  if (!wargv || count < 1 || count >= INT_MAX / ((int)sizeof (char *)))
    {
      if (wargv)
        {
          LocalFree ((HLOCAL)wargv);
        }

      errno = EINVAL;
      return 0;
    }

  result = (char **)calloc ((size_t)count + 1U, sizeof (*result));
  if (!result)
    {
      LocalFree ((HLOCAL)wargv);
      errno = ENOMEM;
      return 0;
    }

  for (i = 0; i < count; i++)
    {
      if (!wargv[i])
        {
          break;
        }

      /* WC_ERR_INVALID_CHARS rejects unpaired UTF-16 surrogates. */
      n = WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1,
                               NULL, 0, NULL, NULL);
      if (n <= 0 || n > 32768)
        {
          break;
        }

      result[i] = (char *)malloc ((size_t)n);
      if (!result[i])
        {
          errno = ENOMEM;
          break;
        }

      if (WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1,
                               result[i], n, NULL, NULL)
          != n)
        {
          break;
        }

      if (memchr (result[i], 0, (size_t)n - 1U) != NULL)
        {
          break;
        }
    }

  LocalFree ((HLOCAL)wargv);
  if (i != count)
    {
      xtr_win_utf8_free_argv (count, result);
      if (errno != ENOMEM)
        {
          errno = EINVAL;
        }

      return 0;
    }

  *argc = count;
  *argv = result;
  return 1;
}
