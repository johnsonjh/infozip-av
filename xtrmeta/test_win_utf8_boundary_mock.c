/* Strict-C89 simulated Windows UTF-16 API boundary. MIT-0. */
#include "xtrwin_utf8path.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifndef O_BINARY
# define O_BINARY 0x8000
#endif /* ifndef O_BINARY */

static unsigned calls;
static wchar_t observed[128];

static void
observe (const wchar_t *w)
{
  size_t n = 0;

  calls++;
  while (w[n] && n + 1U < sizeof (observed) / sizeof (observed[0]))
    {
      observed[n] = w[n];
      n++;
    }
  observed[n] = 0;
}

UINT
GetACP (void)
{
  return 1252U;
}
int
MultiByteToWideChar (UINT cp, DWORD flags, const char *s, int slen,
                     wchar_t *out, int cap)
{
  int i = 0, n = 0;

  (void)flags;
  if (slen != -1)
    {
      return 0;
    }

  for (;;)
    {
      unsigned char c = (unsigned char)s[i];
      unsigned v = c, step = 1U;
      if (!c)
        {
          if (out && n < cap)
            {
              out[n] = 0;
            }

          return n + 1;
        }

      if (cp == CP_UTF8)
        {
          if (c >= 0xc2U && c <= 0xdfU)
            {
              v = c & 31U;
              step = 2U;
            }
          else if (c >= 0xe0U && c <= 0xefU)
            {
              v = c & 15U;
              step = 3U;
            }
          else if (c >= 0xf0U && c <= 0xf4U)
            {
              v = c & 7U;
              step = 4U;
            }

          if (step > 1U)
            {
              unsigned j;
              for (j = 1; j < step; j++)
                {
                  v = (v << 6) | ((unsigned char)s[i + (int)j] & 63U);
                }
            }
        }

      if (out)
        {
          if (n >= cap)
            {
              return 0;
            }

          out[n] = (wchar_t)v;
        }

      n++;
      i += (int)step;
    }
}
int
WideCharToMultiByte (UINT cp, DWORD flags, const wchar_t *w, int slen,
                     char *out, int cap, const char *def, BOOL *used)
{
  int i, n = 0;

  (void)flags;
  (void)def;
  if (used)
    {
      *used = FALSE;
    }

  if (slen != -1)
    {
      return 0;
    }

  for (i = 0;; i++)
    {
      unsigned v = (unsigned)w[i];
      if (!v)
        {
          if (out && n < cap)
            {
              out[n] = 0;
            }

          return n + 1;
        }

      if (cp != CP_UTF8)
        {
          if (v > 255U)
            {
              if (used)
                {
                  *used = TRUE;
                }

              return 0;
            }

          if (out)
            {
              if (n >= cap)
                {
                  return 0;
                }

              out[n] = (char)v;
            }

          n++;
        }
      else
        {
          unsigned j, k;
          char b[4];
          if (v < 128U)
            {
              b[0] = (char)v;
              k = 1U;
            }
          else if (v < 2048U)
            {
              b[0] = (char)(0xc0U | (v >> 6));
              b[1] = (char)(0x80U | (v & 63U));
              k = 2U;
            }
          else if (v < 65536U)
            {
              b[0] = (char)(0xe0U | (v >> 12));
              b[1] = (char)(0x80U | ((v >> 6) & 63U));
              b[2] = (char)(0x80U | (v & 63U));
              k = 3U;
            }
          else
            {
              b[0] = (char)(0xf0U | (v >> 18));
              b[1] = (char)(0x80U | ((v >> 12) & 63U));
              b[2] = (char)(0x80U | ((v >> 6) & 63U));
              b[3] = (char)(0x80U | (v & 63U));
              k = 4U;
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
}
HANDLE
CreateFileW (const wchar_t *p, DWORD a, DWORD s, void *security, DWORD d,
             DWORD flags, HANDLE template_handle)
{
  (void)a;
  (void)s;
  (void)security;
  (void)d;
  (void)flags;
  (void)template_handle;
  observe (p);
  return (HANDLE)1;
}
DWORD
GetFileAttributesW (const wchar_t *p)
{
  observe (p);
  return 32U;
}
BOOL
SetFileAttributesW (const wchar_t *p, DWORD attrs)
{
  (void)attrs;
  observe (p);
  return TRUE;
}
int
_wstati64 (const wchar_t *p, struct _stati64 *st)
{
  (void)st;
  observe (p);
  return 0;
}
int
_wmkdir (const wchar_t *p)
{
  observe (p);
  return 0;
}
int
_waccess (const wchar_t *p, int mode)
{
  (void)mode;
  observe (p);
  return 0;
}
int
_wunlink (const wchar_t *p)
{
  observe (p);
  return 0;
}
int
_wrename (const wchar_t *a, const wchar_t *b)
{
  observe (a);
  observe (b);
  return 0;
}
int
_wchmod (const wchar_t *p, int mode)
{
  (void)mode;
  observe (p);
  return 0;
}
FILE *
_wfopen (const wchar_t *p, const wchar_t *mode)
{
  (void)mode;
  observe (p);
  return (FILE *)1;
}
int
_wopen (const wchar_t *p, int flags, ...)
{
  if (flags != (O_RDONLY | _O_BINARY))
    {
      return -1;
    }

  observe (p);
  return 17;
}

int
main (void)
{
  const char *snow = "snow-\xe9\x9b\xaa.bin";
  const char *not_utf8 = "\xf4\x90\x80\x80";
  char *converted;
  wchar_t *wide;
  unsigned old;

  if (xtr_win_u8_open (snow, 1U, 1U, 3U, 0U) == INVALID_HANDLE_VALUE)
    {
      return 1;
    }

  if (calls != 1U || observed[5] != 0x96eaU)
    {
      return 2;
    }

  old = calls;
  if (xtr_win_u8_open (not_utf8, 1U, 1U, 3U, 0U) != INVALID_HANDLE_VALUE
      || calls != old)
    {
      return 3;
    }

  if (xtr_win_u8_open ("C:/dir/missing.", 1U, 1U, 3U, 0U)
          != INVALID_HANDLE_VALUE
      || xtr_win_u8_open ("C:/dir/hidden:$DATA", 1U, 1U, 3U, 0U)
             != INVALID_HANDLE_VALUE
      || xtr_win_u8_open ("\\\\?\\C:\\dir", 1U, 1U, 3U, 0U)
             != INVALID_HANDLE_VALUE
      || calls != old)
    {
      return 7;
    }

  {
    static const char *bad_names[] = { "NUL",
                                       "nul.txt",
                                       "C:/prefix/CoN.log",
                                       "nested/PRN",
                                       "LPT9.bin",
                                       "COM1",
                                       "LPT\xc2\xb9.log",
                                       "COM\xc2\xb2.data",
                                       "COM\xc2\xb3",
                                       "a<b",
                                       "a>b",
                                       "a\"b",
                                       "a|b",
                                       "a?b",
                                       "a*b",
                                       "dir/aux .txt",
                                       "trailing.",
                                       "CONIN$",
                                       "CONOUT$.txt",
                                       "clock$" };
    unsigned k;
    for (k = 0; k < sizeof (bad_names) / sizeof (bad_names[0]); k++)
      {
        if (xtr_win_u8_open (bad_names[k], 1U, 1U, 3U, 0U)
                != INVALID_HANDLE_VALUE
            || calls != old)
          {
            return 8;
          }
      }

    if (xtr_win_u8_open ("COM10.txt", 1U, 1U, 3U, 0U) == INVALID_HANDLE_VALUE
        || xtr_win_u8_open ("NULx", 1U, 1U, 3U, 0U) == INVALID_HANDLE_VALUE
        || calls != old + 2U)
      {
        return 9;
      }

    old = calls;
  }
  {
    static const char *unsafe[] = { "NUL.txt",
                                    "nested/COM1.txt",
                                    "nested/LPT\xc2\xb9.bin",
                                    "../escape.txt",
                                    "dir/../escape",
                                    "dir//bad",
                                    "file:ads",
                                    "a|b",
                                    "/rooted",
                                    "back\\slash" };
    static const char *safe[]
        = { "snow-\xe9\x9b\xaa.bin", "dir/\xe9\x9b\xaa.bin", "dir/",
            "COM10.bin", "folder/.hidden" };
    unsigned k;
    for (k = 0; k < sizeof (unsafe) / sizeof (unsafe[0]); k++)
      {
        if (xtr_win_u8_member_safe (unsafe[k]))
          {
            return 10;
          }
      }

    for (k = 0; k < sizeof (safe) / sizeof (safe[0]); k++)
      {
        if (!xtr_win_u8_member_safe (safe[k]))
          {
            return 11;
          }
      }
  }
  converted = xtr_win_acp_u8 ("folder/\xe9.bin");
  if (!converted || strcmp (converted, "folder/\xc3\xa9.bin"))
    {
      return 4;
    }

  free (converted);
  wide = xtr_win_u8_wide (snow);
  if (!wide || wide[5] != 0x96eaU)
    {
      return 5;
    }

  free (wide);
  if (xtr_win_u8_mkdir (snow) != 0
      || xtr_win_u8_set_attributes (snow, 32U) != 1 || calls != old + 2U)
    {
      return 6;
    }

  old = calls;
  if (xtr_win_u8_archive_fd (
          "C:/archives/"
          "\xe5\xbd\x92\xe6\xa1\xa3-\xe9\x9b\xaa-\xf0\x9f\xa7\xaa.zip")
          != 17
      || calls != old + 1U || observed[12] != 0x5f52U)
    {
      return 20;
    }

  old = calls;
  if (xtr_win_u8_archive_fd (not_utf8) != -1 || calls != old
      || errno != EINVAL)
    {
      return 21;
    }

  if (xtr_win_u8_archive_fd ("NUL.txt") != -1 || calls != old
      || errno != EINVAL)
    {
      return 22;
    }

  printf ("PASS: Windows UTF-8 wide-path API boundary; 46 checks\n");
  return 0;
}
