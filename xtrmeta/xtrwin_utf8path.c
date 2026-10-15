/* Lossless UTF-8 <-> UTF-16 boundary for Windows extraction and ZIP archive
 * pathnames. SPDX-License-Identifier: MIT-0.
 * This is not used for passwords or private staging paths. */
#include "xtrwin_utf8path.h"
#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Reject invalid UTF-8 even on Windows versions where the conversion API's
 * input-error reporting has been historically inconsistent. */
int
xtr_win_u8_valid (const char *s)
{
  const unsigned char *p = (const unsigned char *)s;

  if (!p || !*p)
    {
      return 0;
    }

  while (*p)
    {
      unsigned v, minimum, n, i;
      if (*p < 0x80U)
        {
          p++;
          continue;
        }

      if (*p >= 0xc2U && *p <= 0xdfU)
        {
          n = 1U;
          minimum = 0x80U;
          v = *p & 31U;
        }
      else if (*p >= 0xe0U && *p <= 0xefU)
        {
          n = 2U;
          minimum = 0x800U;
          v = *p & 15U;
        }
      else if (*p >= 0xf0U && *p <= 0xf4U)
        {
          n = 3U;
          minimum = 0x10000U;
          v = *p & 7U;
        }
      else
        {
          return 0;
        }

      ++p;
      for (i = 0; i < n; i++)
        {
          if (!p[i] || p[i] < 0x80U || p[i] > 0xbfU)
            {
              return 0;
            }

          v = (v << 6) | (p[i] & 63U);
        }

      if (v < minimum || v > 0x10ffffUL || (v >= 0xd800U && v <= 0xdfffU))
        {
          return 0;
        }

      p += n;
    }
  return 1;
}

/* Windows reserves device basenames even with an extension. Do not allow
 * an archive member to address a DOS device through the ordinary file APIs.
 * Compare ASCII without locale-dependent case conversion; the three Latin-1
 * superscript digits in COM/LPT names use their exact UTF-8 encodings. */
static int
xtr_win_reserved_name (const unsigned char *p, size_t n)
{
  unsigned char up[4];
  size_t i, root = 0;

  while (root < n && p[root] != '.' && p[root] != ' ')
    {
      root++;
    }
  if (root == 0U)
    {
      return 0;
    }

  if (root == 3U)
    {
      for (i = 0; i < 3U; i++)
        {
          unsigned char c = p[i];
          up[i] = (unsigned char)((c >= 'a' && c <= 'z') ? c - 32U : c);
        }

      if ((up[0] == 'C' && up[1] == 'O' && up[2] == 'N')
          || (up[0] == 'P' && up[1] == 'R' && up[2] == 'N')
          || (up[0] == 'A' && up[1] == 'U' && up[2] == 'X')
          || (up[0] == 'N' && up[1] == 'U' && up[2] == 'L'))
        {
          return 1;
        }
    }

  if (root == 6U || root == 7U)
    {
      static const char *devices[] = { "CONIN$", "CONOUT$", "CLOCK$" };
      size_t k;
      for (k = 0; k < sizeof (devices) / sizeof (devices[0]); k++)
        {
          const char *d = devices[k];
          size_t j = 0;
          while (j < root && d[j])
            {
              unsigned char c = p[j];
              if (c >= 'a' && c <= 'z')
                {
                  c = (unsigned char)(c - 32U);
                }

              if (c != (unsigned char)d[j])
                {
                  break;
                }

              j++;
            }
          if (j == root && !d[j])
            {
              return 1;
            }
        }
    }

  if (root == 4U || root == 5U)
    {
      for (i = 0; i < 3U; i++)
        {
          unsigned char c = p[i];
          up[i] = (unsigned char)((c >= 'a' && c <= 'z') ? c - 32U : c);
        }

      if ((up[0] == 'C' && up[1] == 'O' && up[2] == 'M')
          || (up[0] == 'L' && up[1] == 'P' && up[2] == 'T'))
        {
          if (root == 4U && p[3] >= '1' && p[3] <= '9')
            {
              return 1;
            }

          if (root == 5U && p[3] == 0xc2U
              && (p[4] == 0xb9U || p[4] == 0xb2U || p[4] == 0xb3U))
            {
              return 1;
            }
        }
    }

  return 0;
}

/* File creation by normal Win32 APIs normalizes trailing dots/spaces and
 * interprets colon as an NTFS stream suffix. Never allow such an encoding
 * to name a different filesystem object than the archive member. */
static int
xtr_win_u8_path_safe (const char *path)
{
  const unsigned char *p = (const unsigned char *)path, *begin, *end;
  size_t index = 0;

  if (!path || !*path || (path[0] == '\\' && path[1] == '\\')
      || (path[0] == '/' && path[1] == '/'))
    {
      return 0;
    }

  begin = p;
  for (;;)
    {
      unsigned char c = *p;
      if ((c > 0 && c < 32U) || c == 127U)
        {
          return 0;
        }

      if (c == ':'
          && !(index == 1U
               && ((path[0] >= 'a' && path[0] <= 'z')
                   || (path[0] >= 'A' && path[0] <= 'Z'))))
        {
          return 0;
        }

      if (c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*')
        {
          return 0;
        }

      if (c == 0 || c == '/' || c == '\\')
        {
          end = p;
          if (end > begin
              && xtr_win_reserved_name (begin, (size_t)(end - begin)))
            {
              return 0;
            }

          if (end > begin && (end[-1] == ' ' || end[-1] == '.'))
            {
              size_t n = (size_t)(end - begin);
              if (!(n == 1U && begin[0] == '.')
                  && !(n == 2U && begin[0] == '.' && begin[1] == '.'))
                {
                  return 0;
                }
            }

          if (c == 0)
            {
              break;
            }

          begin = p + 1;
        }

      p++;
      index++;
    }

  return 1;
}

/* Raw archive member names use '/' separators. Verify BEFORE mapname()
 * replaces illegal characters with underscores or removes ../ segments.
 * Directory records may end in '/', but empty interior components and
 * parent traversal are rejected instead of silently redirected. */
int
xtr_win_u8_member_safe (const char *name)
{
  const char *p, *part;

  if (!xtr_win_u8_valid (name) || !xtr_win_u8_path_safe (name)
      || name[0] == '/' || name[0] == '\\')
    {
      return 0;
    }

  part = name;
  for (p = name; *p; p++)
    {
      if (*p == '\\' || *p == ':')
        {
          return 0;
        }

      if (*p == '/')
        {
          size_t n = (size_t)(p - part);
          if (n == 0U || (n == 1U && part[0] == '.')
              || (n == 2U && part[0] == '.' && part[1] == '.'))
            {
              return 0;
            }

          part = p + 1;
        }
    }

  if (part == p)
    {
      return 1; /* directory terminator */
    }

  return !(part[0] == '.'
           && (part[1] == 0 || (part[1] == '.' && part[2] == 0)));
}

wchar_t *
xtr_win_u8_wide (const char *path)
{
  int count;
  wchar_t *w;

  if (!xtr_win_u8_valid (path) || !xtr_win_u8_path_safe (path)
      || strlen (path) > 32760U)
    {
      errno = EINVAL;
      return NULL;
    }

  count
      = MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
  if (count <= 0 || count > 32768)
    {
      errno = EINVAL;
      return NULL;
    }

  w = (wchar_t *)malloc ((size_t)count * sizeof (*w));
  if (!w)
    {
      errno = ENOMEM;
      return NULL;
    }

  if (MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, w, count)
      != count)
    {
      free (w);
      errno = EINVAL;
      return NULL;
    }

  return w;
}

char *
xtr_win_acp_u8 (const char *path)
{
  int wc, n, converted, back, used;
  BOOL replaced = FALSE;
  DWORD flags;
  UINT cp = GetACP ();
  wchar_t *w = NULL;
  char *out = NULL, *roundtrip = NULL;

  if (!path || !*path || strlen (path) > 32760U)
    {
      errno = EINVAL;
      return NULL;
    }

  wc = MultiByteToWideChar (cp, cp == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0, path,
                            -1, NULL, 0);
  if (wc <= 0 || wc > 32768)
    {
      errno = EINVAL;
      return NULL;
    }

  w = (wchar_t *)malloc ((size_t)wc * sizeof (*w));
  if (!w)
    {
      errno = ENOMEM;
      return NULL;
    }

  if (MultiByteToWideChar (cp, cp == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0, path,
                           -1, w, wc)
      != wc)
    {
      goto fail;
    }

  flags = cp == CP_UTF8 ? 0U : WC_NO_BEST_FIT_CHARS;
  back = WideCharToMultiByte (cp, flags, w, -1, NULL, 0, NULL, NULL);
  if (back <= 0 || (size_t)back != strlen (path) + 1U)
    {
      goto fail;
    }

  roundtrip = (char *)malloc ((size_t)back);
  if (!roundtrip)
    {
      errno = ENOMEM;
      goto fail;
    }

  used = WideCharToMultiByte (cp, flags, w, -1, roundtrip, back, NULL,
                              cp == CP_UTF8 ? NULL : &replaced);
  if (used != back || replaced || strcmp (roundtrip, path))
    {
      goto fail;
    }

  n = WideCharToMultiByte (CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
  if (n <= 0 || n > 32768)
    {
      goto fail;
    }

  out = (char *)malloc ((size_t)n);
  if (!out)
    {
      errno = ENOMEM;
      goto fail;
    }

  converted = WideCharToMultiByte (CP_UTF8, 0, w, -1, out, n, NULL, NULL);
  if (converted != n || !xtr_win_u8_valid (out))
    {
      goto fail;
    }

  free (roundtrip);
  free (w);
  return out;

fail:
  free (out);
  free (roundtrip);
  free (w);
  if (errno != ENOMEM)
    {
      errno = EINVAL;
    }

  return NULL;
}

int
xtr_win_u8_stat (const char *p, struct _stati64 *st)
{
  wchar_t *w = xtr_win_u8_wide (p);
  int r;

  if (!w)
    {
      return -1;
    }

  r = _wstati64 (w, st);
  free (w);
  return r;
}
int
xtr_win_u8_mkdir (const char *p)
{
  wchar_t *w = xtr_win_u8_wide (p);
  int r;

  if (!w)
    {
      return -1;
    }

  r = _wmkdir (w);
  free (w);
  return r;
}
int
xtr_win_u8_access (const char *p, int mode)
{
  wchar_t *w = xtr_win_u8_wide (p);
  int r;

  if (!w)
    {
      return -1;
    }

  r = _waccess (w, mode);
  free (w);
  return r;
}
int
xtr_win_u8_unlink (const char *p)
{
  wchar_t *w = xtr_win_u8_wide (p);
  int r;

  if (!w)
    {
      return -1;
    }

  r = _wunlink (w);
  free (w);
  return r;
}
int
xtr_win_u8_rename (const char *a, const char *b)
{
  wchar_t *wa = xtr_win_u8_wide (a), *wb = xtr_win_u8_wide (b);
  int r = -1;

  if (wa && wb)
    {
      r = _wrename (wa, wb);
    }

  free (wa);
  free (wb);
  return r;
}
int
xtr_win_u8_chmod (const char *p, int mode)
{
  wchar_t *w = xtr_win_u8_wide (p);
  int r;

  if (!w)
    {
      return -1;
    }

  r = _wchmod (w, mode);
  free (w);
  return r;
}
FILE *
xtr_win_u8_fopen (const char *p, const char *mode)
{
  wchar_t *w = xtr_win_u8_wide (p);
  wchar_t mw[16];
  size_t i;
  FILE *f;

  if (!w || !mode)
    {
      free (w);
      errno = EINVAL;
      return NULL;
    }

  for (i = 0; mode[i] && i < 15U; i++)
    {
      mw[i] = (unsigned char)mode[i];
    }

  if (mode[i])
    {
      free (w);
      errno = EINVAL;
      return NULL;
    }

  mw[i] = 0;
  f = _wfopen (w, mw);
  free (w);
  return f;
}
/* fd-based input used by MinGW (USE_STRM_INPUT is not enabled there).
 * Keep the binary/readonly semantics of open(O_RDONLY | O_BINARY), but
 * convert the already-validated UTF-8 pathname to UTF-16 first. */
int
xtr_win_u8_archive_fd (const char *p)
{
  wchar_t *w = xtr_win_u8_wide (p);
  int fd;

  if (!w)
    {
      return -1;
    }

  fd = _wopen (w, O_RDONLY | _O_BINARY);
  free (w);
  return fd;
}
HANDLE
xtr_win_u8_open (const char *p, DWORD access, DWORD share, DWORD creation,
                 DWORD flags)
{
  HANDLE h;
  wchar_t *w = xtr_win_u8_wide (p);

  if (!w)
    {
      return INVALID_HANDLE_VALUE;
    }

  h = CreateFileW (w, access, share, NULL, creation, flags, NULL);
  free (w);
  return h;
}
DWORD
xtr_win_u8_attributes (const char *p)
{
  DWORD attr;
  wchar_t *w = xtr_win_u8_wide (p);

  if (!w)
    {
      return INVALID_FILE_ATTRIBUTES;
    }

  attr = GetFileAttributesW (w);
  free (w);
  return attr;
}
int
xtr_win_u8_set_attributes (const char *p, DWORD attr)
{
  BOOL r;
  wchar_t *w = xtr_win_u8_wide (p);

  if (!w)
    {
      return 0;
    }

  r = SetFileAttributesW (w, attr);
  free (w);
  return r != 0;
}
