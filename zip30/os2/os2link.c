/* SPDX-License-Identifier: MIT-0 */
/* Independently written native OS/2 EA reader for kLIBC symlinks.
 * No kLIBC headers, libraries or runtime are used. */
#define INCL_NOPM
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include "os2link.h"
#include <ctype.h>
#include <errno.h>
#include <os2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IZ_LINK_PATH_CAP 1024U
#define IZ_LINK_MAX_HOPS 32
#define IZ_LINK_EA_BUFFER 4096U

static int
iz_eq_name (const char *a, const char *b, size_t count)
{
  size_t i;

  for (i = 0; i < count; i++)
    {
      if (toupper ((unsigned char)a[i]) != toupper ((unsigned char)b[i]))
        {
          return 0;
        }
    }

  return 1;
}

int
iz_os2_link_target (const char *path, char *target, size_t capacity)
{
  struct
  {
    ULONG cbList, oNextEntryOffset;
    BYTE cbName;
    CHAR szName[8];
  } gea;
  BYTE fea[IZ_LINK_EA_BUFFER];
  EAOP2 op;
  PFEA2LIST list = (PFEA2LIST)fea;
  PFEA2 item;
  size_t at, n, cb;
  APIRET rc;
  if (!path || !target || capacity == 0)
    {
      return -1;
    }

  memset (&gea, 0, sizeof (gea));
  gea.cbList = sizeof (gea);
  gea.cbName = 7;
  memcpy (gea.szName, "SYMLINK", 8);
  memset (fea, 0, sizeof (fea));
  list->cbList = sizeof (fea);
  op.fpGEA2List = (PGEA2LIST)&gea;
  op.fpFEA2List = list;
  op.oError = 0;
  rc = DosQueryPathInfo ((PSZ)path, FIL_QUERYEASFROMLIST, (PVOID)&op,
                         sizeof (op));
  if (rc != NO_ERROR)
    {
      return -1;
    }

  if (list->cbList < sizeof (ULONG) + offsetof (FEA2, szName))
    {
      return -1;
    }

  item = &list->list[0];
  if (item->cbValue == 0)
    {
      return 0;
    }

  if (item->cbName != 7
      || !iz_eq_name ((const char *)item->szName, "SYMLINK", 7))
    {
      return -1;
    }

  at = sizeof (ULONG) + offsetof (FEA2, szName) + (size_t)item->cbName + 1U;
  cb = (size_t)item->cbValue;
  if (at > list->cbList || cb > list->cbList - at || cb < 5U)
    {
      return -1;
    }

  if (fea[at] != 0xfdU || fea[at + 1] != 0xffU)
    {
      return -1;
    }

  n = (size_t)fea[at + 2] + ((size_t)fea[at + 3] << 8);
  if (n == 0 || n != cb - 4U || n >= capacity || n >= IZ_LINK_PATH_CAP)
    {
      return -1;
    }

  if (fea[at + 4] == 0 || memchr (fea + at + 4, 0, n) != NULL)
    {
      return -1;
    }

  memcpy (target, fea + at + 4, n);
  target[n] = 0;
  return 1;
}

/* Construct native path from either relative target, OS/2 drive path,
 * root-relative target, or kLIBC's UNIXROOT absolute-path convention. */
static int
iz_join (const char *prefix, const char *target, const char *suffix, char *out,
         size_t capacity)
{
  const char *head = prefix, *tail = target;
  const char *root;
  size_t a, b, c;
  char driveprefix[IZ_LINK_PATH_CAP];

  if ((target[0] == '/' || target[0] == '\\') && target[1] != '\\')
    {
      root = getenv ("UNIXROOT");
      /* kLIBC absolute Unix paths resolve under UNIXROOT. Reject unknown
       * UNIXROOT instead of interpreting /etc as an OS/2 drive path. */
      if (!root || !isalpha ((unsigned char)root[0]) || root[1] != ':'
          || (root[2] != '/' && root[2] != '\\' && root[2] != 0))
        {
          return -1;
        }

      if (strlen (root) >= sizeof (driveprefix))
        {
          return -1;
        }

      strcpy (driveprefix, root);
      head = driveprefix;
      if ((tail[0] == '/' || tail[0] == '\\') && tail[1] == '@')
        {
          if (strlen (tail + 1) >= 9U && iz_eq_name (tail + 1, "@unixroot", 9)
              && (tail[10] == '/' || tail[10] == '\\' || !tail[10]))
            {
              tail += 10;
            }
        }
    }
  else if (isalpha ((unsigned char)target[0]) && target[1] == ':')
    {
      head = "";
    }

  a = strlen (head);
  b = strlen (tail);
  c = strlen (suffix);
  if (a + b + c + 3U > capacity)
    {
      return -1;
    }

  memcpy (out, head, a);
  if (a && b && out[a - 1] != '/' && out[a - 1] != '\\' && tail[0] != '/'
      && tail[0] != '\\')
    {
      out[a++] = '\\';
    }

  memcpy (out + a, tail, b);
  a += b;
  if (c && a && out[a - 1] != '/' && out[a - 1] != '\\' && suffix[0] != '/'
      && suffix[0] != '\\')
    {
      out[a++] = '\\';
    }

  memcpy (out + a, suffix, c);
  out[a + c] = 0;
  return 0;
}

int
iz_os2_link_resolve (const char *path, char *resolved, size_t capacity,
                     int follow_final)
{
  char pending[IZ_LINK_PATH_CAP];
  char part[IZ_LINK_PATH_CAP];
  char target[IZ_LINK_PATH_CAP];
  char merged[IZ_LINK_PATH_CAP];
  size_t start, end, plen, n;
  int depth, found, rc;

  if (!path || !*path || !resolved || capacity == 0
      || strlen (path) >= sizeof (pending))
    {
      return -1;
    }

  strcpy (pending, path);
  for (depth = 0; depth < IZ_LINK_MAX_HOPS; depth++)
    {
      found = 0;
      n = strlen (pending);
      start = 0;
      /* Component scan: allow X: roots, rooted and relative paths. */
      while (start < n)
        {
          while (start < n
                 && (pending[start] == '/' || pending[start] == '\\'))
            {
              start++;
            }
          if (start == n)
            {
              break;
            }

          end = start;
          while (end < n && pending[end] != '/' && pending[end] != '\\')
            {
              end++;
            }
          if (end >= sizeof (part))
            {
              return -1;
            }

          memcpy (part, pending, end);
          part[end] = 0;
          if (end == 2 && part[1] == ':')
            {
              start = end;
              continue;
            }

          if ((follow_final || end < n) && strcmp (part, ".") != 0
              && strcmp (part, "..") != 0)
            {
              rc = iz_os2_link_target (part, target, sizeof (target));
              if (rc < 0)
                {
                  return -1;
                }

              if (rc == 1)
                {
                  plen = start;
                  if (plen >= sizeof (merged))
                    {
                      return -1;
                    }

                  memcpy (merged, pending, plen);
                  merged[plen] = 0;
                  if (iz_join (merged, target, pending + end, part,
                               sizeof (part)))
                    {
                      return -1;
                    }

                  strcpy (pending, part);
                  found = 1;
                  break;
                }
            }

          start = end;
        }
      if (!found)
        {
          if (strlen (pending) >= capacity)
            {
              return -1;
            }

          strcpy (resolved, pending);
          return 0;
        }
    }

  errno = EINVAL;
  return -1;
}

int
iz_os2_link_lstat (const char *path, struct stat *result)
{
  char resolved[IZ_LINK_PATH_CAP], target[IZ_LINK_PATH_CAP];
  int rc;

  if (iz_os2_link_resolve (path, resolved, sizeof (resolved), 0))
    {
      return -1;
    }

  if (stat (resolved, result))
    {
      return -1;
    }

  rc = iz_os2_link_target (resolved, target, sizeof (target));
  if (rc < 0)
    {
      return -1;
    }

  if (rc == 1)
    {
      result->st_mode = (result->st_mode & ~S_IFMT) | 0xa000;
    }

  return 0;
}
int
iz_os2_link_stat (const char *path, struct stat *result)
{
  char resolved[IZ_LINK_PATH_CAP];

  if (iz_os2_link_resolve (path, resolved, sizeof (resolved), 1))
    {
      return -1;
    }

  return stat (resolved, result);
}
int
iz_os2_link_body (const char *path, char *buffer, size_t capacity)
{
  FILE *f;
  size_t n;
  int c;

  if (!buffer || capacity == 0)
    {
      return -1;
    }

  f = fopen (path, "rb");
  if (!f)
    {
      return -1;
    }

  n = fread (buffer, 1, capacity, f);
  c = fgetc (f);
  if (ferror (f) || c != EOF)
    {
      fclose (f);
      return -1;
    }

  if (fclose (f) != 0)
    {
      return -1;
    }

  return (int)n;
}
