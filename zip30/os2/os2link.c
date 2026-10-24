/* SPDX-License-Identifier: MIT-0 */
/* Independently written native OS/2 EA reader for kLIBC symlinks.
 * No kLIBC headers, libraries or runtime are used. */
#define INCL_NOPM
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include "os2link.h"
#include <ctype.h>
#include <errno.h>
#include <io.h>
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

static int
iz_os2_link_target_query (const char *path, HFILE handle, int use_handle,
                          char *target, size_t capacity)
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
  size_t at, n, cb, i;
  char native_path[IZ_LINK_PATH_CAP];
  APIRET rc;
  if ((!path && !use_handle) || !target || capacity == 0)
    {
      return -1;
    }

  /* Archive names use '/' but the native OS/2 EA API requires a native
   * pathname. Check the same object that the later native EA calls use. */
  if (!use_handle)
    {
      n = strlen (path);
      if (!n || n >= sizeof (native_path))
        {
          return -1;
        }

      for (i = 0; i < n; i++)
        {
          native_path[i] = path[i] == '/' ? '\\' : path[i];
        }
      native_path[n] = '\0';
      /* The archive spells directory members with a final '/'.  OS/2
       * DosQueryPathInfo(FIL_QUERYEASFROMLIST) rejects an ordinary directory
       * pathname ending in '\\' (ERROR_PATH_NOT_FOUND).  Remove only
       * redundant final separators, never the root of a drive or volume. */
      while (n > 1U && native_path[n - 1U] == '\\'
             && !(n == 3U && native_path[1] == ':')
             && !(n == 2U && native_path[0] == '\\'))
        {
          native_path[--n] = '\0';
        }
    }
  else
    {
      strcpy (native_path, "<pinned output handle>");
    }

  memset (&gea, 0, sizeof (gea));
  /* sizeof(gea) includes trailing C structure padding. The OS/2 list
   * length is the actual bytes through the requested name's terminator. */
  gea.cbList = (ULONG)IZ_OS2_GEA2LIST_SIZE (7U);
  gea.cbName = 7;
  memcpy (gea.szName, "SYMLINK", 8);
  memset (fea, 0, sizeof (fea));
  list->cbList = sizeof (fea);
  op.fpGEA2List = (PGEA2LIST)&gea;
  op.fpFEA2List = list;
  op.oError = 0;
  rc = use_handle
           ? DosQueryFileInfo (handle, FIL_QUERYEASFROMLIST, (PVOID)&op,
                               sizeof (op))
           : DosQueryPathInfo ((PSZ)native_path, FIL_QUERYEASFROMLIST,
                               (PVOID)&op, sizeof (op));
  if (rc != NO_ERROR)
    {
      /* oError is an EA-list offset only for EA validation errors.  An
       * arbitrary value returned for an I/O/sharing failure is meaningless. */
      fprintf (stderr, "Xtro-ZIP: OS/2 SYMLINK EA %s query rc=%lu",
               use_handle ? "file-handle" : "path", (unsigned long)rc);
      if (rc == ERROR_INVALID_EA_NAME || rc == ERROR_EA_LIST_INCONSISTENT)
        fprintf (stderr, ", oError=%lu", (unsigned long)op.oError);
      fprintf (stderr, ": %s\n", native_path);
      return -1;
    }

  /* Some filesystems report no matching records as an empty FEA2LIST.
   * Absence is safe, but a failed API call above must remain an error. */
  if (list->cbList == sizeof (ULONG))
    {
      return 0;
    }

  if (list->cbList > sizeof (fea)
      || list->cbList < sizeof (ULONG) + offsetof (FEA2, szName))
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 invalid SYMLINK EA list "
               "(length=%lu): %s\n", (unsigned long)list->cbList,
               native_path);
      return -1;
    }

  item = &list->list[0];
  /* Validate the record's identity and bounds even for a missing EA.
   * A zero cbValue in an unrelated or truncated record is not evidence
   * that the path has no SYMLINK EA. */
  if (item->oNextEntryOffset != 0 || item->cbName != 7)
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 unexpected SYMLINK EA record: %s\n",
               native_path);
      return -1;
    }

  at = sizeof (ULONG) + offsetof (FEA2, szName) + 8U;
  if (at > list->cbList || item->szName[7] != 0
      || !iz_eq_name ((const char *)item->szName, "SYMLINK", 7))
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 invalid SYMLINK EA name: %s\n",
               native_path);
      return -1;
    }

  cb = (size_t)item->cbValue;
  if (cb > list->cbList - at)
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 malformed SYMLINK EA length: %s\n",
               native_path);
      return -1;
    }

  if (cb == 0)
    {
      return 0;
    }

  if (cb < 5U)
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 malformed SYMLINK EA length: %s\n",
               native_path);
      return -1;
    }

  if (fea[at] != 0xfdU || fea[at + 1] != 0xffU)
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 invalid SYMLINK EA type: %s\n",
               native_path);
      return -1;
    }

  n = (size_t)fea[at + 2] + ((size_t)fea[at + 3] << 8);
  if (n == 0 || n != cb - 4U || n >= capacity || n >= IZ_LINK_PATH_CAP)
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 invalid SYMLINK target length: %s\n",
               native_path);
      return -1;
    }

  if (fea[at + 4] == 0 || memchr (fea + at + 4, 0, n) != NULL)
    {
      fprintf (stderr, "Xtro-ZIP: OS/2 invalid SYMLINK target bytes: %s\n",
               native_path);
      return -1;
    }

  memcpy (target, fea + at + 4, n);
  target[n] = 0;
  return 1;
}

int
iz_os2_link_target (const char *path, char *target, size_t capacity)
{
  return iz_os2_link_target_query (path, (HFILE)0, 0, target, capacity);
}

int
iz_os2_link_target_fd (int fd, char *target, size_t capacity)
{
  int handle;
  if (fd < 0)
    return -1;
  handle = _os_handle (fd);
  if (handle < 0)
    return -1;
  return iz_os2_link_target_query (NULL, (HFILE)handle, 1, target, capacity);
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
