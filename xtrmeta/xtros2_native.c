/* SPDX-License-Identifier: MIT-0 */
/* Native Open Watcom OS/2 EA enumeration, no kLIBC linkage. */
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#define INCL_DOSNLS
#include "xtros2_ea.h"
#include "xtros2_native.h"
#include "xtros2_nls.h"
#include <os2.h>
#include <stdlib.h>
#include <string.h>
#define MAX_OS2_EA_LIST (16UL * 1024UL * 1024UL)
int
xtr_os2_query_native_eas (const char *path, unsigned char **output,
                          size_t *length)
{
  FILESTATUS4 st;
  char normalized[CCHMAXPATH];
  size_t pathlen;
  APIRET rc;
  ULONG bytes, seen = (ULONG)-1;
  unsigned char *names = NULL, *wanted = NULL, *values = NULL;
  PDENA2 item;
  PGEA2 entry, previous = NULL;
  PGEA2LIST requests;
  PFEA2LIST result;
  EAOP2 query;
  size_t used = 4U, i, count = 0U;
  int status = -1;

  if (!output || !length)
    {
      return -1;
    }

  *output = NULL;
  *length = 0;
  if (!path || !*path)
    {
      return -1;
    }

  pathlen = strlen (path);
  if (pathlen >= sizeof (normalized))
    {
      return -1;
    }

  memcpy (normalized, path, pathlen + 1U);
  /* OS/2 native API queries directory names without a trailing slash,
   * except for a drive root such as C:\\, which must retain one. */
  while (
      pathlen > 1U
      && (normalized[pathlen - 1U] == '/' || normalized[pathlen - 1U] == '\\')
      && !(pathlen == 3U && normalized[1U] == ':'))
    {
      normalized[--pathlen] = '\0';
    }
  path = normalized;
  rc = DosQueryPathInfo ((PSZ)path, FIL_QUERYEASIZE, &st, sizeof (st));
  if (rc == ERROR_EAS_NOT_SUPPORTED)
    {
      return 1;
    }

  if (rc != NO_ERROR)
    {
      return -1;
    }

  if (st.cbList < 4U || st.cbList > MAX_OS2_EA_LIST)
    {
      return -1;
    }

  bytes = st.cbList > 65536UL ? st.cbList : 65536UL;
  names = (unsigned char *)malloc ((size_t)bytes);
  wanted = (unsigned char *)malloc ((size_t)bytes);
  values = (unsigned char *)malloc ((size_t)bytes);
  if (!names || !wanted || !values)
    {
      goto done;
    }

  rc = DosEnumAttribute (ENUMEA_REFTYPE_PATH, (PVOID)path, 1, names, bytes,
                         &seen, ENUMEA_LEVEL_NO_VALUE);
  if (rc == ERROR_EAS_NOT_SUPPORTED)
    {
      status = 1;
      goto done;
    }

  if (rc != NO_ERROR)
    {
      goto done;
    }

  if (!seen)
    {
      status = 1;
      goto done;
    }

  item = (PDENA2)names;
  requests = (PGEA2LIST)wanted;
  entry = requests->list;
  memset (wanted, 0, (size_t)bytes);
  for (i = 0; i < (size_t)seen; i++)
    {
      size_t namelen, need, aligned, offset;
      if ((unsigned char *)item < names
          || (unsigned char *)item > names + bytes - 9U)
        {
          goto done;
        }

      namelen = (size_t)item->cbName;
      if (namelen == 0U || namelen > 255U
          || (unsigned char *)item + 8U + namelen >= names + bytes
          || item->szName[namelen] != 0)
        {
          goto done;
        }

      need = 8U + namelen + 1U;
      aligned = (need + 3U) & ~(size_t)3U;
      if (aligned > (size_t)bytes - used)
        {
          goto done;
        }

      offset = (size_t)((unsigned char *)entry - wanted);
      if (offset != used)
        {
          goto done;
        }

      entry->cbName = (BYTE)namelen;
      memcpy (entry->szName, item->szName, namelen + 1U);
      entry->oNextEntryOffset = 0;
      if (previous)
        {
          previous->oNextEntryOffset
              = (ULONG)((unsigned char *)entry - (unsigned char *)previous);
        }

      previous = entry;
      used += aligned;
      entry = (PGEA2)(wanted + used);
      if (i + 1U < (size_t)seen)
        {
          ULONG next = item->oNextEntryOffset;
          if (next < 8U + namelen + 1U
              || next > (ULONG)(names + bytes - (unsigned char *)item))
            {
              goto done;
            }

          item = (PDENA2)((unsigned char *)item + next);
        }

      count++;
    }

  requests->cbList = (ULONG)used;
  result = (PFEA2LIST)values;
  result->cbList = bytes;
  query.fpGEA2List = requests;
  query.fpFEA2List = result;
  query.oError = 0;
  rc = DosQueryPathInfo ((PSZ)path, FIL_QUERYEASFROMLIST, &query,
                         sizeof (query));
  if (rc != NO_ERROR || result->cbList < 4U || result->cbList > bytes)
    {
      goto done;
    }

  {
    size_t parsed = 0U;
    if (xtr_os2_ea_parse_ex (values, (size_t)result->cbList, NULL, 0, &parsed,
                             xtr_os2_ea_native_equal, NULL)
            != XTR_OS2_EA_OK
        || parsed != count)
      {
        goto done;
      }
  }
  *output = values;
  *length = (size_t)result->cbList;
  values = NULL;
  status = 0;
done:
  free (names);
  free (wanted);
  free (values);
  return status;
}
