/* SPDX-License-Identifier: MIT-0 */
/* Test-only mock types; never used when building with Open Watcom. */
#ifndef XTR_TEST_OS2_NATIVE_H
# define XTR_TEST_OS2_NATIVE_H
# include <stddef.h>
typedef unsigned int ULONG;
typedef unsigned int APIRET;
typedef unsigned char BYTE;
typedef char CHAR;
typedef void *PVOID;
typedef char *PSZ;
# pragma pack(push, 1)
typedef struct
{
  ULONG oNextEntryOffset;
  BYTE fEA, cbName;
  unsigned short cbValue;
  CHAR szName[1];
} FEA2, *PFEA2, *DENA2, *PDENA2;
typedef struct
{
  ULONG cbList;
  FEA2 list[1];
} FEA2LIST, *PFEA2LIST;
typedef struct
{
  ULONG oNextEntryOffset;
  BYTE cbName;
  CHAR szName[1];
} GEA2, *PGEA2;
typedef struct
{
  ULONG cbList;
  GEA2 list[1];
} GEA2LIST, *PGEA2LIST;
# pragma pack(pop)
typedef struct
{
  PGEA2LIST fpGEA2List;
  PFEA2LIST fpFEA2List;
  ULONG oError;
} EAOP2;
typedef struct
{
  unsigned char blank[32];
  ULONG cbList;
} FILESTATUS4;
# define NO_ERROR 0U
# define ERROR_EAS_NOT_SUPPORTED 282U
# define FIL_QUERYEASIZE 2U
# define FIL_QUERYEASFROMLIST 3U
# define ENUMEA_REFTYPE_PATH 1U
# define ENUMEA_LEVEL_NO_VALUE 1U
# define CCHMAXPATH 260
APIRET DosQueryPathInfo (PSZ, ULONG, PVOID, ULONG);
APIRET DosEnumAttribute (ULONG, PVOID, ULONG, PVOID, ULONG, ULONG *, ULONG);
#endif /* ifndef XTR_TEST_OS2_NATIVE_H */
