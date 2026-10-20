/* Test-only minimal OS/2 EA ABI shim. NOT for production or installation. */
#ifndef OS2_TEST_STUB_H
#define OS2_TEST_STUB_H
#include <stddef.h>
#include <limits.h>
#if UINT_MAX != 0xffffffffU
#error Test ABI shim requires 32-bit unsigned int
#endif
typedef unsigned int ULONG;
typedef unsigned char BYTE;
typedef char CHAR;
typedef unsigned short USHORT;
typedef void *PVOID;
typedef char *PSZ;
typedef ULONG APIRET;
/* Packed layout is required here to match the native FEA2 structure. */
#pragma pack(push,1)
typedef struct _FEA2 {
  ULONG oNextEntryOffset;
  BYTE fEA;
  BYTE cbName;
  USHORT cbValue;
  CHAR szName[1];
} FEA2, *PFEA2;
typedef struct _FEA2LIST {ULONG cbList;FEA2 list[1];} FEA2LIST, *PFEA2LIST;
typedef struct _GEA2LIST {ULONG cbList;} GEA2LIST, *PGEA2LIST;
#pragma pack(pop)
typedef struct _EAOP2 {PGEA2LIST fpGEA2List;PFEA2LIST fpFEA2List;ULONG oError;} EAOP2;
#define FIL_QUERYEASFROMLIST 3U
#define NO_ERROR 0UL
APIRET DosQueryPathInfo(PSZ path,ULONG level,PVOID data,ULONG length);
#endif
