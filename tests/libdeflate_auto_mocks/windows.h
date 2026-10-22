/* Compile-only Win32 API mock for the portable auto-limit regression probe. */
#ifndef XTR_TEST_WINDOWS_H
#define XTR_TEST_WINDOWS_H
typedef unsigned long DWORD;
typedef unsigned long long DWORDLONG;
typedef int BOOL;
typedef void *HMODULE;
#define WINAPI
typedef int (WINAPI *FARPROC)();
typedef struct _MEMORYSTATUSEX {
  DWORD dwLength;
  DWORD dwMemoryLoad;
  DWORDLONG ullTotalPhys;
  DWORDLONG ullAvailPhys;
  DWORDLONG ullTotalPageFile;
  DWORDLONG ullAvailPageFile;
  DWORDLONG ullTotalVirtual;
  DWORDLONG ullAvailVirtual;
  DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
HMODULE GetModuleHandleA (const char *);
FARPROC GetProcAddress (HMODULE, const char *);
#endif
