#include "windows.h"
#include <stdlib.h>
#include <string.h>

static BOOL WINAPI
fake_memory_status (LPMEMORYSTATUSEX info)
{
  if (getenv ("XLD_TEST_FAIL") != NULL)
    return 0;
  info->ullAvailPhys = 1024ULL * 1024ULL * 1024ULL;
  info->ullAvailVirtual = 512ULL * 1024ULL * 1024ULL;
  info->ullAvailPageFile = 800ULL * 1024ULL * 1024ULL;
  return 1;
}

HMODULE
GetModuleHandleA (const char *name)
{
  return strcmp (name, "kernel32.dll") == 0 ? (HMODULE)1 : (HMODULE)0;
}

FARPROC
GetProcAddress (HMODULE module, const char *name)
{
  if (!module || strcmp (name, "GlobalMemoryStatusEx") != 0)
    return (FARPROC)0;
  return (FARPROC)fake_memory_status;
}
