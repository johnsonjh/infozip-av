/* Minimal compile-only Windows ABI surface; NOT a real MinGW header. */
#ifndef MOCK_WINDOWS_H
# define MOCK_WINDOWS_H
# include <stddef.h>
typedef void *PVOID;
typedef void *HANDLE;
typedef void *HMODULE;
typedef unsigned long ULONG_PTR;
typedef unsigned int ULONG;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int LONG;
typedef ULONG *PULONG;
typedef unsigned char BOOLEAN;
typedef long (*FARPROC) (void);
# define NTAPI
# define MAX_PATH 260
# define INVALID_HANDLE_VALUE ((HANDLE)(-1))
# define FILE_READ_EA 8U
# define FILE_WRITE_EA 16U
# define GENERIC_READ 32U
# define GENERIC_WRITE 64U
# define FILE_SHARE_READ 1U
# define FILE_SHARE_WRITE 2U
# define FILE_SHARE_DELETE 4U
# define OPEN_EXISTING 3U
# define FILE_FLAG_OPEN_REPARSE_POINT 1U
HMODULE GetModuleHandleA (const char *name);
FARPROC GetProcAddress (HMODULE mod, const char *name);
UINT GetTempFileNameA (const char *, const char *, UINT, char *);
HANDLE CreateFileA (const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
DWORD GetLastError (void);
int CloseHandle (HANDLE);
int DeleteFileA (const char *);
# define FILE_TYPE_DISK 1U
# define FILE_ATTRIBUTE_REPARSE_POINT 0x400U
typedef struct _BY_HANDLE_FILE_INFORMATION
{
  DWORD dwFileAttributes;
  DWORD ftCreationTime[2];
  DWORD ftLastAccessTime[2];
  DWORD ftLastWriteTime[2];
  DWORD dwVolumeSerialNumber;
  DWORD nFileSizeHigh, nFileSizeLow;
  DWORD nNumberOfLinks;
  DWORD nFileIndexHigh, nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION;
DWORD GetFileType (HANDLE h);
int GetFileInformationByHandle (HANDLE h, BY_HANDLE_FILE_INFORMATION *out);
#endif /* ifndef MOCK_WINDOWS_H */
