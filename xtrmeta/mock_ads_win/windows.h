#ifndef MOCK_ADS_WINDOWS_H
# define MOCK_ADS_WINDOWS_H
# include <wchar.h>
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef long LONG;
typedef struct
{
  long QuadPart;
  DWORD LowPart;
  LONG HighPart;
} LARGE_INTEGER;
typedef struct
{
  DWORD dwFileAttributes, dwVolumeSerialNumber, nFileIndexHigh, nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION;
typedef struct
{
  LARGE_INTEGER StreamSize;
  wchar_t cStreamName[296];
} WIN32_FIND_STREAM_DATA;
# define MAX_PATH 260
# define INVALID_HANDLE_VALUE ((HANDLE)(-1))
# define FILE_ATTRIBUTE_REPARSE_POINT 0x400U
# define FILE_READ_ATTRIBUTES 0x80U
# define GENERIC_READ 0x80000000U
# define GENERIC_WRITE 0x40000000U
# define CREATE_ALWAYS 2U
# define FILE_ATTRIBUTE_NORMAL 0x80U
# define FILE_SHARE_READ 1U
# define FILE_SHARE_WRITE 2U
# define FILE_SHARE_DELETE 4U
# define OPEN_EXISTING 3U
# define FILE_FLAG_OPEN_REPARSE_POINT 0x200000U
# define FILE_FLAG_BACKUP_SEMANTICS 0x2000000U
# define FILE_NAME_OPENED 8U
# define VOLUME_NAME_DOS 0U
# define FindStreamInfoStandard 0
# define ERROR_INVALID_PARAMETER 87U
# define ERROR_NOT_SUPPORTED 50U
# define ERROR_CALL_NOT_IMPLEMENTED 120U
# define ERROR_HANDLE_EOF 38U
# define ERROR_NO_MORE_FILES 18U
# define ERROR_FILE_NOT_FOUND 2U
# define ERROR_PATH_NOT_FOUND 3U
int GetFileInformationByHandle (HANDLE, BY_HANDLE_FILE_INFORMATION *);
DWORD GetFinalPathNameByHandleW (HANDLE, wchar_t *, DWORD, DWORD);
HANDLE CreateFileW (const wchar_t *, DWORD, DWORD, void *, DWORD, DWORD,
                    HANDLE);
HANDLE FindFirstStreamW (const wchar_t *, int, void *, DWORD);
int FindNextStreamW (HANDLE, void *);
int FindClose (HANDLE);
int CloseHandle (HANDLE);
DWORD GetLastError (void);
DWORD GetCurrentDirectoryW (DWORD, wchar_t *);
DWORD GetTempFileNameW (const wchar_t *, const wchar_t *, DWORD, wchar_t *);
int WriteFile (HANDLE, const void *, DWORD, DWORD *, void *);
int ReadFile (HANDLE, void *, DWORD, DWORD *, void *);
int GetFileSizeEx (HANDLE, LARGE_INTEGER *);
int DeleteFileW (const wchar_t *);
/* W3C2A disposable ADS creation mock extensions. */
# ifndef CREATE_NEW
#  define CREATE_NEW 1U
# endif /* ifndef CREATE_NEW */
# define FILE_ATTRIBUTE_DIRECTORY 0x10U
# define FILE_BEGIN 0U
int FlushFileBuffers (HANDLE);
int SetFilePointerEx (HANDLE, LARGE_INTEGER, LARGE_INTEGER *, DWORD);
/* Strongly-typed Unicode name comparison used by W3C2 ADS restore. */
typedef const unsigned short *LPCWCH;
# define CSTR_EQUAL 2
# define TRUE 1
int CompareStringOrdinal (LPCWCH, int, LPCWCH, int, int);

#endif /* MOCK_ADS_WINDOWS_H */
