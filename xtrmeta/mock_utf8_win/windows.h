#ifndef XTR_TEST_WINDOWS_H
# define XTR_TEST_WINDOWS_H
# include <wchar.h>
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void *HANDLE;
# define TRUE 1
# define FALSE 0
# define CP_UTF8 65001U
# define MB_ERR_INVALID_CHARS 8U
# define WC_NO_BEST_FIT_CHARS 0x400U
# define WC_ERR_INVALID_CHARS 0x80U
typedef wchar_t *LPWSTR;
typedef void *HLOCAL;
LPWSTR GetCommandLineW (void);
HLOCAL LocalFree (HLOCAL);
# define INVALID_HANDLE_VALUE ((HANDLE)(-1))
# define INVALID_FILE_ATTRIBUTES 0xffffffffU
UINT GetACP (void);
int MultiByteToWideChar (UINT, DWORD, const char *, int, wchar_t *, int);
int WideCharToMultiByte (UINT, DWORD, const wchar_t *, int, char *, int,
                         const char *, BOOL *);
HANDLE CreateFileW (const wchar_t *, DWORD, DWORD, void *, DWORD, DWORD,
                    HANDLE);
DWORD GetFileAttributesW (const wchar_t *);
BOOL SetFileAttributesW (const wchar_t *, DWORD);
#endif /* ifndef XTR_TEST_WINDOWS_H */
