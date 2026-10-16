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
typedef long LONGLONG; /* mock only, not a Windows ABI header */
typedef struct
{
  LONGLONG QuadPart;
} LARGE_INTEGER;
# define FILE_BEGIN 0U
HANDLE ReOpenFile (HANDLE, DWORD, DWORD, DWORD);
int GetFileSizeEx (HANDLE, LARGE_INTEGER *);
int SetFilePointerEx (HANDLE, LARGE_INTEGER, LARGE_INTEGER *, DWORD);
int SetEndOfFile (HANDLE);
int ReadFile (HANDLE, void *, DWORD, DWORD *, void *);
# define MAX_PATH 260
# define INVALID_HANDLE_VALUE ((HANDLE)(-1))
# define FILE_READ_DATA 0x0001U
# define FILE_WRITE_DATA 0x0002U
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
# define FILE_ATTRIBUTE_DIRECTORY 0x10U
# define FILE_PERSISTENT_ACLS 0x8U
# define CP_ACP 0U
# define CP_UTF8 65001U
UINT GetACP (void);
# define MB_ERR_INVALID_CHARS 0x8U
int MultiByteToWideChar (unsigned int, DWORD, const char *, int, wchar_t *,
                         int);
HANDLE CreateFileW (const wchar_t *, DWORD, DWORD, void *, DWORD, DWORD,
                    HANDLE);
int GetVolumePathNameA (const char *, char *, DWORD);
int GetVolumeInformationA (const char *, char *, DWORD, DWORD *, DWORD *,
                           DWORD *, char *, DWORD);
# define FILE_READ_ATTRIBUTES 0x80U
# define FILE_ATTRIBUTE_NORMAL 0x80U
# define CREATE_NEW 1U
# define FILE_FLAG_BACKUP_SEMANTICS 0x02000000U
# define PROV_RSA_FULL 1U
# define CRYPT_VERIFYCONTEXT 0xF0000000U
# define DWORD unsigned int
# define HCRYPTPROV unsigned long
# define BYTE unsigned char
int CryptAcquireContextA (HCRYPTPROV *, const char *, const char *, DWORD,
                          DWORD);
int CryptGenRandom (HCRYPTPROV, unsigned long, BYTE *);
int CryptReleaseContext (HCRYPTPROV, DWORD);
int CreateDirectoryA (const char *, void *);
int RemoveDirectoryA (const char *);
DWORD GetTempPathA (DWORD, char *);
# define TOKEN_QUERY 1U
# define TokenUser 1U
# define ACL_REVISION 2U
# define GENERIC_ALL 0x10000000U
# define SECURITY_DESCRIPTOR_REVISION 1U
# define TRUE 1
# define FALSE 0
# define SID void
typedef struct
{
  SID *Sid;
  DWORD Attributes;
} SID_AND_ATTRIBUTES;
typedef struct
{
  SID_AND_ATTRIBUTES User;
} TOKEN_USER;
typedef struct
{
  DWORD Revision;
  DWORD Size;
} ACL;
typedef struct
{
  DWORD Mask;
} ACCESS_ALLOWED_ACE;
typedef struct
{
  DWORD Revision;
  DWORD Control;
} SECURITY_DESCRIPTOR;
typedef struct
{
  DWORD nLength;
  void *lpSecurityDescriptor;
  int bInheritHandle;
} SECURITY_ATTRIBUTES;
HANDLE GetCurrentProcess (void);
int OpenProcessToken (HANDLE, DWORD, HANDLE *);
int GetTokenInformation (HANDLE, DWORD, void *, DWORD, DWORD *);
DWORD GetLengthSid (void *);
int InitializeAcl (ACL *, DWORD, DWORD);
int AddAccessAllowedAce (ACL *, DWORD, DWORD, void *);
int InitializeSecurityDescriptor (SECURITY_DESCRIPTOR *, DWORD);
int SetSecurityDescriptorDacl (SECURITY_DESCRIPTOR *, int, ACL *, int);

typedef long INT_PTR;
# ifndef DUPLICATE_SAME_ACCESS
#  define DUPLICATE_SAME_ACCESS 2U
# endif /* ifndef DUPLICATE_SAME_ACCESS */
# define WC_NO_BEST_FIT_CHARS 0x00000400U
int WideCharToMultiByte (unsigned int, DWORD, const wchar_t *, int, char *,
                         int, const char *, int *);
DWORD GetFullPathNameW (const wchar_t *, DWORD, wchar_t *, wchar_t **);
DWORD GetFullPathNameA (const char *, DWORD, char *, char **);
int DuplicateHandle (HANDLE, HANDLE, HANDLE, HANDLE *, DWORD, int, DWORD);

#endif /* MOCK_WINDOWS_H */
