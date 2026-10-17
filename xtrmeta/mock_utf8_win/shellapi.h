#ifndef XTR_UTF8_SHELLAPI_H
# define XTR_UTF8_SHELLAPI_H
# ifndef XTR_TEST_WINDOWS_H
#  error "include windows.h before shellapi.h"
# endif
LPWSTR *CommandLineToArgvW (const wchar_t *, int *);
#endif /* ifndef XTR_UTF8_SHELLAPI_H */
