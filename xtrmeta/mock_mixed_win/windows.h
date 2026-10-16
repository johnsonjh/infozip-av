#ifndef XTR_MIXED_MOCK_WINDOWS_H
# define XTR_MIXED_MOCK_WINDOWS_H
# include "../mock_ads_win/windows.h"
# define TRUE 1
# define CSTR_LESS_THAN 1
# define CSTR_EQUAL 2
# define CSTR_GREATER_THAN 3
int CompareStringOrdinal (LPCWCH, int, LPCWCH, int, int);
#endif /* ifndef XTR_MIXED_MOCK_WINDOWS_H */
