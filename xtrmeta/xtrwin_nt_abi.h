/* SPDX-License-Identifier: MIT-0 */
/* Private native NTAPI declarations; include <windows.h> before this file.
 * Shared with ABI mocks to preserve exact function pointer prototypes. */
#ifndef XTRWIN_NT_ABI_H
# define XTRWIN_NT_ABI_H
typedef struct xwn_iosb
{
  union
  {
    LONG status;
    PVOID pointer;
  } u;
  ULONG_PTR information;
} xwn_iosb;
typedef LONG (NTAPI *xwn_query_fn) (HANDLE, xwn_iosb *, PVOID, ULONG, BOOLEAN,
                                    PVOID, ULONG, PULONG, BOOLEAN);
typedef LONG (NTAPI *xwn_set_fn) (HANDLE, xwn_iosb *, PVOID, ULONG);
#endif /* ifndef XTRWIN_NT_ABI_H */
