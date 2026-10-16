#!/bin/sh
# SPDX-License-Identifier: MIT-0
# Real Windows NTFS tests only; Wine is permitted to return exit 77.
set -eu
CC=${MINGW_CC:-x86_64-w64-mingw32-gcc}
"$CC" -std=c89 -pedantic -Wall -Wextra -Werror -O2 \
    -D_WIN32_WINNT=0x0501 -DWINVER=0x0501 \
    -o test_win_nt_native.exe \
    xtrm.c xtrsha.c xtrv1.c xtrwin_ea.c xtrwin_txn.c xtrwin_nt.c \
    test_win_nt_native.c
printf '%s\n' 'Created xtrmeta/test_win_nt_native.exe'
printf '%s\n' 'Run on Windows: test_win_nt_native.exe C:\\writable-directory'
