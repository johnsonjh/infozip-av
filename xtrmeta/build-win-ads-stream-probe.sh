#!/bin/sh
# SPDX-License-Identifier: MIT-0
set -eu
: "${MINGW_CC:=x86_64-w64-mingw32-gcc}"
"$MINGW_CC" -D_WIN32_WINNT=0x0600 -std=c89 -pedantic -Wall -Wextra -Werror -O2 \
  -o test_win_ads_stream_native.exe \
  xtrwin_ads.c xtrwin_ads_stream.c test_win_ads_stream_native.c
