#!/bin/sh
# SPDX-License-Identifier: MIT-0
set -eu
cd "$(dirname "$0")"
CC=${CC:-gcc}
CFLAGS='-std=c89 -pedantic -Wall -Wextra -Werror -O2'
for t in test_xtrm test_large test_v1 test_platform test_policy test_long_limit fuzz_v1 emit_fixture verify_fixture; do
    src="$t.c"
    "$CC" $CFLAGS -o "$t" xtrm.c xtrsha.c xtrv1.c "$src"
done
./test_xtrm
./test_large
./test_v1
./test_platform
./test_policy
./test_long_limit
./fuzz_v1 120000
python3 test_zip_interop.py
if command -v clang >/dev/null 2>&1; then
    for t in test_v1 test_platform test_policy test_long_limit fuzz_v1; do
       clang -std=c89 -pedantic -Wall -Wextra -Werror -g -O1 \
          -fsanitize=address,undefined -fno-omit-frame-pointer \
          -o "$t.san" xtrm.c xtrsha.c xtrv1.c "$t.c"
    done
    ./test_v1.san
    ./test_platform.san
    ./test_policy.san
    ./test_long_limit.san
    ./fuzz_v1.san 120000
    if clang -std=c89 -pedantic -Wall -Wextra -Werror -g -O1 \
       -fsanitize=fuzzer,address,undefined -o fuzzer_m1 \
       xtrm.c xtrsha.c xtrv1.c fuzzer_m1.c >/dev/null 2>&1; then
       tmp=$(mktemp -d)
       python3 fuzzer_seeds.py "$tmp"
       ASAN_OPTIONS=detect_leaks=1 ./fuzzer_m1 -runs=25000 -max_len=8192 \
           "$tmp" 2>&1 | tail -3
       rm -rf "$tmp"
    fi
fi
printf '\nALL AVAILABLE M1 TESTS PASSED (NOT M2/OS certification)\n'
