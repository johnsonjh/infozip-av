#!/bin/sh
# Host-only POSIX regression for DOS16 external entropy provisioning.
# C89 test; does not replace real DOS/emu2 cryptographic interoperability.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cc=${CC:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 3 15
"$cc" -std=c89 -pedantic -Wall -Wextra -Werror \
    -o "$tmp/test-pool" "$root/tests/dos16/test_aes_pool.c"
(cd "$tmp" && ./test-pool missing)
# Test fresh externally supplied bytes and each 16-byte slot being consumed.
dd if=/dev/urandom of="$tmp/XTRRND.BIN" bs=16 count=3 2>/dev/null
(cd "$tmp" && ./test-pool present)
test ! -e "$tmp/XTRRND.BIN"
test ! -e "$tmp/XTRRND.USE"
# Leftover claim must NOT silently replace an old in-progress or crashed job.
printf 'stale' > "$tmp/XTRRND.USE"
dd if=/dev/urandom of="$tmp/XTRRND.BIN" bs=16 count=1 2>/dev/null
(cd "$tmp" && ./test-pool leftover)
test -s "$tmp/XTRRND.BIN"
test -s "$tmp/XTRRND.USE"
printf '%s\n' 'PASS: DOS16 AES salt pool consumption and fail-closed cases (host C89)'
