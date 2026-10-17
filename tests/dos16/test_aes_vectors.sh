#!/bin/sh
# Strict C89, standalone host crypto vectors; does not emulate an 8086.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cc=${CC:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 3 15
"$cc" -std=c89 -pedantic -Wall -Wextra -Werror -DUNIX \
    -o "$tmp/vectors" "$root/tests/dos16/test_aes_vectors.c" \
    "$root/zip30/wzaes.c"
"$tmp/vectors"
