#!/bin/sh
# Stage only the portable Xtro-ZIP metadata sources needed by ZipOpt/ZipDedup.
# Build executables and Linux-native adapter sources must not be copied.
# SPDX-License-Identifier: MIT-0
set -eu
if [ "$#" -ne 2 ]; then
  printf '%s\n' 'Usage: sh stage-cross.sh SOURCE_XTRMETA DEST_XTRMETA' >&2
  exit 2
fi
src=$1
dst=$2
# Validate *all* required files before creating a partial staging directory.
for name in xtrm.c xtrm.h xtrsha.c xtrsha.h xtrv1.c xtrv1.h \
            xtrrewrite.h xtrverify_inline.h; do
  if [ ! -f "$src/$name" ]; then
    printf 'Missing Xtro-ZIP cross-build input: %s\n' "$src/$name" >&2
    exit 1
  fi
done
mkdir -p "$dst"
for name in xtrm.c xtrm.h xtrsha.c xtrsha.h xtrv1.c xtrv1.h \
            xtrrewrite.h xtrverify_inline.h; do
  cp "$src/$name" "$dst/$name"
done
