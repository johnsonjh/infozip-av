#!/bin/sh
# Sourceable helper: probe_os2_library <codec> <install-prefix> <output-dir>
# Expects WATCOM, PATH (containing wcc386/wlink), INCLUDE, and OS2_OPT_FLAGS.
probe_os2_library()
{
  pl_name=$1
  pl_prefix=$2
  pl_work=$3
  pl_root=$4
  mkdir -p "$pl_work"
  case "$pl_name" in
  lzma) pl_lib=liblzma.lib; pl_hdr=lzma.h ;;
  zstd) pl_lib=libzstd.lib; pl_hdr=zstd.h ;;
  wavpack) pl_lib=libwavpack.lib; pl_hdr=wavpack/wavpack.h ;;
  *) echo "ERROR: unknown codec $pl_name" >&2; return 1 ;;
  esac
  [ -s "$pl_prefix/include/$pl_hdr" ] && [ -s "$pl_prefix/lib/$pl_lib" ] || return 1
  pl_obj="$pl_work/probe-${pl_name}.obj"
  pl_exe="$pl_work/probe-${pl_name}.exe"
  pl_log="$pl_work/probe-${pl_name}.log"
  if ! wcc386 -bt=os2 -ei -3r -mf -zp1 -zq -fr ${OS2_OPT_FLAGS:-} \
      "-I=$pl_prefix/include" -fo="$pl_obj" \
      "$pl_root/tests/os2libs/probe-${pl_name}.c" > "$pl_log" 2>&1; then
    return 1
  fi
  {
    printf 'system os2v2\nname %s\nfile %s\nlibrary %s\n' \
      "$pl_exe" "$pl_obj" "$pl_prefix/lib/$pl_lib"
  } > "$pl_work/probe-${pl_name}.lnk"
  if ! wlink "@$pl_work/probe-${pl_name}.lnk" >> "$pl_log" 2>&1; then
    return 1
  fi
  [ -s "$pl_exe" ] || return 1
  # Do not execute a native OS/2 program on Linux.
  python3 - "$pl_exe" <<'PY'
import struct, sys
p = open(sys.argv[1], 'rb').read()
if len(p) < 64 or p[:2] != b'MZ': sys.exit(1)
o = struct.unpack_from('<I', p, 60)[0]
if o + 2 > len(p) or p[o:o+2] != b'LX': sys.exit(1)
PY
}
