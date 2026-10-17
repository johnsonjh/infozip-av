#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

watcom=${WATCOM:-/opt/watcom}
if [ ! -d "$watcom" ]; then
  printf '%s\n' "ERROR: Open Watcom not found at $watcom (set WATCOM)." >&2
  exit 1
fi

watcom=$(CDPATH= cd -- "$watcom" && pwd -P)

export WATCOM="$watcom"
export INCLUDE="$watcom/h"

if [ -x "$watcom/binl64/wcc" ] && [ -x "$watcom/binl64/wlink" ]; then
  PATH="$watcom/binl64:$PATH"
elif [ -x "$watcom/binl/wcc" ] && [ -x "$watcom/binl/wlink" ]; then
  PATH="$watcom/binl:$PATH"
fi

export PATH

for exe in wcc wlink; do
  if ! command -v "$exe" > /dev/null 2>&1; then
    printf '%s\n' "ERROR: Open Watcom $exe not found under $watcom." >&2
    exit 1
  fi
done

build="$root/build-dos16"
out="$root/dos16"

mkdir -p "$build" "$out"
rm -f "$out"/*.exe

watcom_err_cleanup()
{
  find "$root/zip30" "$root/unzip60" "$root/xtrmeta" "$root/zipdedup" \
    -type f -name '*.err' -exec rm -f '{}' +
}

trap 'watcom_err_cleanup' 0

case "${DOS16_NO_ASM:-0}" in
0) dos16_asm=1 ;;
1) dos16_asm=0 ;;
*)
  echo "ERROR: DOS16_NO_ASM must be 0 or 1" >&2; exit 2
  ;;
esac
if [ "$dos16_asm" = 1 ] && ! command -v wasm > /dev/null 2>&1; then
  echo 'ERROR: Open Watcom wasm not found (assembly enabled).' >&2
  exit 1
fi

case "${DOS16_REQUIRE_AES_POOL:-0}" in
0) dos16_entropy_flag='' ;;
1) dos16_entropy_flag='-DIZ_AES_DOS_REQUIRE_POOL' ;;
*)
  echo 'ERROR: DOS16_REQUIRE_AES_POOL must be 0 or 1' >&2; exit 2
  ;;
esac

case " ${LOCAL_DOS16_CFLAGS:-} " in
*"-DNO_AES"* | *"-DNO_CRYPT"*)
  echo 'ERROR: DOS16 AES is mandatory; do not disable encryption in LOCAL_DOS16_CFLAGS.' >&2
  exit 1
  ;;
*"-DDEFLATE64_SUPPORT"* | *"-DLZFSE_SUPPORT"*)
  echo 'ERROR: DOS16 ZIP Deflate64 and LZFSE encoders are unsupported.' >&2
  exit 1
  ;;
esac

common='-bt=DOS -0 -d0 -zt -zq -os -oh -s'
log="$build/build.log"
: > "$log"
compile()
{
  target=$1
  model=$2
  kind=$3
  name=$4

  case "$kind" in
  z)
    dir="$root/zip30"
    src="$name.c"
    osdef='-DDOS'
    ;;
  u)
    dir="$root/unzip60"
    src="$name.c"
    osdef='-DMSDOS'
    ;;
  zm)
    dir="$root/zip30"
    src="msdos/msdos.c"
    osdef='-DDOS'
    ;;
  um)
    dir="$root/unzip60"
    src="msdos/msdos.c"
    osdef='-DMSDOS'
    ;;
  *)
    echo "ERROR: bad source kind $kind" >&2; exit 2
    ;;
  esac

  obj="$build/${target}_${name}.obj"
  memflags=''
  asmdef='-DNO_ASM'

  if [ "$dos16_asm" = 1 ]; then
    case "$target" in
    zip) asmdef='-DASMV -DASM_CRC' ;;
    zipcloak) asmdef='-DASM_CRC' ;;
    unzip | funzip | sfx) asmdef='-DASM_CRC' ;;
    esac
  fi

  if [ "$target" = zip ]; then
    memflags="-DDYN_ALLOC -DSMALL_MEM -DWSIZE=8192 -DNO_DEFLATE64 -DNO_LZFSE $dos16_entropy_flag"
    [ "$name" = zip ] || memflags="$memflags -zc"
  fi

  case "$target" in
  sfx) define='-DSFX' ;;
  funzip) define='-DFUNZIP' ;;
  zipnote | zipcloak | zipsplit)
    case "$name" in zipfile | fileio | util | crc32 | crypt | msdos) define='-DUTIL' ;; *) define='' ;; esac
    ;;
  *) define='' ;;
  esac

  printf 'CC  %-9s %s\n' "$target" "$src"

  if ! (cd "$dir" && wcc $common "$model" $osdef $asmdef $define $memflags ${LOCAL_DOS16_CFLAGS:-} -fo="$obj" "$src") >> "$log" 2>&1; then
    printf 'ERROR: %s/%s compilation failed. See %s\n' "$target" "$src" "$log" >&2
    tail -35 "$log" >&2
    exit 1
  fi

  objs="$objs$obj\n"
}

link_target()
{
  target=$1
  response="$build/$target.lnk"

  case "$target" in
  zip) stack_bytes=12288 ;;
  unzip | funzip | sfx | zipdedup) stack_bytes=8192 ;;
  zipsplit) stack_bytes=12288 ;; # main() has a 5000-byte errbuf
  *) stack_bytes=4096 ;;
  esac

  printf 'system dos\noption map\noption stack=%s\nname %s\n' \
    "$stack_bytes" "$out/$target.exe" > "$response"
  printf '%b' "$objs" | while IFS= read -r obj; do
    [ -n "$obj" ] && printf 'file %s\n' "$obj"
  done >> "$response"

  printf 'LINK %s.exe\n' "$target"

  if ! (cd "$build" && wlink @"$response") >> "$log" 2>&1; then
    echo "ERROR: $target link failed. See $log" >&2
    tail -45 "$log" >&2
    exit 1
  fi

  test -s "$out/$target.exe" || {
    echo "ERROR: Missing $out/$target.exe" >&2; exit 1
  }
}

assemble()
{
  target=$1
  model=$2
  family=$3
  name=$4
  obj="$build/${target}_${name}_asm.obj"

  case "$family" in
  z)
    dir="$root/zip30"
    extra='-dDYN_ALLOC -dWSIZE=8192'
    ;;
  u)
    dir="$root/unzip60"
    extra=''
    ;;
  *)
    echo "ERROR: invalid assembly family" >&2; exit 2
    ;;
  esac

  printf 'ASM %-9s %s\n' "$target" "$name.asm"

  if ! (cd "$dir" && wasm -0 -bt=dos "$model" $extra \
    "msdos/$name.asm" -fo="$obj") >> "$log" 2>&1; then
    echo "ERROR: $target assembly failed ($name); see $log" >&2
    tail -35 "$log" >&2
    exit 1
  fi

  objs="$objs$obj\n"
}

objs=''

for m in zip crc32 crypt deflate fileio globals trees ttyio util zipfile zipup; do compile zip -ml z "$m"; done

compile zip -ml zm msdos

if [ "$dos16_asm" = 1 ]; then
  assemble zip -ml z crc_i86
  assemble zip -ml z match
fi

link_target zip

objs=''

for m in unzip crc32 crypt envargs explode extract fileio globals inflate list match process ttyio unreduce unshrink zipinfo; do compile unzip -ml u "$m"; done

compile unzip -ml um msdos

if [ "$dos16_asm" = 1 ]; then assemble unzip -ml u crc_i86; fi

link_target unzip

cp -f "$out/unzip.exe" "$out/zipinfo.exe"
cmp "$out/unzip.exe" "$out/zipinfo.exe"

for t in zipnote zipcloak zipsplit; do
  objs=''
  compile "$t" -ml z "$t"

  case "$t" in
  zipnote) supporting='zipfile fileio util globals' ;;
  zipcloak) supporting='crc32 crypt ttyio zipfile fileio util globals' ;;
  zipsplit) supporting='zipfile fileio util globals' ;;
  esac

  for m in $supporting; do compile "$t" -ml z "$m"; done

  compile "$t" -ml zm msdos

  if [ "$dos16_asm" = 1 ] && [ "$t" = zipcloak ]; then
    assemble zipcloak -ml z crc_i86
  fi

  link_target "$t"

done

objs=''
for m in funzip crc32 crypt globals inflate ttyio; do compile funzip -mc u "$m"; done

compile funzip -mc um msdos

if [ "$dos16_asm" = 1 ]; then assemble funzip -mc u crc_i86; fi

link_target funzip

objs=''

for m in unzip crc32 crypt extract fileio globals inflate match process ttyio; do compile sfx -mm u "$m"; done
compile sfx -mm um msdos
if [ "$dos16_asm" = 1 ]; then assemble sfx -mm u crc_i86; fi

link_target sfx

mv "$out/sfx.exe" "$out/unzipsfx.exe"

case "${DOS16_UPX:-1}" in
0) echo 'DOS16: UPX disabled (DOS16_UPX=0).' ;;
1)
  if command -v upx > /dev/null 2>&1; then
    raw_sfx="$build/unzipsfx.raw.exe"
    cp "$out/unzipsfx.exe" "$raw_sfx"

    if upx -qq --8086 --best "$out/unzipsfx.exe"; then
      echo 'DOS16: UPX packed unzipsfx.exe'
    else
      cp "$raw_sfx" "$out/unzipsfx.exe"
      echo 'WARNING: UPX rejected DOS16 unzipsfx.exe; restored raw MZ.' >&2
    fi

    rm -f "$raw_sfx"
  else
    echo 'WARNING: UPX unavailable; retaining raw DOS16 unzipsfx.exe.' >&2
  fi
  ;;
*)
  echo 'ERROR: DOS16_UPX must be 0 or 1' >&2; exit 2
  ;;
esac

printf '\nDOS16: produced DOS builds in %s\n' "$out"

case "${DOS16_EXPERIMENTAL_ZIPDEDUP:-0}" in
0) : ;;
1)
  printf '%s\n' 'Building experimental DOS16 ZipDedup...'
  zdflags="$common -ml -DNO_ASM -DMSDOS -DDLL -DNO_EXCEPT_SIGNALS -DUSE_VFAT -DNO_IZ_CHECK_TZ"

  objs=''

  for m in unzip crc32 crypt envargs explode extract fileio globals inflate list match process ttyio ubz2err unreduce unshrink zipinfo api; do
    obj="$build/zipdedup_uz_$m.obj"
    printf 'CC  zipdedup  unzip60/%s.c\n' "$m"

    if ! (cd "$root/unzip60" && wcc $zdflags ${LOCAL_DOS16_CFLAGS:-} -fo="$obj" "$m.c") >> "$log" 2>&1; then
      echo "ERROR: ZipDedup UnZip API compile failed ($m); see $log" >&2
      tail -35 "$log" >&2; exit 1
    fi

    objs="$objs$obj\n"
  done

  obj="$build/zipdedup_uz_msdos.obj"

  if ! (cd "$root/unzip60" && wcc $zdflags ${LOCAL_DOS16_CFLAGS:-} -fo="$obj" msdos/msdos.c) >> "$log" 2>&1; then
    echo "ERROR: ZipDedup DOS adapter compile failed; see $log" >&2
    tail -35 "$log" >&2; exit 1
  fi

  objs="$objs$obj\n"

  for m in xtrm xtrsha xtrv1; do
    obj="$build/zipdedup_xtr_$m.obj"

    if ! (cd "$root/xtrmeta" && wcc $zdflags ${LOCAL_DOS16_CFLAGS:-} -fo="$obj" "$m.c") >> "$log" 2>&1; then
      echo "ERROR: ZipDedup Xtro compile failed ($m); see $log" >&2
      tail -35 "$log" >&2; exit 1
    fi

    objs="$objs$obj\n"
  done

  for m in zipdedup refptr9903; do
    obj="$build/zipdedup_$m.obj"

    if ! (cd "$root/zipdedup" && wcc $zdflags -DZD_DOS16 -I../unzip60 ${LOCAL_DOS16_CFLAGS:-} -fo="$obj" "$m.c") >> "$log" 2>&1; then
      echo "ERROR: ZipDedup source compile failed ($m); see $log" >&2
      tail -35 "$log" >&2; exit 1
    fi

    objs="$objs$obj\n"
  done

  link_target zipdedup

  printf '%s\n' 'NOTE: ZipDedup is experimental!'
  ;;
*)
  echo 'ERROR: DOS16_EXPERIMENTAL_ZIPDEDUP must be 0 or 1' >&2; exit 2
  ;;
esac
