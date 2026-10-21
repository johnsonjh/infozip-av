#!/bin/sh
# Cross-compile to 32-bit OS/2 LX, Open Watcom V2
# Built-in vendored bzip2; optional OW2 static codec libraries detected.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
watcom=${WATCOM:-/opt/watcom}
if [ ! -d "$watcom" ]; then
  echo "ERROR: Open Watcom missing at $watcom; set WATCOM" >&2
  exit 1
fi
watcom=$(CDPATH= cd -- "$watcom" && pwd -P)
export WATCOM="$watcom" INCLUDE="$watcom/h:$watcom/h/os2"
if [ -x "$watcom/binl64/wcc386" ] && [ -x "$watcom/binl64/wlink" ]; then
  PATH="$watcom/binl64:$PATH"
elif [ -x "$watcom/binl/wcc386" ] && [ -x "$watcom/binl/wlink" ]; then
  PATH="$watcom/binl:$PATH"
else
  echo 'ERROR: Open Watcom Linux wcc386/wlink not found' >&2; exit 1
fi
export PATH
case "${OS2_DEBUG:-0}" in
0) opt='-d0 -ot -oe -ob -oc -oh -oi -ok -ol -ol+ -om -or -s' ;;
1) opt='-d2 -od' ;;
*)
  echo 'ERROR: OS2_DEBUG must be 0 or 1' >&2; exit 2
  ;;
esac
case " ${LOCAL_OS2_CFLAGS:-} " in
*-DNO_AES* | *-DNO_CRYPT*)
  echo 'ERROR: OS/2 encryption may not be disabled' >&2; exit 2
  ;;
esac
# -zp1 matches the OS/2 EA ABI and preexisting makefile.os2 settings.
# Disable ASM; optional codecs require verified OW2 LX link probes.
# Keep compiler diagnostics in build-os2/build.log only.
common="-bt=os2 -ei -3r -mf -zp1 -zq -fr -DNO_ASM -D__32BIT__ -DZSTD_DISABLE_DEPRECATE_WARNINGS -I=$root/vendor/bzip2 $opt"
build="$root/build-os2"
out="$root/os2"
mkdir -p "$build" "$out"
log="$build/build.log"
: > "$log"

# Never trust header/archive existence alone: a stale host .a or incompatible
# OW2 library must fail a target link probe before enabling a ZIP method.
. "$root/tests/os2libs/probe-library.sh"
zip_extra_flags=''
unzip_extra_flags=''
aux_extra_flags=''
extra_include_flags=''
optional_libs=''
check_os2_codec()
{
  codec=$1
  setting=$2
  defdir=$3
  header=$4
  archive=$5
  # Fixed cases avoid `eval` on user-supplied library directory strings.
  case "$setting" in
  OS2_LZMA)
    mode=${OS2_LZMA:-auto}
    prefix=${OS2_LZMA_DIR:-$defdir}
    explicit=${OS2_LZMA_DIR+x}
    ;;
  OS2_ZSTD)
    mode=${OS2_ZSTD:-auto}
    prefix=${OS2_ZSTD_DIR:-$defdir}
    explicit=${OS2_ZSTD_DIR+x}
    ;;
  OS2_WAVPACK)
    mode=${OS2_WAVPACK:-auto}
    prefix=${OS2_WAVPACK_DIR:-$defdir}
    explicit=${OS2_WAVPACK_DIR+x}
    ;;
  *)
    echo "ERROR: unexpected $setting" >&2; exit 2
    ;;
  esac
  case "$mode" in auto | on | off) ;; *)
    echo "ERROR: $setting must be auto, on, off" >&2; exit 2
    ;;
  esac
  [ "$mode" != off ] || {
    echo "OS/2: $codec disabled"; return 0
  }
  case "$prefix" in
  *' '* | *'	'* | *'
'*)
    echo "ERROR: OS/2 codec path contains whitespace: $prefix" >&2; exit 2
    ;;
  esac
  if [ ! -e "$prefix/include/$header" ] && [ ! -e "$prefix/lib/$archive" ]; then
    if [ "$mode" = on ] || [ -n "$explicit" ]; then
      echo "ERROR: $codec explicitly required, but not installed under $prefix" >&2; exit 1
    fi
    echo "OS/2: $codec not installed (using built-in methods)"
    return 0
  fi
  if [ ! -s "$prefix/include/$header" ] || [ ! -s "$prefix/lib/$archive" ]; then
    echo "ERROR: incomplete $codec installation at $prefix" >&2; exit 1
  fi
  if ! probe_os2_library "$codec" "$prefix" "$build" "$root"; then
    echo "ERROR: $codec OW2 link probe failed: $build/probe-$codec.log" >&2
    tail -35 "$build/probe-$codec.log" >&2 || :
    exit 1
  fi
  echo "OS/2: enabled $codec from $prefix"
  extra_include_flags="$extra_include_flags -I=$prefix/include"
  optional_libs="$optional_libs $prefix/lib/$archive"
  case "$codec" in
  lzma)
    zip_extra_flags="$zip_extra_flags -DLZMA_SUPPORT"
    unzip_extra_flags="$unzip_extra_flags -DUSE_LZMA -DUSE_XZ"
    aux_extra_flags="$aux_extra_flags -DZO_WITH_LZMA"
    ;;
  zstd)
    zip_extra_flags="$zip_extra_flags -DZSTD_SUPPORT"
    unzip_extra_flags="$unzip_extra_flags -DUSE_ZSTD"
    aux_extra_flags="$aux_extra_flags -DZO_WITH_ZSTD"
    ;;
  wavpack)
    unzip_extra_flags="$unzip_extra_flags -DUSE_WAVP"
    ;;
  esac
}
# AUTO only selects libraries that are fully staged and link-probed.
check_os2_codec lzma OS2_LZMA "$root/build-os2-libs/lzma/install" lzma.h liblzma.lib
check_os2_codec zstd OS2_ZSTD "$root/build-os2-libs/zstd/install" zstd.h libzstd.lib
check_os2_codec wavpack OS2_WAVPACK "$root/build-os2-libs/wavpack/install" wavpack/wavpack.h libwavpack.lib
common="$common $extra_include_flags"
compile()
{
  target=$1
  family=$2
  source=$3
  name=$4
  special=$5
  case "$family" in
  zip)
    srcdir="$root/zip30"
    osdef='-DOS2'
    ;;
  unzip)
    srcdir="$root/unzip60"
    osdef='-DOS2'
    ;;
  *)
    echo 'ERROR: invalid source family' >&2; exit 2
    ;;
  esac
  obj="$build/${target}_${name}.obj"
  echo "CC  $target  $source"
  if ! (cd "$srcdir" && wcc386 $common $osdef $special ${LOCAL_OS2_CFLAGS:-} \
    -fo="$obj" "$source") >> "$log" 2>&1; then
    echo "ERROR: $target/$source compilation failed; see $log" >&2
    tail -40 "$log" >&2
    exit 1
  fi
  objs="${objs}${obj}\n"
}
link_target()
{
  target=$1
  response="$build/$target.lnk"
  {
    printf 'system os2v2\noption map\noption stack=131072\nname %s\n' "$out/$target.exe"
    printf '%b' "$objs" | while IFS= read -r obj; do
      [ -n "$obj" ] && printf 'file %s\n' "$obj"
    done
    if [ "${use_bz2:-0}" = 1 ]; then
      printf 'library %s\n' "$bzlib"
    fi
    if [ "${use_optional:-0}" = 1 ]; then
      for os2lib in $optional_libs; do
        printf 'library %s\n' "$os2lib"
      done
    fi
  } > "$response"
  echo "LINK $target.exe"
  if ! (cd "$build" && wlink "@$response") >> "$log" 2>&1; then
    echo "ERROR: $target link failed; see $log" >&2
    tail -55 "$log" >&2
    exit 1
  fi
  # OS/2 LX executable is an MZ stub followed by the LX header at e_lfanew.
  if ! python3 - "$out/$target.exe" << 'PY'
import struct, sys
p = open(sys.argv[1], 'rb').read()
o = struct.unpack_from('<I', p, 0x3c)[0] if len(p) >= 0x40 else 0
if p[:2] != b'MZ' or p[o:o+2] != b'LX':
    sys.exit('ERROR: not an OS/2 LX executable: ' + sys.argv[1])
PY
  then exit 1; fi
}
# Full upstream libbz2 (no BZ_NO_STDIO) is built as an OS/2 static archive.
# Keep all intermediate files outside vendor/ so upstream source remains clean.
bzlib="$build/libbz2.lib"
bzobjects=''
for unit in blocksort huffman crctable randtable compress decompress bzlib; do
  obj="$build/bz2_${unit}.obj"
  echo "CC  libbz2  $unit.c"
  if ! (cd "$root" && wcc386 $common -za -DBZ_STRICT_ANSI \
    ${LOCAL_OS2_CFLAGS:-} -fo="$obj" "vendor/bzip2/$unit.c") >> "$log" 2>&1; then
    echo "ERROR: vendored libbz2/$unit compilation failed; see $log" >&2
    tail -40 "$log" >&2; exit 1
  fi
  bzobjects="$bzobjects +$obj"
done
rm -f "$bzlib"
echo 'LIB libbz2.lib'
if ! (cd "$build" && wlib -q -n "$bzlib" $bzobjects) >> "$log" 2>&1; then
  echo "ERROR: OS/2 libbz2 archive failed; see $log" >&2
  tail -40 "$log" >&2; exit 1
fi
# UnZip OS/2 source is linked into each relevant executable.
# The native OS/2 SYMLINK EA backend replaces POSIX lstat/readlink.
# UnZip restores link EAs through native DosSetPathInfo, not kLIBC.
zipflags="-DOS2_KLIBC_SYMLINKS -DXTR_OS2_NATIVE -DBZIP2_SUPPORT $zip_extra_flags"
unzipflags="-DSET_DIR_ATTRIB -DXTR_OS2_NATIVE -DUSE_BZIP2 $unzip_extra_flags"
use_bz2=1
use_optional=1
objs=''
for m in zip crc32 crypt deflate fileio globals trees ttyio util zipfile zipup zbz2err; do
  compile zip zip "$m.c" "$m" "$zipflags"
done
compile zip zip os2/os2.c os2 "$zipflags"
compile zip zip os2/os2zip.c os2zip "$zipflags"
compile zip zip os2/os2acl.c os2acl "$zipflags"
compile zip zip os2/os2link.c os2link "$zipflags"
compile zip zip xtrzip_os2.c xtrzip "$zipflags"
for m in xtros2_ea xtros2_nls xtros2_native xtros2_memory xtrm xtrv1 xtrsha; do
  compile zip zip "../xtrmeta/$m.c" "$m" "$zipflags"
done
link_target zip
objs=''
for m in unzip crc32 crypt envargs explode extract fileio globals inflate list match process ttyio ubz2err unreduce unshrink zipinfo; do
  compile unzip unzip "$m.c" "$m" "$unzipflags"
done
compile unzip unzip os2/os2.c os2 "$unzipflags"
compile unzip unzip os2/os2acl.c os2acl "$unzipflags"
for m in xtros2_ea xtros2_nls xtros2_decode xtros2_memory xtrm xtrv1 xtrsha; do
  compile unzip zip "../xtrmeta/$m.c" "$m" "$unzipflags"
done
compile unzip zip os2/os2link.c os2link "$unzipflags"
link_target unzip
cp "$out/unzip.exe" "$out/zipinfo.exe"
for tool in zipnote zipcloak zipsplit; do
  use_optional=0
  use_bz2=0
  objs=''
  case "$tool" in
  zipnote) supporting='zipfile fileio util globals' ;;
  zipcloak) supporting='crc32 crypt ttyio zipfile fileio util globals' ;;
  zipsplit) supporting='zipfile fileio util globals' ;;
  esac
  compile "$tool" zip "$tool.c" "$tool" '-DUTIL -DNO_SYMLINKS'
  for m in $supporting; do
    compile "$tool" zip "$m.c" "$m" '-DUTIL -DNO_SYMLINKS'
  done
  compile "$tool" zip os2/os2.c os2 '-DUTIL -DNO_SYMLINKS'
  compile "$tool" zip os2/os2zip.c os2zip '-DUTIL -DNO_SYMLINKS'
  compile "$tool" zip os2/os2acl.c os2acl '-DUTIL -DNO_SYMLINKS'
  link_target "$tool"
done
use_bz2=0
use_optional=0
objs=''
for m in funzip crc32 crypt globals inflate ttyio; do
  compile funzip unzip "$m.c" "$m" "$unzipflags -DFUNZIP"
done
compile funzip unzip os2/os2.c os2 "$unzipflags -DFUNZIP"
compile funzip unzip os2/os2acl.c os2acl "$unzipflags -DFUNZIP"
link_target funzip
use_bz2=1
use_optional=0
objs=''
for m in unzip crc32 crypt extract fileio globals inflate match process ttyio ubz2err; do
  compile unzipsfx unzip "$m.c" "$m" '-DSFX -DSET_DIR_ATTRIB -DUSE_BZIP2 -DBZIP2_SFX'
done
compile unzipsfx unzip os2/os2.c os2 '-DSFX -DSET_DIR_ATTRIB -DUSE_BZIP2 -DBZIP2_SFX'
compile unzipsfx unzip os2/os2acl.c os2acl '-DSFX -DSET_DIR_ATTRIB -DUSE_BZIP2 -DBZIP2_SFX'
for m in xtros2_ea xtros2_nls xtros2_decode xtros2_memory xtrm xtrv1 xtrsha; do
  compile unzipsfx zip "../xtrmeta/$m.c" "$m" '-DSFX -DSET_DIR_ATTRIB -DUSE_BZIP2 -DBZIP2_SFX'
done
compile unzipsfx zip os2/os2link.c os2link '-DSFX -DSET_DIR_ATTRIB -DUSE_BZIP2 -DBZIP2_SFX'
link_target unzipsfx
printf 'OS/2: 7 LX executables and ZipInfo alias in %s\n' "$out"
# An explicitly enabled, disposable-data EA probe for native beta testers.
# It is not part of the user-facing archiver suite.
case "${OS2_TEST_HELPERS:-0}" in
0) ;;
1)
  use_bz2=0
  objs=''
  echo 'CC  ea-fixture  tests/os2native/ea-fixture.c'
  if ! (cd "$root" && wcc386 $common -DOS2 ${LOCAL_OS2_CFLAGS:-} \
    -fo="$build/ea-fixture.obj" 'tests/os2native/ea-fixture.c') >> "$log" 2>&1; then
    echo "ERROR: native EA fixture compilation failed; see $log" >&2
    tail -40 "$log" >&2; exit 1
  fi
  objs="$build/ea-fixture.obj\n"
  link_target ea-fixture
  ;;
*)
  echo 'ERROR: OS2_TEST_HELPERS must be 0 or 1' >&2; exit 2
  ;;
esac

# The two optimization utilities use a private UnZip decoder so that archive
# verification does not depend on an external unzip.exe or foreign libraries.
# NO_ZLIB_NG / ZO_SELECT_EXTERNAL_CODECS selects built-in methods only.
# These tools are cross-link tested, but native publication semantics and
# >2 GiB behavior must be verified before release.
case "${OS2_AUX_TOOLS:-1}" in
0) ;;
1)
  echo 'OS/2: building experimental zipopt/zipdedup utilities'
  use_optional=1
  uzobjs=''
  use_bz2=1
  objs=''
  for m in unzip crc32 crypt envargs explode extract fileio globals inflate list match process ttyio ubz2err unreduce unshrink zipinfo api; do
    compile auxuz unzip "$m.c" "$m" "-DDLL -DZIPOPT_EMBED -DNO_EXCEPT_SIGNALS -DNO_IZ_CHECK_TZ -DNO_ZLIB_NG -DUSE_BZIP2 $unzip_extra_flags"
  done
  compile auxuz unzip os2/os2.c os2 "-DDLL -DZIPOPT_EMBED -DNO_EXCEPT_SIGNALS -DNO_IZ_CHECK_TZ -DNO_ZLIB_NG -DUSE_BZIP2 $unzip_extra_flags"
  compile auxuz unzip os2/os2acl.c os2acl "-DDLL -DZIPOPT_EMBED -DNO_EXCEPT_SIGNALS -DNO_IZ_CHECK_TZ -DNO_ZLIB_NG -DUSE_BZIP2 $unzip_extra_flags"
  uzobjs=$objs
  auxflags="-DOS2 -DNO_EXCEPT_SIGNALS -DNO_ZLIB_NG -DZO_SELECT_EXTERNAL_CODECS -DZIPOPT_EMBED -DZO_WITH_BZIP2 $aux_extra_flags"
  compile_aux()
  {
    atarget=$1
    source=$2
    aname=$3
    extras=$4
    obj="$build/${atarget}_${aname}.obj"
    echo "CC  $atarget  $source"
    if ! (cd "$root" && wcc386 $common $auxflags $extras \
      "-I=$root/unzip60" "-I=$root/zipopt" \
      ${LOCAL_OS2_CFLAGS:-} -fo="$obj" "$source") >> "$log" 2>&1; then
      echo "ERROR: $atarget/$source compilation failed; see $log" >&2
      tail -40 "$log" >&2; exit 1
    fi
    objs="${objs}${obj}\n"
  }
  objs=''
  compile_aux zipdedup zipdedup/zipdedup.c main '-DDLL'
  compile_aux zipdedup zipdedup/refptr9903.c refptr ''
  for m in xtrm xtrsha xtrv1; do
    compile_aux xtr xtrmeta/$m.c "$m" ''
  done
  xtr_objs=$(printf '%b' "$objs" | grep '/xtr_' | sed '/^$/d')
  objs="${objs}${uzobjs}"
  link_target zipdedup
  objs=''
  for m in archive writer extract codec zip_deflate zipopt; do
    special=''
    [ "$m" = codec ] && special='-DZO_SHARED_UNZIP_CODECS'
    compile_aux zipopt zipopt/$m.c "$m" "$special"
  done
  objs="${objs}$(printf '%s\n' "$xtr_objs" | sed '/^$/d; s/$/\\n/')${uzobjs}"
  link_target zipopt
  use_bz2=0
  use_optional=0
  objs=''
  compile_aux preflight zipopt/archive.c archive ''
  compile_aux preflight zipopt/preflight.c main ''
  link_target zipopt-preflight
  use_bz2=1
  use_optional=1
  objs=''
  compile_aux decodecheck zipopt/archive.c archive ''
  compile_aux decodecheck zipopt/extract.c extract ''
  compile_aux decodecheck zipopt/decodecheck.c main ''
  objs="${objs}${uzobjs}"
  link_target zipopt-decodecheck
  echo 'OS/2: zipopt, zipdedup, preflight, decodecheck link complete'
  ;;
*)
  echo 'ERROR: OS2_AUX_TOOLS must be 0 or 1' >&2; exit 2
  ;;
esac

# Optional native EA fixture inspector for beta-testers. This is not part
# of the production ZIP suite and must only be used on disposable files.
case "${OS2_TEST_HELPERS:-0}" in
0) ;;
1)
  use_bz2=0
  obj="$build/ea-fixture.obj"
  echo 'CC  ea-fixture  tests/os2native/ea-fixture.c'
  if ! (cd "$root" && wcc386 $common -DOS2 ${LOCAL_OS2_CFLAGS:-} \
    -fo="$obj" tests/os2native/ea-fixture.c) >> "$log" 2>&1; then
    echo 'ERROR: native EA fixture utility compilation failed' >&2
    tail -40 "$log" >&2; exit 1
  fi
  objs="${obj}\\n"
  link_target ea-fixture
  ;;
*)
  echo 'ERROR: OS2_TEST_HELPERS must be 0 or 1' >&2; exit 2
  ;;
esac
