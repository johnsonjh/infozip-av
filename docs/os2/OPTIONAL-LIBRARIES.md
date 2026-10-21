# Optional OS/2 codec libraries — Open Watcom V2

## Scope and source provenance

`build-os2-libs.sh` builds *target* static libraries using the Linux-hosted
Open Watcom V2 compiler and `wlib`. The resulting executables remain OS/2 LX
binaries and require no GCC, DJGPP or kLIBC runtime. It uses upstream Git
repositories **without vendoring or patching their source trees**:

| Codec | Upstream repository | Last-known-working commit |
|---|---|---|
| liblzma (highest priority) | `https://codeberg.org/tukaani/xz` | `299eb5c3f597f107fd6019bf156885ac8bfaa5ea` |
| Zstandard | `https://github.com/facebook/zstd` | `49cf51799ea051457f57243527aa2058f999f005` |
| WavPack (lowest priority) | `https://github.com/dbry/wavpack` | `c9515833d1867d9ec03774d954369107f2e88a73` |

These revisions **passed Linux-hosted OW2 optimized static-library compilation,
OS/2 LX API link probes, and full Xtro-ZIP optimized and diagnostic cross-linking**.
They are NOT evidence of native OS/2 runtime compatibility. Record native
acceptance separately after testing. This table is guidance only: the script
uses the current upstream default branch tip when allowed to fetch, not these
pinned revisions. Upstream changes may require updating the adapter patches.

## Build and checkout selection

```sh
# By default, build all three optional static libraries:
WATCOM=/opt/watcom ./build-os2-libs.sh
./build-os2.sh

# To prioritize only liblzma or restrict the set:
OS2_LIBS=lzma ./build-os2-libs.sh
OS2_LIBS='lzma zstd' ./build-os2-libs.sh

# Existing source checkouts, with no network access:
OS2_LIBS_FETCH=0 ./build-os2-libs.sh
```

By default `OS2_LIBS` selects **all three** in priority order: liblzma,
Zstandard, and WavPack. Successful libraries remain staged if another fails;
the overall script exits nonzero, and failed installs are removed. Select
`OS2_LIBS=lzma` for a focused first build.

By default, newly cloned source comes from the repository's default branch
tip. Existing clean checkouts on their tracked default branch are fetched
and fast-forwarded. Any detached commit, custom branch or dirty checkout is
left unchanged. To retain precisely the current source revision on the next
build, set `OS2_LIBS_FETCH=0` (requires an existing clone; never starts a
network checkout). You may also checkout a specific commit in
`build-os2-libs/<codec>/source/` yourself. No script force-resets or calls
`git clean` on upstream source.

The script clones in `build-os2-libs/<codec>/source/`, copies a snapshot
(excluding `.git`) to `build-os2-libs/<codec>/ow2-source/`, and applies a
strict zero-fuzz compatibility patch from `tests/os2libs/patches/` to that
**generated snapshot only**. The Git checkout never gets patched, reset, or
cleaned. The liblzma patch adapts Watcom's limited C99 compound-literal and
dynamic-initializer handling and OS/2 signal-mask availability. WavPack's
patch selects C-only library configuration, without changing upstream's
CMakeLists.txt in Git. Build-specific CMake cache overrides disable misleading
compiler-builtin probes (`__builtin_bswapXX`, `__builtin_assume_aligned`,
`__builtin_clz`), force standard-sized enum fields (`-ei`), and disable
unsupported liblzma CPU-core detection plus optional MicroLZMA/lzip code.
This does **not** disable ordinary method 14 LZMA1 or method 95 XZ/LZMA2.

The script builds in `build-os2-libs/<codec>/build/` and stages accepted
artifacts in `build-os2-libs/<codec>/install/{include,lib}`. A successful
build must pass both compilation and a native `wlink system os2v2` API probe;
no OS/2 executable is attempted on the Linux host. The exact Git commit is
recorded as `install/built-from-commit.txt`. An unsuccessful attempt removes
its incomplete installation so it cannot be silently selected next time.

Required host tools: Git, CMake (with Unix Makefiles), Make, Python 3,
GNU-compatible tar, patch, and Open Watcom V2 (`wcc386`, `wlink`, `wlib`). If upstream code changes require
new portability work, the failure is reported with a per-library `build.log`.
This recipe does not pin a commit; the small source adapters are explicitly
recorded and maintained under `tests/os2libs/patches/`. An upstream change
which makes a patch inapplicable results in a hard failure rather than a
partial build. No native runtime acceptance has yet been claimed.

## How `build-os2.sh` chooses codecs

- `OS2_LZMA=auto|on|off`, `OS2_ZSTD=auto|on|off`, `OS2_WAVPACK=auto|on|off`
  (all default to `auto`).
- `auto` enables only an installed library that passes its OW2 compilation,
  OS/2 LX link, and required public-symbol probes. Missing installations are
  reported as disabled. Incomplete or incompatible installations fail the
  build rather than silently downgrading an apparently installed codec.
- `on` requires the specified library; `off` unconditionally disables it.
- Optional `OS2_LZMA_DIR`, `OS2_ZSTD_DIR`, and `OS2_WAVPACK_DIR` override the
  install prefix, containing `include/` and `lib/`.
- Standard Zip, UnZip and the ZipOpt/ZipDedup private decoder use enabled
  codecs. WinZip JPEG decoder support (method 96) is tied to liblzma. WavPack
  method 97 is decoder-only in UnZip. Methods 14 and 95 use liblzma; 20 and
  93 use Zstandard. The new libraries are **never added to the default
  UnZipSFX or fUnZip build**. The previously selected BZip2 SFX profile is
  deliberately not modified by this optional-codec change.

## Library build acceptance and diagnostics

The CMake-to-OW2 cross-compilation toolchain is a small, independent adapter.
Its rule for compiling is Watcom-specific (`-fo=` instead of GCC `-c/-o`).
Upstream Autotools configuration intended for MinGW/DJGPP is not reused as
an OS/2 compiler configuration. Upstream build configuration and feature
checks may need adaptation for newer branches. A static archive is never
considered proof that its code behaves correctly under OS/2.

* Build release and diagnostic OW2 configurations (set `OS2_DEBUG=1`).
* Confirm absence of kLIBC DLL imports; inspect `build-os2/build.log`.
* Verify method 14 (including LZMA1EXT/EOS variants), method 95 (XZ),
  method 96 (WinZip JPEG test corpus), 20/93 Zstd, and 97 WavPack.
* Use large, empty, highly compressible, incompressible and corrupt inputs.
* Test archive mutation/rewrite paths under `zipopt` and `zipdedup`.
* Test insufficient RAM, interrupted writes, wrong passwords, and metadata
  companion preservation with `--xattrs` on HPFS and JFS.
* Run on at least OS/2 Warp, eComStation and ArcaOS where available. Record
  exact OS version, filesystem, codepage, library SHA, command, exit code and
  full log. Mark cases PASS, FAIL, UNSUPPORTED, or NOT RUN.
* Check that a default `unzipsfx.exe` remains unchanged in its supported
  codec list and is not linked with the new optional codec libraries.

Until these native tests pass, the codec-specific OS/2 runtime status remains
**not verified**, even if cross-compilation and link probes succeed.

## Cleanup

`./clean.sh` removes OW2 object directories, temporary source snapshots,
installed static archives, and probe results, while preserving original Git
checkouts and selected commits.
Delete `build-os2-libs/` manually only if you wish to discard Git clones.
