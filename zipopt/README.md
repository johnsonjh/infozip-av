# zipopt — lossless per-member ZIP compression optimizer

**NOTE: Pure AI/LLM generated README based on the source code, so it's likely terrible.**

`zipopt` is a standalone, in-process optimizer built against this source tree.
It uses the source tree's compression codecs and a **private** embedded UnZip
build.  It never launches external executables.  In version 1, Unix/POSIX
platforms are supported; native Windows and DOS builds have not been ported or
tested.  The implementation uses C89 source syntax, with the same 64-bit integer
compiler extension already required on 32-bit-long targets by the LZFSE fork.

Build on Unix with GNU Make (`gmake` on systems where `make` is BSD Make),
GCC/Clang, libbz2, liblzma and libzstd development headers:

    make -C zipopt all
    make -C zipopt test

Invoke:

    zipopt/zipopt [--verbose] [--methods=all] input.zip output.zip
    zipopt/zipopt --methods=store,deflate,ppmd input.zip output.zip
    zipopt/zipopt --methods=implode input.zip output.zip
    zipopt/zipopt --methods=help
    zipopt/zipopt --zopfli-iterations=30 input.zip output.zip
    zipopt/zipopt --dcl-implode-optimal input.zip output.zip
    zipopt/zipopt --fwkcs-md5 --methods=store input.zip output.zip

New configurable compression settings:

    zipopt/zipopt --version
    zipopt/zipopt --methods=reduce input.zip output.zip
    zipopt/zipopt --compress-level=all=5 input.zip output.zip
    zipopt/zipopt --compress-level=all=5 --compress-level=zstd=9 input.zip output.zip
    zipopt/zipopt --zstd-level=22 --methods=zstd input.zip output.zip
    zipopt/zipopt --methods=deflate --disable-zopfli input.zip output.zip
    zipopt/zipopt --methods=deflate,deflate64 --huffman-optimize-extra input.zip output.zip
    zipopt/zipopt --methods=deflate,libdeflate --libdeflate-size=1MiB input.zip output.zip

`--compress-level=NAME=N` accepts a Zip-style level of 1..9 or 11 for
adjustable candidates (Deflate, Deflate64, DCL Implode, bzip2, LZMA, XZ,
Zstandard, and PPMd). `NAME=all` affects only adjustable codecs; fixed
methods (STORE, Shrink, Reduce, Implode) cannot receive explicit levels.
Use `NAME=dcl-implode` to affect both DCL variants. Settings are evaluated in
command-line order; the last relevant override wins. The initial defaults
remain unchanged, including Zopfli Deflate with 15 iterations, native Zstd 22,
and nonoptimal DCL. Deflate levels 1..9 use a zlib-compatible raw Deflate
backend, level 11 uses Zopfli; `--disable-zopfli` uses the ordinary backend
at level 9 instead. `--zopfli-iterations` requires that Zopfli is actually
selected. `--compress-level=dcl-implode=11` and `all=11` enable DCL optimal
parsing; a later non-11 level disables it. `--zstd-level=1..22` sets the
native Zstandard level, also respecting last-option-wins. Explicit
per-candidate controls are rejected if that candidate is not selected.
`--version` reports the release and the CRC acceleration actually available
in zipopt's private UnZip decoder. Ordinary Deflate now uses
`ZO_DEFLATE_BACKEND=auto` by default. Like Zip and UnZip's configure scripts,
zipopt tests whether native zlib-ng headers and library **compile and link**
with the active compiler and flags. If they do, levels 1..9 use native zlib-ng;
otherwise zipopt uses the bundled Info-ZIP encoder in `zip30/deflate.c` and
`zip30/trees.c`. This fallback has no external zlib dependency and is not
thread-safe, consistent with zipopt's sequential candidate execution.

`--huffman-optimize-extra` is an opt-in header-only optimization for
Deflate and Deflate64 at every supported compression level. It evaluates
exact code-length RLE, alternating Huffman/RLE refinement, and bounded
Kraft-capacity R7 search for each dynamic block. It never replaces any
legacy header unless the complete serialized header is strictly smaller.
This can increase CPU usage substantially and is disabled by default.
When an external zlib/zlib-ng Deflate backend is selected, this option
routes the affected candidate through the always-built internal encoder;
other invocations retain their normal external backend. The codecs for
unrelated methods are unaffected.  On memory-constrained systems, any
allocation failure in the R7 search safely leaves the earlier candidates.

`ZO_DEFLATE_BACKEND=native`, `zlib` and `internal` force a specific backend;
`native` fails at build time when native zlib-ng is not linkable.
`EXTERNAL_ZLIB=-DUSE_ZLIB`, `-DUSE_ZLIB_NG` or `-DNO_ZLIB_NG` selects the
same backends as in Zip and UnZip. Explicit conflicting requests fail rather
than silently selecting a different library. The `IZ_ZLIBNG_CFLAGS` and
`IZ_ZLIBNG_LIBS` variables (otherwise pkg-config, with `-lz-ng` fallback)
and `IZ_ZLIB_CFLAGS` / `IZ_ZLIB_LIBS` are supported. `make -C zipopt
print-deflate-backend` reports the effective selection without building.
Changing backends regenerates the codec adapter and relinks the executable;
`make clean` is still recommended when changing other build configuration
flags. The embedded UnZip decoder continues to use its internal Deflate
implementation independently of the selected compression backend.

Optional libdeflate support is automatically enabled when its header and
library pass a compiler/linker probe (override discovery with
`ZO_LIBDEFLATE_CFLAGS` and `ZO_LIBDEFLATE_LIBS`). Standalone builds may use
`ZO_LIBDEFLATE=off` to disable it or `ZO_LIBDEFLATE=on` to require it;
`build-unix.sh` forwards the result of its own detection.
When compiled, the separate `libdeflate` candidate is available immediately,
even if Zopfli is also selected. It never replaces the existing `deflate`
candidate. `--methods=libdeflate` selects only this candidate, and
`--methods=all` considers both. Levels 1..9 map directly; level 11 uses
libdeflate level 12. The maximum uncompressed member size is 1MiB by default,
configurable via `--libdeflate-size=N` using positive binary byte units
(`1M`, `1MiB`, `1mb`, etc.). Larger members skip *only* this candidate.
On Linux, Windows XP or later, and DJGPP/DPMI hosts reporting usable free
memory, `--libdeflate-size=auto` instead uses half the available memory at
option parsing time. A failed or unsupported memory query is a fatal error;
OS/2 and other platforms require an explicit numeric limit. The calculated
limit is also passed numerically to zipopt's embedded UnZip decoder.

For reproducible archives, `SOURCE_DATE_EPOCH` and `auto` are incompatible:
the same limit must be chosen explicitly to avoid host-dependent output.
The same cap also enables the private libdeflate decompressor for method-8
input members **only when both their compressed and declared uncompressed
lengths fit**; other members use the pre-existing streaming decoder.
The size option requires compiled-in libdeflate but does not require the
libdeflate candidate to be selected. zipopt does **not** accept Zip's
`--use-libdeflate` toggle.

`--methods=` accepts comma-separated names from the registry in `codec.c`:
store, shrink, reduce-l1 through reduce-l4, implode-4k-2, implode-4k-3,
implode-8k-2, implode-8k-3, deflate, deflate64, dcl-implode-binary,
dcl-implode-ascii, bzip2, lzma, zstd, xz, and ppmd. The aliases `implode`, `reduce`,
and `dcl-implode` expand to all corresponding variants. `--methods=help`
prints the complete compiled-in candidate list (also printed for unknown method
names). Default `all` runs all compiled-in configurations, sequentially,
for every member; this can be very slow and
temporary-file intensive, especially with Zopfli and PPMd. All codecs are
attempted even if an existing stream is smaller. Zopfli defaults to 15
iterations (set --zopfli-iterations to 1..10000). DCL optimal parsing is
always off unless --dcl-implode-optimal is explicitly requested; it can be
extremely slow. Both controls affect only the relevant codecs.

A supported original compressed stream may win only when its **method number**
is enabled, regardless of the original encoder parameters; original method 6
Implode is therefore eligible if *any* Implode variant is enabled. Original
LZFSE, CMPSC and legacy Zstandard method 20 are never retained under `all`.

The input is parsed strictly and each member must decode with the linked UnZip
and match the original CRC and size. FWKCS MD5 extras are accepted and verified.
By default they are removed from the output; with `--fwkcs-md5`, the output
central directory includes FWKCS MD5 for each regular file (including empty
files), never newly adding it to directories. Pre-existing valid directory
FWKCS is retained if enabled.  The digest covers uncompressed bytes and never
appears in local extras.  The option never changes the compressed member
selection. Encryption, PKAV, RefPtr, SFX prefixes,  split archives, digital
signatures, and unrecognized extra fields are rejected.  Existing safe metadata,
member names/order/comments, archive comments, and compatible timestamps are
copied; ZIP64 and other compression-dependent records  are regenerated. Only
regular single-disk ZIP archives are supported.

Progress always identifies the member being processed, with filenames safely
escaped. The `[member current/total] index` prefix shows a right-aligned,
one-based position out of all central-directory entries (including directories),
followed by the original zero-based archive index. When multiple candidates are
enabled, a flushed progress dot appears as soon
as optimization begins and after each candidate completes; single-candidate
runs omit dots. Each selected-member line shows uncompressed size, original
packed member size, final packed member size, and three ZIP-style rounded
percentages (original compression ratio, savings relative to original packed
bytes, and final compression ratio relative to uncompressed bytes). The
selected method prints its three sizes on one line, then the three percentages
and the relative number of packed bytes saved or added on a second, aligned
line. The final archive summary shows the sum of uncompressed
member sizes, original physical ZIP file size, final physical ZIP file size,
and three percentages (original overall compression ratio, reduction from the
original physical ZIP size, and final overall compression ratio), followed by
the physical number of archive bytes saved (or added if output grew).
Archive physical sizes include headers, extras, and comments; member packed
sizes refer only to member compressed streams. Every reported byte quantity
uses comma-separated thousands, independent of locale; member counts and
ordinals remain ungrouped. Empty denominators display 0%. The 64-bit decimal
formatter also works when unsigned long is 32 bits.
On success, the first completion line names the output archive and number of
members (for example, `output.zip: complete [3 members]`). The physical sizes
appear on the following `zipopt:` line, and the ratios and bytes saved/added
on a second line indented to align after `zipopt: `. In verbose mode a blank
line separates the last member report from the completion header, after which
a right-aligned table lists the **actual output ZIP
methods**, sorted by ascending member count (then method number), and includes
directory entries as STORE. Implode and DCL configurations sharing a ZIP
method number are counted together. The method table is omitted in normal
mode. In verbose mode, the original stream and
all attempted candidates are listed in descending packed-size order (largest
first), with deterministic ties (original first, then method-registry order).
Verbose rows also show compression relative to the uncompressed member
size (one decimal place) and a signed percentage change against the original
packed stream: `+` means larger, `-` means smaller, and `=` means equal.
For example, `(+ 53.0%)` means the candidate is 53.0% larger than the original
packed stream. For zero-length original streams, a nonzero candidate reports
`n/a` instead of an undefined percentage. The original row identifies its
actual ZIP method, including whether the method is excluded by the selection.
All three verbose columns are right-aligned to the widest observed values
for the member; a blank line separates successive member records, including
directories.
Directory entries are canonicalized as empty STORE records and are not passed
through the codec search. On POSIX systems, SIGINT, SIGTERM, SIGHUP, and
SIGQUIT remove the named output temporary file before termination; unlinked
`tmpfile()` scratch files are cleaned up by the operating system. The private
UnZip build does not install conflicting process-wide signal handlers.

A private same-directory temporary output is completely finalized and each
member is decoded again and compared **byte-for-byte** with the source before
atomic no-overwrite publication. An existing output file is never replaced.
Any decoder, encoder, validation, or filesystem failure aborts and removes the
temporary archive. The input is checked for metadata, inode/path identity and
full-file fingerprint changes before publication; detection covers ordinary
concurrent file mutation, not malicious transformations that can restore the
original bytes and metadata between checks. Ordinary Zip/UnZip/zipdedup object files are not reused or
replaced by this build.

## WavPack / WinZip method 97 (optional encoder)

WavPack method 97 is included in `--methods=all` when libwavpack headers
and the encoder are linkable. Use `--methods=wavpack` to limit compression to
supported lossless WAV input, or `--methods=store,wavpack` to add a fallback.
If the library is absent, all other methods build as before; an explicit
`--methods=wavpack` fails with `codec wavpack was not built`.
The method is a strictly opt-in build dependency, not a new global ZIP option.

The settings `--wavpack-level=1|2|3|4|fast|standard|high|extra|very|veryhigh|very-high`
and `--wavpack-extra-level=0..6` default to `extra` and `6`. A zero extra
level disables only extra analysis, not WavPack compression. These settings
are accepted but ignored when the method is not selected. On success the
encoder calls **WavpackSetConfiguration()**, the legacy, compatible API,
and checks the *entire* emitted block stream for the WinZip-compatible
WavPack version `0x407`. It never produces the newer `0x410` stream.

Only ordinary RIFF/WAVE files with structurally valid 8/16/24/32-bit
PCM, 32-bit float, or their supported WAVEFORMATEXTENSIBLE variants are
candidates. Files are detected by content, not extension. Strict RIFF
length, chunk bounds, block alignment and sample-rate checks reject
unsupported formats as skipped candidates. Header and trailing RIFF chunks
(including padding) are saved losslessly through the WavPack wrapper API.
Large wrappers above 16 MiB, RF64, RIFX, Wave64, compressed WAV and unknown
formats are deliberately not WavPack candidates; other selected methods can
still compete. An already-encoded method-97 member may win unchanged whenever
WavPack is selected, following zipopt's general original retention rule.
When libwavpack decoding is linked, existing method-97 input is decoded even
with `--methods=store` or other selections that do not include WavPack.
WZ-MP3 and WZ-JPEG candidate/retention policies are unchanged.

`--wavpack-compat-reencode` (off by default) excludes original method-97
streams containing any WavPack 5 (`0x410`) block from original-stream
retention. A smaller alternative enabled by `--methods=` can still win; if
WavPack wins, it is freshly encoded as a WinZip-compatible V4 `0x407` stream,
even when this increases the archive size. Existing V4 streams may still win
unchanged. The option does not select an encoder and is accepted even without
WavPack support. If the only selected method is WavPack and it cannot
re-encode the decoded content, optimization fails without publishing output.
The final pre-publication verification independently rejects any method-97
output that is not a complete sequence of recognized pre-V5 blocks, including
opaque Xtro companions that cannot be rewritten.  The original archive is
never rewritten in place. Without the flag, existing retention behavior is
unchanged.

On Unix, `ZO_WAVPACK=auto` (default) checks that the header and encoder
library both compile and link (pkg-config, with `-lwavpack` fallback).
Set `ZO_WAVPACK=off` to disable both encoder and private decoder, or
`ZO_WAVPACK=on` to require a working SDK. Override `ZO_WAVPACK_CFLAGS` and
`ZO_WAVPACK_LIBS` for nonstandard installations.

The native Windows and DOS386 makefiles never auto-link WavPack. To opt in,
provide **both** the target encoder `-DZO_WITH_WAVPACK` (`WIN_CODEC_CPPFLAGS`
/ `DOS386_CODEC_CPPFLAGS`) and decoder `-DUSE_WAVP`
(`WIN_UNZIP_CPPFLAGS` / `DOS386_UNZIP_CPPFLAGS`), the target WavPack header
include flags, and the target WavPack library in `WIN_STATIC_LIBS` /
`DOS386_ZO_LIBS`. Omitting all these settings preserves the existing builds.

Run `python3 tests/test_zipopt_wavpack_encoder.py` after building. This test
checks WinZip stream-version headers, all 28 compression profiles, WAV
eligibility, lossless round trips, and original-stream retention. It does not
replace testing with actual WinZip releases or native DOS/Windows builds.

## Validation and scope

The shell/C regression suite in `tests/` checks the 19 encoders, the ordinal
UnZip decoder, ZIP writer, directory entries, SIGINT cleanup, and no-clobber
behavior. Optional real-world input fixtures can be provided using
`ZIPOPT_EXTRA_ARCHIVE=/path/to/sample.zip`.

The initial Unix backend uses `fseeko`/`ftello` and POSIX `mkstemp`, `link`,
and `unlink` for safe atomic publication; Windows requires a separate platform
backend, particularly for no-clobber output publication. Windows execution,
32-bit/DOS targets, ZIP64 files larger than 4 GiB, and external 7-Zip
interoperability remain separate release-certification tasks. There is no
threaded optimization in v1.
