# WinZip WZ-MP3, ZIP Method 94

Original independently authored C89 decoder modules are stored here.
From any directory run `sh unzip60/wzmp3-src/amalgamate.sh` (or invoke
this script directly). It deterministically regenerates checked-in
`unzip60/wzmp3.c` and `unzip60/wzmp3.h`. Normal builds compile the existing
`extract.c`, which includes `wzmp3.c` conditionally. There is no on-build
generation, object target, or external MP3 dependency. Do not edit generated
files; make changes here and regenerate both files, and check them in.

Enabled by default in normal UnZip on non-16-bit builds. Disable via
`-DNO_WZMP3`. In UnZipSFX default is disabled; pass `D_USE_WZMP3_SFX=-DWZMP3_SFX`
to the Unix Makefile to enable (or set WZMP3_SFX for other platforms).
Excluded from fUnZip. For 16-bit builds, opt-in `-DWZMP3_16BIT` is possible
but NOT tested and may exceed conventional memory/segment limits.

Only decoding is provided. Supports the tested packMP3 stream version 1.0,
MPEG-1 Layer III mono/stereo. The output is the original MP3 bitstream, not
a PCM audio render. The ZIP layer checks the final CRC-32 and output sizes.

License: new decoder code MIT-0; MPEG Huffman data CC0 (or MIT-0) minimp3.

RefPtr (Method 92) is updated to permit Method 94 as a source where both
features are enabled; it re-decompresses the source directly from the ZIP.

The adapter bounds both compressed size addition and frame state allocation.
The MPEG decoder buffers the reconstructed main-data stream for reservoir
placement. It enforces a per-decoding-operation budget of 1,000,000,000 bytes
for all decoder-owned requested heap allocations, including allocation
bookkeeping, dynamically grown contexts, metadata, frame tables, and main
stream buffering. The adapter also reserves the static MPEG codebook-array
size from that budget. Allocator implementation overhead and UnZip's unrelated
memory usage are outside this portable, C89 decoder-local accounting.
Allocation failure or an exhausted budget returns PK_MEM3; malformed data
continues to return PK_ERR. This is why Method 94 is disabled by default for
16-bit builds. The limits do not change source-file CRC verification.

Integration regression details and test-coverage qualifications are recorded
in `INTEGRATION-TESTS.md`.
