# WZ-MP3 (ZIP Method 94) - standalone ANSI C89 decoder

This directory contains a **self-contained standalone decoder** for WinZip
WZ-MP3 / packMP3 stream version 1.0. It reconstructs the original MPEG-1
Layer III bitstream byte-for-byte. It does **not** decode audio to PCM,
compress files, link to packMP3, or depend on any system MP3 decoder.

The decoder source is independently written and **MIT-0** licensed. The MPEG
Huffman codebook data in `wzmp3_codebooks.c` is derived solely from the
user-supplied [`minimp3.h`](https://github.com/lieff/minimp3) (CC0-1.0,
public-domain dedication), or MIT-0 at your option.  No LGPL packMP3
source code, objects, or Huffman tables were used.

## Building

From this directory, compile with an ANSI C89 compiler:

```sh
cc -std=c89 -pedantic -Wall -Wextra -Werror -O2 -o wzmp3decode \
  wzmp3_core.c wzmp3_ppm.c wzmp3_binary.c wzmp3_regions.c \
  wzmp3_granule.c wzmp3_spectral.c wzmp3_mpeg.c wzmp3_tail.c \
  wzmp3_make.c wzmp3_join.c wzmp3_decode.c wzmp3_codebooks.c wzmp3_cli.c
```

The CLI takes a **raw Method 94 / `.pmp` bitstream**, an output filename,
and the **expected uncompressed output length in bytes**:

```sh
./wzmp3decode input.pmp reconstructed.mp3 81127
```

When extracting ZIP Method 94, the expected size comes from the ZIP central
directory. This standalone CLI does not parse ZIP containers or verify ZIP
CRC-32; those checks belong in the planned UnZip integration. The CLI deletes
partial output on decoding failure and refuses identical textual input/output
paths. It requires no original MP3 or external codebook file at runtime.

## Verified interoperability

Four authentic WinZip Method 94 samples (extracted from the supplied `.zipx`
archives) were reconstructed **byte-for-byte** using only their PMP payloads,
with the expected output size taken from the ZIP header:

- `output_tone.mp3`, MPEG-1 mono, 81,127 bytes
- `sample-15s-cbr-320kbps.mp3`, stereo CBR, 602,950 bytes
- `sample-15s-id3v2.mp3`, stereo with ID3, 369,869 bytes
- `sample-15s-vbr-v0.mp3`, stereo VBR, 299,525 bytes

GCC and Clang strict C89 builds, AddressSanitizer/UndefinedBehaviorSanitizer,
and truncated-input rejection are covered by the accompanying verification
report. Run `test_codebooks.c` against `wzmp3_codebooks.c` for pair/count-one
completeness and prefix-code consistency. The original MP3/audio test files
are **not redistributed** in this source archive.

## Compatibility scope

The demonstrated profile is MPEG-1 Layer III with its tested mono/stereo,
metadata, and CBR/VBR variations. MPEG CRC-protected frames, other MPEG
layers/versions, and untested encoder variants are **not** claimed as supported.
The implementation checks stream boundaries, output size, and many malformed
conditions but does not replace a ZIP CRC verification or authenticated input.

This is the unamalgamated upstream decoder source. In the integrated
UnZip tree, the checked-in `../wzmp3.c` and `../wzmp3.h` are its compiled
amalgamation; `amalgamate.sh` regenerates both deterministically. Refer to
`INTEGRATION.md` for the precise build-feature and SFX policies.
