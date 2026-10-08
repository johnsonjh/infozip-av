# WZ-MP3 Method 94 — final standalone regression report

## Build and unit tests

- GCC `-std=c89 -pedantic -Wall -Wextra -Werror`: **PASS**
- Clang `-std=c89 -pedantic -Wall -Wextra -Werror`: **PASS**
- Included codebook tests (pair/quad completeness and prefix-free codes): **PASS**
- Independent 31-bit arithmetic range coder: **6000/6000 symbols PASS**
- MPEG frame assembler boundary and output-failure tests: **PASS**
- GCC AddressSanitizer + UndefinedBehaviorSanitizer: **PASS** on all four
  positive streams; no reported memory/undefined behavior errors.

## Genuine WinZip ZIPX interoperability

The compressed Method 94 payloads were read **directly** from the ZIP local
headers in the supplied `mp3.zipx` and `mono.zipx`. Uncompressed byte sizes
and CRCs were taken from each ZIP central-directory record. The standalone
C89 decoder operated only on those compressed bytes and the known output size,
not on an original-file header, MP3 data, packMP3 executable, or separate
Huffman fixture. Original MP3s supplied by the user served only as comparison
files after decoding.

| File | ZIP compressed size | Restored size | ZIP CRC-32 | Result |
| --- | ---: | ---: | --- | --- |
| output_tone.mp3 | 45,113 | 81,127 | 0B794CC2 | byte-exact PASS |
| sample-15s-cbr-320kbps.mp3 | 451,655 | 602,950 | 89883FDD | byte-exact PASS |
| sample-15s-id3v2.mp3 | 307,683 | 369,869 | 54FEB508 | byte-exact PASS |
| sample-15s-vbr-v0.mp3 | 255,018 | 299,525 | 6E9F805B | byte-exact PASS |

Verified SHA-256 hashes of the reconstructed output:

```
9b3f14491c489ba5941d0f4e1eb1f6f64119d0c20b7a34b964771d643bddcf4a  output_tone.mp3
6c1f6e100606bfc708cb1e093ffd233fcdc6e697a1bed1f773d7db6b7e52e874  sample-15s-cbr-320kbps.mp3
2b372f993ad7a8c65e64a5bc000f2b21d0a32e802f61ba416515e8782c0cb55c  sample-15s-id3v2.mp3
82db1c69ecdb6adc051d7a49035745b3639b643b0133a3a6b10b7abd68ed6a4c  sample-15s-vbr-v0.mp3
```

Both GCC and Clang builds and the GCC sanitizer build reproduced these exact
bytes from the standalone stream corpus.

## Malformed inputs

A negative test set of **38** modified or shortened mono Method 94 inputs
(31 truncations, 7 header corruption cases) was rejected, with no successful
extraction. Four representative cases were separately checked under the
sanitizer build. Invalid output-size arguments and wrong expected output
sizes are also rejected.

## Scope/limitations

These results establish precise interoperability for the supplied four
MPEG-1 Layer III/packMP3 1.0 streams, not every conceivable ZIP Method 94
payload. CRC-bearing MPEG frames, MPEG-2/2.5, untested frame combinations,
and maliciously altered arithmetic streams have not been comprehensively
validated. The CLI is not a ZIP extractor and does not calculate ZIP CRC-32.
UnZip integration has deliberately not been performed.

No Python regression harness, original MP3 fixture, reference implementation,
LGPL codebook, or compiled library is bundled with the source release.
