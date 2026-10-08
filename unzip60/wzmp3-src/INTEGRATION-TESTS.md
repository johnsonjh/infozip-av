# WZ-MP3 Method 94 integration verification (cu14 baseline)

This file describes tests run on the integrated decoder (not tests claimed for
untested MPEG profiles or older operating systems). No Python test harness is
checked into the source tree.

* The checked-in amalgamation (`../wzmp3.c` and `../wzmp3.h`) was regenerated
  by `sh wzmp3-src/amalgamate.sh` and the SHA-256 hashes matched byte-for-byte.
* The amalgamation compiled under GCC and Clang, `-std=c89 -pedantic -Wall
  -Wextra -Werror`. The original C89 standalone codebook, arithmetic and frame
  joining unit tests also passed with GCC and Clang.
* Normal UnZip built with the cu14 Unix `generic_gcc` configuration. Both
  authentic Method 94 WinZip archives passed `unzip -t`; `unzip -p` outputs
  for all four members matched the original MP3s byte-for-byte (mono, CBR,
  VBR, and ID3). The original BZip2 control entry in mp3.zipx also passed.
* Thirty-two alterations of Method 94 member payloads (signature, header,
  beginning, middle and end of streams) were tested. All were rejected with
  nonzero status; none was reported as successfully extracted.
* Method 96 JPEG: all five JPEG entries in `Q1 pictures.zipx` passed. Stored,
  Deflate and Method 92 RefPtr candidates passed an independent synthetic
  mixed-method archive. A Method 92 entry referencing a Method 94 source
  also passed both CRC and SHA-1 verification and produced the original bytes.
* GCC AddressSanitizer and UndefinedBehaviorSanitizer builds passed authentic
  Method 94 archives, Method 96 JPEG, and the synthetic RefPtr archives,
  without reported findings. The `REENTRANT` extraction compilation succeeded.
* Default SFX: Method 94 is excluded and is reported as unsupported. With
  `D_USE_WZMP3_SFX=-DWZMP3_SFX`, a SFX archive containing a Method 94 entry
  passed. Enabling both `WZMP3_SFX` and `REFPTR_SFX` successfully tested an
  archive referencing a Method 94 source.
* A full `-DNO_WZMP3` build reported Method 94 as unsupported while still
  building successfully. The `-D__16BIT__` preprocessor test confirmed the
  feature is not compiled by default; no real 16-bit compiler was available.
* The patch was applied to a fresh cu14 extraction. The normal build,
  JPEG, MP3 and synthetic RefPtr tests passed again. A `-xa` extraction of
  the mono MP3 reported `[binary]` and matched the original file.
