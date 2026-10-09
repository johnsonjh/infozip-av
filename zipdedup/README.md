# zipdedup

- Source archives must be single-disk, not encrypted and not damaged.

- Archives with PKAV, AES, authenticated certificate extras, central-directory
  digital signatures, or unknown central-directory trailing data are refused.

- ZIP64 sizes, offsets, and end records work on platforms with file-position
  support for the archives offsets, but the current code is using `long` for
  seeking positions, which means that on 32-bit platforms, members bigger
  than `LONG_MAX` cannot (yet) be handled.

- Zip64 complex extensible data support is out of scope too (at least for now).

- The UnZip build is what determines what methods can be hashed.

- Duplicated member names and names containing wildcard characters get refused
  when hashing because they would be ambiguous through the existing API.

- No support for split archives.

- No support for atomic creation on non-POSIX platforms.

- Proper support for Windows and DOS, and "secure" UUID generation needs
  separate platform support.

- The WinZip dedup checksum is:

  ```
  LE32(method) || LE16(DOS time) || LE16(DOS date) || LE32(file CRC32) || UUID[16]
  ```

  It is calculated using the standard ZIP CRC32. See `test_refptr9903.c`.
  Unix timestamp extra data is not mixed/substituted into this checksum, which
  seems to be the correct thing to do currently.  More information is needed.

- Missing/bad/wrong `0x9903` metadata or UUID problems produce warnings and
  warn if file contents otherwise pass all integrity checks.

- Any SHA1 hash mismatch, uncompressed size mismatch, or CRC32 mismatch will
  cause an error.

- Any selected references and their verified sources are verified but any
  unrelated (invalid) references does not affect (selective) extractions.

- A regression suite run with `make test` is included.  Please note that it
  was generated using AI/LLM assistance but does seem sound!  `make test`
  only after the rest of the project is built or errors are expected.

- Similarly AI/LLM was used for making the man page (so it probably sucks).
