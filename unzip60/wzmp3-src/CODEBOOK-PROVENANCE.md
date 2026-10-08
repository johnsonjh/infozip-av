# MPEG Layer III Huffman table provenance

The codewords in `wzmp3_codebooks.c` were generated exclusively from the
supplied `minimp3.h`, by the lieff/minimp3 authors. Its introductory notice
dedicates the source under Creative Commons Zero (CC0-1.0). The codebook data
in this file remains CC0; the new WZ-MP3 decoder logic is separately MIT-0.

Source data inside `L3_huffman` in minimp3:

- `tabs`: compact signed lookup table for MPEG Layer III pair symbols
- `tabindex`: individual Huffman table offsets
- `g_linbits`: MPEG table-specific extended-value widths
- `tab32` and `tab33`: four-value (count-one) tables

For each of the MPEG pair codebooks, the table-generation procedure enumerated
all first-level lookup prefixes. On a negative lookup entry, it followed the
secondary-lookup offset and consumed the indicated additional bits. On a
positive leaf, the final codeword is the concatenation of the consumed prefix
bits, truncated to its actual length. The **first** coefficient is in the low
nibble of a minimp3 leaf and the second is in its upper nibble. Swapping these
is an error; doing so caused initial full-file checks to fail.

The count-one tables were inverted similarly, including `tab32` secondary
entries. Reserved pair tables 4 and 14 have no codewords; table 0 emits no
Huffman bits for the (0,0) pair. Books 16..23 share the same base Huffman
codewords but have distinct linbits, as do books 24..31, so their base arrays
are stored once and reused during initialization.

The generated provider sets up the existing `wzmp3_codebook[34]` format using
only ISO C89 features. No LGPL implementation table or data is included.

Validation:

- Every pair codebook has the expected `(maxvalue+1)^2` codewords.
- Both count-one codebooks contain all sixteen codewords.
- No nonempty codeword is a prefix of another codeword in its book.
- Correct linbits widths are supplied for all books.
- Four genuine WinZip Method 94 streams reconstruct bit-identically to their
  original MP3s when using **only** these generated tables.

These checks are reproduced by `make test` and the interoperability matrix
in `TEST-REPORT.md`.
