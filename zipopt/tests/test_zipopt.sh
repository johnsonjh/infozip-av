#!/bin/sh
# AI/LLM generated codec and archive writer acceptance tests.
# SPDX-License-Identifier: MIT-0
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
rm -f build/candidate-*.zip build/progress-*.zip build/output-store.zip build/output-mixed.zip \
  build/output-implode.zip build/output-extra.zip build/bad-method.zip \
  build/output-empty.zip build/output-signed-desc.zip build/output-unsigned-desc.zip \
  build/output-directory.zip build/bad-directory-out.zip \
  build/output-iter1.zip build/output-iter20.zip build/output-dcl-optimal.zip \
  build/report-expanded.zip build/output-empty-report.zip \
  build/report-verbose.zip build/repetitive-source.zip build/three-report.zip \
  build/report-tie.zip build/report-all.zip build/report-columns.zip \
  build/report-method-eligible.zip build/report-method-counts.zip build/report-nonverbose-counts.zip \
  build/report-twelve.zip
printf 'zipopt test text text text text text\nabcabcabcabcabcabcabc\n' > build/input.dat
# All 19 candidate bitstreams must decode through the embedded UnZip API.
i=0
while test "$i" -lt 19; do
  ./codec-probe "$i" build/input.dat "build/candidate-$i.zip"
  ./zipopt-decodecheck "build/candidate-$i.zip" >/dev/null
  i=$((i+1))
done
# Strict structural preflight, empty output and descriptor processing.
./zipopt --methods=store build/empty-structure.zip build/output-empty.zip
./zipopt-decodecheck build/output-empty.zip
if ./zipopt-preflight build/bad-empty-prefix.zip >/dev/null 2>&1; then
  echo 'FAILED: prefixed empty archive accepted' >&2
  exit 1
fi
./zipopt --methods=store build/signed-desc.zip build/output-signed-desc.zip
./zipopt-decodecheck build/output-signed-desc.zip
./zipopt --methods=store build/unsigned-desc.zip build/output-unsigned-desc.zip
./zipopt-decodecheck build/output-unsigned-desc.zip
# Directories are empty structural entries and bypass every encoder.
./zipopt --methods=deflate build/directory-structure.zip build/output-directory.zip \
    2>build/directory.log
./zipopt-decodecheck build/output-directory.zip
if ! grep '"folder/": directory' build/directory.log >/dev/null ||
   grep 'compressor ' build/directory.log >/dev/null; then
  echo 'FAILED: directory status or bypass' >&2
  exit 1
fi
if ./zipopt --methods=store build/bad-directory.zip build/bad-directory-out.zip \
     >/dev/null 2>&1; then
  echo 'FAILED: directory with nonempty data accepted' >&2
  exit 1
fi
# Method help is authoritative and works without archive positional arguments.
./zipopt --methods=help >build/methods-help.log
for method in store shrink reduce-l1 reduce-l4 implode-8k-3 deflate64 \
              dcl-implode-binary dcl-implode-ascii zstd ppmd \
              pkzip1 pkzip2 winzip; do
  if ! grep "$method" build/methods-help.log >/dev/null; then
    echo "FAILED: --methods=help omitted $method" >&2; exit 1
  fi
done
if ./zipopt --methods=unknown-method >build/methods-invalid.log 2>&1; then
  echo 'FAILED: unknown --methods token accepted' >&2; exit 1
fi
if ! grep 'invalid --methods selection' build/methods-invalid.log >/dev/null ||
   ! grep 'implode-8k-3' build/methods-invalid.log >/dev/null; then
  echo 'FAILED: invalid method did not show valid method list' >&2; exit 1
fi
# The profiles and exclusions must be usable together in the real CLI.
# Each expression below reduces to STORE alone, so outputs must match.
./zipopt --methods=store build/candidate-0.zip build/progress-method-ref.zip \
    2>build/progress-method-ref.log
for selection in 'pkzip1,-shrink,-reduce,-implode' \
                 'pkzip2,-shrink,-reduce,-implode,-deflate' \
                 'winzip,-all,store' \
                 'all,-bzip2,bzip2,-bzip2,-all,store' \
                 '-all,store'; do
  ./zipopt "--methods=$selection" build/candidate-0.zip \
      build/progress-method-test.zip 2>build/progress-method-test.log
  if ! cmp -s build/progress-method-ref.zip build/progress-method-test.zip; then
    echo "FAILED: --methods=$selection did not select STORE only" >&2; exit 1
  fi
done
if ./zipopt --methods=-all build/candidate-0.zip build/progress-method-empty.zip \
      >build/progress-method-empty.log 2>&1 ||
   ! grep 'selects no available candidates' build/progress-method-empty.log >/dev/null; then
  echo 'FAILED: empty final --methods selection was not rejected' >&2; exit 1
fi
# One selected method does not emit progress dots. Multiple selected methods do.
./zipopt --methods=store build/candidate-0.zip build/progress-single.zip \
  2>build/progress-single.log
if ! grep 'optimizing$' build/progress-single.log >/dev/null ||
   grep 'optimizing\.' build/progress-single.log >/dev/null ||
   ! grep '^            (.*% -> .*% -> .*%) \[.* bytes saved\]$' build/progress-single.log >/dev/null; then
  echo 'FAILED: single-method progress/ratio' >&2; exit 1
fi
./zipopt --methods=store,deflate build/candidate-0.zip build/progress-multi.zip \
  2>build/progress-multi.log
if ! grep 'optimizing\.\.' build/progress-multi.log >/dev/null ||
   ! grep '^            (.*% -> .*% -> .*%) \[.* bytes saved\]$' build/progress-multi.log >/dev/null; then
  echo 'FAILED: multi-method progress/ratio' >&2; exit 1
fi
./zipopt-decodecheck build/progress-single.zip
./zipopt-decodecheck build/progress-multi.zip
# Three-size reporting compares uncompressed, input packed, and final packed
# member bytes. Archive totals use physical input/output ZIP lengths, so
# metadata overhead is included and may produce negative percentages.
source_bytes=$(wc -c < build/candidate-0.zip | tr -d '[:space:]')
result_bytes=$(wc -c < build/progress-single.zip | tr -d '[:space:]')
unpacked_bytes=$(wc -c < build/input.dat | tr -d '[:space:]')
if ! grep -Fx "  selected: original, $unpacked_bytes bytes -> $unpacked_bytes bytes -> $unpacked_bytes bytes" \
     build/progress-single.log >/dev/null ||
   ! grep -Fx '            (0% -> 0% -> 0%) [0 bytes saved]' \
     build/progress-single.log >/dev/null ||
   ! grep -Fx '[member 1/1] "data": optimizing' \
     build/progress-single.log >/dev/null ||
   ! grep -Fx "build/progress-single.zip: complete [1 member]" build/progress-single.log >/dev/null ||
   ! grep -Fx "zipopt: $unpacked_bytes bytes -> $source_bytes bytes -> $result_bytes bytes" \
     build/progress-single.log >/dev/null ||
   ! grep -F '0 bytes saved]' build/progress-single.log >/dev/null; then
  echo 'FAILED: three-size member or archive summary' >&2; exit 1
fi
# A real improvement must report physical ZIP-file bytes saved, not merely
# the sum of compressed member payloads.
smaller_bytes=$(wc -c < build/progress-multi.zip | tr -d '[:space:]')
if test "$smaller_bytes" -ge "$source_bytes" ||
   ! grep -Fx "zipopt: $unpacked_bytes bytes -> $source_bytes bytes -> $smaller_bytes bytes" \
      build/progress-multi.log >/dev/null ||
   ! grep -F "$((source_bytes - smaller_bytes)) bytes saved]" \
      build/progress-multi.log >/dev/null; then
  echo 'FAILED: physical archive savings report' >&2; exit 1
fi
# A disallowed original Deflate stream expands when recompressed with STORE.
# Verify signed percentages and an archive-level "bytes added" result.
rm -f build/report-expanded.zip
./zipopt --methods=store build/candidate-8.zip build/report-expanded.zip \
    2>build/report-expanded.log
./zipopt-decodecheck build/report-expanded.zip
packed_input=$(wc -c < build/candidate-8.zip | tr -d '[:space:]')
packed_result=$(wc -c < build/report-expanded.zip | tr -d '[:space:]')
if test "$packed_result" -le "$packed_input" ||
   ! grep -E "^  selected: store, $unpacked_bytes bytes -> [0-9]+ bytes -> $unpacked_bytes bytes$" \
      build/report-expanded.log >/dev/null ||
   ! grep -E '^            \([0-9]+% -> -[0-9]+% -> 0%\) \[[0-9,]+ bytes added\]$' \
      build/report-expanded.log >/dev/null ||
   ! grep -Fx "zipopt: $unpacked_bytes bytes -> $packed_input bytes -> $packed_result bytes" \
      build/report-expanded.log >/dev/null ||
   ! grep -F "$((packed_result - packed_input)) bytes added]" \
      build/report-expanded.log >/dev/null; then
  echo 'FAILED: expansion ratios or archive bytes added' >&2; exit 1
fi
# Verbose sizes must align to the widest observed size, even when STORE
# expands the original packed size from two digits to five digits.
awk 'BEGIN {for(i=0;i<10000;i++)printf "AAAA"}' > build/repetitive-input.dat
./codec-probe 10 build/repetitive-input.dat build/repetitive-source.zip
./zipopt -v --methods=store,shrink \
    build/repetitive-source.zip build/report-verbose.zip \
    2>build/report-verbose.log
./zipopt-decodecheck build/report-verbose.zip
if ! awk '
    BEGIN {n=0}
    /^  (original|store|shrink) +[0-9,]+ bytes/ {
        col=index($0," bytes");
        if(!first)first=col;
        if(col!=first)bad=1;
        n++;
    }
    END {if(bad || n!=3)exit 1}
' build/report-verbose.log ||
   ! grep -E '^  selected: shrink, 40,000 bytes -> [0-9,]+ bytes -> [0-9,]+ bytes$' \
      build/report-verbose.log >/dev/null ||
   ! grep -E '^            \([0-9]+% -> -[0-9]+% -> [0-9]+%\) \[[0-9,]+ bytes added\]$' \
      build/report-verbose.log >/dev/null; then
  echo 'FAILED: verbose alignment, starting ratio, or negative savings' >&2
  exit 1
fi
# The verbose list (including the original compressed stream) must be
# largest-to-smallest, without losing the aligned columns or the selected
# method. This fixture exercises three distinct compressed stream sizes.
if ! awk '
    BEGIN {n=0}
    /^  (original|store|shrink) +[0-9,]+ bytes/ {
        size=$2;gsub(/,/,"",size);
        if(n && size+0>previous)bad=1;
        previous=size+0;
        label[n]=$1;
        n++;
    }
    END {
        if(n!=3 || bad || label[0]!="store" ||
           label[1]!="shrink" || label[2]!="original")exit 1;
    }
' build/report-verbose.log; then
  echo 'FAILED: verbose results not in descending packed-size order' >&2
  exit 1
fi
# On a tie, the original must precede the equal-sized STORE candidate.
# Choosing the same method must not change the actual output stream.
./zipopt -v --methods=store build/candidate-0.zip build/report-tie.zip \
    2>build/report-tie.log
./zipopt-decodecheck build/report-tie.zip
if ! awk '
    BEGIN {n=0}
    /^  (original|store) +[0-9,]+ bytes/ {
        if(n==0 && $1!="original")bad=1;
        size=$2;gsub(/,/,"",size);
        if(n==1 && ($1!="store" || size+0!=previous))bad=1;
        previous=size+0;
        n++;
    }
    END {if(bad || n!=2)exit 1}
' build/report-tie.log ||
   ! grep '^  selected: original,' build/report-tie.log >/dev/null; then
  echo 'FAILED: verbose original/candidate tie order or selection' >&2
  exit 1
fi
# The complete default candidate set must also sort without dropping or
# duplicating entries: 19 encoded candidates plus the original stream.
./zipopt -v --methods=all build/candidate-0.zip build/report-all.zip \
    2>build/report-all.log
./zipopt-decodecheck build/report-all.zip
if ! awk '
    BEGIN {n=0}
    /^  [a-z][a-z0-9-]* +[0-9,]+ bytes/ {
        size=$2;gsub(/,/,"",size);
        if(n && size+0>previous)bad=1;
        previous=size+0;
        n++;
    }
    END {if(bad || n!=20)exit 1}
' build/report-all.log; then
  echo 'FAILED: full verbose candidate list order/count' >&2
  exit 1
fi
# Verbose ratio and relative-change columns must be aligned for rows with
# larger, equal, and smaller packed sizes. Preserve method identification.
./zipopt -v --methods=store,shrink,deflate \
    build/candidate-8.zip build/report-columns.zip \
    2>build/report-columns.log
./zipopt-decodecheck build/report-columns.zip
if ! awk '
    /^  (original|store|shrink|deflate) +[0-9,]+ bytes/ {
        n++;
        size=index($0," bytes");
        ratio=index($0,"%   (");
        closing=index($0,"%)");
        if(!size || !ratio || !closing)bad=1;
        if(n==1) {base_size=size;base_ratio=ratio;base_close=closing}
        if(size!=base_size || ratio!=base_ratio || closing!=base_close)bad=1;
    }
    END {if(n!=4 || bad)exit 1}
' build/report-columns.log ||
   ! grep -E '^  store +59 bytes +0\.0% +\(\+ *18\.0%\)' \
       build/report-columns.log >/dev/null ||
   ! grep -E '^  original +50 bytes +15\.3% +\(= *0\.0%\) \[implode, method 6, excluded\]$' \
       build/report-columns.log >/dev/null ||
   ! grep -E '^  shrink +39 bytes +33\.9% +\(- *22\.0%\)' \
       build/report-columns.log >/dev/null ||
   ! grep -E '^  deflate +23 bytes +61\.0% +\(- *54\.0%\)' \
       build/report-columns.log >/dev/null; then
  echo 'FAILED: signed verbose percentages, method names or alignment' >&2
  exit 1
fi
# An original stream that is eligible must identify its actual method
# without an excluded suffix. Equal-sized candidate results use '=' too.
./zipopt -v --methods=deflate \
    build/candidate-10.zip build/report-method-eligible.zip \
    2>build/report-method-eligible.log
./zipopt-decodecheck build/report-method-eligible.zip
if ! grep -E '^  original +[0-9]+ bytes +[0-9]+\.[0-9]% +\(= *0\.0%\) \[deflate, method 8\]$' \
      build/report-method-eligible.log >/dev/null ||
   ! grep -E '^  deflate +[0-9]+ bytes +[0-9]+\.[0-9]% +\(= *0\.0%\)$' \
      build/report-method-eligible.log >/dev/null; then
  echo 'FAILED: eligible original method label or equal-size change' >&2
  exit 1
fi
# Verbose output must separate all member types, including directories,
# without a leading separator before the first member.
./zipopt -v --methods=store build/three-structure.zip build/three-report.zip \
    2>build/three-report.log
./zipopt-decodecheck build/three-report.zip
if ! awk '
    /^\[member [ 0-9]+\/[0-9]+\] / {
        if(seen && previous!="")bad=1;
        if(!seen && lines!=0)bad=1;
        seen++;
    }
    {previous=$0;lines++}
    END {if(bad || seen!=3)exit 1}
' build/three-report.log ||
   ! grep '"folder/": directory' build/three-report.log >/dev/null; then
  echo 'FAILED: verbose per-member spacing' >&2
  exit 1
fi
# Progress is one-based and right-aligned to the decimal width of the total,
# while the archive index after the bracket remains zero-based. This includes
# empty STORE directories in both ordinal and total counts.
./zipopt -v --methods=store build/twelve-structure.zip build/report-twelve.zip \
    2>build/report-twelve.log
./zipopt-decodecheck build/report-twelve.zip
if ! grep -Fx '[member  1/12] "d00/": directory' build/report-twelve.log >/dev/null ||
   ! grep -Fx '[member  9/12] "d08/": directory' build/report-twelve.log >/dev/null ||
   ! grep -Fx '[member 10/12] "d09/": directory' build/report-twelve.log >/dev/null ||
   ! grep -Fx '[member 12/12] "d11/": directory' build/report-twelve.log >/dev/null ||
   ! grep -Fx 'build/report-twelve.zip: complete [12 members]' build/report-twelve.log >/dev/null; then
  echo 'FAILED: member count/prefix alignment or directory accounting' >&2; exit 1
fi
# Per-method method-ID histogram is verbose-only, counts the actual written
# methods including directory STORE records, and sorts by ascending counts.
# The archive summary uses physical file bytes and three ratios. Its total
# includes commas even when the ordinary member ordinal does not.
./zipopt -v --methods=store,deflate \
    build/three-mixed.zip build/report-method-counts.zip \
    2>build/report-method-counts.log
./zipopt-decodecheck build/report-method-counts.zip
if ! awk '
    /^build\/report-method-counts\.zip: complete/ {
        if(last!="")bad=1;
        seen++;
    }
    {last=$0}
    END {if(bad || seen!=1)exit 1}
' build/report-method-counts.log; then
  echo 'FAILED: verbose completion lacks blank-line separator' >&2; exit 1
fi
if ! awk '
    /^build\/report-method-counts\.zip: complete \[3 members\]$/ {section=1;next}
    section && /^  +[0-9]+ / {
        tally++;
        if(tally==1 && !($1==1 && $2=="deflate"))bad=1;
        if(tally==2 && !($1==2 && $2=="store"))bad=1;
        next;
    }
    section && /^zipopt: / {section=0;summary++}
    END {if(bad || tally!=2 || summary!=1)exit 1}
' build/report-method-counts.log ||
   ! grep -E '^zipopt: 4,099 bytes -> [0-9,]+ bytes -> [0-9,]+ bytes$' \
    build/report-method-counts.log >/dev/null ||
   ! grep -E '^        \(-?[0-9]+% -> -?[0-9]+% -> -?[0-9]+%\) \[[0-9,]+ bytes saved\]$' \
    build/report-method-counts.log >/dev/null; then
  echo 'FAILED: method histogram, physical size comma grouping or summary ratios' >&2
  exit 1
fi
./zipopt --methods=store,deflate build/three-mixed.zip \
    build/report-nonverbose-counts.zip 2>build/report-nonverbose-counts.log
if grep -E '^  +[0-9]+ (deflate|store)$' \
     build/report-nonverbose-counts.log >/dev/null; then
  echo 'FAILED: method histogram leaked into non-verbose output' >&2
  exit 1
fi
if ! awk '
    /^build\/report-nonverbose-counts\.zip: complete/ {
        if(last=="")bad=1;
        seen++;
    }
    {last=$0}
    END {if(bad || seen!=1)exit 1}
' build/report-nonverbose-counts.log; then
  echo 'FAILED: non-verbose completion has unexpected separator' >&2; exit 1
fi
# Multiple-digit groupings must also be present in verbose candidate and
# member selected lines. This validates the display without locale settings.
if ! grep -E '^  store +40,000 bytes' build/report-verbose.log >/dev/null ||
   ! grep 'selected: shrink, 40,000 bytes -> ' \
      build/report-verbose.log >/dev/null; then
  echo 'FAILED: grouped member sizes in verbose output' >&2
  exit 1
fi
# Empty archives have no members; summary must still use finite ratios.
./zipopt --methods=store build/empty-structure.zip build/output-empty-report.zip \
    2>build/output-empty-report.log
if ! grep -Fx 'zipopt: 0 bytes -> 22 bytes -> 22 bytes' \
      build/output-empty-report.log >/dev/null ||
   ! grep -Fx '        (0% -> 0% -> 0%) [0 bytes saved]' \
      build/output-empty-report.log >/dev/null ||
   ! grep -Fx 'build/output-empty-report.zip: complete [0 members]' \
      build/output-empty-report.log >/dev/null; then
  echo 'FAILED: empty-archive summary' >&2; exit 1
fi
if ./zipopt-preflight build/bad-local-timestamp.zip >/dev/null 2>&1; then
  echo 'FAILED: mismatched local/central DOS timestamp accepted' >&2; exit 1
fi
# Test the production writer and candidate-selection dispatcher.
./zipopt --methods=store build/candidate-0.zip build/output-store.zip
./zipopt-decodecheck build/output-store.zip
./zipopt --methods=store,deflate build/candidate-0.zip build/output-mixed.zip
./zipopt-decodecheck build/output-mixed.zip
./zipopt --methods=implode build/candidate-6.zip build/output-implode.zip
./zipopt-decodecheck build/output-implode.zip
# Tunable Zopfli must honor different valid iteration counts.
./zipopt --methods=deflate --zopfli-iterations=1 \
    build/candidate-0.zip build/output-iter1.zip
./zipopt-decodecheck build/output-iter1.zip
./zipopt --methods=deflate --zopfli-iterations 20 \
    build/candidate-0.zip build/output-iter20.zip
./zipopt-decodecheck build/output-iter20.zip
# The default DCL search remains non-optimal; opt-in enables both modes.
./zipopt --methods=dcl-implode --dcl-implode-optimal \
    build/candidate-0.zip build/output-dcl-optimal.zip
./zipopt-decodecheck build/output-dcl-optimal.zip
for bad in 0 10001 garbage -5 +2 1x; do
  if ./zipopt --zopfli-iterations="$bad" --methods=store \
       build/candidate-0.zip build/bad-option.zip >/dev/null 2>&1; then
    echo 'FAILED: invalid Zopfli iteration count accepted' >&2; exit 1
  fi
done
if ./zipopt --methods=store --zopfli-iterations=12 \
     build/candidate-0.zip build/bad-option.zip >/dev/null 2>&1; then
  echo 'FAILED: Zopfli control silently accepted without Deflate' >&2
  exit 1
fi
if ./zipopt --methods=store --dcl-implode-optimal \
     build/candidate-0.zip build/bad-option.zip >/dev/null 2>&1; then
  echo 'FAILED: DCL control silently accepted without a DCL candidate' >&2
  exit 1
fi
# Local/central extraction version mismatch must be rejected by preflight.
if ./zipopt-preflight build/bad-local-version.zip >/dev/null 2>&1; then
  echo 'FAILED: mismatched local and central extraction versions' >&2; exit 1
fi
# Disallow overwrite; it must not damage the existing output.
if ./zipopt --methods=store build/candidate-0.zip build/output-store.zip; then
  echo 'FAILED: existing output was overwritten' >&2
  exit 1
fi
# Reject ambiguous and invalid method lists.
if ./zipopt --methods=made-up build/candidate-0.zip build/bad-method.zip; then
  echo 'FAILED: invalid method was accepted' >&2
  exit 1
fi
if test -n "${ZIPOPT_EXTRA_ARCHIVE:-}"; then
  ./zipopt --methods=store,deflate "$ZIPOPT_EXTRA_ARCHIVE" build/output-extra.zip
  ./zipopt-decodecheck build/output-extra.zip
fi
printf '%s\n' 'PASS: 19 codecs, tunable parsers, writer, source stability, rejects'
