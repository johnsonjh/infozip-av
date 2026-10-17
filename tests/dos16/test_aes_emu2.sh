#!/bin/sh
# DOS16 AES runtime regression under emu2 with a controlling terminal.
# Tests ordinary PIT salts, explicit external pools and no silent downgrade.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
bin=${1:-"$root/dos16"}
emu=${2:-emu2}
bin=$(CDPATH= cd -- "$bin" && pwd -P)
emu=$(command -v "$emu") || { echo 'ERROR: emu2 not found' >&2; exit 2; }
command -v timeout >/dev/null 2>&1 || { echo 'ERROR: timeout required' >&2; exit 2; }
command -v script >/dev/null 2>&1 || { echo 'ERROR: script PTY required' >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 3 15
cd "$tmp"
printf 'AES DOS16 regression file\n' > CHECK.TXT
i=0
while [ "$i" -lt 80 ]; do
    printf 'Repeatable DOS16 compressed input 0123456789\n' >> LARGE.TXT
    i=$((i + 1))
done
run()
{
    tool=$1
    shift
    # Controlled 8.3 filenames and literal options only.
    timeout 120 script -q -e -c "'$emu' -c 8086 -m 640 '$bin/$tool.exe' $* -- TZ=UTC" /dev/null > run.log 2>&1
}
# Default DOS16 needs no external salt file for AES.  Exercise all strengths,
# two entries each, and verify with DOS UnZip under the same 8086 limit.
for strength in 128 192 256; do
    test ! -e XTRRND.BIN
    run zip -9 -eP dos16test --aes-strength "$strength" "PIT$strength.ZIP" CHECK.TXT LARGE.TXT
    grep 'PIT-derived salts' run.log >/dev/null || {
        cat run.log >&2
        echo 'FAIL: expected DOS16 PIT fallback notice' >&2
        exit 1
    }
    run unzip -t -P dos16test "PIT$strength.ZIP"
    grep 'No errors detected' run.log >/dev/null || {
        cat run.log >&2
        exit 1
    }
    echo "PASS: emu2 8086/640K PIT AES-$strength creation and verification"
done
# An explicitly selected external source retains priority and is consumed.
[ -r /dev/urandom ] || { echo 'ERROR: /dev/urandom required for pool regression' >&2; exit 2; }
dd if=/dev/urandom of=XTRRND.BIN bs=16 count=16 2>/dev/null
run zip -9 -eP dos16test --aes-strength 256 POOL.ZIP CHECK.TXT LARGE.TXT
if grep 'PIT-derived salts' run.log >/dev/null; then
    echo 'FAIL: unexpectedly switched to PIT despite external pool' >&2
    exit 1
fi
run unzip -t -P dos16test POOL.ZIP
grep 'No errors detected' run.log >/dev/null
test ! -e XTRRND.BIN && test ! -e XTRRND.USE && test ! -e xtrrnd.use || {
    echo 'FAIL: salt pool not consumed and cleaned' >&2
    exit 1
}
# A named-but-missing pool must error, not silently switch to PIT.
if timeout 120 script -q -e -c "'$emu' -c 8086 -m 640 '$bin/zip.exe' -9 -eP dos16test NAMED.ZIP CHECK.TXT -- TZ=UTC XTR_AES_POOL=MISSING.BIN" /dev/null > run.log 2>&1; then
    echo 'FAIL: missing explicitly selected AES pool was accepted' >&2
    exit 1
else
    code=$?
    if [ "$code" -ne 21 ]; then
        cat run.log >&2
        echo "FAIL: wrong missing-pool code $code" >&2
        exit 1
    fi
fi
printf 'PASS: DOS16 PIT salts, pool priority, and explicit missing-pool failure\n'
