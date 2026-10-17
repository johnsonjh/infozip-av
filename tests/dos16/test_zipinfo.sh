#!/bin/sh
# Validate that DOS16 ZipInfo is the exact UnZip binary, optionally in emu2.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
bin=${1:-"$root/dos16"}
test -s "$bin/unzip.exe"
test -s "$bin/zipinfo.exe"
cmp "$bin/unzip.exe" "$bin/zipinfo.exe"
printf '%s\n' 'PASS: DOS16 zipinfo.exe is byte-identical to unzip.exe'
if [ "${2:-}" != '' ]; then
    emu=$2
    output=$("$emu" -m 640 -c 8086 "$bin/zipinfo.exe" -h) || {
        echo 'FAIL: ZipInfo help did not execute under emu2' >&2
        exit 1
    }
    case "$output" in
        *'ZipInfo archive utility'*'usage:  zipinfo'*)
            printf '%s\n' 'PASS: 8086/640K emu2 entered ZipInfo mode' ;;
        *)
            echo 'FAIL: zipinfo.exe did not select ZipInfo mode' >&2
            exit 1 ;;
    esac
fi
