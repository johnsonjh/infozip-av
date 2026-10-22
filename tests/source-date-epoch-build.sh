#!/bin/sh
# SPDX-License-Identifier: MIT-0
# Validate SOURCE_DATE_EPOCH before compilation and produce safe preprocessor
# token definitions. POSIX sh/awk only: no eval, date(1), or shell input code.
set -eu
LC_ALL=C
export LC_ALL
case "${1-}" in
validate | flags | utc) ;;
*)
  printf '%s\n' 'usage: source-date-epoch-build.sh validate|flags|utc' >&2; exit 2
  ;;
esac
if [ "${SOURCE_DATE_EPOCH+x}" != x ]; then
  exit 0
fi
awk -v format="$1" '
BEGIN {
  s = ENVIRON["SOURCE_DATE_EPOCH"]
  if (s == "" || s !~ /^[0-9]+$/) bad()
  sub(/^0+/, "", s)
  if (s == "") s = "0"
  if (length(s) < 9 || length(s) > 10) bad()
  n = s + 0
  if (n < 315532800 || n > 2147483647) bad()
  if (format == "validate") exit 0

  # Howard Hinnant civil_from_days, with nonnegative days for this range.
  days = int(n / 86400)
  seconds = n - days * 86400
  z = days + 719468
  era = int(z / 146097)
  doe = z - era * 146097
  yoe = int((doe - int(doe / 1460) + int(doe / 36524) \
             - int(doe / 146096)) / 365)
  y = yoe + era * 400
  doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
  mp = int((5 * doy + 2) / 153)
  d = doy - int((153 * mp + 2) / 5) + 1
  m = mp + (mp < 10 ? 3 : -9)
  if (m <= 2) y++
  hh = int(seconds / 3600)
  mm = int((seconds - hh * 3600) / 60)
  ss = seconds - hh * 3600 - mm * 60
  date = sprintf("%04d-%02d-%02d", y, m, d)
  time = sprintf("%02d:%02d:%02d", hh, mm, ss)
  if (format == "utc") {
    printf "%sT%sZ\n", date, time
  } else {
    printf "-DIZ_BUILD_YEAR=%04d -DIZ_BUILD_MONTH=%02d -DIZ_BUILD_DAY=%02d ", y, m, d
    printf "-DIZ_BUILD_HOUR=%02d -DIZ_BUILD_MINUTE=%02d -DIZ_BUILD_SECOND=%02d\n", hh, mm, ss
  }
  exit 0
}
function bad() {
  exit 2
}
' < /dev/null || {
  printf '%s\n' 'ERROR: SOURCE_DATE_EPOCH must be decimal seconds in [315532800,2147483647] without whitespace or signs' >&2
  exit 2
}
