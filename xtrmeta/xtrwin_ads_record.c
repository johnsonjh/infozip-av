/* SPDX-License-Identifier: MIT-0 */
/* Pure portable C89 ADS -> Xtro V1 source preparation; no Win32 dependency. */
#include "xtrwin_ads_record.h"
#include <string.h>
static const unsigned char ads_namespace[4] = { 'n', 't', 'f', 's' };
int
xtr_ads_record_source (const xtr_ads_name *name, xtr_u64 length,
                       xtr_read_cb read, void *ctx, xtr1_source *out,
                       unsigned char native_tlvs[22])
{
  unsigned short raw[XTR_ADS_MAX_NAME + 8U];
  xtr_ads_name parsed;
  unsigned i;

  if (!out || !native_tlvs || !name || name->utf16_len == 0U
      || name->utf16_len > XTR_ADS_MAX_NAME || name->utf8_len == 0U
      || name->utf8_len > XTR_ADS_MAX_UTF8
      || ((length.lo || length.hi) && !read) || length.lo > 0xffffffffUL
      || length.hi > 0xffffffffUL)
    {
      return XTR_CORRUPT;
    }

  raw[0] = ':';
  for (i = 0; i < name->utf16_len; i++)
    {
      raw[i + 1U] = name->utf16[i];
    }

  raw[1U + name->utf16_len] = ':';
  raw[2U + name->utf16_len] = '$';
  raw[3U + name->utf16_len] = 'D';
  raw[4U + name->utf16_len] = 'A';
  raw[5U + name->utf16_len] = 'T';
  raw[6U + name->utf16_len] = 'A';
  if (xtr_ads_parse_stream (raw, (size_t)name->utf16_len + 7U, &parsed)
          != XTR_ADS_OK
      || parsed.utf8_len != name->utf8_len
      || memcmp (parsed.utf8, name->utf8, name->utf8_len) != 0)
    {
      return XTR_CORRUPT;
    }

  memset (out, 0, sizeof (*out));
  memset (native_tlvs, 0, 22U);
  native_tlvs[0] = 1U;
  native_tlvs[4] = 2U;
  native_tlvs[8] = 9U;
  native_tlvs[10] = 11U;
  native_tlvs[14] = 4U;
  native_tlvs[18] = 0x80U;
  out->record.type = 3U;
  out->record.origin = 7U;
  out->record.encoding = 0U;
  out->record.ns_len = 4UL;
  out->record.name_len = (unsigned long)name->utf8_len;
  out->record.native_len = 22UL;
  out->record.value_len = length;
  out->ns = ads_namespace;
  out->name = name->utf8;
  out->native = native_tlvs;
  out->read_value = read;
  out->value_context = ctx;
  return XTR_OK;
}
