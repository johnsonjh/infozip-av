/* SPDX-License-Identifier: MIT-0 */
/* Win32 NTFS $DATA stream-name classification; C89, portable, no Win32 ABI. */
#ifndef XTRWIN_ADS_H
# define XTRWIN_ADS_H
# include <stddef.h>
# define XTR_ADS_MAX_NAME 255U
# define XTR_ADS_MAX_UTF8 (4U * XTR_ADS_MAX_NAME)
# define XTR_ADS_OK 0
# define XTR_ADS_DEFAULT 1
# define XTR_ADS_CORRUPT 2
# define XTR_ADS_UNSUPPORTED 3
typedef struct xtr_ads_name
{
  unsigned char utf8[XTR_ADS_MAX_UTF8 + 1U];
  size_t utf8_len;
  unsigned short utf16[XTR_ADS_MAX_NAME + 1U];
  size_t utf16_len;
} xtr_ads_name;
/* Input: WIN32_FIND_STREAM_DATA.cStreamName, e.g. ':name:$DATA'.
 * A default '::$DATA' stream is not a metadata stream. Refuse unrecognized
 * stream types or Unicode sequences rather than silently dropping data.
 * Only named $DATA streams are in scope. No filesystem writes here. */
int xtr_ads_parse_stream (const unsigned short *name, size_t units,
                          xtr_ads_name *out);
#endif /* ifndef XTRWIN_ADS_H */
