/* SPDX-License-Identifier: MIT-0 */
/* Binary-safe Unicode validation for NTFS alternate data stream names. */
#include "xtrwin_ads.h"
#include <string.h>
static int
xas_eq (unsigned short a, char b)
{
  if (a >= 'a' && a <= 'z')
    {
      a = (unsigned short)(a - ('a' - 'A'));
    }

  if (b >= 'a' && b <= 'z')
    {
      b = (char)(b - ('a' - 'A'));
    }

  return a == (unsigned short)(unsigned char)b;
}
static int
xas_suffix (const unsigned short *s, size_t n)
{
  static const char type[] = ":$DATA";
  size_t i;

  if (n < 6U)
    {
      return 0;
    }

  for (i = 0; i < 6U; i++)
    {
      if (!xas_eq (s[n - 6U + i], type[i]))
        {
          return 0;
        }
    }

  return 1;
}
static int
xas_forbidden (unsigned long code)
{
  return code < 32UL || code == 127UL || code == ':' || code == '/'
         || code == '\\' || code == '<' || code == '>' || code == '"'
         || code == '|' || code == '?' || code == '*';
}
static int
xas_put (unsigned char *dst, size_t *pos, unsigned long cp)
{
  size_t at = *pos;

  if (cp < 0x80UL)
    {
      dst[at++] = (unsigned char)cp;
    }
  else if (cp < 0x800UL)
    {
      dst[at++] = (unsigned char)(0xc0UL | (cp >> 6));
      dst[at++] = (unsigned char)(0x80UL | (cp & 63UL));
    }
  else if (cp < 0x10000UL)
    {
      dst[at++] = (unsigned char)(0xe0UL | (cp >> 12));
      dst[at++] = (unsigned char)(0x80UL | ((cp >> 6) & 63UL));
      dst[at++] = (unsigned char)(0x80UL | (cp & 63UL));
    }
  else
    {
      dst[at++] = (unsigned char)(0xf0UL | (cp >> 18));
      dst[at++] = (unsigned char)(0x80UL | ((cp >> 12) & 63UL));
      dst[at++] = (unsigned char)(0x80UL | ((cp >> 6) & 63UL));
      dst[at++] = (unsigned char)(0x80UL | (cp & 63UL));
    }

  *pos = at;
  return 0;
}
int
xtr_ads_parse_stream (const unsigned short *s, size_t n, xtr_ads_name *out)
{
  size_t i, chars, utf8 = 0;

  if (!out)
    {
      return XTR_ADS_CORRUPT;
    }

  memset (out, 0, sizeof (*out));
  if (!s || n < 7U || s[0] != ':' || !xas_suffix (s, n))
    {
      return XTR_ADS_CORRUPT;
    }

  chars = n - 7U;
  if (!chars)
    {
      return XTR_ADS_DEFAULT;
    }

  if (chars > XTR_ADS_MAX_NAME)
    {
      return XTR_ADS_UNSUPPORTED;
    }

  if (s[chars] == '.' || s[chars] == ' ')
    {
      return XTR_ADS_UNSUPPORTED;
    }

  for (i = 0; i < chars; i++)
    {
      unsigned long cp = (unsigned long)s[i + 1U];
      if (cp >= 0xd800UL && cp <= 0xdbffUL)
        {
          if (i + 1U >= chars || s[i + 2U] < 0xdc00U || s[i + 2U] > 0xdfffU)
            {
              return XTR_ADS_CORRUPT;
            }

          cp = 0x10000UL + ((cp - 0xd800UL) << 10)
               + ((unsigned long)s[i + 2U] - 0xdc00UL);
          out->utf16[i] = s[i + 1U];
          i++;
        }
      else if (cp >= 0xdc00UL && cp <= 0xdfffUL)
        {
          return XTR_ADS_CORRUPT;
        }

      if (xas_forbidden (cp))
        {
          return XTR_ADS_UNSUPPORTED;
        }

      out->utf16[i] = s[i + 1U];
      xas_put (out->utf8, &utf8, cp);
    }

  out->utf8[utf8] = 0;
  out->utf8_len = utf8;
  out->utf16_len = chars;
  out->utf16[chars] = 0;
  return XTR_ADS_OK;
}
