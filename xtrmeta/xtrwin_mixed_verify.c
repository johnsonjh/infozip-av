/* SPDX-License-Identifier: MIT-0 */
/* Strict ANSI C89 portable decoder for mixed Windows NT EA and NTFS ADS.
 * This never opens a file, changes an EA or publishes an ADS.
 * Validation occurs AFTER Xtro SHA-256/XTCS verification. */
#include "xtrwin_ads.h"
#include "xtrwin_mixed_verify.h"
#include <stdlib.h>
#include <string.h>
#define XMV_RECORD_LIMIT 1024U
#define XMV_MANIFEST_LIMIT (32UL * 1024UL * 1024UL)
#define XMV_NAME_LIMIT (4U * XTR_ADS_MAX_NAME)
typedef struct xmv_name
{
  unsigned kind;
  unsigned char *bytes;
  size_t len;
} xmv_name;
typedef struct xmv_ctx
{
  xtr_record rec;
  unsigned char ns[4], native[22], name[XMV_NAME_LIMIT + 1U];
  size_t ns_at, native_at, name_at;
  unsigned long value_at;
  xmv_name *seen;
  unsigned count, active;
  int error;
  xtr_win_mixed_summary summary;
} xmv_ctx;
static unsigned long
xmv_u32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned
xmv_ascii_fold (unsigned a)
{
  return a >= 'a' && a <= 'z' ? a - ('a' - 'A') : a;
}
static int
xmv_equal (const unsigned char *a, size_t na, const unsigned char *b,
           size_t nb)
{
  size_t i;

  if (na != nb)
    {
      return 0;
    }

  for (i = 0; i < na; i++)
    {
      if (xmv_ascii_fold (a[i]) != xmv_ascii_fold (b[i]))
        {
          return 0;
        }
    }

  return 1;
}
/* Decode canonical UTF-8 to a validated $DATA stream name; prevent alternate
 * encodings, delimiter injection, invalid surrogate pairs and overlong UTF-8.
 */
static int
xmv_ads_name (const unsigned char *utf8, size_t n, xtr_ads_name *output)
{
  unsigned short raw[XTR_ADS_MAX_NAME + 8U];
  size_t at = 0, units = 1, i;
  xtr_ads_name parsed;

  raw[0] = ':';
  while (at < n)
    {
      unsigned long code, c;
      unsigned bytes, j;
      c = utf8[at];
      if (c < 0x80U)
        {
          code = c;
          bytes = 1U;
        }
      else if (c >= 0xc2U && c <= 0xdfU)
        {
          code = c & 31U;
          bytes = 2U;
        }
      else if (c >= 0xe0U && c <= 0xefU)
        {
          code = c & 15U;
          bytes = 3U;
        }
      else if (c >= 0xf0U && c <= 0xf4U)
        {
          code = c & 7U;
          bytes = 4U;
        }
      else
        {
          return 0;
        }

      if (bytes > n - at)
        {
          return 0;
        }

      for (j = 1; j < bytes; j++)
        {
          c = utf8[at + j];
          if (c < 0x80U || c > 0xbfU)
            {
              return 0;
            }

          code = (code << 6) | (c & 63U);
        }

      if ((bytes == 2U && code < 0x80UL) || (bytes == 3U && code < 0x800UL)
          || (bytes == 4U && code < 0x10000UL) || code > 0x10ffffUL
          || (code >= 0xd800UL && code <= 0xdfffUL) || code == 0U)
        {
          return 0;
        }

      if (code <= 0xffffUL)
        {
          if (units > XTR_ADS_MAX_NAME)
            {
              return 0;
            }

          raw[units++] = (unsigned short)code;
        }
      else
        {
          if (units >= XTR_ADS_MAX_NAME)
            {
              return 0;
            }

          code -= 0x10000UL;
          raw[units++] = (unsigned short)(0xd800U + (code >> 10));
          raw[units++] = (unsigned short)(0xdc00U + (code & 1023U));
        }

      at += bytes;
    }
  if (units <= 1U || units - 1U > XTR_ADS_MAX_NAME)
    {
      return 0;
    }

  raw[units++] = ':';
  raw[units++] = '$';
  raw[units++] = 'D';
  raw[units++] = 'A';
  raw[units++] = 'T';
  raw[units++] = 'A';
  if (xtr_ads_parse_stream (raw, units, &parsed) != XTR_ADS_OK
      || parsed.utf8_len != n || memcmp (parsed.utf8, utf8, n) != 0)
    {
      return 0;
    }

  for (i = 0; i < parsed.utf16_len; i++)
    {
      if (parsed.utf16[i] == 0U)
        {
          return 0;
        }
    }

  if (output)
    {
      *output = parsed;
    }

  return 1;
}
int
xtr_win_ads_from_utf8 (const unsigned char *utf8, size_t n,
                       xtr_ads_name *output)
{
  if (!output)
    {
      return XTR_CORRUPT;
    }

  memset (output, 0, sizeof (*output));
  return xmv_ads_name (utf8, n, output) ? XTR_OK : XTR_UNSUPPORTED;
}
static int
xmv_ea_name (const unsigned char *p, size_t n)
{
  size_t i;

  if (!n || n >= 255U)
    {
      return 0;
    }

  for (i = 0; i < n; i++)
    {
      if (p[i] < 32U || p[i] > 126U || p[i] == '\\' || p[i] == '/'
          || p[i] == ':' || p[i] == '*' || p[i] == '?' || p[i] == '"'
          || p[i] == '<' || p[i] == '>' || p[i] == '|' || p[i] == ','
          || p[i] == '+' || p[i] == '=' || p[i] == '[' || p[i] == ']'
          || p[i] == ';')
        {
          return 0;
        }
    }

  return 1;
}
static int
xmv_finish (xmv_ctx *x)
{
  size_t i;
  unsigned kind = x->rec.type;
  xmv_name *seen;

  if (!x->active)
    {
      return 0;
    }

  if (x->ns_at != (kind == 1U ? 2U : 4U)
      || x->name_at != (size_t)x->rec.name_len
      || x->native_at != (kind == 1U ? 19U : 22U)
      || x->value_at != x->rec.value_len.lo || x->native[0] != 1U
      || x->native[1] || xmv_u32 (x->native + 4) != 2UL || x->native[2]
      || x->native[3] || x->native[9] || x->native[11] || x->native[12]
      || x->native[13] || x->native[15] || x->native[16] || x->native[17]
      || x->native[10] != (kind == 1U ? 3U : 11U) || x->native[11]
      || x->native[12] || x->native[13]
      || xmv_u32 (x->native + 14) != (kind == 1U ? 1UL : 4UL))
    {
      x->error = XTR_CORRUPT;
      return 1;
    }

  if (kind == 1U)
    {
      if (memcmp (x->ns, "nt", 2) != 0 || x->native[8] != 8U
          || (x->native[18] != 0U && x->native[18] != 128U)
          || !xmv_ea_name (x->name, x->name_at))
        {
          x->error = XTR_UNSUPPORTED;
          return 1;
        }

      x->summary.ea_count++;
      x->summary.ea_bytes.lo += x->rec.value_len.lo;
      if (!x->rec.value_len.lo)
        {
          x->summary.has_zero_ea = 1U;
        }
    }
  else
    {
      if (memcmp (x->ns, "ntfs", 4) != 0 || x->native[8] != 9U
          || xmv_u32 (x->native + 18) != 0x80UL
          || !xmv_ads_name (x->name, x->name_at, NULL))
        {
          x->error = XTR_UNSUPPORTED;
          return 1;
        }

      x->summary.ads_count++;
      x->summary.ads_bytes.lo += x->rec.value_len.lo;
    }

  if (x->count >= XMV_RECORD_LIMIT)
    {
      x->error = XTR_LIMIT;
      return 1;
    }

  for (i = 0; i < x->count; i++)
    {
      if (x->seen[i].kind == kind
          && xmv_equal (x->seen[i].bytes, x->seen[i].len, x->name, x->name_at))
        {
          x->error = XTR_CORRUPT;
          return 1;
        }
    }

  seen = &x->seen[x->count];
  seen->bytes = (unsigned char *)malloc (x->name_at + 1U);
  if (!seen->bytes)
    {
      x->error = XTR_LIMIT;
      return 1;
    }

  memcpy (seen->bytes, x->name, x->name_at);
  seen->bytes[x->name_at] = 0;
  seen->len = x->name_at;
  seen->kind = kind;
  x->count++;
  x->active = 0;
  return 0;
}
static int
xmv_begin (void *context, const xtr_record *r)
{
  xmv_ctx *x = (xmv_ctx *)context;

  if (xmv_finish (x))
    {
      return 1;
    }

  if ((r->type != 1U && r->type != 3U) || r->origin != 7U || r->flags
      || r->encoding || r->value_len.hi || r->value_len.lo > XMV_MANIFEST_LIMIT
      || r->name_len == 0U || r->name_len > XMV_NAME_LIMIT
      || r->ns_len != (r->type == 1U ? 2UL : 4UL)
      || r->native_len != (r->type == 1U ? 19UL : 22UL)
      || (r->type == 1U
          && (r->name_len >= 255UL || r->value_len.lo > 65535UL)))
    {
      x->error = XTR_UNSUPPORTED;
      return 1;
    }

  x->rec = *r;
  x->active = 1;
  x->ns_at = x->name_at = x->native_at = 0;
  x->value_at = 0;
  memset (x->native, 0, sizeof (x->native));
  return 0;
}
static int
xmv_data (void *context, const xtr_record *record, unsigned field,
          const unsigned char *data, size_t n)
{
  xmv_ctx *x = (xmv_ctx *)context;
  unsigned char *dst = NULL;
  size_t *at = NULL, limit = 0;

  (void)record;
  if (!x->active)
    {
      x->error = XTR_CORRUPT;
      return 1;
    }

  switch (field)
    {
    case 0:
      dst = x->ns;
      at = &x->ns_at;
      limit = sizeof (x->ns);
      break;

    case 1:
      dst = x->name;
      at = &x->name_at;
      limit = sizeof (x->name) - 1U;
      break;

    case 2:
      dst = x->native;
      at = &x->native_at;
      limit = sizeof (x->native);
      break;

    case 3:
      if (n > x->rec.value_len.lo - x->value_at)
        {
          x->error = XTR_CORRUPT;
          return 1;
        }

      x->value_at += (unsigned long)n;
      return 0;

    default:
      x->error = XTR_CORRUPT;
      return 1;
    }
  if (n > limit - *at)
    {
      x->error = XTR_CORRUPT;
      return 1;
    }

  if (n)
    {
      memcpy (dst + *at, data, n);
    }

  *at += n;
  return 0;
}
static size_t
xmv_read (void *context, unsigned char *out, size_t n)
{
  return fread (out, 1, n, (FILE *)context);
}
int
xtr_win_mixed_verify (FILE *stage, xtr_u64 encoded, const xtr_extra *outer,
                      const unsigned char *sha32,
                      xtr_win_mixed_summary *summary)
{
  xtr_reader r;
  xtr_manifest manifest;
  xtr1_policy policy;
  xtr1_digest digest;
  xmv_ctx x;
  unsigned i;
  int rc;

  if (!stage || !outer || !summary)
    {
      return XTR_CORRUPT;
    }

  memset (summary, 0, sizeof (*summary));
  memset (&policy, 0, sizeof (policy));
  policy.max_records = XMV_RECORD_LIMIT;
  policy.max_field = 1024UL * 1024UL;
  policy.max_manifest.lo = XMV_MANIFEST_LIMIT;
  memset (&r, 0, sizeof (r));
  r.context = stage;
  r.read = xmv_read;
  if (fseek (stage, 0, SEEK_SET) != 0)
    {
      return XTR_IO;
    }

  rc = xtr1_check_manifest (&r, encoded, outer, sha32, &policy, &digest);
  if (rc)
    {
      return rc;
    }

  if (!digest.schema_supported)
    {
      return XTR_UNSUPPORTED;
    }

  memset (&x, 0, sizeof (x));
  x.seen = (xmv_name *)calloc (XMV_RECORD_LIMIT, sizeof (*x.seen));
  if (!x.seen)
    {
      return XTR_LIMIT;
    }

  r.sink_context = &x;
  r.begin = xmv_begin;
  r.data = xmv_data;
  r.max_records = policy.max_records;
  r.max_field = policy.max_field;
  r.max_total = policy.max_manifest;
  if (fseek (stage, 0, SEEK_SET) != 0)
    {
      rc = XTR_IO;
    }
  else
    {
      rc = xtr_parse_manifest (&r, digest.manifest_length, &manifest);
    }

  if (rc == XTR_OK && xmv_finish (&x))
    {
      rc = x.error ? x.error : XTR_CORRUPT;
    }

  if (rc == XTR_IO && x.error)
    {
      rc = x.error;
    }

  if (rc == XTR_OK
      && (x.summary.ea_count + x.summary.ads_count != (unsigned long)x.count
          || manifest.count != x.count))
    {
      rc = XTR_CORRUPT;
    }

  if (rc == XTR_OK)
    {
      *summary = x.summary;
    }

  for (i = 0; i < x.count; i++)
    {
      free (x.seen[i].bytes);
    }

  free (x.seen);
  return rc;
}
