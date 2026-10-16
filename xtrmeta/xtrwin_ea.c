/* SPDX-License-Identifier: MIT-0 */
/* Windows NT EA <-> Xtro V1, no native filesystem access. Strict C89.
 * IMPORTANT: FILE_FULL_EA_INFORMATION EaValueLength==0 means DELETE when
 * passed to NtSetEaFile, not setting an empty EA. The packer is a structural
 * buffer encoder, NOT authorization to use the buffer as a SET request. */
#include "xtrwin_ea.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define XW_MAX_EAS 1024U
#define XW_MAX_BYTES (1024UL * 1024UL)
#define XW_MAX_MANIFEST (32UL * 1024UL * 1024UL)
static const unsigned char xw_ns[2] = { 'n', 't' };
static unsigned
xw_16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}
static unsigned long
xw_32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static void
xw_put16 (unsigned char *p, unsigned n)
{
  p[0] = (unsigned char)n;
  p[1] = (unsigned char)(n >> 8);
}
static void
xw_put32 (unsigned char *p, unsigned long n)
{
  unsigned i;

  for (i = 0; i < 4U; i++)
    {
      p[i] = (unsigned char)n;
      n >>= 8;
    }
}
static unsigned
xw_up (unsigned c)
{
  return c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c;
}
static int
xw_cmp_ci (const unsigned char *a, size_t n, const unsigned char *b, size_t m)
{
  size_t i;

  for (i = 0; i < n && i < m; i++)
    {
      if (xw_up (a[i]) != xw_up (b[i]))
        {
          return xw_up (a[i]) < xw_up (b[i]) ? -1 : 1;
        }
    }

  return n < m ? -1 : n > m ? 1 : 0;
}
static int
xw_cmp_raw (const void *a, const void *b)
{
  const xtr_win_ea *x = (const xtr_win_ea *)a, *y = (const xtr_win_ea *)b;
  size_t n = x->name_len < y->name_len ? x->name_len : y->name_len;
  int c = memcmp (x->name, y->name, n);

  return c                           ? c
         : x->name_len < y->name_len ? -1
         : x->name_len > y->name_len ? 1
                                     : 0;
}
static int
xw_name (const unsigned char *p, size_t n)
{
  size_t i;

  if (!p || n == 0U || n >= 255U)
    {
      return 0;
    }

  for (i = 0; i < n; i++)
    {
      /* Windows EA names are 8-bit ASCII. Reject ambiguous/nonportable
       * bytes rather than silently uppercasing or recoding the name. */
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
void
xtr_win_ea_free (xtr_win_ea_list *a)
{
  size_t i;

  if (!a)
    {
      return;
    }

  for (i = 0; i < a->count; i++)
    {
      free (a->items[i].name);
      free (a->items[i].value);
    }

  free (a->items);
  a->items = NULL;
  a->count = 0;
}
static int
xw_new (xtr_win_ea_list *a, const unsigned char *name, size_t n,
        const unsigned char *value, size_t v, unsigned flags)
{
  xtr_win_ea *it;
  size_t i;

  if (!xw_name (name, n) || (flags & ~128U) || v > 65535U || (v && !value)
      || a->count >= XW_MAX_EAS)
    {
      return XTR_UNSUPPORTED;
    }

  for (i = 0; i < a->count; i++)
    {
      if (!xw_cmp_ci (a->items[i].name, a->items[i].name_len, name, n))
        {
          return XTR_CORRUPT;
        }
    }

  it = (xtr_win_ea *)realloc (a->items, (a->count + 1U) * sizeof (*it));
  if (!it)
    {
      return XTR_LIMIT;
    }

  a->items = it;
  it = &a->items[a->count];
  memset (it, 0, sizeof (*it));
  it->name = (unsigned char *)malloc (n + 1U);
  it->value = (unsigned char *)malloc (v ? v : 1U);
  if (!it->name || !it->value)
    {
      free (it->name);
      free (it->value);
      memset (it, 0, sizeof (*it));
      return XTR_LIMIT;
    }

  memcpy (it->name, name, n);
  it->name[n] = 0;
  if (v)
    {
      memcpy (it->value, value, v);
    }

  it->name_len = n;
  it->value_len = v;
  it->flags = flags;
  a->count++;
  return XTR_OK;
}
static int
xw_copy_sorted (const xtr_win_ea_list *in, xtr_win_ea_list *out)
{
  size_t i, j, total = 0;
  int rc;

  memset (out, 0, sizeof (*out));
  if (!in || (in->count && !in->items) || in->count > XW_MAX_EAS)
    {
      return XTR_CORRUPT;
    }

  for (i = 0; i < in->count; i++)
    {
      const xtr_win_ea *p = &in->items[i];
      if (p->value_len > XW_MAX_BYTES - total)
        {
          rc = XTR_LIMIT;
          goto failed;
        }

      total += p->value_len;
      rc = xw_new (out, p->name, p->name_len, p->value, p->value_len,
                   p->flags);
      if (rc)
        {
          goto failed;
        }
    }

  if (out->count > 1U)
    {
      qsort (out->items, out->count, sizeof (*out->items), xw_cmp_raw);
    }

  for (i = 0; i < out->count; i++)
    {
      for (j = 0; j < i; j++)
        {
          if (!xw_cmp_ci (out->items[i].name, out->items[i].name_len,
                          out->items[j].name, out->items[j].name_len))
            {
              rc = XTR_CORRUPT;
              goto failed;
            }
        }
    }

  return XTR_OK;

failed:
  xtr_win_ea_free (out);
  return rc;
}
int
xtr_win_ea_parse (const unsigned char *p, size_t used, xtr_win_ea_list *out)
{
  size_t at = 0, total = 0;
  int rc = XTR_OK;

  if (!out)
    {
      return XTR_CORRUPT;
    }

  memset (out, 0, sizeof (*out));
  if (!used)
    {
      return XTR_OK;
    }

  if (!p || used > XW_MAX_BYTES)
    {
      return XTR_LIMIT;
    }

  while (at < used)
    {
      unsigned long next;
      size_t n, v, min_len, slot, i;
      unsigned flags;
      if (used - at < 10U)
        {
          rc = XTR_CORRUPT;
          break;
        }

      next = xw_32 (p + at);
      flags = p[at + 4U];
      n = p[at + 5U];
      v = xw_16 (p + at + 6U);
      if (n == 0 || n > used - at - 9U)
        {
          rc = XTR_CORRUPT;
          break;
        }

      min_len = 9U + n + v;
      if (min_len > used - at || p[at + 8U + n] != 0)
        {
          rc = XTR_CORRUPT;
          break;
        }

      if (v > XW_MAX_BYTES - total)
        {
          rc = XTR_LIMIT;
          break;
        }

      if (next)
        {
          if ((next & 3UL) != 0 || next < min_len || next > used - at)
            {
              rc = XTR_CORRUPT;
              break;
            }

          slot = (size_t)next;
          if (slot - min_len > 3U)
            {
              rc = XTR_CORRUPT;
              break;
            }
        }
      else
        {
          slot = used - at;
          if (slot - min_len > 3U)
            {
              rc = XTR_CORRUPT;
              break;
            }
        }

      for (i = min_len; i < slot; i++)
        {
          if (p[at + i] != 0)
            {
              rc = XTR_CORRUPT;
              break;
            }
        }

      if (rc)
        {
          break;
        }

      rc = xw_new (out, p + at + 8U, n, p + at + 9U + n, v, flags);
      if (rc)
        {
          break;
        }

      total += v;
      at += slot;
      if (!next)
        {
          if (at != used)
            {
              rc = XTR_CORRUPT;
            }

          break;
        }

      if (at == used)
        {
          rc = XTR_CORRUPT;
          break;
        }
    }
  if (rc)
    {
      xtr_win_ea_free (out);
    }

  return rc;
}
int
xtr_win_ea_pack (const xtr_win_ea_list *in, unsigned char **buffer,
                 size_t *used)
{
  xtr_win_ea_list a;
  size_t i, at = 0, total = 0;
  unsigned char *p;
  int rc;

  if (!buffer || !used)
    {
      return XTR_CORRUPT;
    }

  *buffer = NULL;
  *used = 0;
  rc = xw_copy_sorted (in, &a);
  if (rc)
    {
      return rc;
    }

  for (i = 0; i < a.count; i++)
    {
      size_t len = 9U + a.items[i].name_len + a.items[i].value_len;
      size_t slot = i + 1U < a.count ? ((len + 3U) & ~(size_t)3U) : len;
      if (slot > XW_MAX_BYTES - total)
        {
          rc = XTR_LIMIT;
          goto failed;
        }

      total += slot;
    }

  if (!a.count)
    {
      xtr_win_ea_free (&a);
      return XTR_OK;
    }

  p = (unsigned char *)calloc (total, 1);
  if (!p)
    {
      rc = XTR_LIMIT;
      goto failed;
    }

  for (i = 0; i < a.count; i++)
    {
      const xtr_win_ea *v = &a.items[i];
      size_t len = 9U + v->name_len + v->value_len;
      size_t slot = i + 1U < a.count ? ((len + 3U) & ~(size_t)3U) : len;
      xw_put32 (p + at, i + 1U < a.count ? (unsigned long)slot : 0UL);
      p[at + 4U] = (unsigned char)v->flags;
      p[at + 5U] = (unsigned char)v->name_len;
      xw_put16 (p + at + 6U, (unsigned)v->value_len);
      memcpy (p + at + 8U, v->name, v->name_len);
      if (v->value_len)
        {
          memcpy (p + at + 9U + v->name_len, v->value, v->value_len);
        }

      at += slot;
    }

  *buffer = p;
  *used = total;
  rc = XTR_OK;
failed:
  xtr_win_ea_free (&a);
  return rc;
}
int
xtr_win_ea_pack_set (const xtr_win_ea_list *in, unsigned char **out,
                     size_t *used)
{
  size_t i;

  if (!out || !used)
    {
      return XTR_CORRUPT;
    }

  *out = NULL;
  *used = 0;
  if (!in || (in->count && !in->items))
    {
      return XTR_CORRUPT;
    }

  for (i = 0; i < in->count; i++)
    {
      if (in->items[i].value_len == 0U)
        {
          return XTR_UNSUPPORTED;
        }
    }

  return xtr_win_ea_pack (in, out, used);
}
static void
xw_policy (xtr1_policy *p)
{
  memset (p, 0, sizeof (*p));
  p->max_records = XW_MAX_EAS;
  p->max_field = XW_MAX_BYTES;
  p->max_manifest.lo = XW_MAX_MANIFEST;
  p->max_manifest.hi = 0;
}
static xtr_u64
xw_size (size_t n)
{
  xtr_u64 v;

  v.lo = ((unsigned long)n) & 0xffffffffUL;
  v.hi = ((unsigned long)n) >> 16 >> 16;
  return v;
}
typedef struct xw_source
{
  const xtr_win_ea *ea;
  size_t pos;
} xw_source;
static size_t
xw_source_read (void *ctx, unsigned char *out, size_t n)
{
  xw_source *s = (xw_source *)ctx;
  size_t rem = s->ea->value_len - s->pos;

  if (n > rem)
    {
      n = rem;
    }

  if (n)
    {
      memcpy (out, s->ea->value + s->pos, n);
    }

  s->pos += n;
  return n;
}
static int
xw_write_file (void *ctx, const unsigned char *p, size_t n)
{
  return fwrite (p, 1, n, (FILE *)ctx) == n ? 0 : 1;
}
static size_t
xw_read_file (void *ctx, unsigned char *p, size_t n)
{
  return fread (p, 1, n, (FILE *)ctx);
}
int
xtr_win_ea_to_manifest (const xtr_win_ea_list *input,
                        const unsigned char owner[16], FILE *stage,
                        int encrypted, xtr1_digest *digest)
{
  xtr_win_ea_list a;
  xtr1_source *records = NULL;
  xw_source *src = NULL;
  unsigned char *tlvs = NULL;
  xtr1_policy policy;
  xtr1_sink sink;
  size_t i;
  int rc;

  if (!owner || !stage || !digest || (encrypted != 0 && encrypted != 1))
    {
      return XTR_CORRUPT;
    }

  rc = xw_copy_sorted (input, &a);
  if (rc)
    {
      return rc;
    }

  records = (xtr1_source *)calloc (a.count ? a.count : 1U, sizeof (*records));
  src = (xw_source *)calloc (a.count ? a.count : 1U, sizeof (*src));
  tlvs = (unsigned char *)calloc (a.count ? a.count : 1U, 19U);
  if (!records || !src || !tlvs)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  for (i = 0; i < a.count; i++)
    {
      unsigned char *t = tlvs + i * 19U;
      xtr1_source *v = &records[i];
      t[0] = 1;
      t[4] = 2;
      t[8] = 8; /* TLV interface 8 (Windows EA) */
      t[10] = 3;
      t[14] = 1;
      t[18] = (unsigned char)a.items[i].flags;
      v->record.type = 1;
      v->record.origin = 7;
      v->record.encoding = 0;
      v->record.ns_len = 2;
      v->record.name_len = (unsigned long)a.items[i].name_len;
      v->record.native_len = 19;
      v->record.value_len = xw_size (a.items[i].value_len);
      v->ns = xw_ns;
      v->name = a.items[i].name;
      v->native = t;
      src[i].ea = &a.items[i];
      v->read_value = xw_source_read;
      v->value_context = &src[i];
    }

  xw_policy (&policy);
  sink.write = xw_write_file;
  sink.context = stage;
  if (fseek (stage, 0, SEEK_SET))
    {
      rc = XTR_IO;
    }
  else
    {
      rc = xtr1_write_manifest (owner, records, a.count, encrypted, &policy,
                                &sink, digest);
    }

  if (rc == XTR_OK && (fflush (stage) || fseek (stage, 0, SEEK_SET)))
    {
      rc = XTR_IO;
    }

done:
  free (records);
  free (src);
  free (tlvs);
  xtr_win_ea_free (&a);
  return rc;
}
typedef struct xw_restore
{
  xtr_win_ea_list list;
  xtr_record rec;
  unsigned char *name, *value;
  size_t name_at, value_at, ns_at, native_at;
  unsigned char ns[2], native[19];
  int have, error;
} xw_restore;
static int
xw_flush (xw_restore *x)
{
  int rc;

  if (!x->have)
    {
      return 0;
    }

  if (x->ns_at != 2U || memcmp (x->ns, xw_ns, 2)
      || x->name_at != (size_t)x->rec.name_len || x->native_at != 19U
      || x->value_at != (size_t)x->rec.value_len.lo)
    {
      x->error = XTR_CORRUPT;
      return 1;
    }

  if (x->native[0] != 1 || x->native[1] != 0 || xw_32 (x->native + 4) != 2
      || x->native[8] != 8 || x->native[9] != 0 || x->native[10] != 3
      || x->native[11] != 0 || xw_32 (x->native + 14) != 1
      || (x->native[18] & 127U) || x->native[2] || x->native[3]
      || x->native[12] || x->native[13])
    {
      x->error = XTR_UNSUPPORTED;
      return 1;
    }

  rc = xw_new (&x->list, x->name, x->name_at, x->value, x->value_at,
               x->native[18]);
  if (rc)
    {
      x->error = rc;
      return 1;
    }

  free (x->name);
  free (x->value);
  x->name = x->value = NULL;
  x->have = 0;
  return 0;
}
static int
xw_begin (void *ctx, const xtr_record *r)
{
  xw_restore *x = (xw_restore *)ctx;

  if (xw_flush (x))
    {
      return 1;
    }

  if (r->type != 1U || r->origin != 7U || r->encoding != 0U || r->flags
      || r->ns_len != 2 || r->name_len == 0 || r->name_len > 255U
      || r->native_len != 19 || r->value_len.hi || r->value_len.lo > 65535UL)
    {
      x->error = XTR_UNSUPPORTED;
      return 1;
    }

  x->name = (unsigned char *)malloc ((size_t)r->name_len + 1U);
  x->value = (unsigned char *)malloc (r->value_len.lo ? (size_t)r->value_len.lo
                                                      : 1U);
  if (!x->name || !x->value)
    {
      x->error = XTR_LIMIT;
      return 1;
    }

  x->rec = *r;
  x->name_at = x->value_at = x->ns_at = x->native_at = 0;
  x->have = 1;
  return 0;
}
static int
xw_data (void *ctx, const xtr_record *r, unsigned field,
         const unsigned char *p, size_t n)
{
  xw_restore *x = (xw_restore *)ctx;
  unsigned char *dst = NULL;
  size_t *at = NULL, limit = 0;

  (void)r;
  if (!x->have)
    {
      x->error = XTR_CORRUPT;
      return 1;
    }

  switch (field)
    {
    case 0:
      dst = x->ns;
      at = &x->ns_at;
      limit = 2U;
      break;

    case 1:
      dst = x->name;
      at = &x->name_at;
      limit = (size_t)x->rec.name_len;
      break;

    case 2:
      dst = x->native;
      at = &x->native_at;
      limit = 19U;
      break;

    case 3:
      dst = x->value;
      at = &x->value_at;
      limit = (size_t)x->rec.value_len.lo;
      break;

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
      memcpy (dst + *at, p, n);
    }

  *at += n;
  return 0;
}
int
xtr_win_ea_from_manifest (FILE *stage, xtr_u64 encoded_size,
                          const xtr_extra *outer, const unsigned char *sha32,
                          xtr_win_ea_list *output)
{
  xtr_reader r;
  xtr1_policy policy;
  xtr1_digest digest;
  xtr_manifest manifest;
  xw_restore x;
  int rc;

  if (!output)
    {
      return XTR_CORRUPT;
    }

  memset (output, 0, sizeof (*output));
  if (!stage || !outer)
    {
      return XTR_CORRUPT;
    }

  xw_policy (&policy);
  memset (&r, 0, sizeof (r));
  r.context = stage;
  r.read = xw_read_file;
  if (fseek (stage, 0, SEEK_SET))
    {
      return XTR_IO;
    }

  rc = xtr1_check_manifest (&r, encoded_size, outer, sha32, &policy, &digest);
  if (rc)
    {
      return rc;
    }

  if (!digest.schema_supported)
    {
      return XTR_UNSUPPORTED;
    }

  memset (&x, 0, sizeof (x));
  r.sink_context = &x;
  r.begin = xw_begin;
  r.data = xw_data;
  r.max_records = policy.max_records;
  r.max_field = policy.max_field;
  r.max_total = policy.max_manifest;
  if (fseek (stage, 0, SEEK_SET))
    {
      rc = XTR_IO;
    }
  else
    {
      rc = xtr_parse_manifest (&r, digest.manifest_length, &manifest);
    }

  if (!rc && xw_flush (&x))
    {
      rc = x.error ? x.error : XTR_IO;
    }

  if (rc == XTR_IO && x.error)
    {
      rc = x.error;
    }

  free (x.name);
  free (x.value);
  if (rc)
    {
      xtr_win_ea_free (&x.list);
      return rc;
    }

  *output = x.list;
  return XTR_OK;
}
