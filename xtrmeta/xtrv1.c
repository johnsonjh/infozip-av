/* SPDX-License-Identifier: MIT-0 */
/* Xtro ZIP strict, portable C89 V1 metadata serializer/parser. */
#include "xtrv1.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define MASK 0xffffffffUL
#define XTR_TRAILER 36U
static unsigned
get16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}
static unsigned long
get32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static xtr_u64
get64 (const unsigned char *p)
{
  xtr_u64 v;

  v.lo = get32 (p);
  v.hi = get32 (p + 4);
  return v;
}
static void
put32 (unsigned char *p, unsigned long v)
{
  p[0] = (unsigned char)v;
  p[1] = (unsigned char)(v >> 8);
  p[2] = (unsigned char)(v >> 16);
  p[3] = (unsigned char)(v >> 24);
}
static void
put64 (unsigned char *p, xtr_u64 v)
{
  put32 (p, v.lo);
  put32 (p + 4, v.hi);
}
static int
valid64 (xtr_u64 v)
{
  return v.lo <= MASK && v.hi <= MASK;
}
static int
eq64 (xtr_u64 a, xtr_u64 b)
{
  return a.lo == b.lo && a.hi == b.hi;
}
static int
less64 (xtr_u64 a, xtr_u64 b)
{
  return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo);
}
static xtr_u64
u64small (unsigned long n)
{
  xtr_u64 v;

  v.lo = n & MASK;
  v.hi = (n >> 16 >> 16) & MASK;
  return v;
}
static int
add64 (xtr_u64 *v, xtr_u64 a)
{
  unsigned long old = v->lo, hi;

  if (!valid64 (*v) || !valid64 (a))
    {
      return 0;
    }

  v->lo = (v->lo + a.lo) & MASK;
  if (v->lo < old && a.hi == MASK)
    {
      return 0;
    }

  hi = a.hi + (v->lo < old ? 1UL : 0UL);
  if (hi > MASK || v->hi > MASK - hi)
    {
      return 0;
    }

  v->hi += hi;
  return 1;
}
static int
subsmall (xtr_u64 *v, unsigned long n)
{
  if (v->hi == 0 && v->lo < n)
    {
      return 0;
    }

  if (v->lo < n)
    {
      v->lo = (v->lo + ((MASK - n) + 1UL)) & MASK;
      v->hi--;
    }
  else
    {
      v->lo -= n;
    }

  return 1;
}
static int
eqzero (const unsigned char *p, size_t n)
{
  size_t i;

  for (i = 0; i < n; i++)
    {
      if (p[i])
        {
          return 0;
        }
    }

  return 1;
}
static void *
getmem (const xtr1_policy *p, size_t n)
{
  if (p->alloc)
    {
      return p->alloc (p->context, n ? n : 1U);
    }

  return malloc (n ? n : 1U);
}
static void
freemem (const xtr1_policy *p, void *m)
{
  if (!m)
    {
      return;
    }

  if (p->release)
    {
      p->release (p->context, m);
    }
  else
    {
      free (m);
    }
}
static int
goodpolicy (const xtr1_policy *p)
{
  return p && p->max_records && p->max_field && valid64 (p->max_manifest)
         && ((!p->alloc && !p->release) || (p->alloc && p->release));
}
static int
cmpbytes (const unsigned char *a, size_t an, const unsigned char *b, size_t bn)
{
  int v = (an && bn) ? memcmp (a, b, an < bn ? an : bn) : 0;

  if (v)
    {
      return v < 0 ? -1 : 1;
    }

  return an < bn ? -1 : (an > bn ? 1 : 0);
}
static int
keycmp (const xtr_record *a, const unsigned char *ans,
        const unsigned char *aname, unsigned ai, const xtr_record *b,
        const unsigned char *bns, const unsigned char *bname, unsigned bi)
{
  int c;

  if (a->type != b->type)
    {
      return a->type < b->type ? -1 : 1;
    }

  if (a->origin != b->origin)
    {
      return a->origin < b->origin ? -1 : 1;
    }

  if (a->encoding != b->encoding)
    {
      return a->encoding < b->encoding ? -1 : 1;
    }

  c = cmpbytes (ans, (size_t)a->ns_len, bns, (size_t)b->ns_len);
  if (c)
    {
      return c;
    }

  c = cmpbytes (aname, (size_t)a->name_len, bname, (size_t)b->name_len);
  if (c)
    {
      return c;
    }

  return ai < bi ? -1 : (ai > bi ? 1 : 0);
}
static int
known_origin (unsigned origin, unsigned type, unsigned iface)
{
  if (type == 1U)
    {
      return (origin == 1 && iface == 1) || (origin == 2 && iface == 2)
             || (origin == 3 && iface == 4) || (origin == 4 && iface == 5)
             || (origin == 5 && iface == 6) || (origin == 7 && iface == 8)
             || (origin == 8 && iface == 10);
    }

  if (type == 2U)
    {
      return (origin == 2 && iface == 3) || (origin == 6 && iface == 7);
    }

  if (type == 3U)
    {
      return origin == 7 && iface == 9;
    }

  if (type == 4U)
    {
      return origin == 4 && iface == 11;
    }

  if (type == 5U)
    {
      return origin == 4 && iface == 12;
    }

  return 0;
}
/* Schema-check TLVs. Unknown noncritical fields remain preserve-only.
 * Known fields have unique, ascending numeric tags and fixed sizes.
 * Return unsupported applicability independently from structural validity. */
static int
check_native (const xtr_record *r, const unsigned char *p, size_t len,
              unsigned *iface, int *supported)
{
  size_t at = 0;
  unsigned prev = 0;

  *iface = 0;
  *supported = 1;
  while (at < len)
    {
      unsigned id, fl;
      unsigned long n;
      if (len - at < 8U)
        {
          return XTR_CORRUPT;
        }

      id = get16 (p + at);
      fl = get16 (p + at + 2);
      n = get32 (p + at + 4);
      at += 8;
      if (id == 0 || id <= prev || n > len - at)
        {
          return XTR_CORRUPT;
        }

      prev = id;
      switch (id)
        {
        case 1:
          if (n != 2)
            {
              return XTR_CORRUPT;
            }

          *iface = get16 (p + at);
          if (*iface < 1U || *iface > 12U)
            {
              *supported = 0;
            }

          break;

        case 2:
        case 4:
        case 5:
        case 10:
        case 11:
        case 12:
          if (n != 4)
            {
              return XTR_CORRUPT;
            }

          if (id == 2 && r->type != 2U)
            {
              *supported = 0;
            }

          if (id == 11 && r->type != 3U)
            {
              *supported = 0;
            }

          break;

        case 3:
          if (n != 1)
            {
              return XTR_CORRUPT;
            }

          if (r->origin != 7 || r->type != 1 || (p[at] & 0x7fU))
            {
              *supported = 0;
            }

          break;

        case 6:
        case 7:
        case 8:
        case 9:
          if (n != 12)
            {
              return XTR_CORRUPT;
            }

          if (get32 (p + at + 8) > 999999999UL)
            {
              return XTR_CORRUPT;
            }

          if (r->type != 2U)
            {
              *supported = 0;
            }

          break;

        default:
          *supported = 0;
          break;
        }
      if (fl & ~1U)
        {
          *supported = 0;
        }

      if (id > 12)
        {
          *supported = 0;
        }

      at += (size_t)n;
    }
  if (at != len)
    {
      return XTR_CORRUPT;
    }

  if (r->type >= 1U && r->type <= 5U)
    {
      if (!*iface)
        {
          return XTR_CORRUPT;
        }

      if (!known_origin (r->origin, r->type, *iface))
        {
          *supported = 0;
        }
    }
  else
    {
      *supported = 0;
    }

  if (r->type == 0 || r->type == 65535U || r->encoding > 2U
      || (r->encoding == 2U && (r->name_len & 1UL)))
    {
      return XTR_CORRUPT;
    }

  if (r->type <= 5U && !r->name_len)
    {
      return XTR_CORRUPT;
    }

  if (r->flags & ~1U)
    {
      *supported = 0;
    }

  if ((r->flags & 1U) && !*supported)
    {
      *supported = 0;
    }

  return XTR_OK;
}
/* Parse state, bounded only by max_field, never by value size. */
typedef struct state
{
  const xtr1_policy *policy;
  xtr_reader *input;
  xtr_record current, previous;
  unsigned char *buf, *prevbuf;
  size_t buflen, prevlen, pos[3];
  unsigned iface, previface;
  int have, can_apply, error;
  unsigned long crc32;
  xtr_sha256 sha;
} state;
static size_t
hashing_read (void *opaque, unsigned char *out, size_t n)
{
  state *s = (state *)opaque;
  size_t got = s->input->read (s->input->context, out, n);

  if (got <= n && got)
    {
      s->crc32 = xtr_crc32_update (s->crc32, out, got);
      xtr_sha256_update (&s->sha, out, got);
    }

  return got;
}
static int
finish (state *s)
{
  unsigned iface;
  int supported, c;
  unsigned char *b = s->buf, *p = s->prevbuf;
  size_t n0, n1;

  if (!s->have)
    {
      return XTR_OK;
    }

  n0 = (size_t)s->current.ns_len;
  n1 = (size_t)s->current.name_len;
  if (s->pos[0] != n0 || s->pos[1] != n1
      || s->pos[2] != (size_t)s->current.native_len)
    {
      return XTR_CORRUPT;
    }

  c = check_native (&s->current, b + n0 + n1, (size_t)s->current.native_len,
                    &iface, &supported);
  if (c)
    {
      return c;
    }

  if (!supported)
    {
      s->can_apply = 0;
    }

  if (s->prevbuf)
    {
      c = keycmp (&s->previous, p, p + (size_t)s->previous.ns_len,
                  s->previface, &s->current, b, b + n0, iface);
      if (c >= 0)
        {
          return XTR_CORRUPT; /* out of order OR semantic duplicate */
        }
    }

  freemem (s->policy, s->prevbuf);
  s->prevbuf = s->buf;
  s->prevlen = s->buflen;
  s->previous = s->current;
  s->previface = iface;
  s->buf = NULL;
  s->buflen = 0;
  s->have = 0;
  return XTR_OK;
}
static int
onbegin (void *opaque, const xtr_record *r)
{
  state *s = (state *)opaque;
  size_t n;
  unsigned long maxsize = (unsigned long)(size_t)-1;
  int c = finish (s);

  if (c)
    {
      s->error = c;
      return 1;
    }

  if (r->ns_len > s->policy->max_field || r->name_len > s->policy->max_field
      || r->native_len > s->policy->max_field)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  if (r->ns_len > maxsize || r->name_len > maxsize || r->native_len > maxsize)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  n = (size_t)r->ns_len;
  if ((size_t)r->name_len > (size_t)-1 - n)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  n += (size_t)r->name_len;
  if ((size_t)r->native_len > (size_t)-1 - n)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  n += (size_t)r->native_len;
  s->buf = (unsigned char *)getmem (s->policy, n + (n == 0));
  if (!s->buf)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  s->buflen = n;
  s->current = *r;
  s->pos[0] = s->pos[1] = s->pos[2] = 0;
  s->have = 1;
  return 0;
}
static int
ondata (void *opaque, const xtr_record *r, unsigned field,
        const unsigned char *b, size_t n)
{
  state *s = (state *)opaque;
  size_t off, lim;

  (void)r;
  if (field == 3)
    {
      return 0; /* binary attribute values remain streaming */
    }

  if (field > 2U || !s->have)
    {
      s->error = XTR_CORRUPT;
      return 1;
    }

  off = field == 0 ? 0
        : field == 1
            ? (size_t)s->current.ns_len
            : ((size_t)s->current.ns_len + (size_t)s->current.name_len);
  lim = field == 0   ? (size_t)s->current.ns_len
        : field == 1 ? (size_t)s->current.name_len
                     : (size_t)s->current.native_len;
  if (s->pos[field] > lim || n > lim - s->pos[field])
    {
      s->error = XTR_CORRUPT;
      return 1;
    }

  memcpy (s->buf + off + s->pos[field], b, n);
  s->pos[field] += n;
  return 0;
}
static int
readexact (xtr_reader *r, unsigned char *b, size_t n)
{
  size_t at = 0, got;

  while (at < n)
    {
      got = r->read (r->context, b + at, n - at);
      if (!got || got > n - at)
        {
          return XTR_IO;
        }

      at += got;
    }
  return XTR_OK;
}
int
xtr1_check_manifest (xtr_reader *source, xtr_u64 encoded,
                     const xtr_extra *outer, const unsigned char *central_sha,
                     const xtr1_policy *policy, xtr1_digest *result)
{
  state s;
  xtr_reader rd;
  xtr_manifest m;
  xtr_u64 total = encoded;
  unsigned char calc[32], trailer[36];
  int rc, encrypted;

  if (!goodpolicy (policy) || !source || !source->read || !outer || !result
      || !valid64 (encoded) || !valid64 (outer->manifest_len)
      || eqzero (outer->owner, 16))
    {
      return XTR_CORRUPT;
    }

  if (outer->mode != 1U && outer->mode != 2U)
    {
      return XTR_CORRUPT;
    }

  encrypted = (outer->flags & 1U) != 0;
  if (outer->flags & ~1U || (outer->mode == 1U && encrypted))
    {
      return XTR_CORRUPT;
    }

  if (encrypted)
    {
      if (outer->count || outer->manifest_len.lo || outer->manifest_len.hi
          || outer->crc32)
        {
          return XTR_CORRUPT;
        }

      if (!subsmall (&total, XTR_TRAILER))
        {
          return XTR_CORRUPT;
        }
    }

  if (less64 (policy->max_manifest, total))
    {
      return XTR_LIMIT;
    }

  if (!encrypted && !eq64 (outer->manifest_len, total))
    {
      return XTR_CORRUPT;
    }

  memset (&s, 0, sizeof (s));
  s.policy = policy;
  s.input = source;
  s.can_apply = 1;
  xtr_sha256_init (&s.sha);
  memset (&rd, 0, sizeof (rd));
  rd.context = &s;
  rd.read = hashing_read;
  rd.sink_context = &s;
  rd.begin = onbegin;
  rd.data = ondata;
  rd.max_records = policy->max_records;
  rd.max_field = policy->max_field;
  rd.max_total = policy->max_manifest;
  rc = xtr_parse_manifest (&rd, total, &m);
  if (rc == XTR_IO && s.error)
    {
      rc = s.error;
    }

  if (rc == XTR_OK)
    {
      rc = finish (&s);
    }

  if (rc == XTR_OK && memcmp (m.owner, outer->owner, 16))
    {
      rc = XTR_CORRUPT;
    }

  if (rc == XTR_OK && (!encrypted)
      && (m.count != outer->count || s.crc32 != outer->crc32))
    {
      rc = XTR_CORRUPT;
    }

  xtr_sha256_final (&s.sha, calc);
  if (rc == XTR_OK && !encrypted && outer->mode == 2U
      && (!central_sha || memcmp (calc, central_sha, 32)))
    {
      rc = XTR_CORRUPT;
    }

  if (rc == XTR_OK && encrypted)
    {
      rc = readexact (source, trailer, 36);
      if (rc == XTR_OK
          && (memcmp (trailer, "XTCS", 4) || memcmp (trailer + 4, calc, 32)))
        {
          rc = XTR_CORRUPT;
        }
    }

  if (rc == XTR_OK)
    {
      result->manifest_length = total;
      result->count = m.count;
      result->crc32 = s.crc32;
      memcpy (result->sha256, calc, 32);
      result->schema_supported = s.can_apply;
    }

  freemem (policy, s.buf);
  freemem (policy, s.prevbuf);
  return rc;
}
/* Write helpers: digest only the XTMD body, never the encrypted XTCS footer.
 */
typedef struct emit
{
  xtr1_sink *sink;
  xtr_sha256 sha;
  unsigned long crc;
} emit;
static int
emitbytes (emit *e, const unsigned char *p, size_t n)
{
  if (n && e->sink->write (e->sink->context, p, n))
    {
      return XTR_IO;
    }

  if (n)
    {
      xtr_sha256_update (&e->sha, p, n);
      e->crc = xtr_crc32_update (e->crc, p, n);
    }

  return XTR_OK;
}
int
xtr1_write_manifest (const unsigned char owner[16], const xtr1_source *items,
                     size_t count, int encrypted, const xtr1_policy *policy,
                     xtr1_sink *sink, xtr1_digest *result)
{
  xtr_u64 total, records;
  unsigned long maxsize = (unsigned long)(size_t)-1;
  xtr_manifest mh;
  unsigned char h[36], rh[28], buf[4096], digest[32], tail[36];
  unsigned intf = 0, prev_intf = 0;
  int rc, supported = 1, all_known = 1;
  size_t i;
  emit e;

  if (!owner || eqzero (owner, 16) || !goodpolicy (policy) || !sink
      || !sink->write || !result || (count && !items) || count > MASK
      || (unsigned long)count > policy->max_records
      || (encrypted != 0 && encrypted != 1))
    {
      return XTR_CORRUPT;
    }

  records = u64small (0);
  /* Preflight all lengths, identities and TLVs BEFORE writing anything. */
  for (i = 0; i < count; i++)
    {
      const xtr1_source *v = &items[i];
      xtr_u64 length = u64small (28);
      if (v->record.ns_len > policy->max_field
          || v->record.name_len > policy->max_field
          || v->record.native_len > policy->max_field)
        {
          return XTR_LIMIT;
        }

      if (v->record.ns_len > maxsize || v->record.name_len > maxsize
          || v->record.native_len > maxsize)
        {
          return XTR_LIMIT;
        }

      if ((v->record.ns_len && !v->ns) || (v->record.name_len && !v->name)
          || (v->record.native_len && !v->native)
          || ((v->record.value_len.lo || v->record.value_len.hi)
              && !v->read_value))
        {
          return XTR_CORRUPT;
        }

      if (xtr_record_header (rh, &v->record) != XTR_OK)
        {
          return XTR_CORRUPT;
        }

      rc = check_native (&v->record, v->native, (size_t)v->record.native_len,
                         &intf, &supported);
      if (rc)
        {
          return rc;
        }

      if (!supported)
        {
          all_known = 0;
        }

      if (i
          && keycmp (&items[i - 1].record, items[i - 1].ns, items[i - 1].name,
                     prev_intf, &v->record, v->ns, v->name, intf)
                 >= 0)
        {
          return XTR_CORRUPT;
        }

      prev_intf = intf;
      if (!add64 (&length, u64small (v->record.ns_len))
          || !add64 (&length, u64small (v->record.name_len))
          || !add64 (&length, u64small (v->record.native_len))
          || !add64 (&length, v->record.value_len)
          || !add64 (&records, length))
        {
          return XTR_LIMIT;
        }
    }

  total = records;
  if (!add64 (&total, u64small (36)) || less64 (policy->max_manifest, total))
    {
      return XTR_LIMIT;
    }

  memset (&mh, 0, sizeof (mh));
  memcpy (mh.owner, owner, 16);
  mh.count = (unsigned long)count;
  mh.records_len = records;
  if (xtr_manifest_header (h, &mh))
    {
      return XTR_CORRUPT;
    }

  memset (&e, 0, sizeof (e));
  e.sink = sink;
  xtr_sha256_init (&e.sha);
  rc = emitbytes (&e, h, 36);
  if (rc)
    {
      return rc;
    }

  for (i = 0; i < count; i++)
    {
      const xtr1_source *v = &items[i];
      xtr_u64 remain = v->record.value_len;
      if (xtr_record_header (rh, &v->record))
        {
          return XTR_CORRUPT;
        }

      if ((rc = emitbytes (&e, rh, 28)))
        {
          return rc;
        }

      if ((rc = emitbytes (&e, v->ns, (size_t)v->record.ns_len)))
        {
          return rc;
        }

      if ((rc = emitbytes (&e, v->name, (size_t)v->record.name_len)))
        {
          return rc;
        }

      if ((rc = emitbytes (&e, v->native, (size_t)v->record.native_len)))
        {
          return rc;
        }

      while (remain.lo || remain.hi)
        {
          size_t want = sizeof (buf), got, at = 0;
          if (!remain.hi && remain.lo < (unsigned long)want)
            {
              want = (size_t)remain.lo;
            }

          while (at < want)
            {
              got = v->read_value (v->value_context, buf + at, want - at);
              if (!got || got > want - at)
                {
                  return XTR_IO;
                }

              at += got;
            }
          if ((rc = emitbytes (&e, buf, want)))
            {
              return rc;
            }

          if (!subsmall (&remain, (unsigned long)want))
            {
              return XTR_CORRUPT;
            }
        }
    }

  xtr_sha256_final (&e.sha, digest);
  if (encrypted)
    {
      memcpy (tail, "XTCS", 4);
      memcpy (tail + 4, digest, 32);
      if (sink->write (sink->context, tail, 36))
        {
          return XTR_IO;
        }
    }

  result->manifest_length = total;
  result->count = (unsigned long)count;
  result->crc32 = e.crc;
  memcpy (result->sha256, digest, 32);
  result->schema_supported = all_known;
  return XTR_OK;
}
int
xtr1_extra_encode (unsigned char *out, size_t cap, const xtr_extra *e,
                   int central, const unsigned char *inline_payload,
                   size_t inline_size, const unsigned char *sha32,
                   size_t *written)
{
  size_t n = 40;

  if (!out || !e || !written || !valid64 (e->manifest_len) || e->count > MASK
      || e->crc32 > MASK || (e->mode != 1 && e->mode != 2) || (e->flags & ~1U)
      || eqzero (e->owner, 16))
    {
      return XTR_CORRUPT;
    }

  if (!central && (inline_payload || inline_size || sha32))
    {
      return XTR_CORRUPT;
    }

  if (e->mode == 1)
    {
      if (e->flags
          || (central
              && (e->manifest_len.hi || e->manifest_len.lo != inline_size
                  || inline_size < 36 || !inline_payload || sha32)))
        {
          return XTR_CORRUPT;
        }

      if (central)
        {
          if (inline_size > 65535U - 40U)
            {
              return XTR_LIMIT;
            }

          if (memcmp (inline_payload, "XTMD\001\000\000\000", 8)
              || memcmp (inline_payload + 8, e->owner, 16)
              || get32 (inline_payload + 24) != e->count
              || !eq64 (get64 (inline_payload + 28),
                        u64small ((unsigned long)(inline_size - 36)))
              || xtr_crc32_update (0, inline_payload, inline_size) != e->crc32)
            {
              return XTR_CORRUPT;
            }

          n += inline_size;
        }
    }
  else
    {
      if (inline_payload || inline_size
          || (e->flags
              && (e->count || e->manifest_len.lo || e->manifest_len.hi
                  || e->crc32)))
        {
          return XTR_CORRUPT;
        }

      if (central && !e->flags)
        {
          if (!sha32)
            {
              return XTR_CORRUPT;
            }

          n = 72;
        }
      else if (sha32)
        {
          return XTR_CORRUPT;
        }
    }

  if (n > cap)
    {
      return XTR_LIMIT;
    }

  memcpy (out, "XTRO", 4);
  out[4] = 1;
  out[5] = 0;
  out[6] = (unsigned char)e->mode;
  out[7] = (unsigned char)e->flags;
  memcpy (out + 8, e->owner, 16);
  put32 (out + 24, e->count);
  put64 (out + 28, e->manifest_len);
  put32 (out + 36, e->crc32);
  if (central && e->mode == 1)
    {
      memcpy (out + 40, inline_payload, inline_size);
    }

  if (central && e->mode == 2 && !e->flags)
    {
      memcpy (out + 40, sha32, 32);
    }

  *written = n;
  return XTR_OK;
}
int
xtr1_extra_decode (const unsigned char *p, size_t n, int central, xtr_extra *e,
                   unsigned char sha32[32])
{
  if (!p || !e || n < 40U || n > 65535U || memcmp (p, "XTRO", 4))
    {
      return XTR_CORRUPT;
    }

  if (p[4] != 1 || p[5] != 0)
    {
      return XTR_UNSUPPORTED;
    }

  e->mode = p[6];
  e->flags = p[7];
  memcpy (e->owner, p + 8, 16);
  e->count = get32 (p + 24);
  e->manifest_len = get64 (p + 28);
  e->crc32 = get32 (p + 36);
  if (eqzero (e->owner, 16))
    {
      return XTR_CORRUPT;
    }

  if (e->mode == 1)
    {
      if (e->flags || (!central && n != 40)
          || (central
              && (n < 76 || e->manifest_len.hi
                  || e->manifest_len.lo != (unsigned long)(n - 40)
                  || memcmp (p + 40, "XTMD\001\000\000\000", 8)
                  || memcmp (p + 48, e->owner, 16)
                  || get32 (p + 64) != e->count
                  || !eq64 (get64 (p + 68), u64small ((unsigned long)(n - 76)))
                  || xtr_crc32_update (0, p + 40, n - 40) != e->crc32)))
        {
          return XTR_CORRUPT;
        }
    }
  else if (e->mode == 2)
    {
      if (e->flags & ~1U || n != (size_t)(central && !e->flags ? 72 : 40)
          || (e->flags
              && (e->count || e->manifest_len.lo || e->manifest_len.hi
                  || e->crc32)))
        {
          return XTR_CORRUPT;
        }

      if (central && !e->flags && sha32)
        {
          memcpy (sha32, p + 40, 32);
        }
    }
  else
    {
      return XTR_CORRUPT;
    }

  return XTR_OK;
}
int
xtr1_check_headers (const unsigned char *loc, size_t ln,
                    const unsigned char *cen, size_t cn, xtr_extra *e,
                    unsigned char sha32[32])
{
  xtr_extra a, b;
  int rc = xtr1_extra_decode (loc, ln, 0, &a, NULL);

  if (rc)
    {
      return rc;
    }

  rc = xtr1_extra_decode (cen, cn, 1, &b, sha32);
  if (rc)
    {
      return rc;
    }

  if (memcmp (loc, cen, 40) || a.mode != b.mode || a.flags != b.flags
      || memcmp (a.owner, b.owner, 16))
    {
      return XTR_CORRUPT;
    }

  if (e)
    {
      *e = b;
    }

  return XTR_OK;
}
int
xtr1_check_fwkcs (const unsigned char *p, size_t n, int central)
{
  if (!central || !p || n != 19 || memcmp (p, "MD5", 3))
    {
      return XTR_CORRUPT;
    }

  return XTR_OK;
}
int
xtr1_scan_extra_list (const unsigned char *p, size_t n, int central,
                      int *has_xtr, int *has_fwkcs)
{
  size_t at = 0, bytes;
  unsigned id;

  if (n > 65535U || (!p && n) || !has_xtr || !has_fwkcs)
    {
      return XTR_CORRUPT;
    }

  *has_xtr = *has_fwkcs = 0;
  while (at < n)
    {
      if (n - at < 4U)
        {
          return XTR_CORRUPT;
        }

      id = get16 (p + at);
      bytes = get16 (p + at + 2);
      at += 4;
      if (bytes > n - at)
        {
          return XTR_CORRUPT;
        }

      if (id == XTR_V1_EXTRA_ID)
        {
          xtr_extra x;
          int rc;
          if (*has_xtr)
            {
              return XTR_CORRUPT;
            }

          rc = xtr1_extra_decode (p + at, bytes, central, &x, NULL);
          if (rc)
            {
              return rc;
            }

          *has_xtr = 1;
        }
      else if (id == 0x4b46U)
        {
          if (*has_fwkcs || xtr1_check_fwkcs (p + at, bytes, central))
            {
              return XTR_CORRUPT;
            }

          *has_fwkcs = 1;
        }

      at += bytes;
    }
  return XTR_OK;
}
int
xtr1_crypto_check (unsigned owner, unsigned companion, int zip_ok,
                   int authenticated)
{
  if (owner > 4 || companion > 4 || owner != companion)
    {
      return XTR_CORRUPT;
    }

  if (owner == 0)
    {
      return zip_ok ? XTR_OK : XTR_IO;
    }

  if (owner == 1)
    {
      return zip_ok ? XTR_OK : XTR_IO;
    }

  return (zip_ok && authenticated) ? XTR_OK : XTR_IO;
}
int
xtr1_companion_name (const unsigned char owner[16], char out[52])
{
  static const char hex[] = "0123456789abcdef";
  static const char prefix[] = "__XTRO_ZIP__/x/";
  unsigned i;

  if (!owner || !out || eqzero (owner, 16))
    {
      return XTR_CORRUPT;
    }

  memcpy (out, prefix, 15);
  for (i = 0; i < 16; i++)
    {
      out[15 + 2 * i] = hex[owner[i] >> 4];
      out[16 + 2 * i] = hex[owner[i] & 15];
    }

  memcpy (out + 47, ".xtm", 5);
  return XTR_OK;
}
int
xtr1_companion_matches (const unsigned char owner[16], const char *name,
                        size_t len)
{
  char expected[52];

  if (!name || len != 51)
    {
      return XTR_CORRUPT;
    }

  if (xtr1_companion_name (owner, expected))
    {
      return XTR_CORRUPT;
    }

  return memcmp (expected, name, 51) == 0 ? XTR_OK : XTR_CORRUPT;
}

/* Pairing validation across an archive's central-directory entry occurrences.
 * No file content is modified; caller must stage any later rewrite. */
typedef struct pairing
{
  unsigned char id[16];
  unsigned mode;
  int companion;
} pairing;
static int
paircompare (const void *aa, const void *bb)
{
  const pairing *a = (const pairing *)aa, *b = (const pairing *)bb;
  int c = memcmp (a->id, b->id, 16);

  if (c)
    {
      return c;
    }

  return a->companion == b->companion ? 0 : (a->companion ? -1 : 1);
}
static int
nibble (unsigned char c)
{
  if (c >= '0' && c <= '9')
    {
      return c - '0';
    }

  if (c >= 'a' && c <= 'f')
    {
      return c - 'a' + 10;
    }

  return -1;
}
int
xtr1_check_archive_index (const xtr1_index_entry *v, size_t count,
                          const xtr1_policy *p)
{
  pairing *pairs;
  size_t used = 0, i, j;
  int rc = XTR_OK;
  static const char prefix[] = "__XTRO_ZIP__/";

  if (!goodpolicy (p) || (count && !v) || count > p->max_records
      || count > (size_t)-1 / sizeof (pairing))
    {
      return XTR_LIMIT;
    }

  pairs = (pairing *)getmem (p, (count ? count : 1U) * sizeof (pairing));
  if (!pairs)
    {
      return XTR_LIMIT;
    }

  for (i = 0; i < count; i++)
    {
      const xtr1_index_entry *it = &v[i];
      int reserved
          = it->name && it->name_len >= 13U && !memcmp (it->name, prefix, 13U);
      if (!it->name || (it->name_len && !it->name) || (it->mode > 2)
          || (it->mode != 0 && !it->owner_id))
        {
          rc = XTR_CORRUPT;
          break;
        }

      if (it->companion)
        {
          if (!reserved || it->mode || it->owner_id || it->name_len != 51
              || memcmp (it->name, "__XTRO_ZIP__/x/", 15)
              || memcmp (it->name + 47, ".xtm", 4))
            {
              rc = XTR_CORRUPT;
              break;
            }

          for (j = 0; j < 16; j++)
            {
              int h = nibble ((unsigned char)it->name[15 + 2 * j]);
              int l = nibble ((unsigned char)it->name[16 + 2 * j]);
              if (h < 0 || l < 0)
                {
                  rc = XTR_CORRUPT;
                  break;
                }

              pairs[used].id[j] = (unsigned char)(h * 16 + l);
            }

          if (rc)
            {
              break;
            }

          pairs[used].companion = 1;
          pairs[used].mode = 0;
          used++;
        }
      else
        {
          if (reserved)
            {
              rc = XTR_CORRUPT;
              break;
            }

          if (it->mode)
            {
              if (eqzero (it->owner_id, 16))
                {
                  rc = XTR_CORRUPT;
                  break;
                }

              memcpy (pairs[used].id, it->owner_id, 16);
              pairs[used].mode = it->mode;
              pairs[used].companion = 0;
              used++;
            }
        }
    }

  if (rc == XTR_OK)
    {
      qsort (pairs, used, sizeof (pairing), paircompare);
      i = 0;
      while (i < used)
        {
          size_t k = i + 1;
          int owners = 0, comps = 0;
          unsigned mode = 0;
          while (k < used && !memcmp (pairs[i].id, pairs[k].id, 16))
            {
              k++;
            }
          for (j = i; j < k; j++)
            {
              if (pairs[j].companion)
                {
                  comps++;
                }
              else
                {
                  owners++;
                  mode = pairs[j].mode;
                }
            }

          if (owners != 1 || comps != (int)(mode == 2))
            {
              rc = XTR_CORRUPT;
              break;
            }

          i = k;
        }
    }

  freemem (p, pairs);
  return rc;
}

/* Metadata policy is a separate step after the ZIP implementation has
 * decrypted, decompressed and validated the exact companion payload. */
int
xtr1_check_member_policy_dir (const xtr_extra *e, unsigned owner_crypto,
                              unsigned companion_crypto, int owner_is_directory,
                              int zip_ok, int authenticated,
                              int companion_has_fwkcs, int fwkcs_all_required)
{
  if (!e || owner_crypto > 4U || companion_crypto > 4U
      || (e->mode != XTR_V1_INLINE && e->mode != XTR_V1_COMPANION)
      || (e->flags & ~XTR_V1_ENCRYPTED) || eqzero (e->owner, 16)
      || (e->mode == XTR_V1_INLINE && e->flags))
    {
      return XTR_CORRUPT;
    }

  if (e->mode == XTR_V1_INLINE)
    {
      if (owner_crypto != 0U || companion_crypto != 0U || companion_has_fwkcs)
        {
          return XTR_UNSUPPORTED;
        }

      return zip_ok ? XTR_OK : XTR_IO;
    }

  if (owner_is_directory && owner_crypto != 0U)
    return XTR_CORRUPT;

  /* Directory owners are deliberately unencrypted ZIP entries. V1 permits
   * their metadata ONLY in an encrypted companion (never inline). No other
   * unencrypted-owner/encrypted-companion relationship is valid. */
  if (owner_is_directory && owner_crypto == 0U
      && companion_crypto != 0U && (e->flags & XTR_V1_ENCRYPTED))
    {
      if (companion_has_fwkcs)
        return XTR_CORRUPT;
      if (fwkcs_all_required)
        return XTR_UNSUPPORTED;
      return xtr1_crypto_check (companion_crypto, companion_crypto,
                                zip_ok, authenticated);
    }
  if (owner_crypto != companion_crypto
      || (!!(e->flags & XTR_V1_ENCRYPTED)) != (owner_crypto != 0U))
    {
      return XTR_CORRUPT;
    }

  if (owner_crypto != 0U)
    {
      if (companion_has_fwkcs)
        {
          return XTR_CORRUPT;
        }

      if (fwkcs_all_required)
        {
          return XTR_UNSUPPORTED;
        }
    }

  return xtr1_crypto_check (owner_crypto, companion_crypto, zip_ok,
                            authenticated);
}
/* Preserve the original strict API for callers which cannot independently
 * establish the owner's directory status from verified ZIP structures. */
int
xtr1_check_member_policy (const xtr_extra *e, unsigned owner_crypto,
                          unsigned companion_crypto, int zip_ok,
                          int authenticated, int companion_has_fwkcs,
                          int fwkcs_all_required)
{
  return xtr1_check_member_policy_dir (e, owner_crypto, companion_crypto, 0,
                                       zip_ok, authenticated,
                                       companion_has_fwkcs,
                                       fwkcs_all_required);
}
static int
sameowner (const unsigned char *a, const unsigned char *b)
{
  return a && b && !memcmp (a, b, 16);
}
int
xtr1_check_rewrite_decisions (const xtr1_rewrite_entry *items, size_t count)
{
  size_t i;

  if (count && !items)
    {
      return XTR_CORRUPT;
    }

  for (i = 0; i < count; i++)
    {
      const xtr1_rewrite_entry *r = &items[i];
      if (r->operation > XTR1_CLONE || r->old_mode > 2U || r->new_mode > 2U
          || (r->old_mode && (!r->old_owner || eqzero (r->old_owner, 16)))
          || (r->new_mode && (!r->new_owner || eqzero (r->new_owner, 16)))
          || (!r->old_mode && r->old_owner) || (!r->new_mode && r->new_owner))
        {
          return XTR_CORRUPT;
        }

      switch (r->operation)
        {
        case XTR1_RETAIN:
        case XTR1_RENAME:
          if (r->old_mode != r->new_mode
              || (r->old_mode && !sameowner (r->old_owner, r->new_owner))
              || r->manifest_rebuilt)
            {
              return XTR_CORRUPT;
            }

          break;

        case XTR1_DELETE:
          if (r->new_mode || r->manifest_rebuilt)
            {
              return XTR_CORRUPT;
            }

          break;

        case XTR1_REPLACE:
          if (r->new_mode
              && (!r->manifest_rebuilt
                  || (r->old_mode && sameowner (r->old_owner, r->new_owner))))
            {
              return XTR_CORRUPT;
            }

          if (!r->new_mode && r->manifest_rebuilt)
            {
              return XTR_CORRUPT;
            }

          break;

        case XTR1_CLONE:
          if (r->old_mode != r->new_mode
              || (r->old_mode
                  && (!r->manifest_rebuilt
                      || sameowner (r->old_owner, r->new_owner)))
              || (!r->old_mode && r->manifest_rebuilt))
            {
              return XTR_CORRUPT;
            }

          break;
        }
    }

  return XTR_OK;
}

/* Convert ONLY the uncompressed metadata representation; ZipCloak's normal
 * byte-copy cipher cannot do this because a new XTCS footer changes the
 * compressed plaintext and the ZIP member CRC/length. */
int
xtr1_reframe_companion (xtr_reader *source, xtr_u64 source_size,
                        const xtr_extra *old_extra,
                        const unsigned char *old_central_sha,
                        const xtr1_policy *policy, xtr1_reset_cb reset,
                        void *reset_context, xtr1_sink *staged_output,
                        int encrypted_target, xtr_extra *new_extra,
                        xtr1_digest *manifest_digest)
{
  xtr1_digest initial;
  xtr_extra replacement;
  xtr_u64 remaining;
  xtr_sha256 hasher;
  unsigned char chunk[4096], digest[32], tail[36];
  unsigned long crc = 0UL;
  size_t got, want, at;
  int rc;

  if (!source || !source->read || !old_extra || !policy || !reset
      || !staged_output || !staged_output->write || !new_extra
      || !manifest_digest || (encrypted_target != 0 && encrypted_target != 1)
      || (old_extra->mode != XTR_V1_INLINE
          && old_extra->mode != XTR_V1_COMPANION))
    {
      return XTR_CORRUPT;
    }

  /* This is deliberately a two-pass API: malformed metadata must not be
   * passed to a production output writer or native filesystem backend. */
  rc = xtr1_check_manifest (source, source_size, old_extra, old_central_sha,
                            policy, &initial);
  if (rc != XTR_OK)
    {
      return rc;
    }

  if (reset (reset_context) != 0)
    {
      return XTR_IO;
    }

  remaining = initial.manifest_length;
  xtr_sha256_init (&hasher);
  while (remaining.lo || remaining.hi)
    {
      want = sizeof (chunk);
      if (!remaining.hi && remaining.lo < (unsigned long)want)
        {
          want = (size_t)remaining.lo;
        }

      at = 0;
      while (at < want)
        {
          got = source->read (source->context, chunk + at, want - at);
          if (!got || got > want - at)
            {
              return XTR_IO;
            }

          at += got;
        }
      xtr_sha256_update (&hasher, chunk, want);
      crc = xtr_crc32_update (crc, chunk, want);
      if (staged_output->write (staged_output->context, chunk, want))
        {
          return XTR_IO;
        }

      if (!subsmall (&remaining, (unsigned long)want))
        {
          return XTR_CORRUPT;
        }
    }
  xtr_sha256_final (&hasher, digest);
  if (memcmp (digest, initial.sha256, 32) || crc != initial.crc32)
    {
      return XTR_CORRUPT;
    }

  if (old_extra->flags & XTR_V1_ENCRYPTED)
    {
      rc = readexact (source, tail, 36);
      if (rc != XTR_OK)
        {
          return rc;
        }

      if (memcmp (tail, "XTCS", 4) || memcmp (tail + 4, digest, 32))
        {
          return XTR_CORRUPT;
        }
    }

  if (encrypted_target)
    {
      memcpy (tail, "XTCS", 4);
      memcpy (tail + 4, digest, 32);
      if (staged_output->write (staged_output->context, tail, 36))
        {
          return XTR_IO;
        }
    }

  memset (&replacement, 0, sizeof (replacement));
  memcpy (replacement.owner, old_extra->owner, 16);
  replacement.mode = XTR_V1_COMPANION;
  replacement.flags = encrypted_target ? XTR_V1_ENCRYPTED : 0;
  if (!encrypted_target)
    {
      replacement.count = initial.count;
      replacement.manifest_len = initial.manifest_length;
      replacement.crc32 = initial.crc32;
    }

  *new_extra = replacement;
  *manifest_digest = initial;
  return XTR_OK;
}

/* M6E2B: ZIP extra-list surgery. These are pure C89 memory operations, not
 * archive publication primitives. The destination buffers may be touched
 * only after all input fields and both output capacities are validated. */
static int
xtr1_find_owner_field (const unsigned char *p, size_t n, size_t *where,
                       size_t *field_len)
{
  size_t at = 0;
  int seen = 0;

  if (n > 65535U || (!p && n))
    {
      return XTR_CORRUPT;
    }

  while (at < n)
    {
      unsigned id;
      size_t v;
      if (n - at < 4U)
        {
          return XTR_CORRUPT;
        }

      id = get16 (p + at);
      v = (size_t)get16 (p + at + 2U);
      if (v > n - at - 4U)
        {
          return XTR_CORRUPT;
        }

      if (id == XTR_V1_EXTRA_ID)
        {
          if (seen)
            {
              return XTR_CORRUPT;
            }

          seen = 1;
          *where = at;
          *field_len = v + 4U;
        }

      at += 4U + v;
    }
  return seen ? XTR_OK : XTR_CORRUPT;
}
/* Copy all fields, replacing the selected field at its original position.
 * Caller already calculated the exact destination capacity and validated
 * the source field boundaries. */
static void
xtr1_replace_field (const unsigned char *src, size_t len, size_t where,
                    size_t old_size, const unsigned char *new_field,
                    size_t new_size, unsigned char *dst)
{
  if (where)
    {
      memcpy (dst, src, where);
    }

  memcpy (dst + where, new_field, new_size);
  if (where + old_size < len)
    {
      memcpy (dst + where + new_size, src + where + old_size,
              len - where - old_size);
    }
}
static void
xtr1_field_header (unsigned char *p, unsigned id, size_t n)
{
  p[0] = (unsigned char)id;
  p[1] = (unsigned char)(id >> 8);
  p[2] = (unsigned char)n;
  p[3] = (unsigned char)(n >> 8);
}
int
xtr1_rewrite_owner_extras (const unsigned char *old_local, size_t old_ln,
                           const unsigned char *old_central, size_t old_cn,
                           const xtr_extra *new_owner,
                           const unsigned char *inline_payload,
                           size_t inline_len, const unsigned char *sha32,
                           unsigned char *new_local, size_t local_cap,
                           size_t *local_written, unsigned char *new_central,
                           size_t central_cap, size_t *central_written)
{
  unsigned char lnew[44], csmall[76];
  unsigned char *cnew = csmall;
  size_t lo = 0, co = 0, ls = 0, cs = 0, lpsz = 0, cpsz = 0, nl, nc;
  int has, has_fwkcs, rc;
  xtr_extra old;
  unsigned char oldsha[32];

  if (!local_written || !central_written || local_written == central_written)
    {
      return XTR_CORRUPT;
    }

  *local_written = *central_written = 0;
  if (!new_owner || !new_local || !new_central || new_local == new_central
      || old_ln > 65535U || old_cn > 65535U || (old_ln && !old_local)
      || (old_cn && !old_central))
    {
      return XTR_CORRUPT;
    }

  rc = xtr1_scan_extra_list (old_local, old_ln, 0, &has, &has_fwkcs);
  if (rc)
    {
      return rc;
    }

  if (has != 1 || has_fwkcs)
    {
      return XTR_CORRUPT;
    }

  rc = xtr1_scan_extra_list (old_central, old_cn, 1, &has, &has_fwkcs);
  if (rc)
    {
      return rc;
    }

  if (has != 1)
    {
      return XTR_CORRUPT;
    }

  if (xtr1_find_owner_field (old_local, old_ln, &lo, &ls)
      || xtr1_find_owner_field (old_central, old_cn, &co, &cs))
    {
      return XTR_CORRUPT;
    }

  rc = xtr1_check_headers (old_local + lo + 4U, ls - 4U, old_central + co + 4U,
                           cs - 4U, &old, oldsha);
  if (rc)
    {
      return rc;
    }

  if (memcmp (old.owner, new_owner->owner, 16))
    {
      return XTR_CORRUPT;
    }

  if (new_owner->flags && new_owner->mode != XTR_V1_COMPANION)
    {
      return XTR_CORRUPT;
    }

  rc = xtr1_extra_encode (lnew + 4U, sizeof (lnew) - 4U, new_owner, 0, NULL, 0,
                          NULL, &lpsz);
  if (rc)
    {
      return rc;
    }

  /* Large inline envelopes use bounded heap scratch instead of 65 KiB
   * of automatic storage (notably relevant to small-stack DOS builds). */
  if (new_owner->mode == XTR_V1_INLINE)
    {
      if (inline_len > 65531U - 40U)
        {
          return XTR_LIMIT;
        }

      cnew = (unsigned char *)malloc (44U + inline_len);
      if (!cnew)
        {
          return XTR_LIMIT;
        }
    }

  rc = xtr1_extra_encode (
      cnew + 4U,
      new_owner->mode == XTR_V1_INLINE ? 40U + inline_len
                                       : sizeof (csmall) - 4U,
      new_owner, 1, inline_payload, inline_len, sha32, &cpsz);
  if (rc)
    {
      if (cnew != csmall)
        {
          free (cnew);
        }

      return rc;
    }

  xtr1_field_header (lnew, XTR_V1_EXTRA_ID, lpsz);
  xtr1_field_header (cnew, XTR_V1_EXTRA_ID, cpsz);
  if (lpsz > 65531U || cpsz > 65531U || old_ln - ls > 65535U - 4U - lpsz
      || old_cn - cs > 65535U - 4U - cpsz)
    {
      if (cnew != csmall)
        {
          free (cnew);
        }

      return XTR_LIMIT;
    }

  nl = old_ln - ls + 4U + lpsz;
  nc = old_cn - cs + 4U + cpsz;
  if (nl > local_cap || nc > central_cap)
    {
      if (cnew != csmall)
        {
          free (cnew);
        }

      return XTR_LIMIT;
    }

  xtr1_replace_field (old_local, old_ln, lo, ls, lnew, lpsz + 4U, new_local);
  xtr1_replace_field (old_central, old_cn, co, cs, cnew, cpsz + 4U,
                      new_central);
  *local_written = nl;
  *central_written = nc;
  if (cnew != csmall)
    {
      free (cnew);
    }

  return XTR_OK;
}
/* Companion entries themselves have no Xtro extra field. This operation
 * deliberately removes old FWKCS so a stale MD5 cannot outlive reframe.
 * The regenerated MD5 belongs only in the new central directory. */
int
xtr1_rewrite_companion_extras (const unsigned char *old_local, size_t old_ln,
                               const unsigned char *old_central, size_t old_cn,
                               int encrypted_target, int fwkcs_required,
                               const unsigned char *regenerated_fwkcs,
                               unsigned char *new_local, size_t local_cap,
                               size_t *local_written,
                               unsigned char *new_central, size_t central_cap,
                               size_t *central_written)
{
  size_t pos = 0, at = 0, old_md5 = 0, out_cn, cnwrite = 0;
  int has = 0, has_fwkcs = 0, rc;

  if (!local_written || !central_written || local_written == central_written)
    {
      return XTR_CORRUPT;
    }

  *local_written = *central_written = 0;
  if ((encrypted_target != 0 && encrypted_target != 1)
      || (fwkcs_required != 0 && fwkcs_required != 1) || !new_local
      || !new_central || new_local == new_central || old_ln > 65535U
      || old_cn > 65535U || (old_ln && !old_local) || (old_cn && !old_central))
    {
      return XTR_CORRUPT;
    }

  rc = xtr1_scan_extra_list (old_local, old_ln, 0, &has, &has_fwkcs);
  if (rc)
    {
      return rc;
    }

  if (has || has_fwkcs)
    {
      return XTR_CORRUPT;
    }

  rc = xtr1_scan_extra_list (old_central, old_cn, 1, &has, &has_fwkcs);
  if (rc)
    {
      return rc;
    }

  if (has)
    {
      return XTR_CORRUPT;
    }

  old_md5 = (size_t)has_fwkcs;
  if (encrypted_target && (fwkcs_required || regenerated_fwkcs))
    {
      return XTR_UNSUPPORTED;
    }

  if (!encrypted_target && (old_md5 || fwkcs_required) && !regenerated_fwkcs)
    {
      return XTR_UNSUPPORTED;
    }

  if (regenerated_fwkcs && xtr1_check_fwkcs (regenerated_fwkcs, 19U, 1))
    {
      return XTR_CORRUPT;
    }

  out_cn = old_cn - (old_md5 ? 23U : 0U);
  if (regenerated_fwkcs)
    {
      if (out_cn > 65535U - 23U)
        {
          return XTR_LIMIT;
        }

      out_cn += 23U;
    }

  if (old_ln > local_cap || out_cn > central_cap)
    {
      return XTR_LIMIT;
    }

  if (old_ln)
    {
      memcpy (new_local, old_local, old_ln);
    }

  /* Keep all other central extra fields in their original order. A new
   * FWKCS field is emitted at the end of the list after rehashing. */
  while (at < old_cn)
    {
      size_t v = (size_t)get16 (old_central + at + 2U) + 4U;
      if (get16 (old_central + at) != 0x4b46U)
        {
          memcpy (new_central + pos, old_central + at, v);
          pos += v;
        }

      at += v;
    }
  cnwrite = pos;
  if (regenerated_fwkcs)
    {
      xtr1_field_header (new_central + pos, 0x4b46U, 19U);
      memcpy (new_central + pos + 4U, regenerated_fwkcs, 19U);
      cnwrite += 23U;
    }

  *local_written = old_ln;
  *central_written = cnwrite;
  return XTR_OK;
}
