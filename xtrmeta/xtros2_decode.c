/* SPDX-License-Identifier: MIT-0 */
#include "xtros2_decode.h"
#include "xtros2_memory.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define MAX_OS2_META (32UL * 1024UL * 1024UL + 36UL)
typedef struct parser
{
  xtr_os2_ea_item *items;
  size_t count, capacity, current;
  size_t *name_pos, *value_pos;
  unsigned char native[22];
  size_t native_pos;
  int failed;
} parser;
static int
begin (void *ctx, const xtr_record *r)
{
  parser *p = (parser *)ctx;
  size_t idx;
  xtr_os2_ea_item *it;
  unsigned char *nm, *val;

  if (p->failed || p->count >= p->capacity || r->type != 1U || r->origin != 8U
      || r->encoding != 0U || r->ns_len != 0UL || !r->name_len
      || r->name_len > 255UL || r->native_len != 22UL || r->value_len.hi
      || r->value_len.lo > 65535UL)
    {
      p->failed = 1;
      return 1;
    }

  idx = p->count++;
  it = &p->items[idx];
  it->name_len = (size_t)r->name_len;
  it->value_len = (size_t)r->value_len.lo;
  nm = (unsigned char *)malloc (it->name_len);
  if (!nm)
    {
      p->failed = 1;
      return 1;
    }

  val = (unsigned char *)malloc (it->value_len ? it->value_len : 1U);
  if (!val)
    {
      free (nm);
      p->failed = 1;
      return 1;
    }

  it->name = nm;
  it->value = val;
  p->current = idx;
  p->native_pos = 0U;
  p->name_pos[idx] = p->value_pos[idx] = 0U;
  return 0;
}
static int
data (void *ctx, const xtr_record *r, unsigned field, const unsigned char *b,
      size_t n)
{
  parser *p = (parser *)ctx;
  xtr_os2_ea_item *it;
  size_t *pos, limit;
  unsigned char *dst;

  (void)r;
  if (p->failed || p->count == 0 || field > 3U)
    {
      p->failed = 1;
      return 1;
    }

  it = &p->items[p->current];
  if (field == 0U)
    {
      if (n)
        {
          p->failed = 1;
          return 1;
        }

      return 0;
    }

  if (field == 1U)
    {
      pos = &p->name_pos[p->current];
      limit = it->name_len;
      dst = (unsigned char *)it->name;
    }
  else if (field == 2U)
    {
      pos = &p->native_pos;
      limit = 22U;
      dst = p->native;
    }
  else
    {
      pos = &p->value_pos[p->current];
      limit = it->value_len;
      dst = (unsigned char *)it->value;
    }

  if (*pos > limit || n > limit - *pos)
    {
      p->failed = 1;
      return 1;
    }

  if (n)
    {
      memcpy (dst + *pos, b, n);
    }

  *pos += n;
  if (field == 2U && p->native_pos == 22U)
    {
      static const unsigned char tags[22]
          = { 1, 0, 0, 0, 2, 0, 0, 0, 10, 0, 10,
              0, 0, 0, 4, 0, 0, 0, 0, 0,  0, 0 };
      unsigned flags;
      if (memcmp (p->native, tags, 18U) != 0 || p->native[19U]
          || p->native[20U] || p->native[21U])
        {
          p->failed = 1;
          return 1;
        }

      flags = p->native[18U];
      if (flags & ~XTR_OS2_EA_REQUIRED)
        {
          p->failed = 1;
          return 1;
        }

      it->flags = flags;
    }

  return 0;
}
static void
discard (parser *p)
{
  size_t i;

  if (!p)
    {
      return;
    }

  for (i = 0; i < p->count; i++)
    {
      free ((void *)p->items[i].name);
      if (p->items[i].value)
        {
          volatile unsigned char *v
              = (volatile unsigned char *)p->items[i].value;
          size_t k;
          for (k = 0; k < p->items[i].value_len; k++)
            {
              v[k] = 0;
            }

          free ((void *)p->items[i].value);
        }
    }

  free (p->items);
  free (p->name_pos);
  free (p->value_pos);
  memset (p, 0, sizeof (*p));
}
int
xtr_os2_decode_manifest (const unsigned char *bytes, size_t bytes_len,
                         const xtr_extra *outer, const unsigned char *sha,
                         xtr_os2_ea_equal_cb equal, void *ctx,
                         unsigned char **native, size_t *native_len)
{
  xtr_os2_memory mem;
  xtr_reader rd;
  xtr1_policy pol;
  xtr1_digest dig;
  xtr_manifest manifest;
  xtr_u64 n;
  parser p;
  size_t cap, i;
  int rc;

  if (!native || !native_len)
    {
      return XTR_CORRUPT;
    }

  *native = NULL;
  *native_len = 0U;
  if (!bytes || !outer || bytes_len > MAX_OS2_META || !equal)
    {
      return XTR_CORRUPT;
    }

  xtr_os2_memory_init (&mem, bytes_len);
  /* Use the caller-owned immutable encoded bytes without copying. */
  mem.bytes = (unsigned char *)bytes;
  mem.length = bytes_len;
  n.lo = (unsigned long)bytes_len;
  n.hi = 0;
  memset (&pol, 0, sizeof (pol));
  pol.max_records = 65536UL;
  pol.max_field = 65536UL;
  pol.max_manifest.lo = MAX_OS2_META;
  memset (&rd, 0, sizeof (rd));
  rd.context = &mem;
  rd.read = xtr_os2_memory_read;
  rc = xtr1_check_manifest (&rd, n, outer, sha, &pol, &dig);
  if (rc != XTR_OK)
    {
      return rc;
    }

  if (!dig.schema_supported)
    {
      return XTR_UNSUPPORTED;
    }

  cap = (size_t)dig.count;
  /* Bound total allocations by actual decoded bytes: names and values
   * are allocated per record in the second pass instead of trusting
   * hostile count*65536 amplification. */
  memset (&p, 0, sizeof (p));
  if (cap > bytes_len / 28U)
    {
      return XTR_CORRUPT;
    }

  p.capacity = cap;
  if (cap)
    {
      if (cap > (size_t)-1 / sizeof (*p.items))
        {
          return XTR_LIMIT;
        }

      p.items = (xtr_os2_ea_item *)calloc (cap, sizeof (*p.items));
      p.name_pos = (size_t *)calloc (cap, sizeof (size_t));
      p.value_pos = (size_t *)calloc (cap, sizeof (size_t));
      if (!p.items || !p.name_pos || !p.value_pos)
        {
          discard (&p);
          return XTR_LIMIT;
        }
    }

  mem.position = 0U;
  rd.sink_context = &p;
  rd.begin = begin;
  rd.data = data;
  rd.max_records = pol.max_records;
  rd.max_field = pol.max_field;
  rd.max_total = pol.max_manifest;
  rc = xtr_parse_manifest (&rd, dig.manifest_length, &manifest);
  if (rc == XTR_OK && (p.failed || p.count != cap))
    {
      rc = XTR_CORRUPT;
    }

  for (i = 0; rc == XTR_OK && i < cap; i++)
    {
      if (p.name_pos[i] != p.items[i].name_len
          || p.value_pos[i] != p.items[i].value_len)
        {
          rc = XTR_CORRUPT;
        }
    }

  if (rc == XTR_OK
      && xtr_os2_ea_pack_list (p.items, cap, native, native_len, equal, ctx)
             != XTR_OS2_EA_OK)
    {
      rc = XTR_CORRUPT;
    }

  discard (&p);
  if (rc != XTR_OK)
    {
      free (*native);
      *native = NULL;
      *native_len = 0;
    }

  return rc;
}
