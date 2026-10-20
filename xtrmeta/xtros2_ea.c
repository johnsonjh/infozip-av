/* SPDX-License-Identifier: MIT-0 */
#include "xtros2_ea.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static unsigned long
le32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned
le16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}
static unsigned
upper_ascii (unsigned x)
{
  return x >= (unsigned)'a' && x <= (unsigned)'z' ? x - 32U : x;
}
static int
nameequal (const unsigned char *a, size_t al, const unsigned char *b,
           size_t bl)
{
  size_t i;

  if (al != bl)
    {
      return 0;
    }

  for (i = 0; i < al; i++)
    {
      if (upper_ascii (a[i]) != upper_ascii (b[i]))
        {
          return 0;
        }
    }

  return 1;
}
static int
valid_item (const xtr_os2_ea_item *it)
{
  size_t i;
  unsigned n;

  if (!it || !it->name || (!it->value && it->value_len) || it->name_len == 0U
      || it->name_len > 255U || it->value_len > 65535U
      || (it->flags & ~XTR_OS2_EA_REQUIRED))
    {
      return 0;
    }

  for (i = 0; i < it->name_len; i++)
    {
      if (!it->name[i])
        {
          return 0;
        }
    }

  if (!nameequal (it->name, it->name_len, (const unsigned char *)"SYMLINK",
                  7U))
    {
      return 1;
    }

  if (it->value_len < 5U || it->value[0] != 0xfdU || it->value[1] != 0xffU)
    {
      return 0;
    }

  n = le16 (it->value + 2);
  if (!n || (size_t)n != it->value_len - 4U || !it->value[4]
      || memchr (it->value + 4, 0, (size_t)n) != NULL)
    {
      return 0;
    }

  return 1;
}
static int
equal_cb (const unsigned char *a, size_t al, const unsigned char *b, size_t bl,
          xtr_os2_ea_equal_cb callback, void *context)
{
  return callback ? callback (a, al, b, bl, context)
                  : nameequal (a, al, b, bl);
}
int
xtr_os2_ea_parse_ex (const unsigned char *p, size_t length,
                     xtr_os2_ea_item *out, size_t cap, size_t *count,
                     xtr_os2_ea_equal_cb callback, void *context)
{
  size_t pos = 4U, seen = 0U, j, prev;

  if (count)
    {
      *count = 0;
    }

  if (!p || !count || length < 4U || length > 16U * 1024U * 1024U
      || le32 (p) != (unsigned long)length || (cap && !out))
    {
      return XTR_OS2_EA_BAD;
    }

  while (pos < length)
    {
      unsigned long next;
      size_t need, nl, vl;
      xtr_os2_ea_item item;
      if (seen >= 65536U || length - pos < 9U)
        {
          return XTR_OS2_EA_BAD;
        }

      next = le32 (p + pos);
      nl = p[pos + 5U];
      vl = le16 (p + pos + 6U);
      need = 8U + nl + 1U + vl;
      if (!nl || need > length - pos || p[pos + 8U + nl] != 0)
        {
          return XTR_OS2_EA_BAD;
        }

      item.name = p + pos + 8U;
      item.name_len = nl;
      item.value = p + pos + 9U + nl;
      item.value_len = vl;
      item.flags = p[pos + 4U];
      if (!valid_item (&item))
        {
          return XTR_OS2_EA_BAD;
        }

      prev = 4U;
      for (j = 0; j < seen; j++)
        {
          size_t pn = p[prev + 5U];
          unsigned long step = le32 (p + prev);
          int equal = equal_cb (item.name, item.name_len, p + prev + 8U, pn,
                                callback, context);
          if (equal != 0)
            {
              return XTR_OS2_EA_BAD;
            }

          if (!step || step > pos - prev)
            {
              return XTR_OS2_EA_BAD;
            }

          prev += (size_t)step;
        }

      if (out && seen < cap)
        {
          out[seen] = item;
        }

      seen++;
      if (!next)
        {
          size_t t;
          if (length - pos - need > 3U)
            {
              return XTR_OS2_EA_BAD;
            }

          for (t = pos + need; t < length; t++)
            {
              if (p[t])
                {
                  return XTR_OS2_EA_BAD;
                }
            }

          *count = seen;
          return seen > cap && out ? XTR_OS2_EA_LIMIT : XTR_OS2_EA_OK;
        }

      if (next < need || (next & 3U) || (unsigned long)(length - pos) < next)
        {
          return XTR_OS2_EA_BAD;
        }

      /* FEA2 next offsets include alignment bytes: their contents are
       * not part of an EA name/value and must not be interpreted. */
      pos += (size_t)next;
    }
  *count = seen;
  return pos == length && seen == 0U ? XTR_OS2_EA_OK : XTR_OS2_EA_BAD;
}
int
xtr_os2_ea_parse (const unsigned char *p, size_t length, xtr_os2_ea_item *out,
                  size_t cap, size_t *count)
{
  return xtr_os2_ea_parse_ex (p, length, out, cap, count, NULL, NULL);
}
int
xtr_os2_ea_reconcile_ex (const xtr_os2_ea_item *a, size_t na,
                         const xtr_os2_ea_item *b, size_t nb,
                         xtr_os2_ea_equal_cb callback, void *context)
{
  size_t i, j, k;

  if ((na && !a) || (nb && !b))
    {
      return XTR_OS2_EA_BAD;
    }

  for (i = 0; i < na; i++)
    {
      if (!valid_item (a + i))
        {
          return XTR_OS2_EA_BAD;
        }

      for (k = 0; k < i; k++)
        {
          if (equal_cb (a[i].name, a[i].name_len, a[k].name, a[k].name_len,
                        callback, context)
              != 0)
            {
              return XTR_OS2_EA_BAD;
            }
        }
    }

  for (j = 0; j < nb; j++)
    {
      if (!valid_item (b + j))
        {
          return XTR_OS2_EA_BAD;
        }

      for (k = 0; k < j; k++)
        {
          if (equal_cb (b[j].name, b[j].name_len, b[k].name, b[k].name_len,
                        callback, context)
              != 0)
            {
              return XTR_OS2_EA_BAD;
            }
        }

      for (i = 0; i < na; i++)
        {
          int equal = equal_cb (a[i].name, a[i].name_len, b[j].name,
                                b[j].name_len, callback, context);
          if (equal < 0)
            {
              return XTR_OS2_EA_BAD;
            }

          if (equal
              && (a[i].flags != b[j].flags || a[i].value_len != b[j].value_len
                  || (a[i].value_len
                      && memcmp (a[i].value, b[j].value, a[i].value_len))))
            {
              return XTR_OS2_EA_CONFLICT;
            }
        }
    }

  return XTR_OS2_EA_OK;
}
int
xtr_os2_ea_reconcile (const xtr_os2_ea_item *a, size_t na,
                      const xtr_os2_ea_item *b, size_t nb)
{
  return xtr_os2_ea_reconcile_ex (a, na, b, nb, NULL, NULL);
}
int
xtr_os2_ea_item_compare (const void *p, const void *q)
{
  const xtr_os2_ea_item *a = (const xtr_os2_ea_item *)p;
  const xtr_os2_ea_item *b = (const xtr_os2_ea_item *)q;
  size_t len = a->name_len < b->name_len ? a->name_len : b->name_len;
  int rc = len ? memcmp (a->name, b->name, len) : 0;

  if (rc)
    {
      return rc;
    }

  return a->name_len < b->name_len ? -1 : a->name_len > b->name_len ? 1 : 0;
}
static size_t
readvalue (void *context, unsigned char *p, size_t max)
{
  xtr_os2_ea_source *s = (xtr_os2_ea_source *)context;
  size_t n;

  if (s->position > s->length)
    {
      return 0;
    }

  n = s->length - s->position;
  if (n > max)
    {
      n = max;
    }

  if (n)
    {
      memcpy (p, s->value + s->position, n);
    }

  s->position += n;
  return n;
}
int
xtr_os2_ea_source_init (xtr_os2_ea_source *s, const xtr_os2_ea_item *it)
{
  unsigned long f;

  if (!s || !valid_item (it))
    {
      return XTR_OS2_EA_BAD;
    }

  memset (s, 0, sizeof (*s));
  s->source.record.type = 1U;
  s->source.record.origin = 8U;
  s->source.record.encoding = 0U;
  s->source.record.name_len = (unsigned long)it->name_len;
  s->source.record.native_len = XTR_OS2_EA_NATIVE_LEN;
  s->source.record.value_len.lo = (unsigned long)it->value_len;
  s->source.name = it->name;
  s->source.native = s->tlv;
  s->source.read_value = readvalue;
  s->source.value_context = s;
  s->length = it->value_len;
  s->value = it->value;
  /* TLV interface=10 (tag 1, payload u16); native flags (tag 10, u32). */
  s->tlv[0] = 1;
  s->tlv[4] = 2;
  s->tlv[8] = 10;
  s->tlv[10] = 10;
  s->tlv[14] = 4;
  f = (unsigned long)it->flags;
  s->tlv[18] = (unsigned char)f;
  return XTR_OS2_EA_OK;
}

/* Encode a subset as a well-formed FEA2LIST, preserving the original
 * native value bytes and flags. A final FEA2 has oNextEntryOffset == 0;
 * preceding records use aligned relative offsets. */
static void
put32 (unsigned char *p, unsigned long n)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      p[i] = (unsigned char)(n >> (i * 8));
    }
}
static int
partition_group (const xtr_os2_ea_item *items, size_t n, int links,
                 xtr_os2_ea_equal_cb equal, void *context,
                 unsigned char **output, size_t *length)
{
  static const unsigned char linkname[] = "SYMLINK";
  size_t i, sz = 4U, used = 4U, count = 0U, last = 0U, last_need = 0U;
  unsigned char *dst;

  *output = NULL;
  *length = 0U;
  for (i = 0; i < n; i++)
    {
      const xtr_os2_ea_item *item = items + i;
      int is_link = equal_cb (item->name, item->name_len, linkname, 7U, equal,
                              context);
      size_t need = 8U + item->name_len + 1U + item->value_len;
      if (is_link < 0)
        {
          return XTR_OS2_EA_BAD;
        }

      if (links != 2 && (is_link != 0) != links)
        {
          continue;
        }

      if (count)
        {
          sz = (sz + 3U) & ~(size_t)3U;
        }

      if (need > (size_t)-1 - sz)
        {
          return XTR_OS2_EA_LIMIT;
        }

      sz += need;
      count++;
    }

  if (!count)
    {
      return XTR_OS2_EA_OK;
    }

#if ULONG_MAX > 0xffffffffUL
  if (sz > 0xffffffffUL)
    {
      return XTR_OS2_EA_LIMIT;
    }

#endif /* if ULONG_MAX > 0xffffffffUL */
  dst = (unsigned char *)malloc (sz);
  if (!dst)
    {
      return XTR_OS2_EA_LIMIT;
    }

  memset (dst, 0, sz);
  for (i = 0; i < n; i++)
    {
      const xtr_os2_ea_item *item = items + i;
      int is_link = equal_cb (item->name, item->name_len, linkname, 7U, equal,
                              context);
      size_t need = 8U + item->name_len + 1U + item->value_len;
      if (is_link < 0)
        {
          free (dst);
          return XTR_OS2_EA_BAD;
        }

      if (links != 2 && (is_link != 0) != links)
        {
          continue;
        }

      if (used > 4U)
        {
          size_t next = (last_need + 3U) & ~(size_t)3U;
          put32 (dst + last, (unsigned long)next);
          used = last + next;
        }

      last = used;
      last_need = need;
      dst[used + 4] = (unsigned char)item->flags;
      dst[used + 5] = (unsigned char)item->name_len;
      dst[used + 6] = (unsigned char)(item->value_len & 255U);
      dst[used + 7] = (unsigned char)((item->value_len >> 8) & 255U);
      memcpy (dst + used + 8U, item->name, item->name_len);
      if (item->value_len)
        {
          memcpy (dst + used + 9U + item->name_len, item->value,
                  item->value_len);
        }

      used += need;
    }

  put32 (dst, (unsigned long)sz);
  *length = sz;
  *output = dst;
  return XTR_OS2_EA_OK;
}
void
xtr_os2_ea_partition_free (xtr_os2_ea_partition *p)
{
  if (!p)
    {
      return;
    }

  free (p->ordinary);
  free (p->symlink);
  memset (p, 0, sizeof (*p));
}
int
xtr_os2_ea_partition_list (const unsigned char *bytes, size_t length,
                           xtr_os2_ea_partition *out,
                           xtr_os2_ea_equal_cb equal, void *context)
{
  xtr_os2_ea_item *items = NULL;
  size_t n = 0U, count = 0U;
  int rc;

  if (!out)
    {
      return XTR_OS2_EA_BAD;
    }

  memset (out, 0, sizeof (*out));
  rc = xtr_os2_ea_parse_ex (bytes, length, NULL, 0, &n, equal, context);
  if (rc != XTR_OS2_EA_OK)
    {
      return rc;
    }

  if (n > (size_t)-1 / sizeof (*items))
    {
      return XTR_OS2_EA_LIMIT;
    }

  if (n)
    {
      items = (xtr_os2_ea_item *)malloc (n * sizeof (*items));
      if (!items)
        {
          return XTR_OS2_EA_LIMIT;
        }

      rc = xtr_os2_ea_parse_ex (bytes, length, items, n, &count, equal,
                                context);
      if (rc != XTR_OS2_EA_OK || count != n)
        {
          free (items);
          return XTR_OS2_EA_BAD;
        }
    }

  rc = partition_group (items, n, 0, equal, context, &out->ordinary,
                        &out->ordinary_len);
  if (rc == XTR_OS2_EA_OK)
    {
      rc = partition_group (items, n, 1, equal, context, &out->symlink,
                            &out->symlink_len);
    }

  free (items);
  if (rc != XTR_OS2_EA_OK)
    {
      xtr_os2_ea_partition_free (out);
    }

  return rc;
}

int
xtr_os2_ea_pack_list (const xtr_os2_ea_item *items, size_t count,
                      unsigned char **output, size_t *length,
                      xtr_os2_ea_equal_cb names_equal, void *context)
{
  int rc;

  if (!output || !length)
    {
      return XTR_OS2_EA_BAD;
    }

  *output = NULL;
  *length = 0;
  rc = xtr_os2_ea_reconcile_ex (items, count, NULL, 0U, names_equal, context);
  if (rc != XTR_OS2_EA_OK)
    {
      return rc;
    }

  return partition_group (items, count, 2, names_equal, context, output,
                          length);
}
