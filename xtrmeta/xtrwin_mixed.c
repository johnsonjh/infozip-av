/* SPDX-License-Identifier: MIT-0 */
/* Windows NT EA and NTFS ADS capture in ONE verified Xtro V1 manifest.
 * All stream bytes are first copied into a caller-owned private spool,
 * whose lifetime extends through manifest serialization. No ZIP bytes are
 * committed by this module. Non-atomic filesystem snapshots are reported
 * as errors where identity/length changes are detectable. */
#include "xtrwin_mixed.h"
#if defined(_WIN32)
/* FindFirstStreamW and CompareStringOrdinal require Windows Vista or newer.
 * Leave ordinary Windows/DOS builds untouched when XTR_WIN_NATIVE is off. */
# ifndef WINVER
#  define WINVER 0x0600
# elif WINVER < 0x0600
#  error XTR_WIN_NATIVE ADS capture requires Windows Vista or later
# endif /* ifndef WINVER */
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN 1
# endif /* ifndef WIN32_LEAN_AND_MEAN */
# include "xtrwin_ads_native.h"
# include "xtrwin_ads_record.h"
# include "xtrwin_ads_stream.h"
# include <limits.h>
# include <stdlib.h>
# include <string.h>
# include <windows.h>
# define XWM_MAX_STREAMS 128U
# define XWM_MAX_BYTES (32UL * 1024UL * 1024UL)
# define XWM_MAX_RECORDS 1024UL
/* Important: Never use untrusted stream names to create spool paths. */
typedef struct xwm_item
{
  xtr_ads_name name;
  xtr_u64 size;
  long off, pos;
  FILE *spool;
  unsigned char tlv[22];
} xwm_item;
typedef struct xwm_easrc
{
  const xtr_win_ea *ea;
  size_t pos;
} xwm_easrc;
typedef struct xwm_state
{
  void *pinned;
  FILE *spool;
  xwm_item *items;
  size_t count;
  unsigned long total;
  int error;
} xwm_state;
static int
xwm_bytes (void *opaque, const unsigned char *data, size_t n)
{
  FILE *f = (FILE *)opaque;

  return fwrite (data, 1, n, f) == n ? 0 : 1;
}
static int
xwm_visit (void *opaque, const xtr_ads_name *name, unsigned long high,
           unsigned long low)
{
  xwm_state *s = (xwm_state *)opaque;
  xwm_item *v;
  size_t i;
  long off;

  if (s->count >= XWM_MAX_STREAMS || high != 0UL
      || low > XWM_MAX_BYTES - s->total || low > (unsigned long)LONG_MAX)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  for (i = 0; i < s->count; i++)
    {
      /* NTFS stream names are case-insensitive, including Unicode. */
      int comparison = CompareStringOrdinal (
          (LPCWCH)s->items[i].name.utf16, (int)s->items[i].name.utf16_len,
          (LPCWCH)name->utf16, (int)name->utf16_len, TRUE);
      if (comparison == CSTR_EQUAL || comparison == 0)
        {
          s->error = XTR_CORRUPT;
          return 1;
        }
    }

  if (fseek (s->spool, 0, SEEK_END) != 0 || (off = ftell (s->spool)) < 0
      || (unsigned long)off > XWM_MAX_BYTES - low)
    {
      s->error = XTR_IO;
      return 1;
    }

  v = &s->items[s->count];
  memset (v, 0, sizeof (*v));
  v->name = *name;
  v->size.lo = low;
  v->size.hi = 0;
  v->off = off;
  v->spool = s->spool;
  if (xtr_win_ads_read_stream ((HANDLE)s->pinned, name, high, low, xwm_bytes,
                               s->spool)
      != 0)
    {
      s->error = XTR_IO;
      return 1;
    }

  s->total += low;
  s->count++;
  return 0;
}
static int
xwm_sort_name (const void *a, const void *b)
{
  const xwm_item *x = (const xwm_item *)a, *y = (const xwm_item *)b;
  size_t n = x->name.utf8_len < y->name.utf8_len ? x->name.utf8_len
                                                 : y->name.utf8_len;
  int c = memcmp (x->name.utf8, y->name.utf8, n);

  return c                                     ? c
         : x->name.utf8_len < y->name.utf8_len ? -1
         : x->name.utf8_len > y->name.utf8_len ? 1
                                               : 0;
}
static int
xwm_ea_sort (const void *a, const void *b)
{
  const xtr_win_ea *x = (const xtr_win_ea *)a, *y = (const xtr_win_ea *)b;
  size_t n = x->name_len < y->name_len ? x->name_len : y->name_len;
  int c = memcmp (x->name, y->name, n);

  return c                           ? c
         : x->name_len < y->name_len ? -1
         : x->name_len > y->name_len ? 1
                                     : 0;
}
static size_t
xwm_ear (void *ctx, unsigned char *p, size_t n)
{
  xwm_easrc *e = (xwm_easrc *)ctx;
  size_t remain = e->ea->value_len - e->pos;

  if (n > remain)
    {
      n = remain;
    }

  if (n)
    {
      memcpy (p, e->ea->value + e->pos, n);
    }

  e->pos += n;
  return n;
}
static size_t
xwm_streamr (void *ctx, unsigned char *p, size_t n)
{
  xwm_item *v = (xwm_item *)ctx;
  unsigned long remain = v->size.lo - (unsigned long)v->pos;
  size_t got;

  if (n > remain)
    {
      n = (size_t)remain;
    }

  if (!n)
    {
      return 0;
    }

  if (v->off > LONG_MAX - v->pos
      || fseek (v->spool, v->off + v->pos, SEEK_SET) != 0)
    {
      return 0;
    }

  got = fread (p, 1, n, v->spool);
  v->pos += (long)got;
  return got;
}
static int
xwm_write (void *ctx, const unsigned char *p, size_t n)
{
  return fwrite (p, 1, n, (FILE *)ctx) == n ? 0 : 1;
}
int
xtr_win_mixed_capture (void *pinned, const unsigned char owner[16],
                       FILE *manifest, FILE *spool, int with_eas,
                       int encrypted, xtr1_digest *digest)
{
  xtr_win_ea_list eas;
  xwm_state state;
  xtr1_source *src = NULL;
  xwm_easrc *ea_src = NULL;
  unsigned char *ea_tlv = NULL;
  xtr1_policy policy;
  xtr1_sink sink;
  size_t i, n;
  int rc = XTR_OK, ads_rc;
  static const unsigned char ea_ns[2] = { 'n', 't' };

  if (!pinned || !owner || !manifest || !spool || !digest
      || (with_eas != 0 && with_eas != 1)
      || (encrypted != 0 && encrypted != 1))
    {
      return XTR_CORRUPT;
    }

  memset (&eas, 0, sizeof (eas));
  memset (&state, 0, sizeof (state));
  state.pinned = pinned;
  state.spool = spool;
  state.items = (xwm_item *)calloc (XWM_MAX_STREAMS, sizeof (xwm_item));
  if (!state.items)
    {
      return XTR_LIMIT;
    }

  if (with_eas)
    {
      rc = xtr_win_nt_snapshot_handle (pinned, &eas);
      if (rc != XTR_OK)
        {
          goto done;
        }

      if (eas.count > 1U)
        {
          qsort (eas.items, eas.count, sizeof (*eas.items), xwm_ea_sort);
        }
    }

  ads_rc = xtr_win_ads_enumerate_handle ((HANDLE)pinned, xwm_visit, &state);
  if (ads_rc != 0)
    {
      rc = state.error ? state.error : ads_rc == 2 ? XTR_UNSUPPORTED : XTR_IO;
      goto done;
    }

  n = eas.count + state.count;
  if (n > XWM_MAX_RECORDS)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  src = (xtr1_source *)calloc (n ? n : 1U, sizeof (*src));
  ea_src = (xwm_easrc *)calloc (eas.count ? eas.count : 1U, sizeof (*ea_src));
  ea_tlv = (unsigned char *)calloc (eas.count ? eas.count : 1U, 19U);
  if (!src || !ea_src || !ea_tlv)
    {
      rc = XTR_LIMIT;
      goto done;
    }

  for (i = 0; i < eas.count; i++)
    {
      xtr1_source *v = &src[i];
      unsigned char *t = ea_tlv + i * 19U;
      const xtr_win_ea *ea = &eas.items[i];
      t[0] = 1U;
      t[4] = 2U;
      t[8] = 8U;
      t[10] = 3U;
      t[14] = 1U;
      t[18] = (unsigned char)ea->flags;
      v->record.type = 1U;
      v->record.origin = 7U;
      v->record.ns_len = 2UL;
      v->record.name_len = (unsigned long)ea->name_len;
      v->record.native_len = 19UL;
      v->record.value_len.lo = (unsigned long)ea->value_len;
      v->ns = ea_ns;
      v->name = ea->name;
      v->native = t;
      ea_src[i].ea = ea;
      v->read_value = xwm_ear;
      v->value_context = &ea_src[i];
    }

  if (state.count > 1U)
    {
      qsort (state.items, state.count, sizeof (*state.items), xwm_sort_name);
    }

  for (i = 0; i < state.count; i++)
    {
      xwm_item *item = &state.items[i];
      rc = xtr_ads_record_source (&item->name, item->size, xwm_streamr, item,
                                  &src[eas.count + i], item->tlv);
      if (rc != XTR_OK)
        {
          goto done;
        }
    }

  memset (&policy, 0, sizeof (policy));
  policy.max_records = XWM_MAX_RECORDS;
  policy.max_field = 1024UL * 1024UL;
  policy.max_manifest.lo = XWM_MAX_BYTES;
  sink.context = manifest;
  sink.write = xwm_write;
  if (fflush (spool) != 0 || fseek (manifest, 0, SEEK_SET) != 0)
    {
      rc = XTR_IO;
      goto done;
    }

  rc = xtr1_write_manifest (owner, src, n, encrypted, &policy, &sink, digest);
  if (rc == XTR_OK
      && (fflush (manifest) != 0 || fseek (manifest, 0, SEEK_SET) != 0))
    {
      rc = XTR_IO;
    }

done:
  free (ea_tlv);
  free (ea_src);
  free (src);
  xtr_win_ea_free (&eas);
  free (state.items);
  return rc;
}
#else  /* if defined( _WIN32 ) */
typedef int xtr_win_mixed_disabled_translation_unit;
#endif /* if defined( _WIN32 ) */
