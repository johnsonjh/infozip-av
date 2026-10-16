/* SPDX-License-Identifier: MIT-0 */
/* Conversion of a fully authenticated Xtro mixed manifest into distinct,
 * independently selectable NT EA and ADS restoration plans. Strict C89. */
#include "xtrwin_restore_plan.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define XRP_RECORDS 1024U
#define XRP_EA_TOTAL (1024UL * 1024UL)
#define XRP_NAME_MAX XTR_ADS_MAX_UTF8
typedef struct xrp_ctx
{
  FILE *stage;
  long pos;
  xtr_win_restore_plan *plan;
  unsigned select;
  xtr_record rec;
  unsigned char name[XRP_NAME_MAX + 1U], native[22];
  size_t name_at, native_at;
  unsigned long value_at, ea_bytes;
  long value_off;
  int active, error;
} xrp_ctx;
static size_t
xrp_read (void *opaque, unsigned char *buf, size_t n)
{
  xrp_ctx *s = (xrp_ctx *)opaque;
  size_t k = fread (buf, 1, n, s->stage);

  if (k && s->pos <= LONG_MAX - (long)k)
    {
      s->pos += (long)k;
    }
  else if (k)
    {
      s->error = XTR_LIMIT;
    }

  return k;
}
static int
xrp_finish (xrp_ctx *s)
{
  xtr_win_restore_plan *p = s->plan;
  xtr_win_ea *ea;
  xtr_win_ads_part *ads;

  if (!s->active)
    {
      return 0;
    }

  if (s->name_at != s->rec.name_len || s->native_at != s->rec.native_len
      || s->value_at != s->rec.value_len.lo)
    {
      s->error = XTR_CORRUPT;
      return 1;
    }

  if (s->rec.type == 1U && (s->select & XTR_WIN_SELECT_EA))
    {
      ea = &p->eas.items[p->eas.count];
      ea->flags = s->native[18];
      ea->name_len = s->rec.name_len;
      ea->value_len = (size_t)s->rec.value_len.lo;
      /* Commit the record count only after the complete name exists.
       * Failure cleanup owns the in-progress value at [count]. */
      ea->name = (unsigned char *)malloc (ea->name_len + 1U);
      if (!ea->name)
        {
          s->error = XTR_LIMIT;
          return 1;
        }

      memcpy (ea->name, s->name, ea->name_len);
      ea->name[ea->name_len] = 0;
      p->eas.count++;
      /* ea->value was allocated in begin; avoid relying on parsing a
       * malloc(0) for zero-length EAs (native restore rejects these). */
    }
  else if (s->rec.type == 3U && (s->select & XTR_WIN_SELECT_ADS))
    {
      ads = &p->ads[p->ads_count];
      if (xtr_win_ads_from_utf8 (s->name, s->name_at, &ads->name) != XTR_OK)
        {
          s->error = XTR_UNSUPPORTED;
          return 1;
        }

      ads->offset = s->value_off;
      ads->length = s->rec.value_len.lo;
      p->ads_count++;
    }

  s->active = 0;
  return 0;
}
static int
xrp_begin (void *opaque, const xtr_record *r)
{
  xrp_ctx *s = (xrp_ctx *)opaque;
  xtr_win_ea *ea;

  if (xrp_finish (s))
    {
      return 1;
    }

  if ((r->type != 1U && r->type != 3U) || r->value_len.hi
      || r->name_len > XRP_NAME_MAX || r->native_len > sizeof (s->native)
      || r->value_len.lo > XTR_WIN_RESTORE_MAX_BYTES
      || (r->type == 1U && r->value_len.lo > 65535UL)
      || r->value_len.lo > (unsigned long)LONG_MAX || s->pos < 0
      || (unsigned long)s->pos > (unsigned long)LONG_MAX - r->ns_len
                                     - r->name_len - r->native_len)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  if (r->type == 1U && (s->select & XTR_WIN_SELECT_EA))
    {
      if (s->plan->eas.count >= XRP_RECORDS
          || r->value_len.lo > XRP_EA_TOTAL - s->ea_bytes)
        {
          s->error = XTR_LIMIT;
          return 1;
        }

      ea = &s->plan->eas.items[s->plan->eas.count];
      ea->value = (unsigned char *)malloc (
          r->value_len.lo ? (size_t)r->value_len.lo : 1U);
      if (!ea->value)
        {
          s->error = XTR_LIMIT;
          return 1;
        }

      s->ea_bytes += r->value_len.lo;
    }

  if (r->type == 3U && (s->select & XTR_WIN_SELECT_ADS)
      && s->plan->ads_count >= XTR_WIN_RESTORE_MAX_ADS)
    {
      s->error = XTR_LIMIT;
      return 1;
    }

  s->rec = *r;
  s->active = 1;
  s->name_at = s->native_at = 0;
  s->value_at = 0;
  s->value_off
      = s->pos + (long)r->ns_len + (long)r->name_len + (long)r->native_len;
  return 0;
}
static int
xrp_data (void *opaque, const xtr_record *record, unsigned field,
          const unsigned char *data, size_t n)
{
  xrp_ctx *s = (xrp_ctx *)opaque;
  unsigned char *dst = NULL;
  size_t *at = NULL, cap = 0;

  (void)record;
  if (!s->active)
    {
      return 1;
    }

  if (field == 1U)
    {
      dst = s->name;
      at = &s->name_at;
      cap = sizeof (s->name) - 1U;
    }
  else if (field == 2U)
    {
      dst = s->native;
      at = &s->native_at;
      cap = sizeof (s->native);
    }
  else if (field == 3U)
    {
      if (n > s->rec.value_len.lo - s->value_at)
        {
          return 1;
        }

      if (s->rec.type == 1U && (s->select & XTR_WIN_SELECT_EA))
        {
          xtr_win_ea *ea = &s->plan->eas.items[s->plan->eas.count];
          memcpy (ea->value + s->value_at, data, n);
        }

      s->value_at += (unsigned long)n;
      return 0;
    }
  else
    {
      return field == 0U ? 0 : 1;
    }

  if (n > cap - *at)
    {
      return 1;
    }

  if (n)
    {
      memcpy (dst + *at, data, n);
    }

  *at += n;
  return 0;
}
void
xtr_win_restore_plan_free (xtr_win_restore_plan *plan)
{
  if (!plan)
    {
      return;
    }

  xtr_win_ea_free (&plan->eas);
  free (plan->ads);
  plan->ads = NULL;
  plan->ads_count = 0;
}
int
xtr_win_restore_plan_load (FILE *stage, xtr_u64 encoded,
                           const xtr_extra *outer, const unsigned char *sha,
                           unsigned select, xtr_win_restore_plan *plan)
{
  xtr_win_mixed_summary summary;
  xtr_reader rd;
  xtr_manifest manifest;
  xrp_ctx ctx;
  int rc;

  if (!stage || !outer || !plan || (select & ~3U))
    {
      return XTR_CORRUPT;
    }

  memset (plan, 0, sizeof (*plan));
  rc = xtr_win_mixed_verify (stage, encoded, outer, sha, &summary);
  if (rc != XTR_OK)
    {
      return rc;
    }

  if (summary.ea_count > XRP_RECORDS
      || summary.ads_count > XTR_WIN_RESTORE_MAX_ADS)
    {
      return XTR_LIMIT;
    }

  if (select & XTR_WIN_SELECT_EA)
    {
      plan->eas.items = (xtr_win_ea *)calloc (
          (size_t)(summary.ea_count ? summary.ea_count : 1UL),
          sizeof (xtr_win_ea));
      if (!plan->eas.items)
        {
          return XTR_LIMIT;
        }
    }

  if (select & XTR_WIN_SELECT_ADS)
    {
      plan->ads = (xtr_win_ads_part *)calloc (
          (size_t)(summary.ads_count ? summary.ads_count : 1UL),
          sizeof (xtr_win_ads_part));
      if (!plan->ads)
        {
          xtr_win_restore_plan_free (plan);
          return XTR_LIMIT;
        }
    }

  memset (&ctx, 0, sizeof (ctx));
  ctx.stage = stage;
  ctx.plan = plan;
  ctx.select = select;
  memset (&rd, 0, sizeof (rd));
  rd.context = &ctx;
  rd.read = xrp_read;
  rd.sink_context = &ctx;
  rd.begin = xrp_begin;
  rd.data = xrp_data;
  rd.max_records = XRP_RECORDS;
  rd.max_field = 1024UL * 1024UL;
  rd.max_total.lo = XTR_WIN_RESTORE_MAX_BYTES;
  if (outer->flags == XTR_V1_ENCRYPTED)
    {
      if (encoded.hi || encoded.lo < 36UL)
        {
          xtr_win_restore_plan_free (plan);
          return XTR_CORRUPT;
        }

      encoded.lo -= 36UL;
    }

  if (fseek (stage, 0, SEEK_SET) != 0)
    {
      rc = XTR_IO;
    }
  else
    {
      rc = xtr_parse_manifest (&rd, encoded, &manifest);
    }

  /* Encrypted companions append an internal XTCS trailer: parse only the
   * verified manifest portion, not the 36-byte trailer. */
  if (rc != XTR_OK && outer->flags == XTR_V1_ENCRYPTED)
    {
      xtr_win_restore_plan_free (plan);
      return rc;
    }

  if (rc == XTR_OK && xrp_finish (&ctx))
    {
      rc = ctx.error ? ctx.error : XTR_CORRUPT;
    }

  if (rc != XTR_OK)
    {
      /* A begin callback may have allocated a value for an unfinished EA. */
      if (ctx.active && ctx.rec.type == 1U && (select & XTR_WIN_SELECT_EA)
          && plan->eas.items)
        {
          free (plan->eas.items[plan->eas.count].value);
        }

      xtr_win_restore_plan_free (plan);
      return ctx.error ? ctx.error : rc;
    }

  return XTR_OK;
}
