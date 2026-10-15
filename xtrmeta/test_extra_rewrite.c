/* SPDX-License-Identifier: MIT-0 */
/* Regression tests for transactional Xtro ZIP extra-list rewrites. */
#include "xtrv1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long checks, failures;
#define T(c)                                                                  \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(c))                                                               \
        {                                                                     \
          failures++;                                                         \
          fprintf (stderr, "line %d: %s\n", __LINE__, #c);                    \
        }                                                                     \
    }                                                                         \
  while (0)
typedef struct buffer
{
  unsigned char *ptr;
  size_t len, cap;
} buffer;
static void
clear (buffer *b)
{
  free (b->ptr);
  memset (b, 0, sizeof (*b));
}
static int
sink (void *v, const unsigned char *p, size_t n)
{
  buffer *b = (buffer *)v;
  unsigned char *r;
  size_t nc;

  if (n > (size_t)-1 - b->len)
    {
      return 1;
    }

  if (b->len + n > b->cap)
    {
      nc = b->cap ? b->cap * 2U : 128U;
      while (nc < b->len + n)
        {
          if (nc > (size_t)-1 / 2U)
            {
              return 1;
            }

          nc *= 2U;
        }
      r = (unsigned char *)realloc (b->ptr, nc);
      if (!r)
        {
          return 1;
        }

      b->ptr = r;
      b->cap = nc;
    }

  memcpy (b->ptr + b->len, p, n);
  b->len += n;
  return 0;
}
static size_t
vread (void *ctx, unsigned char *p, size_t n)
{
  size_t *pos = (size_t *)ctx, at = 0;

  while (at < n && *pos < 3U)
    {
      p[at++] = (unsigned char)(*pos + 1U);
      (*pos)++;
    }
  return at;
}
static void
field (unsigned char *p, unsigned id, const unsigned char *v, size_t n)
{
  p[0] = (unsigned char)id;
  p[1] = (unsigned char)(id >> 8);
  p[2] = (unsigned char)n;
  p[3] = (unsigned char)(n >> 8);
  if (n)
    {
      memcpy (p + 4U, v, n);
    }
}
static int
equal (const unsigned char *a, const unsigned char *b, size_t n)
{
  return !memcmp (a, b, n);
}
static void
main_test (void)
{
  xtr1_source record;
  xtr1_policy policy;
  xtr1_sink snk;
  xtr1_digest d, d2;
  xtr_extra original, new_owner, parsed;
  unsigned char owner[16], native[10], local_e[44], cent_e[65539];
  unsigned char oldl[400], oldc[500], newl[65535], newc[65535], md5[19];
  unsigned char extra[3] = { 0xabU, 0xcdU, 0xefU }, sha[32];
  buffer manifest;
  size_t i, lv, cv, ln, cn, nl = 0, nc = 0, pos = 0;
  int rc, hasx, hasfw;
  unsigned long seed = 0x345f1234UL;

  memset (&manifest, 0, sizeof (manifest));
  memset (&record, 0, sizeof (record));
  memset (&policy, 0, sizeof (policy));
  for (i = 0; i < 16U; i++)
    {
      owner[i] = (unsigned char)(i + 1U);
    }

  memset (native, 0, sizeof (native));
  native[0] = 1U;
  native[4] = 2U;
  native[8] = 1U;
  record.record.type = 1;
  record.record.origin = 1;
  record.record.ns_len = 4;
  record.record.name_len = 4;
  record.record.native_len = 10;
  record.record.value_len.lo = 3;
  record.ns = (const unsigned char *)"user";
  record.name = (const unsigned char *)"attr";
  record.native = native;
  record.read_value = vread;
  record.value_context = &pos;
  policy.max_records = 100U;
  policy.max_field = 1024;
  policy.max_manifest.lo = 1048576;
  snk.context = &manifest;
  snk.write = sink;
  T (xtr1_write_manifest (owner, &record, 1, 0, &policy, &snk, &d) == XTR_OK);
  memset (&original, 0, sizeof (original));
  memcpy (original.owner, owner, 16);
  original.mode = XTR_V1_INLINE;
  original.count = d.count;
  original.manifest_len = d.manifest_length;
  original.crc32 = d.crc32;
  T (xtr1_extra_encode (local_e, sizeof (local_e), &original, 0, NULL, 0, NULL,
                        &lv)
     == XTR_OK);
  T (xtr1_extra_encode (cent_e, sizeof (cent_e), &original, 1, manifest.ptr,
                        manifest.len, NULL, &cv)
     == XTR_OK);
  /* Build mixed legacy, Xtro and FWKCS lists; preserve original ordering. */
  field (oldl, 0x5455U, extra, 3);
  ln = 7;
  field (oldl + ln, XTR_V1_EXTRA_ID, local_e, lv);
  ln += lv + 4U;
  field (oldl + ln, 0x7855U, extra, 3);
  ln += 7;
  field (oldc, 0x7855U, extra, 3);
  cn = 7;
  field (oldc + cn, XTR_V1_EXTRA_ID, cent_e, cv);
  cn += cv + 4U;
  memcpy (md5, "MD5", 3);
  for (i = 3; i < 19U; i++)
    {
      md5[i] = (unsigned char)i;
    }

  field (oldc + cn, 0x4b46U, md5, 19U);
  cn += 23;
  field (oldc + cn, 0x5455U, extra, 3);
  cn += 7;
  new_owner = original;
  new_owner.mode = XTR_V1_COMPANION;
  new_owner.flags = XTR_V1_ENCRYPTED;
  new_owner.count = 0;
  new_owner.manifest_len.lo = 0;
  new_owner.manifest_len.hi = 0;
  new_owner.crc32 = 0;
  T (xtr1_rewrite_owner_extras (oldl, ln, oldc, cn, &new_owner, NULL, 0, NULL,
                                newl, sizeof (newl), &nl, newc, sizeof (newc),
                                &nc)
     == XTR_OK);
  T (nl == ln && nc == cn + 40U - cv);
  T (equal (newl, oldl, 7U) && equal (newl + nl - 7U, oldl + ln - 7U, 7U));
  T (equal (newc, oldc, 7U) && equal (newc + nc - 30U, oldc + cn - 30U, 30U));
  T (xtr1_check_headers (newl + 11U, 40U, newc + 11U, 40U, &parsed, sha)
     == XTR_OK);
  T (parsed.mode == 2 && parsed.flags == 1 && equal (parsed.owner, owner, 16));
  T (xtr1_scan_extra_list (newc, nc, 1, &hasx, &hasfw) == XTR_OK);
  T (hasx && hasfw); /* FWKCS of the ordinary OWNER remains valid. */
  /* Opposite conversion: encrypted companion -> public with central SHA. */
  new_owner.flags = 0;
  new_owner.count = d.count;
  new_owner.manifest_len = d.manifest_length;
  new_owner.crc32 = d.crc32;
  T (xtr1_rewrite_owner_extras (newl, nl, newc, nc, &new_owner, NULL, 0,
                                d.sha256, oldl, sizeof (oldl), &lv, oldc,
                                sizeof (oldc), &cv)
     == XTR_OK);
  T (xtr1_check_headers (oldl + 11U, 40U, oldc + 11U, 72U, &parsed, sha)
     == XTR_OK);
  T (equal (sha, d.sha256, 32));
  /* Rebuild an inline envelope from a validated public companion. This
   * exercises bounded heap scratch and central-only XTMD insertion. */
  {
    xtr_extra inline_new = original;
    size_t local_inline, central_inline;
    T (xtr1_rewrite_owner_extras (oldl, lv, oldc, cv, &inline_new,
                                  manifest.ptr, manifest.len, NULL, newl,
                                  sizeof (newl), &local_inline, newc,
                                  sizeof (newc), &central_inline)
       == XTR_OK);
    T (xtr1_check_headers (newl + 11U, 40U, newc + 11U, manifest.len + 40U,
                           &parsed, sha)
       == XTR_OK);
    T (parsed.mode == 1 && parsed.flags == 0);
    T (central_inline == cv - 72U + 40U + manifest.len);
    T (equal (newc + 11U + 40U, manifest.ptr, manifest.len));
  }
  /* Do not return capacity overflows as successful 16-bit lengths. */
  {
    xtr_extra inline_new = original;
    unsigned char *huge = (unsigned char *)malloc (65536U);
    T (huge != NULL);
    if (huge)
      {
        memset (huge, 0, 65536U);
        T (xtr1_rewrite_owner_extras (oldl, lv, oldc, cv, &inline_new, huge,
                                      65500U, NULL, newl, sizeof (newl), &nl,
                                      newc, sizeof (newc), &nc)
           == XTR_LIMIT);
        T (nl == 0 && nc == 0);
        free (huge);
      }
  }
  /* Corrupt owner IDs cannot be silently rewritten. */
  new_owner.owner[0] ^= 0x80U;
  memset (newl, 0xa5, sizeof (newl));
  memset (newc, 0x5a, sizeof (newc));
  T (xtr1_rewrite_owner_extras (oldl, lv, oldc, cv, &new_owner, NULL, 0,
                                d.sha256, newl, sizeof (newl), &nl, newc,
                                sizeof (newc), &nc)
     == XTR_CORRUPT);
  T (nl == 0 && nc == 0 && newl[0] == 0xa5 && newc[0] == 0x5a);
  new_owner.owner[0] ^= 0x80U;
  /* Two independent output length slots are mandatory. */
  T (xtr1_rewrite_owner_extras (oldl, lv, oldc, cv, &new_owner, NULL, 0,
                                d.sha256, newl, sizeof (newl), &nl, newc,
                                sizeof (newc), &nl)
     == XTR_CORRUPT);
  /* Bad capacity for either buffer must leave BOTH buffers unchanged. */
  T (xtr1_rewrite_owner_extras (oldl, lv, oldc, cv, &new_owner, NULL, 0,
                                d.sha256, newl, sizeof (newl), &nl, newc, 50U,
                                &nc)
     == XTR_LIMIT);
  T (nl == 0 && nc == 0 && newl[0] == 0xa5 && newc[0] == 0x5a);
  T (xtr1_rewrite_owner_extras (oldl, lv, oldc, cv, &new_owner, NULL, 0,
                                d.sha256, newl, 20U, &nl, newc, sizeof (newc),
                                &nc)
     == XTR_LIMIT);
  T (nl == 0 && nc == 0 && newl[0] == 0xa5 && newc[0] == 0x5a);
  /* FWKCS cannot survive any change to the companion payload. */
  {
    unsigned char cl[20], cc[100], rl[60], rcbuf[100];
    size_t sl = 0, sc = 0, wl = 0, wc = 0;
    field (cl, 0x5455U, extra, 3);
    sl = 7;
    field (cc, 0x7855U, extra, 3);
    sc = 7;
    field (cc + sc, 0x4b46U, md5, 19);
    sc += 23;
    field (cc + sc, 0x5455U, extra, 3);
    sc += 7;
    T (xtr1_rewrite_companion_extras (cl, sl, cc, sc, 1, 0, NULL, rl,
                                      sizeof (rl), &wl, rcbuf, sizeof (rcbuf),
                                      &wc)
       == XTR_OK);
    T (wl == sl && wc == 14 && equal (rl, cl, sl));
    T (equal (rcbuf, cc, 7) && equal (rcbuf + 7, cc + 30, 7));
    T (xtr1_rewrite_companion_extras (cl, sl, cc, sc, 1, 1, NULL, rl,
                                      sizeof (rl), &wl, rcbuf, sizeof (rcbuf),
                                      &wc)
       == XTR_UNSUPPORTED);
    T (wl == 0 && wc == 0);
    T (xtr1_rewrite_companion_extras (cl, sl, cc, sc, 0, 0, NULL, rl,
                                      sizeof (rl), &wl, rcbuf, sizeof (rcbuf),
                                      &wc)
       == XTR_UNSUPPORTED);
    T (xtr1_rewrite_companion_extras (cl, sl, cc, sc, 0, 0, md5, rl,
                                      sizeof (rl), &wl, rcbuf, sizeof (rcbuf),
                                      &wc)
       == XTR_OK);
    T (wc == sc && equal (rcbuf + wc - 23, cc + 7, 23));
    T (xtr1_scan_extra_list (rcbuf, wc, 1, &hasx, &hasfw) == XTR_OK && hasfw
       && !hasx);
    md5[0] = 'B';
    T (xtr1_rewrite_companion_extras (cl, sl, cc, sc, 0, 0, md5, rl,
                                      sizeof (rl), &wl, rcbuf, sizeof (rcbuf),
                                      &wc)
       == XTR_CORRUPT);
    md5[0] = 'M';
    /* Exactly-near-limit field lists must not wrap size_t on 16-bit.
     * This otherwise risked publishing a truncated digest buffer. */
    {
      unsigned char *full = (unsigned char *)malloc (65535U);
      T (full != NULL);
      if (full)
        {
          memset (full, 0, 65535U);
          full[0] = 0x34U;
          full[1] = 0x12U;
          full[2] = (unsigned char)65527U;
          full[3] = (unsigned char)(65527U >> 8);
          T (xtr1_rewrite_companion_extras (NULL, 0, full, 65531U, 0, 0, md5,
                                            rl, sizeof (rl), &wl, rcbuf,
                                            sizeof (rcbuf), &wc)
             == XTR_LIMIT);
          T (wl == 0 && wc == 0);
          free (full);
        }
    }
  }
  /* Deterministic mutation tests. A successful rewrite after mutation is
   * allowed if the mutation merely altered an unrelated opaque field;
   * either way, no rejected rewrite may touch the output buffers. */
  {
    unsigned char validl[400], validc[500], mutl[500], mutc[600];
    size_t valid_ln = lv, valid_cn = cv;
    unsigned i;
    memcpy (validl, oldl, lv);
    memcpy (validc, oldc, cv);
    for (i = 0; i < 20000U; i++)
      {
        size_t target;
        int result;
        seed = (seed * 1664525UL + 1013904223UL) & 0xffffffffUL;
        target = (size_t)(seed % (unsigned long)(valid_ln + valid_cn));
        memcpy (mutl, validl, valid_ln);
        memcpy (mutc, validc, valid_cn);
        if (target < valid_ln)
          {
            mutl[target] ^= (unsigned char)(1U << (i % 8U));
          }
        else
          {
            mutc[target - valid_ln] ^= (unsigned char)(1U << (i % 8U));
          }

        newl[0] = 0xa5;
        newc[0] = 0x5a;
        result = xtr1_rewrite_owner_extras (
            mutl, valid_ln, mutc, valid_cn, &new_owner, NULL, 0, d.sha256,
            newl, sizeof (newl), &nl, newc, sizeof (newc), &nc);
        T (result == XTR_OK || result == XTR_CORRUPT
           || result == XTR_UNSUPPORTED || result == XTR_LIMIT);
        if (result != XTR_OK)
          {
            T (nl == 0 && nc == 0 && newl[0] == 0xa5 && newc[0] == 0x5a);
          }
        else
          {
            T (xtr1_scan_extra_list (newl, nl, 0, &hasx, &hasfw) == XTR_OK
               && hasx);
          }
      }
  }
  /* Schema bound: 16-bit extra-list totals must never wrap. */
  {
    unsigned char huge[65535];
    size_t here = 0;
    memset (huge, 0, sizeof (huge));
    huge[0] = 0x34U;
    huge[1] = 0x12U;
    huge[2] = (unsigned char)65400U;
    huge[3] = (unsigned char)(65400U >> 8);
    here = 65404U;
    memcpy (huge + here, oldl + 7U, 44U);
    here += 44U;
    T (xtr1_scan_extra_list (huge, here, 0, &hasx, &hasfw) == XTR_OK);
    T (hasx);
  }
  (void)d2;
  (void)rc;
  clear (&manifest);
}
int
main (void)
{
  main_test ();
  printf ("M6E2B extra-list rewrite: %lu checks, %lu failures\n", checks,
          failures);
  return failures ? 1 : 0;
}
