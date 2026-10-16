/* SPDX-License-Identifier: MIT-0 */
/* Portable, bounded semantic verification of an inline Xtro manifest.
 * Include only in utilities linking xtrm.c, xtrsha.c and xtrv1.c. */
#ifndef XTR_VERIFY_INLINE_H
# define XTR_VERIFY_INLINE_H
# include "xtrv1.h"
# include <string.h>
typedef struct xr_inline_reader
{
  const unsigned char *p;
  size_t left;
} xr_inline_reader;
static size_t
xr_inline_read (void *ctx, unsigned char *out, size_t len)
{
  xr_inline_reader *r = (xr_inline_reader *)ctx;

  if (len > r->left)
    {
      len = r->left;
    }

  if (len)
    {
      memcpy (out, r->p, len);
    }

  r->p += len;
  r->left -= len;
  return len;
}
static int
xr_inline_verify (const unsigned char *p, size_t n)
{
  xtr_extra x;
  xtr1_policy policy;
  xtr1_digest digest;
  xtr_reader reader;
  xr_inline_reader memory;
  xtr_u64 total;

  if (n < 76 || xtr1_extra_decode (p, n, 1, &x, NULL) != XTR_OK
      || x.mode != XTR_V1_INLINE)
    {
      return 0;
    }

  memset (&reader, 0, sizeof (reader));
  memset (&policy, 0, sizeof (policy));
  memory.p = p + 40;
  memory.left = n - 40;
  total.lo = (unsigned long)(n - 40);
  total.hi = 0;
  policy.max_records = 65536UL;
  policy.max_field = 1048576UL;
  policy.max_manifest.lo = 33554432UL;
  policy.max_manifest.hi = 0;
  reader.context = &memory;
  reader.read = xr_inline_read;
  return xtr1_check_manifest (&reader, total, &x, NULL, &policy, &digest)
             == XTR_OK
         && !memory.left;
}
#endif /* ifndef XTR_VERIFY_INLINE_H */
