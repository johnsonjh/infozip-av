/* SPDX-License-Identifier: MIT-0 */

/* C89, byte-order-independent clipping of known ZIP timestamp extra fields.
 * Preserve all unrecognized/vendor fields, including their original bytes. */
#ifndef XTR_SOURCE_EPOCH_TIMES_H
# define XTR_SOURCE_EPOCH_TIMES_H
# include <time.h>

static unsigned long
xtr_sde_u32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static void
xtr_sde_w32 (unsigned char *p, unsigned long value)
{
  unsigned i;

  for (i = 0; i < 4; i++)
    {
      p[i] = (unsigned char)(value & 255UL);
      value >>= 8;
    }
}

# ifdef XTR_SDE_NEED_DOS
/* Return the UTC epoch rounded down to DOS two-second resolution. */
static unsigned long
xtr_sde_dos (unsigned long epoch)
{
  time_t now = (time_t)(epoch & ~1UL);
  struct tm *t = gmtime (&now);

  if (t == NULL)
    {
      return 0UL;
    }

  return ((unsigned long)(t->tm_year - 80) << 25)
         | ((unsigned long)(t->tm_mon + 1) << 21)
         | ((unsigned long)t->tm_mday << 16)
         | ((unsigned long)t->tm_hour << 11) | ((unsigned long)t->tm_min << 5)
         | ((unsigned long)t->tm_sec >> 1);
}

static void
xtr_sde_clip_dos (unsigned char date_time[4], unsigned long cutoff)
{
  unsigned long packed = xtr_sde_u32 (date_time);

  if (packed > cutoff)
    {
      xtr_sde_w32 (date_time, cutoff);
    }
}
# endif /* XTR_SDE_NEED_DOS */

# ifdef XTR_SDE_NEED_EXTRAS
/* FILETIME cutoff = (epoch + 11644473600) * 10^7. Implement a
 * 32x32 -> 64 multiplication in 32-bit limbs, without long long. */
static void
xtr_sde_filetime_cutoff (unsigned long epoch, unsigned long *hi,
                         unsigned long *lo)
{
  unsigned long result_hi = 0x019db1deUL, result_lo = 0xd53e8000UL;
  unsigned long factor_hi = 0UL, factor_lo = 10000000UL;

  while (epoch != 0UL)
    {
      if (epoch & 1UL)
        {
          unsigned long previous = result_lo;
          result_lo = (result_lo + factor_lo) & 0xffffffffUL;
          result_hi
              = (result_hi + factor_hi + (result_lo < previous ? 1UL : 0UL))
                & 0xffffffffUL;
        }

      factor_hi = ((factor_hi << 1) | (factor_lo >> 31)) & 0xffffffffUL;
      factor_lo = (factor_lo << 1) & 0xffffffffUL;
      epoch >>= 1;
    }
  *hi = result_hi;
  *lo = result_lo;
}

static void
xtr_sde_clip_filetime (unsigned char *p, unsigned long hi, unsigned long lo)
{
  unsigned long value_lo = xtr_sde_u32 (p);
  unsigned long value_hi = xtr_sde_u32 (p + 4);

  if (value_hi > hi || (value_hi == hi && value_lo > lo))
    {
      xtr_sde_w32 (p, lo);
      xtr_sde_w32 (p + 4, hi);
    }
}

/* Validate whole extra-field envelopes before modifying anything. Known
 * timestamp formats are normalized in place; unknown fields are untouched. */
static int
xtr_sde_clip_extras (unsigned char *p, unsigned size, unsigned long epoch)
{
  unsigned at = 0, next;
  unsigned long ntfs_hi, ntfs_lo;

  xtr_sde_filetime_cutoff (epoch, &ntfs_hi, &ntfs_lo);
  while (at < size)
    {
      unsigned id, len;
      if (size - at < 4U)
        {
          return 0;
        }

      id = (unsigned)p[at] | ((unsigned)p[at + 1] << 8);
      len = (unsigned)p[at + 2] | ((unsigned)p[at + 3] << 8);
      if (len > size - at - 4U)
        {
          return 0;
        }

      at += 4U;
      next = at + len;
      if (id == 0x5455U)
        { /* Extended Timestamp: mtime, atime, ctime */
          unsigned bit, pos = at + 1U, flags;
          if (len < 1U)
            {
              return 0;
            }

          flags = (unsigned)p[at];
          for (bit = 0; bit < 3; bit++)
            {
              if (flags & (1U << bit))
                {
                  /* Central UT extras normally store only mtime even when the
                   * flags advertise atime/ctime in the corresponding local
                   * extra. */
                  if (next - pos < 4U)
                    {
                      break;
                    }

                  if (xtr_sde_u32 (p + pos) > epoch)
                    {
                      xtr_sde_w32 (p + pos, epoch);
                    }

                  pos += 4U;
                }
            }
        }
      else if (id == 0x5855U && len >= 8U)
        {
          /* Historical Info-ZIP UX: modification and access seconds. */
          if (xtr_sde_u32 (p + at) > epoch)
            {
              xtr_sde_w32 (p + at, epoch);
            }

          if (xtr_sde_u32 (p + at + 4U) > epoch)
            {
              xtr_sde_w32 (p + at + 4U, epoch);
            }
        }
      else if (id == 0x000aU && len >= 4U)
        {
          /* NTFS tag 1: modification, access, creation FILETIME fields. */
          unsigned pos = at + 4U;
          while (pos < next)
            {
              unsigned tag, n;
              if (next - pos < 4U)
                {
                  return 0;
                }

              tag = (unsigned)p[pos] | ((unsigned)p[pos + 1U] << 8);
              n = (unsigned)p[pos + 2U] | ((unsigned)p[pos + 3U] << 8);
              pos += 4U;
              if (n > next - pos)
                {
                  return 0;
                }

              if (tag == 1U)
                {
                  unsigned i;
                  if (n < 24U)
                    {
                      return 0;
                    }

                  for (i = 0; i < 3U; i++)
                    {
                      xtr_sde_clip_filetime (p + pos + 8U * i, ntfs_hi,
                                             ntfs_lo);
                    }
                }

              pos += n;
            }
        }

      at = next;
    }
  return 1;
}
# endif /* XTR_SDE_NEED_EXTRAS */
#endif /* XTR_SOURCE_EPOCH_TIMES_H */
