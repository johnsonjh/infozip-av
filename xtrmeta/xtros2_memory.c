/* SPDX-License-Identifier: MIT-0 */
#include "xtros2_memory.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
void
xtr_os2_memory_wipe (void *addr, size_t n)
{
  volatile unsigned char *p = (volatile unsigned char *)addr;

  while (n--)
    {
      *p++ = 0;
    }
}
void
xtr_os2_memory_init (xtr_os2_memory *s, size_t max)
{
  if (!s)
    {
      return;
    }

  memset (s, 0, sizeof (*s));
  s->limit = max;
}
int
xtr_os2_memory_write (void *ctx, const unsigned char *p, size_t n)
{
  xtr_os2_memory *s = (xtr_os2_memory *)ctx;
  unsigned char *fresh;
  size_t cap;

  if (!s || (n && !p) || s->length > s->limit || n > s->limit - s->length)
    {
      return 1;
    }

  if (!n)
    {
      return 0;
    }

  if (s->capacity - s->length < n)
    {
      cap = s->capacity ? s->capacity : 1024U;
      while (cap < s->length + n)
        {
          if (cap > s->limit / 2U)
            {
              cap = s->limit;
              break;
            }

          cap *= 2U;
        }
      if (cap < s->length + n)
        {
          return 1;
        }

      fresh = (unsigned char *)malloc (cap);
      if (!fresh)
        {
          return 1;
        }

      if (s->length)
        {
          memcpy (fresh, s->bytes, s->length);
        }

      if (s->bytes)
        {
          xtr_os2_memory_wipe (s->bytes, s->capacity);
          free (s->bytes);
        }

      s->bytes = fresh;
      s->capacity = cap;
    }

  memcpy (s->bytes + s->length, p, n);
  s->length += n;
  return 0;
}
size_t
xtr_os2_memory_read (void *ctx, unsigned char *dst, size_t max)
{
  xtr_os2_memory *s = (xtr_os2_memory *)ctx;
  size_t n;

  if (!s || s->position > s->length || (max && !dst))
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
      memcpy (dst, s->bytes + s->position, n);
    }

  s->position += n;
  return n;
}
void
xtr_os2_memory_rewind (xtr_os2_memory *s)
{
  if (s)
    {
      s->position = 0;
    }
}
void
xtr_os2_memory_free (xtr_os2_memory *s)
{
  if (!s)
    {
      return;
    }

  if (s->bytes)
    {
      xtr_os2_memory_wipe (s->bytes, s->capacity);
      free (s->bytes);
    }

  memset (s, 0, sizeof (*s));
}
