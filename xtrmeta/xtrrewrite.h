/* SPDX-License-Identifier: MIT-0 */
/* Conservative, allocation-bounded Xtro v1 archive rewrite preflight.
 * Header-only so legacy stand-alone ZipOpt and ZipDedup build rules keep
 * their existing link dependencies. This is NOT native restoration or
 * cryptographic authentication of companion payloads. */
#ifndef XTR_REWRITE_H
# define XTR_REWRITE_H
# include <stddef.h>
# include <stdlib.h>
# include <string.h>

typedef struct xr_node
{
  unsigned char id[16];
  unsigned char header[40];
  unsigned char sha[32];
  size_t index;
  unsigned role; /* 0 ordinary, 1 inline owner, 2 companion owner, 3 sidecar */
} xr_node;
# ifdef XTR_REWRITE_IMPLEMENTATION
static unsigned
xr_le16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}
static unsigned long
xr_le32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned long
xr_crc32 (const unsigned char *p, size_t n)
{
  unsigned long c = 0xffffffffUL;
  size_t i;
  unsigned k;

  for (i = 0; i < n; i++)
    {
      c ^= p[i];
      for (k = 0; k < 8; k++)
        {
          c = (c & 1UL) ? ((c >> 1) ^ 0xedb88320UL) : (c >> 1);
        }
    }

  return (c ^ 0xffffffffUL) & 0xffffffffUL;
}
static int
xr_digit (unsigned char c)
{
  if (c >= '0' && c <= '9')
    {
      return (int)(c - '0');
    }

  if (c >= 'a' && c <= 'f')
    {
      return (int)(c - 'a' + 10);
    }

  return -1;
}
/* 0 ordinary name, 1 valid sidecar, -1 invalid reserved-name collision. */
static int
xr_name (const unsigned char *name, size_t n, unsigned char id[16])
{
  size_t k;

  if (n < 13 || memcmp (name, "__XTRO_ZIP__/", 13))
    {
      return 0;
    }

  if (n != 51 || memcmp (name, "__XTRO_ZIP__/x/", 15)
      || memcmp (name + 47, ".xtm", 4))
    {
      return -1;
    }

  for (k = 0; k < 16; k++)
    {
      int a = xr_digit (name[15 + 2 * k]), b = xr_digit (name[16 + 2 * k]);
      if (a < 0 || b < 0)
        {
          return -1;
        }

      id[k] = (unsigned char)((a << 4) | b);
    }

  return 1;
}
/* Validate a complete list, rejecting all ID collision candidates because
 * a transform cannot know whether it would damage their semantics. */
static int
xr_scan (const unsigned char *buf, size_t len, int central, xr_node *node)
{
  size_t at = 0;
  unsigned seen = 0;

  if ((!buf && len) || !node || len > 65535U)
    {
      return 0;
    }

  while (at < len)
    {
      unsigned tag, sz, mode, flags;
      const unsigned char *p;
      unsigned k, nz = 0;
      if (len - at < 4)
        {
          return 0;
        }

      tag = xr_le16 (buf + at);
      sz = xr_le16 (buf + at + 2);
      at += 4;
      if (sz > len - at)
        {
          return 0;
        }

      p = buf + at;
      if (tag == 0x5854U)
        {
          if (seen++ || sz < 40 || memcmp (p, "XTRO\001\000", 6))
            {
              return 0;
            }

          mode = p[6];
          flags = p[7];
          if ((mode != 1 && mode != 2) || (flags & ~1U))
            {
              return 0;
            }

          for (k = 0; k < 16; k++)
            {
              nz |= p[8 + k];
            }

          if (!nz)
            {
              return 0;
            }

          if (mode == 1)
            {
              if (flags || (!central && sz != 40))
                {
                  return 0;
                }

              if (central)
                {
                  const unsigned char *m = p + 40;
                  if (sz < 76 || xr_le32 (p + 32) != 0UL
                      || xr_le32 (p + 28) != (unsigned long)(sz - 40)
                      || memcmp (m, "XTMD\001\000\000\000", 8)
                      || memcmp (m + 8, p + 8, 16)
                      || xr_le32 (m + 24) != xr_le32 (p + 24)
                      || xr_le32 (m + 28) != (unsigned long)(sz - 76)
                      || xr_le32 (m + 32) != 0UL
                      || xr_crc32 (m, sz - 40) != xr_le32 (p + 36))
                    {
                      return 0;
                    }
                }
            }
          else
            {
              if (sz != (unsigned)(central && !flags ? 72 : 40))
                {
                  return 0;
                }

              if (flags
                  && (xr_le32 (p + 24) != 0UL || xr_le32 (p + 28) != 0UL
                      || xr_le32 (p + 32) != 0UL || xr_le32 (p + 36) != 0UL))
                {
                  return 0;
                }
            }

          if (central)
            {
              memcpy (node->header, p, 40);
              if (mode == 2 && central && !flags)
                {
                  memcpy (node->sha, p + 40, 32);
                }

              memcpy (node->id, p + 8, 16);
              node->role = mode;
            }
          else if ((node->role != mode) || memcmp (node->header, p, 40))
            {
              return 0;
            }
        }

      at += sz;
    }
  if (!central && (!!seen != (node->role == 1 || node->role == 2)))
    {
      return 0;
    }

  return 1;
}
static int
xr_node_cmp (const void *a, const void *b)
{
  return memcmp (((const xr_node *)a)->id, ((const xr_node *)b)->id, 16);
}
/* Copy node array because callers must keep original archive order. No
 * O(entry_count^2) behavior on hostile archives. */
static int
xr_graph (xr_node *nodes, size_t count)
{
  xr_node *sorted;
  size_t i, j, used = 0;
  int good = 1;

  if (count > (size_t)-1 / sizeof (*sorted))
    {
      return 0;
    }

  sorted = (xr_node *)malloc ((count ? count : 1) * sizeof (*sorted));
  if (!sorted)
    {
      return 0;
    }

  for (i = 0; i < count; i++)
    {
      if (nodes[i].role)
        {
          if (nodes[i].role > 3)
            {
              good = 0;
              break;
            }

          sorted[used] = nodes[i];
          sorted[used].index = i;
          used++;
        }
    }

  if (good)
    {
      qsort (sorted, used, sizeof (*sorted), xr_node_cmp);
      for (i = 0; i < used; i = j)
        {
          unsigned owners = 0, sides = 0, mode = 0;
          size_t owner_index = 0, side_index = 0;
          for (j = i; j < used && !memcmp (sorted[i].id, sorted[j].id, 16);
               j++)
            {
              if (sorted[j].role == 3)
                {
                  sides++;
                  side_index = sorted[j].index;
                }
              else
                {
                  owners++;
                  mode = sorted[j].role;
                  owner_index = sorted[j].index;
                }
            }

          if (owners != 1 || sides != (mode == 2 ? 1U : 0U))
            {
              good = 0;
              break;
            }

          if (mode == 2)
            {
              memcpy (nodes[side_index].header, nodes[owner_index].header, 40);
              memcpy (nodes[side_index].sha, nodes[owner_index].sha, 32);
            }
        }
    }

  free (sorted);
  return good;
}
# endif /* XTR_REWRITE_IMPLEMENTATION */
#endif /* XTR_REWRITE_H */
