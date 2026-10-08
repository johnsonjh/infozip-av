/*
 * WZ-JPEG decompressor
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/*
 * TODO: Generate test files using current WinZip to test JPEG compression
 * with 12-bit, grayscale, non-interleaved, restart markers, etc.
 * More testing is needed to ensure full compatibility.  Test data was:
 * https://sourceforge.net/p/sevenzip/discussion/45797/thread/28be9fbbc3/
 */

#include <limits.h>
#include <lzma.h>
#include <stdlib.h>
#include <string.h>

#include "wzjpeg.h"

#define WZ96_METADATA_MAX 16777216UL
#define WZ96_CHUNK 8192U

struct wz96_stream
{
  wz96_read_fn read;
  void *opaque;
  unsigned long remain;
};

static int
wz96_get (struct wz96_stream *s, unsigned char *p, size_t n)
{
  size_t have = 0, take;

  if ((unsigned long)n > s->remain)
    {
      return 0;
    }

  while (have < n)
    {
      take = s->read (s->opaque, p + have, n - have);
      if (take == 0 || take > n - have)
        {
          return 0;
        }

      have += take;
    }

  s->remain -= (unsigned long)n;

  return 1;
}

static unsigned long
wz96_le16 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8);
}

static unsigned long
wz96_le32 (const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static unsigned int
wz96_be16 (const unsigned char *p)
{
  return ((unsigned int)p[0] << 8) | p[1];
}

static int
wz96_metadata_lzma (unsigned char *dest, size_t expected,
                    const unsigned char *src, size_t packed)
{
  lzma_stream st = LZMA_STREAM_INIT;
  lzma_options_lzma opt;
  lzma_filter filters[2];
  lzma_ret result;
  unsigned long dict;
  unsigned long i;
  size_t previous_in, previous_out;
  int ok = 0;

  if (expected == 0 || expected > WZ96_METADATA_MAX || packed == 0)
    {
      return 0;
    }

  dict = (unsigned long)((expected + 511U) / 512U) * 512UL;

  if (dict < 1024UL)
    {
      dict = 1024UL;
    }

  if (dict > 524288UL)
    {
      dict = 524288UL;
    }

  memset (&opt, 0, sizeof (opt));
  opt.dict_size = (uint32_t)dict;
  opt.lc = 3;
  opt.lp = 0;
  opt.pb = 2;
  filters[0].id = LZMA_FILTER_LZMA1;
  filters[0].options = &opt;
  filters[1].id = LZMA_VLI_UNKNOWN;
  filters[1].options = NULL;
  result = lzma_raw_decoder (&st, filters);

  if (result != LZMA_OK)
    {
      return 0;
    }

  st.next_in = (const uint8_t *)src;
  st.avail_in = packed;
  st.next_out = (uint8_t *)dest;
  st.avail_out = expected;

  for (i = 0; i <= packed / WZ96_CHUNK + expected / WZ96_CHUNK + 64UL; i++)
    {
      if (st.avail_out == 0)
        {
          ok = 1;

          break;
        }

      previous_in = st.avail_in;
      previous_out = st.avail_out;
      result = lzma_code (&st, LZMA_RUN);

      if (result != LZMA_OK && result != LZMA_STREAM_END)
        {
          break;
        }

      if (result == LZMA_STREAM_END)
        {
          ok = st.avail_out == 0;

          break;
        }

      if (st.avail_in == previous_in && st.avail_out == previous_out)
        {
          break;
        }
    }

  lzma_end (&st);

  return ok;
}

static int
wz96_markers (const unsigned char *data, size_t length, int first,
              wz96_report *r, int *is_scan)
{
  size_t p = 0;
  int soi = !first, frame = 0;
  unsigned int c, i, m, n;

  *is_scan = 0;

  if (first)
    {
      for (p = 0; p + 1 < length && p < 128U; p++)
        {
          if (data[p] == 255 && data[p + 1] == 0xd8)
            {
              break;
            }
        }

      if (p >= 128U || p + 1 >= length)
        {
          return 0;
        }
    }

  while (p < length)
    {
      if (p + 1 >= length || data[p++] != 255)
        {
          return 0;
        }

      while (p < length && data[p] == 255)
        {
          p++;
        }
      if (p >= length)
        {
          return 0;
        }

      m = data[p++];

      if (m == 0x00 || m == 0xff || (m >= 0xd0 && m <= 0xd7))
        {
          return 0;
        }

      if (m == 0xd8)
        {
          if (soi)
            {
              return 0;
            }

          soi = 1;

          continue;
        }

      if (!soi)
        {
          return 0;
        }

      if (m == 0xd9)
        {
          r->reached_eoi = 1;

          return 1;
        }

      if (p + 2 > length)
        {
          return 0;
        }

      n = wz96_be16 (data + p);

      if (n < 2 || (size_t)n > length - p)
        {
          return 0;
        }

      if (m == 0xc0 || m == 0xc1)
        {
          if (n < 11 || (unsigned int)n != 8U + 3U * data[p + 7]
              || (data[p + 2] != 8 && data[p + 2] != 12))
            {
              return 0;
            }

          c = data[p + 7];
          if (c < 1 || c > 4 || wz96_be16 (data + p + 3) == 0
              || wz96_be16 (data + p + 5) == 0)
            {
              return 0;
            }

          for (i = 0; i < c; i++)
            {
              unsigned int factors = data[p + 9 + 3 * i];

              if ((factors >> 4) == 0 || (factors >> 4) > 4
                  || (factors & 15) == 0 || (factors & 15) > 4)
                {
                  return 0;
                }
            }

          r->height = wz96_be16 (data + p + 3);
          r->width = wz96_be16 (data + p + 5);
          r->components = c;
          frame = 1;
        }

      if (m == 0xda)
        {
          if (n < 6 || n != 6U + 2U * data[p + 2] || data[p + 2] < 1
              || data[p + 2] > 4)
            {
              return 0;
            }

          if ((first && !frame) || !r->components)
            {
              return 0;
            }

          if (p + n != length)
            {
              return 0;
            }

          *is_scan = 1;

          return 1;
        }

      p += n;
    }

  return 0;
}

int
wz96_probe (wz96_read_fn reader, void *opaque, unsigned long compressed_len,
            wz96_metadata_fn metadata_cb, void *cbopaque, wz96_report *report)
{
  struct wz96_stream input;
  unsigned char props[4], head[8];
  unsigned char *decoded = NULL, *packed = NULL;
  wz96_report r;
  unsigned long ulen, plen;
  int scan, valid = 0;
  size_t got;

  if (reader == NULL || report == NULL || compressed_len < 8UL)
    {
      return 0;
    }

  memset (&r, 0, sizeof (r));
  input.read = reader;
  input.opaque = opaque;
  input.remain = compressed_len;
  if (!wz96_get (&input, props, 4))
    {
      goto done;
    }

  if (props[0] < 4 || props[1] != 0x10 || props[2] != 1
      || (props[3] & 0xe0) != 0)
    {
      goto done;
    }

  r.slice_option = props[3] & 31;

  /* Properties > 4 bytes are permitted by the specification. */
  while (props[0] > 4)
    {
      unsigned char trash[64];
      got = props[0] - 4U;
      if (got > sizeof (trash))
        {
          got = sizeof (trash);
        }

      if (!wz96_get (&input, trash, got))
        {
          goto done;
        }

      props[0] = (unsigned char)(props[0] - got);
    }

  for (;;)
    {
      if (!wz96_get (&input, head, 4))
        {
          goto done;
        }

      ulen = wz96_le16 (head);
      plen = wz96_le16 (head + 2);

      if (ulen == 65535UL || plen == 65535UL)
        {
          if (ulen != 65535UL || plen != 65535UL)
            {
              goto done;
            }

          if (!wz96_get (&input, head, 8))
            {
              goto done;
            }

          ulen = wz96_le32 (head);
          plen = wz96_le32 (head + 4);
        }

      if (ulen == 0 || ulen > WZ96_METADATA_MAX || plen > WZ96_METADATA_MAX
          || (plen && plen > input.remain))
        {
          goto done;
        }

      decoded = (unsigned char *)malloc ((size_t)ulen);

      if (!decoded)
        {
          goto done;
        }

      if (plen)
        {
          packed = (unsigned char *)malloc ((size_t)plen);
          if (!packed)
            {
              goto done;
            }

          if (!wz96_get (&input, packed, (size_t)plen)
              || !wz96_metadata_lzma (decoded, (size_t)ulen, packed,
                                      (size_t)plen))
            {
              goto done;
            }

          free (packed);
          packed = NULL;
          r.lzma_bundles++;
        }
      else
        {
          if (!wz96_get (&input, decoded, (size_t)ulen))
            {
              goto done;
            }

          r.stored_bundles++;
        }

      if (!wz96_markers (decoded, (size_t)ulen, r.bundles == 0, &r, &scan))
        {
          goto done;
        }

      r.bundles++;
      r.metadata_bytes += ulen;
      if (metadata_cb && !metadata_cb (cbopaque, decoded, (size_t)ulen))
        {
          goto done;
        }

      free (decoded);
      decoded = NULL;
      if (r.reached_eoi)
        {
          valid = input.remain == 0;

          break;
        }

      if (scan)
        {
          r.scans++;
          valid = 0;

          break;
        }
    }

done:
  free (packed);
  free (decoded);
  *report = r;

  return valid;
}

static const unsigned short wz_p[49]
    = { 1024, 895, 795, 706, 628, 559, 493, 437, 379, 331, 287, 247, 212,
        186,  158, 143, 127, 110, 98,  84,  72,  65,  59,  53,  48,  45,
        42,   40,  37,  35,  33,  30,  28,  26,  23,  21,  19,  17,  15,
        13,   11,  9,   7,   5,   4,   3,   2,   1,   1024 };

static const unsigned short wz_q[49]
    = { 0,    272,  502,  726,  941,  1150, 1371,  1578,  1819, 2044,
        2278, 2521, 2765, 2971, 3227, 3382, 3566,  3788,  3965, 4200,
        4435, 4590, 4737, 4899, 5050, 5147, 5250,  5325,  5441, 5527,
        5617, 5758, 5863, 5976, 6157, 6295, 6447,  6616,  6806, 7024,
        7278, 7585, 7972, 8495, 8884, 9309, 10065, 11689, 0 };

static const unsigned short wz_nmax[49]
    = { 16384, 16110, 15105, 14826, 14444, 13975, 13804, 13547, 13265, 13240,
        12915, 12844, 12720, 12648, 12482, 12441, 12319, 12320, 12250, 12180,
        12168, 12155, 12154, 12084, 12096, 12105, 12096, 12080, 12062, 12075,
        12078, 12060, 12068, 12090, 12075, 12075, 12103, 12121, 12150, 12181,
        12221, 12294, 12411, 12615, 13120, 13113, 14574, 21860, 0 };

static const unsigned char wz_half[49]
    = { 8, 8, 7, 7, 7,  6,  6,  6,  6,  6,  6, 6, 6, 6, 6, 6, 6,
        6, 6, 8, 9, 10, 10, 10, 10, 10, 10, 9, 9, 8, 8, 7, 7, 6,
        6, 6, 5, 5, 4,  4,  3,  3,  3,  3,  2, 2, 1, 0, 0 };

static const unsigned char wz_twice[49]
    = { 0,  1,  2, 3, 4, 5, 6, 7, 8, 7, 7, 6, 6, 6,  6,  6,  6,
        6,  6,  6, 6, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 10, 10, 10,
        10, 10, 9, 8, 7, 6, 6, 5, 4, 3, 3, 3, 2, 1,  0 };

/*
 * Expired patent US 4,791,403 logarithmic arithmetic coding antilog constants.
 * These numerical function values are specified in the published patent.
 */

static const unsigned short wz96_ant[1024]
    = { 0x2000, 0x1ffd, 0x1ff7, 0x1ff1, 0x1fec, 0x1fe6, 0x1fe1, 0x1fdb, 0x1fd6,
        0x1fd0, 0x1fcb, 0x1fc5, 0x1fc0, 0x1fba, 0x1fb5, 0x1faf, 0x1faa, 0x1fa4,
        0x1f9f, 0x1f99, 0x1f94, 0x1f8e, 0x1f89, 0x1f83, 0x1f7e, 0x1f79, 0x1f73,
        0x1f6e, 0x1f68, 0x1f63, 0x1f5d, 0x1f58, 0x1f53, 0x1f4d, 0x1f48, 0x1f42,
        0x1f3d, 0x1f37, 0x1f32, 0x1f2d, 0x1f27, 0x1f22, 0x1f1c, 0x1f17, 0x1f12,
        0x1f0c, 0x1f07, 0x1f02, 0x1efc, 0x1ef7, 0x1ef1, 0x1eec, 0x1ee7, 0x1ee1,
        0x1edc, 0x1ed7, 0x1ed1, 0x1ecc, 0x1ec7, 0x1ec1, 0x1ebc, 0x1eb7, 0x1eb1,
        0x1eac, 0x1ea7, 0x1ea1, 0x1e9c, 0x1e97, 0x1e92, 0x1e8c, 0x1e87, 0x1e82,
        0x1e7c, 0x1e77, 0x1e72, 0x1e6d, 0x1e67, 0x1e62, 0x1e5d, 0x1e58, 0x1e52,
        0x1e4d, 0x1e48, 0x1e43, 0x1e3d, 0x1e38, 0x1e33, 0x1e2e, 0x1e28, 0x1e23,
        0x1e1e, 0x1e19, 0x1e14, 0x1e0e, 0x1e09, 0x1e04, 0x1dff, 0x1dfa, 0x1df4,
        0x1def, 0x1dea, 0x1de5, 0x1de0, 0x1dda, 0x1dd5, 0x1dd0, 0x1dcb, 0x1dc6,
        0x1dc1, 0x1dbc, 0x1db6, 0x1db1, 0x1dac, 0x1da7, 0x1da2, 0x1d9d, 0x1d98,
        0x1d93, 0x1d8d, 0x1d88, 0x1d83, 0x1d7e, 0x1d79, 0x1d74, 0x1d6f, 0x1d6a,
        0x1d65, 0x1d5f, 0x1d5a, 0x1d55, 0x1d50, 0x1d4b, 0x1d46, 0x1d41, 0x1d3c,
        0x1d37, 0x1d32, 0x1d2d, 0x1d28, 0x1d23, 0x1d1e, 0x1d19, 0x1d14, 0x1d0e,
        0x1d09, 0x1d04, 0x1cff, 0x1cfa, 0x1cf5, 0x1cf0, 0x1ceb, 0x1ce6, 0x1ce1,
        0x1cdc, 0x1cd7, 0x1cd2, 0x1ccd, 0x1cc8, 0x1cc3, 0x1cbf, 0x1cba, 0x1cb5,
        0x1cb0, 0x1cab, 0x1ca6, 0x1ca1, 0x1c9c, 0x1c97, 0x1c92, 0x1c8d, 0x1c88,
        0x1c83, 0x1c7e, 0x1c79, 0x1c74, 0x1c6f, 0x1c6a, 0x1c65, 0x1c61, 0x1c5c,
        0x1c57, 0x1c52, 0x1c4d, 0x1c48, 0x1c43, 0x1c3e, 0x1c39, 0x1c34, 0x1c2f,
        0x1c2b, 0x1c26, 0x1c21, 0x1c1c, 0x1c17, 0x1c12, 0x1c0d, 0x1c09, 0x1c04,
        0x1bff, 0x1bfa, 0x1bf5, 0x1bf0, 0x1bec, 0x1be7, 0x1be2, 0x1bdd, 0x1bd8,
        0x1bd3, 0x1bcf, 0x1bca, 0x1bc5, 0x1bc0, 0x1bbb, 0x1bb7, 0x1bb2, 0x1bad,
        0x1ba8, 0x1ba3, 0x1b9f, 0x1b9a, 0x1b95, 0x1b90, 0x1b8c, 0x1b87, 0x1b82,
        0x1b7d, 0x1b78, 0x1b74, 0x1b6f, 0x1b6a, 0x1b66, 0x1b61, 0x1b5c, 0x1b57,
        0x1b53, 0x1b4e, 0x1b49, 0x1b44, 0x1b40, 0x1b3b, 0x1b36, 0x1b32, 0x1b2d,
        0x1b28, 0x1b23, 0x1b1f, 0x1b1a, 0x1b15, 0x1b11, 0x1b0c, 0x1b07, 0x1b03,
        0x1afe, 0x1af9, 0x1af5, 0x1af0, 0x1aeb, 0x1ae7, 0x1ae2, 0x1add, 0x1ad9,
        0x1ad4, 0x1acf, 0x1acb, 0x1ac6, 0x1ac1, 0x1abd, 0x1ab8, 0x1ab4, 0x1aaf,
        0x1aaa, 0x1aa6, 0x1aa1, 0x1a9c, 0x1a98, 0x1a93, 0x1a8f, 0x1a8a, 0x1a85,
        0x1a81, 0x1a7c, 0x1a78, 0x1a73, 0x1a6f, 0x1a6a, 0x1a65, 0x1a61, 0x1a5c,
        0x1a58, 0x1a53, 0x1a4f, 0x1a4a, 0x1a46, 0x1a41, 0x1a3c, 0x1a38, 0x1a33,
        0x1a2f, 0x1a2a, 0x1a26, 0x1a21, 0x1a1d, 0x1a18, 0x1a14, 0x1a0f, 0x1a0b,
        0x1a06, 0x1a02, 0x19fd, 0x19f9, 0x19f4, 0x19f0, 0x19eb, 0x19e7, 0x19e2,
        0x19de, 0x19d9, 0x19d5, 0x19d0, 0x19cc, 0x19c7, 0x19c3, 0x19be, 0x19ba,
        0x19b6, 0x19b1, 0x19ad, 0x19a8, 0x19a4, 0x199f, 0x199b, 0x1996, 0x1992,
        0x198e, 0x1989, 0x1985, 0x1980, 0x197c, 0x1978, 0x1973, 0x196f, 0x196a,
        0x1966, 0x1962, 0x195d, 0x1959, 0x1954, 0x1950, 0x194c, 0x1947, 0x1943,
        0x193e, 0x193a, 0x1936, 0x1931, 0x192d, 0x1929, 0x1924, 0x1920, 0x191c,
        0x1917, 0x1913, 0x190f, 0x190a, 0x1906, 0x1902, 0x18fd, 0x18f9, 0x18f5,
        0x18f0, 0x18ec, 0x18e8, 0x18e3, 0x18df, 0x18db, 0x18d6, 0x18d2, 0x18ce,
        0x18ca, 0x18c5, 0x18c1, 0x18bd, 0x18b8, 0x18b4, 0x18b0, 0x18ac, 0x18a7,
        0x18a3, 0x189f, 0x189b, 0x1896, 0x1892, 0x188e, 0x188a, 0x1885, 0x1881,
        0x187d, 0x1879, 0x1874, 0x1870, 0x186c, 0x1868, 0x1863, 0x185f, 0x185b,
        0x1857, 0x1853, 0x184e, 0x184a, 0x1846, 0x1842, 0x183e, 0x1839, 0x1835,
        0x1831, 0x182d, 0x1829, 0x1824, 0x1820, 0x181c, 0x1818, 0x1814, 0x180f,
        0x180b, 0x1807, 0x1803, 0x17ff, 0x17fb, 0x17f7, 0x17f2, 0x17ee, 0x17ea,
        0x17e6, 0x17e2, 0x17de, 0x17da, 0x17d5, 0x17d1, 0x17cd, 0x17c9, 0x17c5,
        0x17c1, 0x17bd, 0x17b9, 0x17b5, 0x17b0, 0x17ac, 0x17a8, 0x17a4, 0x17a0,
        0x179c, 0x1798, 0x1794, 0x1790, 0x178c, 0x1788, 0x1784, 0x177f, 0x177b,
        0x1777, 0x1773, 0x176f, 0x176b, 0x1767, 0x1763, 0x175f, 0x175b, 0x1757,
        0x1753, 0x174f, 0x174b, 0x1747, 0x1743, 0x173f, 0x173b, 0x1737, 0x1733,
        0x172f, 0x172b, 0x1727, 0x1723, 0x171f, 0x171b, 0x1717, 0x1713, 0x170f,
        0x170b, 0x1707, 0x1703, 0x16ff, 0x16fb, 0x16f7, 0x16f3, 0x16ef, 0x16eb,
        0x16e7, 0x16e3, 0x16df, 0x16db, 0x16d7, 0x16d3, 0x16cf, 0x16cb, 0x16c7,
        0x16c3, 0x16bf, 0x16bb, 0x16b7, 0x16b3, 0x16b0, 0x16ac, 0x16a8, 0x16a4,
        0x16a0, 0x169c, 0x1698, 0x1694, 0x1690, 0x168c, 0x1688, 0x1685, 0x1681,
        0x167d, 0x1679, 0x1675, 0x1671, 0x166d, 0x1669, 0x1665, 0x1662, 0x165e,
        0x165a, 0x1656, 0x1652, 0x164e, 0x164a, 0x1647, 0x1643, 0x163f, 0x163b,
        0x1637, 0x1633, 0x162f, 0x162c, 0x1628, 0x1624, 0x1620, 0x161c, 0x1618,
        0x1615, 0x1611, 0x160d, 0x1609, 0x1605, 0x1602, 0x15fe, 0x15fa, 0x15f6,
        0x15f2, 0x15ee, 0x15eb, 0x15e7, 0x15e3, 0x15df, 0x15dc, 0x15d8, 0x15d4,
        0x15d0, 0x15cc, 0x15c9, 0x15c5, 0x15c1, 0x15bd, 0x15b9, 0x15b6, 0x15b2,
        0x15ae, 0x15aa, 0x15a7, 0x15a3, 0x159f, 0x159c, 0x1598, 0x1594, 0x1590,
        0x158d, 0x1589, 0x1585, 0x1581, 0x157e, 0x157a, 0x1576, 0x1573, 0x156f,
        0x156b, 0x1567, 0x1564, 0x1560, 0x155c, 0x1559, 0x1555, 0x1551, 0x154e,
        0x154a, 0x1546, 0x1542, 0x153f, 0x153b, 0x1537, 0x1534, 0x1530, 0x152c,
        0x1529, 0x1525, 0x1521, 0x151e, 0x151a, 0x1516, 0x1513, 0x150f, 0x150b,
        0x1508, 0x1504, 0x1501, 0x14fd, 0x14f9, 0x14f6, 0x14f2, 0x14ee, 0x14eb,
        0x14e7, 0x14e4, 0x14e0, 0x14dc, 0x14d9, 0x14d5, 0x14d2, 0x14ce, 0x14ca,
        0x14c7, 0x14c3, 0x14c0, 0x14bc, 0x14b8, 0x14b5, 0x14b1, 0x14ae, 0x14aa,
        0x14a6, 0x14a3, 0x149f, 0x149c, 0x1498, 0x1495, 0x1491, 0x148d, 0x148a,
        0x1486, 0x1483, 0x147f, 0x147c, 0x1478, 0x1475, 0x1471, 0x146e, 0x146a,
        0x1466, 0x1463, 0x145f, 0x145c, 0x1458, 0x1455, 0x1451, 0x144e, 0x144a,
        0x1447, 0x1443, 0x1440, 0x143c, 0x1439, 0x1435, 0x1432, 0x142e, 0x142b,
        0x1427, 0x1424, 0x1420, 0x141d, 0x1419, 0x1416, 0x1412, 0x140f, 0x140b,
        0x1408, 0x1405, 0x1401, 0x13fd, 0x13fa, 0x13f7, 0x13f3, 0x13f0, 0x13ec,
        0x13e9, 0x13e5, 0x13e2, 0x13de, 0x13db, 0x13d8, 0x13d4, 0x13d1, 0x13cd,
        0x13ca, 0x13c7, 0x13c3, 0x13c0, 0x13bc, 0x13b9, 0x13b5, 0x13b2, 0x13ae,
        0x13ab, 0x13a8, 0x13a4, 0x13a1, 0x139e, 0x139a, 0x1397, 0x1393, 0x1390,
        0x138d, 0x1389, 0x1386, 0x1382, 0x137f, 0x137c, 0x1378, 0x1375, 0x1372,
        0x136e, 0x136b, 0x1367, 0x1364, 0x1361, 0x135d, 0x135a, 0x1357, 0x1353,
        0x1350, 0x134d, 0x1349, 0x1346, 0x1343, 0x133f, 0x133c, 0x1339, 0x1335,
        0x1332, 0x132f, 0x132b, 0x1328, 0x1325, 0x1321, 0x131e, 0x131b, 0x1317,
        0x1314, 0x1311, 0x130e, 0x130a, 0x1307, 0x1304, 0x1300, 0x12fd, 0x12fa,
        0x12f7, 0x12f3, 0x12f0, 0x12ed, 0x12e9, 0x12e6, 0x12e3, 0x12df, 0x12dc,
        0x12d9, 0x12d6, 0x12d2, 0x12cf, 0x12cc, 0x12c9, 0x12c5, 0x12c2, 0x12bf,
        0x12bc, 0x12b8, 0x12b5, 0x12b2, 0x12af, 0x12ac, 0x12a8, 0x12a5, 0x12a2,
        0x129f, 0x129b, 0x1298, 0x1295, 0x1292, 0x128e, 0x128b, 0x1288, 0x1285,
        0x1282, 0x127e, 0x127b, 0x1278, 0x1275, 0x1272, 0x126e, 0x126b, 0x1268,
        0x1265, 0x1262, 0x125e, 0x125b, 0x1258, 0x1255, 0x1252, 0x124f, 0x124b,
        0x1248, 0x1245, 0x1242, 0x123f, 0x123c, 0x1238, 0x1235, 0x1232, 0x122f,
        0x122c, 0x1229, 0x1226, 0x1222, 0x121f, 0x121c, 0x1219, 0x1216, 0x1213,
        0x1210, 0x120c, 0x1209, 0x1206, 0x1203, 0x1200, 0x11fd, 0x11fa, 0x11f7,
        0x11f4, 0x11f0, 0x11ed, 0x11ea, 0x11e7, 0x11e4, 0x11e1, 0x11de, 0x11db,
        0x11d8, 0x11d5, 0x11d1, 0x11ce, 0x11cb, 0x11c8, 0x11c5, 0x11c2, 0x11bf,
        0x11bc, 0x11b9, 0x11b6, 0x11b3, 0x11b0, 0x11ad, 0x11a9, 0x11a6, 0x11a3,
        0x11a0, 0x119d, 0x119a, 0x1197, 0x1194, 0x1191, 0x118e, 0x118b, 0x1188,
        0x1185, 0x1182, 0x117f, 0x117c, 0x1179, 0x1176, 0x1173, 0x1170, 0x116d,
        0x116a, 0x1167, 0x1164, 0x1161, 0x115e, 0x115b, 0x1158, 0x1155, 0x1152,
        0x114f, 0x114c, 0x1149, 0x1146, 0x1143, 0x1140, 0x113d, 0x113a, 0x1137,
        0x1134, 0x1131, 0x112e, 0x112b, 0x1128, 0x1125, 0x1122, 0x111f, 0x111c,
        0x1119, 0x1116, 0x1113, 0x1110, 0x110d, 0x110a, 0x1107, 0x1104, 0x1101,
        0x10fe, 0x10fb, 0x10f8, 0x10f5, 0x10f2, 0x10ef, 0x10ec, 0x10e9, 0x10e6,
        0x10e3, 0x10e0, 0x10de, 0x10db, 0x10d8, 0x10d5, 0x10d2, 0x10cf, 0x10cc,
        0x10c9, 0x10c6, 0x10c3, 0x10c0, 0x10bd, 0x10ba, 0x10b8, 0x10b5, 0x10b2,
        0x10af, 0x10ac, 0x10a9, 0x10a6, 0x10a3, 0x10a0, 0x109e, 0x109b, 0x1098,
        0x1095, 0x1092, 0x108f, 0x108c, 0x1089, 0x1086, 0x1084, 0x1081, 0x107e,
        0x107b, 0x1078, 0x1075, 0x1072, 0x1070, 0x106d, 0x106a, 0x1067, 0x1064,
        0x1061, 0x105e, 0x105c, 0x1059, 0x1056, 0x1053, 0x1050, 0x104d, 0x104a,
        0x1048, 0x1045, 0x1042, 0x103f, 0x103c, 0x1039, 0x1037, 0x1034, 0x1031,
        0x102e, 0x102b, 0x1028, 0x1026, 0x1023, 0x1020, 0x101d, 0x101a, 0x1018,
        0x1015, 0x1012, 0x100f, 0x100c, 0x100a, 0x1007, 0x1004 };

typedef struct
{
  unsigned short state;
  unsigned char run, likely, started;
  int gap;
} wz_bin;

typedef struct
{
  struct wz96_stream *source;
  unsigned long code;
  int interval, prev_interval;
  unsigned char last, previous;
  int exhausted;
} wz_bac;

static unsigned int
wz_bac_byte (wz_bac *b)
{
  unsigned char c = 0;

  b->previous = b->last;
  if (!wz96_get (b->source, &c, 1))
    {
      b->exhausted = 1;
    }

  b->last = c;

  return c;
}

static unsigned long
wz_exp (int scale)
{
  int e = 7 - (scale >> 10);
  unsigned long mant = wz96_ant[scale & 1023];

  if (e >= 0)
    {
      return mant << e;
    }

  return mant >> (-e);
}

static int
wz_lognumber (unsigned long number)
{
  unsigned long hb = number >> 12;
  int whole = 0, shift;
  unsigned long mant;
  int f = 0, high = 1023, mid;

  if (hb == 0)
    {
      return 8192;
    }

  while (hb && hb < 256)
    {
      hb <<= 1;
      whole++;
    }
  if (whole > 8)
    {
      whole = 8;
    }

  shift = 8 - whole;

  if (shift >= 0)
    {
      mant = (number >> shift) & 4095;
    }
  else
    {
      mant = (number << (-shift)) & 4095;
    }

  mant += 4096;

  while (f <= high)
    {
      mid = (f + high) / 2;

      if (wz96_ant[mid] <= mant)
        {
          high = mid - 1;
        }
      else
        {
          f = mid + 1;
        }
    }

  return (whole << 10) - (1024 - f);
}

static int
wz_under (unsigned long sample, int boundary)
{
  return boundary < wz_lognumber (sample);
}

static void
wz_normalize (wz_bac *b)
{
  while (b->interval > 8191)
    {
      if (b->previous == 255 && b->last == 255)
        {
          b->code = (b->code + wz_bac_byte (b)) & 0xffffffffUL;
        }

      b->code = ((b->code << 8) | wz_bac_byte (b)) & 0xffffffffUL;
      b->interval -= 8192;
      b->prev_interval -= 8192;
    }
}

static void
wz_bac_init (wz_bac *b, struct wz96_stream *src)
{
  memset (b, 0, sizeof (*b));
  b->source = src;
  b->code = wz_bac_byte (b) << 8;
  b->code |= wz_bac_byte (b);
  b->interval = 4097;
  b->prev_interval = 4097;

  if (b->code == 65535UL)
    {
      (void)wz_bac_byte (b);
    }
}

static void
wz_index_step (int *state, int *wrap, int double_step)
{
  if (*state > 0)
    {
      if (double_step)
        {
          *state -= wz_twice[*state];
        }
      else
        {
          (*state)--;
        }
    }
  else if (!double_step)
    {
      (*wrap)++;
    }
}

static void
wz_reinforce (wz_bac *a, wz_bin *v)
{
  int i = v->state;

  if (v->run <= 5 && i < 47)
    {
      i++;

      if (v->run <= 1)
        {
          i += wz_half[i];

          if (v->run == 0)
            {
              i += wz_half[i];
            }
        }

      if (i > 47)
        {
          i = 47;
        }

      v->state = (unsigned short)i;
    }

  v->run = 0;
  a->prev_interval = a->interval + wz_nmax[v->state];

  if (a->prev_interval > 2047)
    {
      wz_normalize (a);
    }
}

static void
wz_surprise (wz_bac *a, wz_bin *v)
{
  int i = v->state;

  a->interval += wz_q[i];
  a->prev_interval += wz_q[i];

  if (v->run >= 11)
    {
      int gap = a->prev_interval - a->interval;
      int normal = (int)wz_nmax[i];
      int wrap = 0;

      if (i < 48)
        {
          if (gap >= normal / 2)
            {
              gap = normal - gap;
              if (gap <= normal / 4)
                {
                  wz_index_step (&i, &wrap, 1);
                }

              wz_index_step (&i, &wrap, 1);
            }
          else
            {
              if (gap >= normal / 4)
                {
                  wz_index_step (&i, &wrap, 0);
                }

              wz_index_step (&i, &wrap, 0);
            }

          if (i == 0)
            {
              i = wrap;
              v->likely ^= 1;
            }

          v->state = (unsigned short)i;
        }

      v->run = 0;
      a->prev_interval = a->interval + wz_nmax[v->state];
    }
  else if (a->prev_interval < a->interval)
    {
      a->prev_interval = a->interval;
    }
}

static int
wz_next (wz_bac *a, wz_bin *v)
{
  int bit = v->likely;
  int in_smaller_interval;

  if (!v->started)
    {
      v->gap = 16384;
      v->started = 1;
    }

  a->prev_interval = a->interval + v->gap;

  if (a->prev_interval > 2047)
    {
      wz_normalize (a);
    }

  a->interval += wz_p[v->state];
  in_smaller_interval = wz_under (a->code, a->interval);

  if (!in_smaller_interval || a->interval >= a->prev_interval)
    {
      if (in_smaller_interval)
        {
          wz_reinforce (a, v);
        }
      else
        {
          wz_normalize (a);
          if (wz_under (a->code, a->interval))
            {
              if (a->interval >= a->prev_interval)
                {
                  wz_reinforce (a, v);
                }
            }
          else
            {
              bit ^= 1;
              v->run++;
              a->code -= wz_exp (a->interval);
              wz_surprise (a, v);
            }
        }
    }

  v->gap = a->prev_interval - a->interval;
#ifdef WZ96_TRACE
  {
    static int shown = 0;

    if (a->code > 1000000UL && shown++ < 5)
      {
        fprintf (stderr, "HIGHCODE code=%lu lr=%d prev=%d gap=%d index=%u\n",
                 a->code, a->interval, a->prev_interval, v->gap, v->state);
      }
  }
#endif /* ifdef WZ96_TRACE */

#ifdef WZ96_TRACE
  {
    static unsigned int nn = 0;

    if (nn < 30)
      {
        fprintf (
            stderr, "bac %u bit=%d code=%lu lr=%d lrm=%d gap=%d state=%u\n",
            nn, bit, a->code, a->interval, a->prev_interval, v->gap, v->state);
      }

    nn++;
  }
#endif /* ifdef WZ96_TRACE */
  return bit;
}

#define WZ_COMP 4
#define WZ_COEFF 64
#define WZ_MIN(a, b) ((a) < (b) ? (a) : (b))

static const unsigned char wz_zig[8][8] = {
  { 0, 1, 5, 6, 14, 15, 27, 28 },     { 2, 4, 7, 13, 16, 26, 29, 42 },
  { 3, 8, 12, 17, 25, 30, 41, 43 },   { 9, 11, 18, 24, 31, 40, 44, 53 },
  { 10, 19, 23, 32, 39, 45, 52, 54 }, { 20, 22, 33, 38, 46, 51, 55, 60 },
  { 21, 34, 37, 47, 50, 56, 59, 61 }, { 35, 36, 48, 49, 57, 58, 62, 63 }
};

static unsigned char wz_r[64], wz_c[64], wz_sign_order[64];

static void
wz_build_zig (void)
{
  unsigned int y, x, i, k;

  k = 0;
  for (y = 0; y < 8; y++)
    {
      for (x = 0; x < 8; x++)
        {
          i = wz_zig[y][x];
          wz_r[i] = (unsigned char)y;
          wz_c[i] = (unsigned char)x;
        }
    }

  for (i = 1; i < 64; i++)
    {
      if (wz_r[i] < 2 || wz_c[i] < 2)
        {
          wz_sign_order[i] = (unsigned char)k++;
        }
      else
        {
          wz_sign_order[i] = 255;
        }
    }
}

typedef struct
{
  wz_bin eob[WZ_COMP][13][63];
  wz_bin zero[WZ_COMP][63][3][6];
  wz_bin pivot[WZ_COMP][63][5][7];
  wz_bin mag_ac[WZ_COMP][3][9][9][9];
  wz_bin rem_ac[WZ_COMP][3][7][13];
  wz_bin sign_ac[WZ_COMP][27][3][2];
  wz_bin mag_dc[WZ_COMP][13][10];
  wz_bin rem_dc[WZ_COMP][13][14];
  wz_bin sign_dc[WZ_COMP][2][2][2];
  wz_bin fixed;
} wz_model;

static int
wz_abs (int x)
{
  return x < 0 ? -x : x;
}

static unsigned int
wz_cat (unsigned int n)
{
  unsigned int c = 0;

  while (n)
    {
      c++;
      n >>= 1;
    }

  return c;
}

static unsigned long
wz_region_sum (const int *b, unsigned int at)
{
  unsigned int i;
  unsigned long sum = 0;

  for (i = 1; i < 64; i++)
    {
      if (i != at && wz_r[i] >= wz_r[at] && wz_c[i] >= wz_c[at])
        {
          sum += (unsigned long)wz_abs (b[i]);
        }
    }

  return sum;
}

static unsigned int
wz_avg (unsigned int k, const int *north, const int *west,
        const unsigned int *q)
{
  unsigned int y = wz_r[k], x = wz_c[k], part = 1, at;
  unsigned long sum = (unsigned long)wz_abs (north[k]) + wz_abs (west[k]);

  if (y)
    {
      at = wz_zig[y - 1][x];
      sum += ((unsigned long)(wz_abs (north[at]) + wz_abs (west[at])) * q[at])
             / q[k];
      part++;
    }

  if (x)
    {
      at = wz_zig[y][x - 1];
      sum += ((unsigned long)(wz_abs (north[at]) + wz_abs (west[at])) * q[at])
             / q[k];
      part++;
    }

  if (y && x && k != 4)
    {
      at = wz_zig[y - 1][x - 1];
      sum += ((unsigned long)(wz_abs (north[at]) + wz_abs (west[at])) * q[at])
             / q[k];
      part++;
    }

  return (unsigned int)((sum + part) / (2 * part));
}

static int
wz_border (unsigned int k, const int *cur, const int *north, const int *west,
           const unsigned int *q)
{
  unsigned int y = wz_r[k], x = wz_c[k], at;

  if (!y)
    {
      at = wz_zig[y + 1][x];

      return north[k] - (int)((((long)north[at] + cur[at]) * q[at]) / q[k]);
    }

  at = wz_zig[y][x + 1];

  return west[k] - (int)((((long)west[at] + cur[at]) * q[at]) / q[k]);
}

static unsigned int
wz_decode_universal (wz_bac *bac, wz_bin *unary, wz_bin *remainder,
                     unsigned int bits, unsigned int cap)
{
  unsigned int count = 0, value, i;

  while (count < bits)
    {
      if (!wz_next (bac, &unary[WZ_MIN (count, cap - 1)]))
        {
          break;
        }

      count++;
    }
  if (count < 2)
    {
      return count;
    }

  value = 1U << (count - 1);

  for (i = count - 1; i > 0; i--)
    {
      value |= (unsigned int)wz_next (bac, &remainder[i - 1]) << (i - 1);
    }

  return value;
}

static int
wz_ac_value (wz_bac *bac, wz_model *m, unsigned int comp, unsigned int k,
             const int *cur, const int *north, const int *west,
             const unsigned int *q, int is_last)
{
  unsigned int v1, v2, n, v3, absvalue, sign_index, predicted, group;
  int border, p, sign;

  border = (wz_r[k] == 0 || wz_c[k] == 0);
  p = border ? wz_border (k, cur, north, west, q) : 0;
  v1 = border ? (unsigned int)wz_abs (p) : wz_avg (k, north, west, q);
  v2 = (unsigned int)wz_region_sum (cur, k);

  if (!is_last
      && !wz_next (bac, &m->zero[comp][k - 1][WZ_MIN (wz_cat (v1), 2U)]
                                [WZ_MIN (wz_cat (v2), 5U)]))
    {
      return 0;
    }

  absvalue = 1;

  if (wz_next (bac, &m->pivot[comp][k - 1][WZ_MIN (wz_cat (v1), 4U)]
                             [WZ_MIN (wz_cat (v2), 6U)]))
    {
      if (wz_r[k] == 0)
        {
          n = 0;
          v3 = wz_c[k] - 1;
        }
      else if (wz_c[k] == 0)
        {
          n = 1;
          v3 = wz_r[k] - 1;
        }
      else
        {
          n = 2;
          v3 = wz_cat (k - 4);
        }

      if (v3 > 6)
        {
          return 16384;
        }

      absvalue
          = wz_decode_universal (bac,
                                 m->mag_ac[comp][n][WZ_MIN (wz_cat (v1), 8U)]
                                          [WZ_MIN (wz_cat (v2), 8U)],
                                 m->rem_ac[comp][n][v3], 14, 9)
            + 2;
    }

  if (absvalue > 16383)
    {
      return 16384;
    }

  sign_index = wz_sign_order[k];

  if (sign_index == 255)
    {
      return wz_next (bac, &m->fixed) ? -(int)absvalue : (int)absvalue;
    }

  if (border)
    {
      if (p == 0)
        {
          return wz_next (bac, &m->fixed) ? -(int)absvalue : (int)absvalue;
        }

      predicted = (unsigned int)(p < 0);
    }
  else if (k == 4)
    {
      int x = (north[k] > 0) - (north[k] < 0) + (west[k] > 0) - (west[k] < 0);

      if (x == 0)
        {
          return wz_next (bac, &m->fixed) ? -(int)absvalue : (int)absvalue;
        }

      predicted = (unsigned int)(x < 0);
    }
  else if (wz_r[k] == 1)
    {
      if (north[k] == 0)
        {
          return wz_next (bac, &m->fixed) ? -(int)absvalue : (int)absvalue;
        }

      predicted = (unsigned int)(north[k] < 0);
    }
  else
    {
      if (west[k] == 0)
        {
          return wz_next (bac, &m->fixed) ? -(int)absvalue : (int)absvalue;
        }

      predicted = (unsigned int)(west[k] < 0);
    }

  group = WZ_MIN (wz_cat (absvalue) / 2, 2U);
  sign = wz_next (bac, &m->sign_ac[comp][sign_index][group][predicted]);

  return sign ? -(int)absvalue : (int)absvalue;
}

static int
wz_dc_predict (const int *cur, const int *n, const int *w, int has_n,
               int has_w, const unsigned int *q, int *predict)
{
  double dn, dw, t, scale;
  unsigned int k;
  int delta_n = 0, delta_w = 0;
  long pn = 0, pw = 0;

  if (!has_n && !has_w)
    {
      *predict = 0;

      return 1;
    }

  if (has_n)
    {
      dn = (double)n[0] * 10000.0
           - (double)11038 * q[2] * (n[2] + cur[2]) / q[0];
      pn = (long)((dn + (dn < 0 ? -5000.0 : 5000.0)) / 10000.0);
    }

  if (has_w)
    {
      dw = (double)w[0] * 10000.0
           - (double)11038 * q[1] * (w[1] + cur[1]) / q[0];
      pw = (long)((dw + (dw < 0 ? -5000.0 : 5000.0)) / 10000.0);
    }

  if (!has_w || !has_n)
    {
      *predict = (int)(has_n ? pn : pw);

      return 1;
    }

  for (k = 1; k < 8; k++)
    {
      unsigned int at = wz_zig[k][0];
      delta_n += wz_abs (n[at] - cur[at]);
      at = wz_zig[0][k];
      delta_w += wz_abs (w[at] - cur[at]);
    }

  if (delta_n > delta_w)
    {
      scale = 1U << WZ_MIN (delta_n - delta_w, 30);
      t = (scale * pw + pn) / (scale + 1.0);
    }
  else
    {
      scale = 1U << WZ_MIN (delta_w - delta_n, 30);
      t = (scale * pn + pw) / (scale + 1.0);
    }

  if (t < -32000. || t > 32000.)
    {
      return 0;
    }

  *predict = (int)t;

  return 1;
}

static int
wz_decode_block (wz_bac *bac, wz_model *m, unsigned int comp, int *cur,
                 const int *n, const int *w, int has_n, int has_w,
                 const unsigned int *q)
{
  unsigned int average, ctx, eob, node, k, resid, neg;
  int pred, value;
  static const int zeros[64] = { 0 };

  if (!n)
    {
      n = zeros;
    }

  if (!w)
    {
      w = zeros;
    }

  if (has_n && has_w)
    {
      average
          = (unsigned int)((wz_region_sum (n, 0) + wz_region_sum (w, 0) + 1)
                           / 2);
    }
  else if (has_n)
    {
      average = (unsigned int)wz_region_sum (n, 0);
    }
  else if (has_w)
    {
      average = (unsigned int)wz_region_sum (w, 0);
    }
  else
    {
      average = 0;
    }

  ctx = WZ_MIN (wz_cat (average), 12U);
  node = 1;

  for (k = 0; k < 6; k++)
    {
      node = 2 * node
             + (unsigned int)wz_next (bac, &m->eob[comp][ctx][node - 1]);
    }

  eob = node - 64;
#ifdef WZ96_TRACE
  {
    static unsigned long cnt;
    if (cnt < 12)
      {
        fprintf (stderr, "block%lu comp=%u eob=%u\n", cnt, comp, eob);
      }

    cnt++;
  }
#endif /* ifdef WZ96_TRACE */

  for (k = eob; k > 0; k--)
    {
      cur[k] = wz_ac_value (bac, m, comp, k, cur, n, w, q, k == eob);

      if (cur[k] < -16383 || cur[k] > 16383)
        {
#ifdef WZ96_TRACE
          fprintf (stderr, "ACfail k=%u val=%d eob=%u\n", k, cur[k], eob);
#endif /* ifdef WZ96_TRACE */
          return 0;
        }
    }

  if (!wz_dc_predict (cur, n, w, has_n, has_w, q, &pred))
    {
#ifdef WZ96_TRACE
      fprintf (stderr, "prediction_fail eob=%u\n", eob);
#endif /* ifdef WZ96_TRACE */
      return 0;
    }

  ctx = WZ_MIN (wz_cat ((unsigned int)wz_region_sum (cur, 0)), 12U);
  resid = wz_decode_universal (bac, m->mag_dc[comp][ctx], m->rem_dc[comp][ctx],
                               15, 10);
  if (resid > 32767)
    {
#ifdef WZ96_TRACE
      fprintf (stderr, "residfail val=%u eob=%u\n", resid, eob);
#endif /* ifdef WZ96_TRACE */
      return 0;
    }

  if (!resid)
    {
      neg = 0;
    }
  else
    {
      neg = (unsigned int)wz_next (
          bac, &m->sign_dc[comp][n[0] < pred][w[0] < pred][pred < 0]);
    }

  value = pred + (neg ? -(int)resid : (int)resid);

  if (value < -16384 || value > 16383)
    {
#ifdef WZ96_TRACE
      fprintf (stderr, "DCfail val=%d pred=%d resid=%u eob=%u\n", value, pred,
               resid, eob);
#endif /* ifdef WZ96_TRACE */
      return 0;
    }

  cur[0] = value;
#ifdef WZ96_TRACE
  {
    static unsigned long tt = 0;

    if (tt < 15)
      {
        fprintf (stderr,
                 "COEFF #%lu pred=%d dc=%d resid=%u ac1=%d ac2=%d ac3=%d\n",
                 tt, pred, value, resid, cur[1], cur[2], cur[3]);
      }

    tt++;
  }
#endif /* ifdef WZ96_TRACE */
  return 1;
}

typedef struct
{
  unsigned short code[256];
  unsigned char len[256];
} wz_huffman;

typedef struct
{
  unsigned int id, h, v, q;
} wz_frame_comp;

typedef struct
{
  unsigned int frame_index, dc, ac, blocks_h, blocks_v;
} wz_scan_comp;

typedef struct
{
  unsigned int width, height, precision, frame_count, max_h, max_v;
  wz_frame_comp frame[4];
  unsigned int quant[4][64];
  unsigned char quant_valid[4];
  wz_huffman huff[2][4];
  unsigned int restart, scan_count, mcus_x, mcus_y;
  wz_scan_comp sc[4];
} wz_jpeg;

static int
wz_parse_jpeg (wz_jpeg *j, const unsigned char *data, size_t size, int first,
               int *scan, int *end_image)
{
  size_t p = 0, z, next;
  unsigned int m, len, i, c, v, count, jj, h, k, code;
  int seen_soi = 0;

  *scan = *end_image = 0;

  if (first)
    {
      for (p = 0; p + 1 < size && p < 128; p++)
        {
          if (data[p] == 255 && data[p + 1] == 0xd8)
            {
              break;
            }
        }

      if (p >= 128 || p + 1 >= size)
        {
          return 0;
        }
    }

  while (p < size)
    {
      if (data[p++] != 255)
        {
          return 0;
        }

      while (p < size && data[p] == 255)
        {
          p++;
        }

      if (p >= size)
        {
          return 0;
        }

      m = data[p++];

      if (m == 0xd8)
        {
          if (!first || seen_soi)
            {
              return 0;
            }

          seen_soi = 1;

          continue;
        }

      if (first && !seen_soi)
        {
          return 0;
        }

      if (m == 0xd9)
        {
          *end_image = 1;

          return 1;
        }

      if (m == 0 || (m >= 0xd0 && m <= 0xd7) || p + 2 > size)
        {
          return 0;
        }

      len = wz96_be16 (data + p);

      if (len < 2 || len > size - p)
        {
          return 0;
        }

      next = p + len;
      z = p + 2;

      switch (m)
        {
        case 0xdb:
          while (z < next)
            {
              c = data[z] & 15;
              v = data[z++] >> 4;

              if (c >= 4 || v > 1 || next - z < (v ? 128U : 64U))
                {
                  return 0;
                }

              for (i = 0; i < 64; i++)
                {
                  j->quant[c][i]
                      = v ? wz96_be16 (data + z + 2 * i) : data[z + i];

                  if (!j->quant[c][i])
                    {
                      return 0;
                    }
                }

              j->quant_valid[c] = 1;
              z += (v ? 128 : 64);
            }

          break;

        case 0xc4:
          while (z < next)
            {
              if (next - z < 17)
                {
                  return 0;
                }

              c = data[z] & 15;
              v = data[z++] >> 4;

              if (c >= 4 || v > 1)
                {
                  return 0;
                }

              count = 0;

              for (i = 0; i < 16; i++)
                {
                  count += data[z + i];
                }

              if (next - z - 16 < count)
                {
                  return 0;
                }

              memset (&j->huff[v][c], 0, sizeof (j->huff[v][c]));
              code = 0;
              k = 0;

              for (i = 0; i < 16; i++)
                {
                  for (jj = 0; jj < data[z + i]; jj++)
                    {
                      unsigned int symbol = data[z + 16 + k];

                      if (code >= (1UL << (i + 1))
                          || j->huff[v][c].len[symbol])
                        {
                          return 0;
                        }

                      j->huff[v][c].len[symbol] = (unsigned char)(i + 1);
                      j->huff[v][c].code[symbol] = (unsigned short)code;
                      k++;
                      code++;
                    }

                  code <<= 1;
                }

              z += 16 + count;
            }

          break;

        case 0xc0:
        case 0xc1:
          if (len < 11)
            {
              return 0;
            }

          c = data[z + 5];

          if (c < 1 || c > 4 || len != 8 + 3 * c)
            {
              return 0;
            }

          j->precision = data[z];
          j->height = wz96_be16 (data + z + 1);
          j->width = wz96_be16 (data + z + 3);

          if ((j->precision != 8 && j->precision != 12) || !j->height
              || !j->width)
            {
              return 0;
            }

          j->frame_count = c;
          j->max_h = j->max_v = 1;

          for (i = 0; i < c; i++)
            {
              wz_frame_comp *f = &j->frame[i];
              f->id = data[z + 6 + i * 3];
              f->h = data[z + 7 + i * 3] >> 4;
              f->v = data[z + 7 + i * 3] & 15;
              f->q = data[z + 8 + i * 3];

              if (!f->h || !f->v || f->h > 4 || f->v > 4 || f->q >= 4)
                {
                  return 0;
                }

              if (j->max_h < f->h)
                {
                  j->max_h = f->h;
                }

              if (j->max_v < f->v)
                {
                  j->max_v = f->v;
                }
            }

          break;

        case 0xdd:
          if (len != 4)
            {
              return 0;
            }

          j->restart = wz96_be16 (data + z);

          break;

        case 0xda:
          if (len < 6 || !j->frame_count)
            {
              return 0;
            }

          c = data[z++];

          if (c < 1 || c > j->frame_count || len != 6 + 2 * c)
            {
              return 0;
            }

          j->scan_count = c;

          for (i = 0; i < c; i++)
            {
              wz_scan_comp *s = &j->sc[i];
              unsigned int id = data[z++];
              unsigned int selectors = data[z++];

              for (h = 0; h < j->frame_count; h++)
                {
                  if (j->frame[h].id == id)
                    {
                      break;
                    }
                }

              if (h == j->frame_count)
                {
                  return 0;
                }

              s->frame_index = h;
              s->dc = selectors >> 4;
              s->ac = selectors & 15;

              if (s->dc >= 4 || s->ac >= 4 || !j->quant_valid[j->frame[h].q])
                {
                  return 0;
                }

              if (c == 1)
                {
                  s->blocks_h = s->blocks_v = 1;
                }
              else
                {
                  s->blocks_h = j->frame[h].h;
                  s->blocks_v = j->frame[h].v;
                }
            }

          if (data[z] != 0 || data[z + 1] != 63 || data[z + 2] != 0)
            {
              return 0;
            }

          if (c == 1)
            {
              wz_frame_comp *f = &j->frame[j->sc[0].frame_index];
              j->mcus_x = ((unsigned long)j->width * f->h + (8 * j->max_h - 1))
                          / (8 * j->max_h);
              j->mcus_y
                  = ((unsigned long)j->height * f->v + (8 * j->max_v - 1))
                    / (8 * j->max_v);
            }
          else
            {
              j->mcus_x = (j->width + 8 * j->max_h - 1) / (8 * j->max_h);
              j->mcus_y = (j->height + 8 * j->max_v - 1) / (8 * j->max_v);
            }

          if (!j->mcus_x || !j->mcus_y || next != size)
            {
              return 0;
            }

          *scan = 1;

          return 1;

        default:
          break;
        }
      p = next;
    }

  return 0;
}

typedef struct
{
  wz96_write_fn write;
  void *opaque;
  unsigned long budget, produced;
  unsigned char buf[8192];
  unsigned int used;
  unsigned char partial;
  unsigned int count;
  int failed;
} wz_sink;

static void
wz_sink_drain (wz_sink *s)
{
  if (s->failed || !s->used)
    {
      return;
    }

  if (s->write (s->opaque, s->buf, s->used) != s->used)
    {
      s->failed = 1;
    }

  s->used = 0;
}

static void
wz_sink_byte (wz_sink *s, unsigned int c)
{
  if (s->failed)
    {
      return;
    }

  if (s->produced == s->budget)
    {
      s->failed = 1;

      return;
    }

  s->produced++;
  s->buf[s->used++] = (unsigned char)c;

  if (s->used == sizeof (s->buf))
    {
      wz_sink_drain (s);
    }
}

static void
wz_sink_buffer (wz_sink *s, const unsigned char *src, size_t n)
{
  size_t i;

  for (i = 0; i < n && !s->failed; i++)
    {
      wz_sink_byte (s, src[i]);
    }
}

static void
wz_jpeg_bits (wz_sink *s, unsigned int bits, unsigned int len)
{
  unsigned int bit;

  while (len && !s->failed)
    {
      len--;
      bit = (bits >> len) & 1;
      s->partial = (unsigned char)((s->partial << 1) | bit);
      s->count++;

      if (s->count == 8)
        {
          wz_sink_byte (s, s->partial);

          if (s->partial == 255)
            {
              wz_sink_byte (s, 0);
            }

          s->partial = 0;
          s->count = 0;
        }
    }
}

static void
wz_jpeg_align (wz_sink *s)
{
  if (s->count)
    {
      unsigned int rest = 8 - s->count;
      wz_jpeg_bits (s, (1U << rest) - 1, rest);
    }
}

static void
wz_jpeg_code (wz_sink *s, const wz_huffman *h, unsigned int symbol)
{
  if (symbol >= 256 || !h->len[symbol])
    {
      s->failed = 1;

      return;
    }

  wz_jpeg_bits (s, h->code[symbol], h->len[symbol]);
}

static void
wz_jpeg_block (wz_sink *out, const wz_jpeg *j, unsigned int scan_index,
               const int *b, int *dc_prediction)
{
  const wz_scan_comp *sc = &j->sc[scan_index];
  const wz_huffman *dc = &j->huff[0][sc->dc], *ac = &j->huff[1][sc->ac];
  int diff = b[0] - *dc_prediction, value;
  unsigned int cat, k, zeros = 0;

  *dc_prediction = b[0];
  cat = wz_cat ((unsigned int)wz_abs (diff));

  if (cat > 16)
    {
      out->failed = 1;

      return;
    }

  wz_jpeg_code (out, dc, cat);

  if (cat)
    {
      value = diff < 0 ? diff - 1 : diff;
      wz_jpeg_bits (out, (unsigned int)value & ((1U << cat) - 1), cat);
    }

  for (k = 1; k < 64; k++)
    {
      if (b[k] == 0)
        {
          zeros++;

          continue;
        }

      while (zeros >= 16)
        {
          wz_jpeg_code (out, ac, 0xf0);
          zeros -= 16;
        }
      cat = wz_cat ((unsigned int)wz_abs (b[k]));

      if (cat > 15)
        {
          out->failed = 1;

          return;
        }

      wz_jpeg_code (out, ac, (zeros << 4) | cat);
      value = b[k] < 0 ? b[k] - 1 : b[k];
      wz_jpeg_bits (out, (unsigned int)value & ((1U << cat) - 1), cat);
      zeros = 0;
    }

  if (zeros)
    {
      wz_jpeg_code (out, ac, 0);
    }
}

typedef struct
{
  int *data, *previous_row;
  unsigned int width, height;
} wz_scan_buffer;
static int
wz_decode_scan (struct wz96_stream *input, wz_sink *sink, wz_jpeg *jpeg,
                unsigned int sliceval)
{
  wz_model *model = NULL;
  wz_scan_buffer buffers[4];
  wz_bac arithmetic;
  unsigned int slices_y, done_y = 0, rows, comp, i, y, x, by, bx, h, v, r;
  unsigned long cap, desired, divisor;
  int dc_previous[4] = { 0, 0, 0, 0 };
  unsigned int restart_pos = 0, restart_id = 0;
  int ok = 0;

  memset (buffers, 0, sizeof (buffers));
  model = (wz_model *)calloc (1, sizeof (*model));

  if (!model)
    {
      return 0;
    }

  model->fixed.state = 48;

  if (sliceval)
    {
      if (sliceval + 6 >= (unsigned int)(sizeof (unsigned long) * CHAR_BIT))
        {
          cap = ULONG_MAX;
        }
      else
        {
          cap = 1UL << (sliceval + 6);
        }

      divisor = cap / jpeg->mcus_x;

      if (divisor == 0)
        {
          divisor = 1;
        }

      desired = ((unsigned long)jpeg->mcus_y - 1UL) / divisor + 1UL;
      slices_y = (unsigned int)(((unsigned long)jpeg->mcus_y - 1UL) / desired
                                + 1UL);
    }
  else
    {
      slices_y = jpeg->mcus_y;
    }

  if (slices_y == 0 || slices_y > jpeg->mcus_y)
    {
      goto done;
    }

  for (comp = 0; comp < jpeg->scan_count; comp++)
    {
      wz_scan_buffer *b = &buffers[comp];
      const wz_scan_comp *s = &jpeg->sc[comp];
      size_t n;
      b->width = jpeg->mcus_x * s->blocks_h;
      b->height = slices_y * s->blocks_v;
      n = (size_t)b->width * b->height;

      if (!b->width || !b->height
          || (n / (size_t)b->height) != (size_t)b->width
          || n > 33554432UL / sizeof (int[64]))
        {
          goto done;
        }

      b->data = (int *)calloc (n, sizeof (int[64]));
      b->previous_row = (int *)calloc (b->width, sizeof (int[64]));

      if (!b->data || !b->previous_row)
        {
          goto done;
        }
    }

  while (done_y < jpeg->mcus_y && !sink->failed)
    {
      rows = WZ_MIN (slices_y, jpeg->mcus_y - done_y);
      for (comp = 0; comp < jpeg->scan_count; comp++)
        {
          const wz_scan_comp *s = &jpeg->sc[comp];
          wz_scan_buffer *b = &buffers[comp];
          const unsigned int *q = jpeg->quant[jpeg->frame[s->frame_index].q];
#ifdef WZ96_TRACE
          fprintf (stderr, "BAC_START sliceY=%u comp=%u remaining=%lu\n",
                   done_y, comp, input->remain);
#endif /* ifdef WZ96_TRACE */
          wz_bac_init (&arithmetic, input);

          if (arithmetic.exhausted)
            {
              goto done;
            }

          for (y = 0; y < rows * s->blocks_v; y++)
            {
              for (x = 0; x < b->width; x++)
                {
                  int *current = b->data + 64UL * (y * b->width + x);
                  const int *north = NULL, *west = NULL;

                  if (y)
                    {
                      north = b->data + 64UL * ((y - 1) * b->width + x);
                    }
                  else if (done_y)
                    {
                      north = b->previous_row + 64UL * x;
                    }

                  if (x)
                    {
                      west = b->data + 64UL * (y * b->width + x - 1);
                    }

                  memset (current, 0, sizeof (int[64]));
                  if (!wz_decode_block (&arithmetic, model, comp, current,
                                        north, west, north != NULL,
                                        west != NULL, q)
                      || arithmetic.exhausted)
                    {
#ifdef WZ96_TRACE
                      fprintf (stderr,
                               "scan_fail slice_y=%u component=%u y=%u x=%u "
                               "code=%lu lr=%d prev=%d eof=%d\n",
                               done_y, comp, y, x, arithmetic.code,
                               arithmetic.interval, arithmetic.prev_interval,
                               arithmetic.exhausted);
#endif /* ifdef WZ96_TRACE */
                      goto done;
                    }
                }
            }

          wz_normalize (&arithmetic);

          if (arithmetic.previous == 255 && arithmetic.last == 255)
            {
              (void)wz_bac_byte (&arithmetic);
            }

          if (arithmetic.exhausted)
            {
              goto done;
            }

#ifdef WZ96_TRACE
          fprintf (stderr, "BAC_END sliceY=%u comp=%u remaining=%lu\n", done_y,
                   comp, input->remain);
#endif /* ifdef WZ96_TRACE */
          memcpy (b->previous_row,
                  b->data + 64UL * (rows * s->blocks_v - 1) * b->width,
                  sizeof (int[64]) * (size_t)b->width);
        }

      for (y = 0; y < rows && !sink->failed; y++)
        {
          for (x = 0; x < jpeg->mcus_x && !sink->failed; x++)
            {
              if (jpeg->restart && restart_pos == jpeg->restart)
                {
                  wz_jpeg_align (sink);
                  wz_sink_byte (sink, 255);
                  wz_sink_byte (sink, 0xd0 + (restart_id++ & 7));
                  restart_pos = 0;

                  for (comp = 0; comp < jpeg->scan_count; comp++)
                    {
                      dc_previous[comp] = 0;
                    }
                }

              for (comp = 0; comp < jpeg->scan_count && !sink->failed; comp++)
                {
                  const wz_scan_comp *s = &jpeg->sc[comp];
                  wz_scan_buffer *b = &buffers[comp];

                  for (v = 0; v < s->blocks_v; v++)
                    {
                      for (h = 0; h < s->blocks_h; h++)
                        {
                          by = y * s->blocks_v + v;
                          bx = x * s->blocks_h + h;
                          r = 64UL * (by * b->width + bx);
                          wz_jpeg_block (sink, jpeg, comp, b->data + r,
                                         &dc_previous[comp]);
                        }
                    }
                }

              restart_pos++;
            }
        }

      done_y += rows;
    }

  wz_jpeg_align (sink);
  ok = !sink->failed;

done:
  for (i = 0; i < 4; i++)
    {
      free (buffers[i].data);
      free (buffers[i].previous_row);
    }

  free (model);

  return ok;
}

int
wz96_decode (wz96_read_fn reader, void *src, unsigned long compressed_len,
             wz96_write_fn writer, void *dst, unsigned long uncompressed_len,
             wz96_report *report)
{
  struct wz96_stream input;
  wz_sink output;
  wz_jpeg jpeg;
  wz96_report r;
  unsigned char props[4], header[8], *decoded = NULL, *packed = NULL;
  unsigned long ul, cl;
  size_t extra;
  int has_scan, has_end, ok = 0;

  if (!reader || !writer || !report || compressed_len < 8UL)
    {
      return 0;
    }

  memset (&r, 0, sizeof (r));
  memset (&jpeg, 0, sizeof (jpeg));
  memset (&output, 0, sizeof (output));
  wz_build_zig ();
  output.write = writer;
  output.opaque = dst;
  output.budget = uncompressed_len;
  input.read = reader;
  input.opaque = src;
  input.remain = compressed_len;

  if (!wz96_get (&input, props, 4))
    {
      goto done;
    }

  if (props[0] < 4 || props[1] != 0x10 || props[2] != 1 || (props[3] & 0xe0))
    {
      goto done;
    }

  r.slice_option = props[3] & 31;
  extra = props[0] - 4;

  while (extra)
    {
      unsigned char ignored[64];
      size_t amount = WZ_MIN (extra, sizeof (ignored));
      if (!wz96_get (&input, ignored, amount))
        {
          goto done;
        }

      extra -= amount;
    }

  while (input.remain && !output.failed)
    {
      if (!wz96_get (&input, header, 4))
        {
          goto done;
        }

      ul = wz96_le16 (header);
      cl = wz96_le16 (header + 2);

      if (ul == 65535UL || cl == 65535UL)
        {
          if (ul != 65535UL || cl != 65535UL || !wz96_get (&input, header, 8))
            {
              goto done;
            }

          ul = wz96_le32 (header);
          cl = wz96_le32 (header + 4);
        }

      if (!ul || ul > 16777216UL || cl > 16777216UL
          || (cl && cl > input.remain) || (!cl && ul > input.remain))
        {
          goto done;
        }

      decoded = (unsigned char *)malloc ((size_t)ul);

      if (!decoded)
        {
          goto done;
        }

      if (cl)
        {
          packed = (unsigned char *)malloc ((size_t)cl);

          if (!packed || !wz96_get (&input, packed, (size_t)cl)
              || !wz96_metadata_lzma (decoded, (size_t)ul, packed, (size_t)cl))
            {
              goto done;
            }

          free (packed);
          packed = NULL;
          r.lzma_bundles++;
        }
      else
        {
          if (!wz96_get (&input, decoded, (size_t)ul))
            {
              goto done;
            }

          r.stored_bundles++;
        }

      if (!wz_parse_jpeg (&jpeg, decoded, (size_t)ul, r.bundles == 0,
                          &has_scan, &has_end))
        {
          goto done;
        }

      r.bundles++;
      r.metadata_bytes += ul;
      r.width = jpeg.width;
      r.height = jpeg.height;
      r.components = jpeg.frame_count;
      wz_sink_buffer (&output, decoded, (size_t)ul);
      free (decoded);
      decoded = NULL;

      if (output.failed)
        {
          goto done;
        }

      if (has_end)
        {
          r.reached_eoi = 1;
          ok = (input.remain == 0 && output.produced == uncompressed_len);

          break;
        }

      if (!has_scan)
        {
          goto done;
        }

      r.scans++;

      if (!wz_decode_scan (&input, &output, &jpeg, r.slice_option))
        {
          goto done;
        }
    }

  wz_sink_drain (&output);
  ok = ok && !output.failed;

done:
  free (packed);
  free (decoded);
  *report = r;

  return ok;
}
