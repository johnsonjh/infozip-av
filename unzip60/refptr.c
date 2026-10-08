/*
 * WinZip ZIP method 92 (RefPtr)
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifier: MIT-0
 */

/*
 * The 20 payload bytes are the SHA-1 of the uncompressed source member.
 * This module only reads archives; it never manufactures filesystem links.
 * Source candidates must be unencrypted, non-reference members of the same
 * archive.  A probe decodes each candidate without producing output before
 * a second pass writes the reference member.  The digest is checked on both
 * passes; size and CRC are checked independently as well.
 */

#ifdef USE_REFPTR
# include <stdlib.h>
# include <string.h>

/* Check only methods supported in this build.  No recursive RefPtr targets. */
static int
refptr_method_supported (unsigned method)
{
  switch (method)
    {
    case STORED:
    case DEFLATED:
      return TRUE;

# ifndef SFX
    case DCLIMPLODED:
    case IMPLODED:
      return TRUE;
# endif /* ifndef SFX */

# ifdef USE_DEFLATE64
    case ENHDEFLATED:
      return TRUE;
# endif /* ifdef USE_DEFLATE64 */

# ifdef USE_BZIP2
    case BZIPPED:
      return TRUE;
# endif /* ifdef USE_BZIP2 */

# ifdef USE_LZMA
    case LZMAED:
      return TRUE;
# endif /* ifdef USE_LZMA */

# ifdef USE_XZ
    case XZED:
      return TRUE;
# endif /* ifdef USE_XZ */

# ifdef USE_ZSTD
    case ZSTD_OLD:
    case ZSTDED:
      return TRUE;
# endif /* ifdef USE_ZSTD */

# ifdef USE_WAVP
    case WAVPACKED:
      return TRUE;
# endif /* ifdef USE_WAVP */

# ifdef USE_WZJPEG
    case WZJPEGED:
      return TRUE;
# endif /* ifdef USE_WZJPEG */

# ifdef USE_PPMD
    case PPMDED:
      return TRUE;
# endif /* ifdef USE_PPMD */

    default:
      return FALSE;
    }
}

static int
refptr_build_index (__G) __GDEF
{
  cdir_file_hdr saved_crec = G.crec;
  local_file_hdr saved_lrec = G.lrec;
  min_info *saved_info = G.pInfo;
  uch *saved_extra = G.extra_field;
  zoff_t saved_csize = G.csize;
  zucn_t k;
  int r = PK_COOL, found = FALSE;
  zoff_t cdpos = G.ecrec.offset_start_central_directory;

  G.refptr_count = G.refptr_capacity = 0;
  G.refptr_index = (refptr_candidate *)NULL;
  G.extra_field = (uch *)NULL;
  G.pInfo = G.info;
  r = seek_zipf (__G__ cdpos);

  if (r != PK_COOL)
    {
      goto done;
    }

  for (k = 0; k < G.ecrec.total_entries_central_dir; ++k)
    {
      refptr_candidate c;
      refptr_candidate *tmp;
      size_t newcap;

      if (readbuf (__G__ G.sig, 4) != 4
          || memcmp (G.sig, central_hdr_sig, 4) != 0)
        {
          r = PK_ERR;

          break;
        }

      /* getZip64Data also inspects lrec, so clear stale sentinels. */
      memset (&G.lrec, 0, sizeof (G.lrec));
      G.pInfo->zip64 = FALSE;

      if (process_cdir_file_hdr (__G) != PK_COOL
          || do_string (__G__ G.crec.filename_length, SKIP) != PK_COOL)
        {
          r = PK_ERR;

          break;
        }

      if (G.extra_field != (uch *)NULL)
        {
          free (G.extra_field);
          G.extra_field = (uch *)NULL;
        }

      if (do_string (__G__ G.crec.extra_field_length, EXTRA_FIELD) != PK_COOL
          || do_string (__G__ G.crec.file_comment_length, SKIP) != PK_COOL)
        {
          r = PK_ERR;

          break;
        }

      if (G.crec.compression_method == REFPTR)
        {
          found = TRUE;
        }

      if ((G.crec.general_purpose_bit_flag & 1) != 0
          || G.crec.disk_number_start != 0
          || !refptr_method_supported (G.crec.compression_method))
        {
          continue;
        }

      /* Reject bogus offset/size values rather than allowing an
       * out-of-range seek or signed decoder-size conversion. */
      if ((zoff_t)G.crec.relative_offset_local_header < 0
          || G.crec.csize > (zusz_t)G.ziplen
          || G.crec.relative_offset_local_header > (zusz_t)G.ziplen)
        {
          continue;
        }

      c.offset = (zoff_t)G.crec.relative_offset_local_header;
      c.compressed = G.crec.csize;
      c.uncompressed = G.crec.ucsize;
      c.crc = G.crec.crc32;
      c.method = G.crec.compression_method;
      c.flags = G.crec.general_purpose_bit_flag;

      if (G.refptr_count == G.refptr_capacity)
        {
          if (G.refptr_capacity > ((size_t)-1) / 2U
              || (newcap = G.refptr_capacity ? G.refptr_capacity * 2U : 16U)
                     > ((size_t)-1) / sizeof (refptr_candidate))
            {
              r = PK_MEM;

              break;
            }

          tmp = (refptr_candidate *)realloc (
              G.refptr_index, newcap * sizeof (refptr_candidate));
          if (tmp == NULL)
            {
              r = PK_MEM;

              break;
            }

          G.refptr_index = tmp;
          G.refptr_capacity = newcap;
        }

      G.refptr_index[G.refptr_count++] = c;
    }

done:
  if (G.extra_field != (uch *)NULL)
    {
      free (G.extra_field);
    }

  G.extra_field = saved_extra;
  G.crec = saved_crec;
  G.lrec = saved_lrec;
  G.pInfo = saved_info;
  G.csize = saved_csize;

  /* Reset from the beginning, not from a cached slice of the CDR. */
  if (seek_zipf (__G__ cdpos) != PK_COOL)
    {
      r = PK_BADERR;
    }

  if (!found || r != PK_COOL)
    {
      free (G.refptr_index);
      G.refptr_index = (refptr_candidate *)NULL;
      G.refptr_count = G.refptr_capacity = 0;
    }

  /* Other files must retain ordinary UnZip behavior even if a preliminary
   * scan of a nonconforming directory did not succeed. */
  return r == PK_BADERR ? r : PK_COOL;
}

/* Position the normal decoder on a non-reference candidate's compressed
 * bytes and validate its local header against the indexed central entry. */
static int refptr_select_source (__G__ c) __GDEF const refptr_candidate *c;
{
  cdir_file_hdr save_crec = G.crec;
  local_file_hdr save_lrec = G.lrec;
  min_info *save_pinfo = G.pInfo;
  min_info srcinfo;
  uch *saved_extra = G.extra_field;
  int r;

  memset (&srcinfo, 0, sizeof (srcinfo));
  srcinfo.crc = c->crc;
  srcinfo.compr_size = c->compressed;
  srcinfo.uncompr_size = c->uncompressed;
  srcinfo.compression_method = c->method;
  G.pInfo = &srcinfo;
  G.extra_field = (uch *)NULL;
  r = seek_zipf (__G__ c->offset);
  if (r != PK_COOL || readbuf (__G__ G.sig, 4) != 4
      || memcmp (G.sig, local_hdr_sig, 4) != 0
      || process_local_file_hdr (__G) != PK_COOL)
    {
      r = PK_ERR;

      goto out;
    }

  if (G.lrec.compression_method != c->method
      || (G.lrec.general_purpose_bit_flag & 1)
      || G.lrec.general_purpose_bit_flag != c->flags
      || do_string (__G__ G.lrec.filename_length, SKIP) != PK_COOL
      || do_string (__G__ G.lrec.extra_field_length, EXTRA_FIELD) != PK_COOL)
    {
      r = PK_ERR;

      goto out;
    }

  if (!(c->flags & 8)
      && (G.lrec.crc32 != c->crc || G.lrec.csize != c->compressed
          || G.lrec.ucsize != c->uncompressed))
    {
      r = PK_ERR;

      goto out;
    }

  /* Data descriptor sources already inherited the indexed sizes. */
  G.lrec.crc32 = c->crc;
  G.lrec.csize = c->compressed;
  G.lrec.ucsize = c->uncompressed;
  G.csize = (zoff_t)c->compressed;
  if (G.csize < 0 || (zusz_t)G.csize != c->compressed)
    {
      r = PK_ERR;

      goto out;
    }

  defer_leftover_input (__G);
  r = PK_COOL;

out:
  if (G.extra_field != (uch *)NULL)
    {
      free (G.extra_field);
    }

  G.extra_field = saved_extra;
  G.crec = save_crec;
  G.pInfo = save_pinfo;

  if (r != PK_COOL)
    {
      G.lrec = save_lrec;
    }

  return r;
}

/* Dispatch through the existing payload decoders.  Both passes enter here
 * with the identical member state and byte bounds. */
static int
refptr_decode_source (__G) __GDEF
{
  int c, r;
  unsigned n = 0;

  switch (G.lrec.compression_method)
    {
    case STORED:
      while ((c = NEXTBYTE) != EOF)
        {
          slide[n++] = (uch)c;

          if (n == WSIZE)
            {
              r = flush (__G__ slide, n, 0);
              n = 0;

              if (r != PK_COOL)
                {
                  return r;
                }
            }
        }
      if (n)
        {
          return flush (__G__ slide, n, 0);
        }

      return PK_COOL;

    case DEFLATED:
# ifdef USE_DEFLATE64
    case ENHDEFLATED:
# endif /* ifdef USE_DEFLATE64 */

# ifdef USE_ZLIB
      r = UZinflate (__G__ (G.lrec.compression_method == ENHDEFLATED));
# else  /* ifdef USE_ZLIB */
      r = inflate (__G__ (G.lrec.compression_method == ENHDEFLATED));
# endif /* ifdef USE_ZLIB */
      return r == 0 ? PK_COOL : (r == 3 ? PK_MEM3 : PK_ERR);

# ifndef SFX
    case IMPLODED:
      r = explode (__G);
      return r == 0 ? PK_COOL : (r == 3 ? PK_MEM3 : PK_ERR);

    case DCLIMPLODED:
      r = dcl_explode (__G);
      return r == 0 ? PK_COOL : (r == 3 ? PK_MEM3 : PK_ERR);
# endif /* ifndef SFX */

# ifdef USE_BZIP2
    case BZIPPED:
      r = UZbunzip2 (__G);
      return r == 0 ? PK_COOL : (r == 3 ? PK_MEM3 : PK_ERR);
# endif /* ifdef USE_BZIP2 */

# ifdef USE_LZMA
    case LZMAED:
      return uz_lzma_decompress (__G);
# endif /* ifdef USE_LZMA */

# ifdef USE_XZ
    case XZED:
      return uz_xz_decompress (__G);
# endif /* ifdef USE_XZ */

# ifdef USE_ZSTD
    case ZSTD_OLD:
    case ZSTDED:
      return uz_zstd_decompress (__G);
# endif /* ifdef USE_ZSTD */

# ifdef USE_PPMD
    case PPMDED:
      return uz_ppmd_decompress (__G);
# endif /* ifdef USE_PPMD */

# ifdef USE_WAVP
    case WAVPACKED:
      return uz_wavpack_decompress (__G);
# endif /* ifdef USE_WAVP */

# ifdef USE_WZJPEG
    case WZJPEGED:
      return uz_wzjpeg_decompress (__G);
# endif /* ifdef USE_WZJPEG */

    default:
      return PK_ERR;
    }
}

/* Called from the normal method-92 extraction dispatch after output setup.
 * All source selections are independent of filename filters and order. */
static int
refptr_extract (__G) __GDEF
{
  local_file_hdr reference = G.lrec;
  uch expected[20], actual[20];
  zoff_t end_of_ref;
  size_t i;
  iz_sha1 sh;
  int r = PK_ERR, found = FALSE;
  int saved_test = uO.tflag;
  int saved_fwkcs = G.fwkcs_active;
  ulg source_crc;
  zusz_t source_bytes;

  if ((reference.general_purpose_bit_flag & 1) || G.pInfo->encrypted
      || reference.csize != 20 || G.csize < 0 || G.incnt < 0
      || (zusz_t)G.csize + (zusz_t)G.incnt != 20)
    {
      return PK_ERR;
    }

  for (i = 0; i < sizeof (expected); ++i)
    {
      int c = NEXTBYTE;

      if (c == EOF)
        {
          return PK_ERR;
        }

      expected[i] = (uch)c;
    }

  if (G.csize + (zoff_t)G.incnt != 0)
    {
      return PK_ERR;
    }

  end_of_ref = G.cur_zipfile_bufstart + (G.inptr - G.inbuf) - G.extra_bytes;

  if (end_of_ref < 0)
    {
      return PK_ERR;
    }

  /* During the probe no output is written and no FWKCS/PKAV state is
   * modified.  Only ZIP CRC and SHA-1 are accumulated. */
  uO.tflag = TRUE;
  G.fwkcs_active = FALSE;
  G.refptr_probe = TRUE;

  for (i = 0; i < G.refptr_count; ++i)
    {
      const refptr_candidate *candidate = &G.refptr_index[i];

      if (candidate->uncompressed != reference.ucsize
          || candidate->crc != reference.crc32)
        {
          continue;
        }

      undefer_input (__G);

      if (refptr_select_source (__G__ candidate) != PK_COOL)
        {
          continue;
        }

      G.bits_left = 0;
      G.bitbuf = 0L;
      G.zipeof = 0;
      G.newfile = TRUE;
      G.crc32val = CRCVAL_INITIAL;
      G.refptr_bytes = 0;
      G.refptr_expected = reference.ucsize;
      iz_sha1_init (&sh);
      G.refptr_sha = &sh;
      r = refptr_decode_source (__G);
      G.refptr_sha = (iz_sha1 *)NULL;
      source_crc = G.crc32val;
      source_bytes = G.refptr_bytes;
      iz_sha1_finish (&sh, actual);

      if (r == PK_COOL && source_bytes == reference.ucsize
          && source_crc == candidate->crc
          && memcmp (expected, actual, sizeof (expected)) == 0)
        {
          found = TRUE;

          break;
        }
    }

  G.refptr_probe = FALSE;
  G.refptr_sha = (iz_sha1 *)NULL;
  uO.tflag = saved_test;
  G.fwkcs_active = saved_fwkcs;

  if (!found)
    {
      r = PK_ERR;

      goto restore;
    }

  undefer_input (__G);
  r = refptr_select_source (__G__ & G.refptr_index[i]);

  if (r != PK_COOL)
    {
      goto restore;
    }

  G.bits_left = 0;
  G.bitbuf = 0L;
  G.zipeof = 0;
  G.newfile = TRUE;
  G.crc32val = CRCVAL_INITIAL;

  if (G.fwkcs_active)
    {
      fwkcs_md5_init (__G);
    }

  G.refptr_bytes = 0;
  G.refptr_expected = reference.ucsize;
  iz_sha1_init (&sh);
  G.refptr_sha = &sh;
  r = refptr_decode_source (__G);
  G.refptr_sha = (iz_sha1 *)NULL;
  source_crc = G.crc32val;
  source_bytes = G.refptr_bytes;
  iz_sha1_finish (&sh, actual);

  if (r == PK_COOL
      && (source_bytes != reference.ucsize || source_crc != reference.crc32
          || memcmp (expected, actual, sizeof (expected)) != 0))
    {
      r = PK_ERR;
    }

restore:
  /* The caller's overlap accounting must cover the 20-byte RefPtr
   * payload, not the source compressed bytes read during either pass. */
  undefer_input (__G);

  if (seek_zipf (__G__ end_of_ref) != PK_COOL && r == PK_COOL)
    {
      r = PK_ERR;
    }

  G.lrec = reference;
  G.csize = 0;
  G.refptr_sha = (iz_sha1 *)NULL;
  G.refptr_probe = FALSE;
  G.fwkcs_active = saved_fwkcs;
  uO.tflag = saved_test;

  return r;
}
#endif /* USE_REFPTR */
