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

/* WinZip 0x9903 occurs in the CENTRAL directory, NOT necessarily in
 * local headers!  The checksum is IEEE CRC-32 of a 28-byte, fixed-layout
 * record.  No filename, relative offset or extended timestamp is included.
 * Keep this calculation local to the decoder (no new link dependencies). */
static ulg
refptr_uuid_crc (ush method, ulg dos_datetime, ulg file_crc,
                 const uch uuid[16])
{
  uch buf[28];
  unsigned j;

  buf[0] = (uch)(method & 255U);
  buf[1] = (uch)((method >> 8) & 255U);
  buf[2] = buf[3] = 0;
  for (j = 0; j < 4; ++j)
    {
      buf[4 + j] = (uch)((dos_datetime >> (j * 8)) & 255UL);
      buf[8 + j] = (uch)((file_crc >> (j * 8)) & 255UL);
    }
  memcpy (buf + 12, uuid, 16);
  return crc32 (CRCVAL_INITIAL, buf, (extent)sizeof (buf)) & 0xffffffffUL;
}

/* Check all bounded extra-field records.  A missing WinZip field is distinct
 * from a malformed one; unrelated well-formed fields do not matter.  Never
 * read past the central-directory extra-field buffer. */
static void
refptr_parse_uuid (refptr_candidate *c, const uch *extra, unsigned len)
{
  unsigned off = 0;
  int seen = FALSE;

  c->uuid_status = 0;
  c->uuid_crc_stored = c->uuid_crc_expected = 0;
  memset (c->uuid, 0, sizeof (c->uuid));
  /* Difference test avoids 16-bit unsigned wrap at the ZIP limit 65535. */
  while (off <= len && len - off >= 4U)
    {
      unsigned id = (unsigned)extra[off]
                    | ((unsigned)extra[off + 1] << 8);
      unsigned size = (unsigned)extra[off + 2]
                      | ((unsigned)extra[off + 3] << 8);
      off += 4;
      if (id == 0x9903U)
        {
          if (seen)
            {
              c->uuid_status = 4;
              return;
            }
          seen = TRUE;
          if (size != 20U || size > len - off)
            {
              c->uuid_status = 3;
              return;
            }
          c->uuid_crc_stored = (ulg)extra[off]
              | ((ulg)extra[off + 1] << 8)
              | ((ulg)extra[off + 2] << 16)
              | ((ulg)extra[off + 3] << 24);
          memcpy (c->uuid, extra + off + 4, 16);
          c->uuid_crc_expected = refptr_uuid_crc (
              c->method, c->dos_datetime, c->crc, c->uuid);
          c->uuid_status = c->uuid_crc_stored == c->uuid_crc_expected ? 1 : 2;
        }
      if (size > len - off)
        {
          /* An unrelated malformed record is the core parser's concern. */
          return;
        }
      off += size;
    }
}

/* The reference is looked up by its central-directory local-header offset,
 * so callers are independent of filename filters and extraction ordering. */
static const refptr_candidate *
refptr_find_entry (__G__ offset) __GDEF zoff_t offset;
{
  size_t j;
  for (j = 0; j < G.refptr_count; ++j)
    if (G.refptr_index[j].offset == offset
        && G.refptr_index[j].method == REFPTR)
      return &G.refptr_index[j];
  return (const refptr_candidate *)NULL;
}

static int
refptr_uuid_match (const refptr_candidate *a, const refptr_candidate *b)
{
  return a != NULL && a->uuid_status == 1 && b->uuid_status == 1
         && memcmp (a->uuid, b->uuid, 16) == 0;
}

/* Emit diagnostics only for a reference which has passed the SHA-1/CRC/size
 * verification.  This keeps metadata errors nonfatal without concealing a
 * content-integrity error.  0x401 directs diagnostics to the normal error
 * stream even when output is otherwise quiet or redirected to stdout. */
static int
refptr_warn_uuid (__G__ reference, source) __GDEF
    const refptr_candidate *reference;
    const refptr_candidate *source;
{
  int warn = FALSE;
  const refptr_candidate *m[2];
  unsigned j;
  m[0] = reference;
  m[1] = source;
  for (j = 0; j < 2; ++j)
    {
      const char *part = j ? "physical source" : "reference";
      int status = m[j] == NULL ? 0 : m[j]->uuid_status;
      if (status == 1) continue;
      warn = TRUE;
      if (status == 0)
        Info (slide, 0x401, ((char *)slide,
              "warning: RefPtr %s missing central 0x9903: %s\n",
              part, FnFilter1 (G.filename)));
      else if (status == 2)
        Info (slide, 0x401, ((char *)slide,
              "warning: RefPtr %s 0x9903 CRC mismatch: %s"
              " (stored %08lx, expected %08lx)\n",
              part, FnFilter1 (G.filename),
              (unsigned long)m[j]->uuid_crc_stored,
              (unsigned long)m[j]->uuid_crc_expected));
      else
        Info (slide, 0x401, ((char *)slide,
              "warning: RefPtr %s %s 0x9903: %s\n",
              part, status == 4 ? "duplicate" : "malformed",
              FnFilter1 (G.filename)));
    }
  if (reference != NULL && source != NULL
      && reference->uuid_status >= 1 && reference->uuid_status <= 2
      && source->uuid_status >= 1 && source->uuid_status <= 2
      && memcmp (reference->uuid, source->uuid, 16) != 0)
    {
      warn = TRUE;
      Info (slide, 0x401, ((char *)slide,
            "warning: RefPtr source/reference UUID mismatch: %s\n",
            FnFilter1 (G.filename)));
    }
  if (warn)
    Info (slide, 0x401, ((char *)slide,
          "warning: RefPtr metadata inconsistent; decoded data verified: %s\n",
          FnFilter1 (G.filename)));
  return warn;
}

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
#  ifdef USE_OLDUNZIP
    case SHRUNK:
    case REDUCED1:
    case REDUCED2:
    case REDUCED3:
    case REDUCED4:
      return TRUE;
#  endif
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

# ifdef USE_WZMP3
    case WZMP3ED:
      return TRUE;
# endif /* ifdef USE_WZMP3 */

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

/* Recognized ZIP methods are indexed even when their decoder is absent,
 * solely to give a conditional diagnostic for a size/CRC candidate. Unknown
 * methods must not be described as having a known missing codec. */
static int
refptr_method_recognized (unsigned method)
{
  switch (method)
    {
    case STORED: case DEFLATED: case ENHDEFLATED: case REFPTR:
    case SHRUNK: case REDUCED1: case REDUCED2:
    case REDUCED3: case REDUCED4:
    case IMPLODED: case DCLIMPLODED: case BZIPPED:
    case LZMAED: case XZED: case ZSTD_OLD: case ZSTDED:
    case PPMDED: case WZJPEGED: case WZMP3ED: case WAVPACKED:
      return TRUE;
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
          || !refptr_method_recognized (G.crec.compression_method))
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
      c.dos_datetime = G.crec.last_mod_dos_datetime;
      c.method = G.crec.compression_method;
      c.flags = G.crec.general_purpose_bit_flag;
      c.supported = refptr_method_supported (c.method);
      refptr_parse_uuid (&c, G.extra_field, G.crec.extra_field_length);

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
#  ifdef USE_OLDUNZIP
    case SHRUNK:
      return unshrink (__G);
    case REDUCED1:
    case REDUCED2:
    case REDUCED3:
    case REDUCED4:
      return unreduce (__G);
#  endif
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

# ifdef USE_WZMP3
    case WZMP3ED:
      return uz_wzmp3_decompress (__G);
# endif /* ifdef USE_WZMP3 */

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
  int pass, passes;
  const refptr_candidate *ref_meta;
  iz_sha1 sh;
  int r = PK_ERR, found = FALSE;
  ush missing_codec = 0;
  int saved_test = uO.tflag;
  int saved_fwkcs = G.fwkcs_active;
  ulg source_crc;
  zusz_t source_bytes;

  G.refptr_missing_method = 0;
  ref_meta = refptr_find_entry (__G__ G.pInfo->offset);
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

  /* Prefer a checksum-valid matching UUID when available.  In a damaged
   * archive, fall back to any digest-verified physical source so contents
   * remain recoverable with a warning instead of becoming unextractable. */
  passes = ref_meta != NULL && ref_meta->uuid_status == 1 ? 2 : 1;
  for (pass = 0; pass < passes && !found; ++pass)
  for (i = 0; i < G.refptr_count; ++i)
    {
      const refptr_candidate *candidate = &G.refptr_index[i];

      if (candidate->method == REFPTR
          || candidate->uncompressed != reference.ucsize
          || candidate->crc != reference.crc32)
        {
          continue;
        }
      if (passes == 2
          && (refptr_uuid_match (ref_meta, candidate) != (pass == 0)))
        continue;
      if (!candidate->supported)
        {
          if (!missing_codec) missing_codec = candidate->method;
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
      G.refptr_missing_method = missing_codec;
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

  /* Only a successfully decoded reference may return our advisory PK_WARN.
   * A codec warning from the source decoder is not a validated reference. */
  if (r == PK_WARN)
    r = PK_ERR;
  if (r == PK_COOL
      && (source_bytes != reference.ucsize || source_crc != reference.crc32
          || memcmp (expected, actual, sizeof (expected)) != 0))
    {
      r = PK_ERR;
    }
  if (r == PK_COOL
      && refptr_warn_uuid (__G__ ref_meta, &G.refptr_index[i]))
    r = PK_WARN;

restore:
  /* The caller's overlap accounting must cover the 20-byte RefPtr
   * payload, not the source compressed bytes read during either pass. */
  undefer_input (__G);

  if (seek_zipf (__G__ end_of_ref) != PK_COOL && r <= PK_WARN)
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
