/* SPDX-License-Identifier: MIT-0 */
/* Archive-entry identity graph for safe Xtro ZIP copy/delete operations.
 * This only validates CENTRAL occurrence associations. It does NOT verify
 * metadata contents or authorize native restoration or rewriting values.
 * Included in zip.c after zip.h; no new build dependency on legacy targets.
 */
#ifndef XTRO_ZIP_PAIR_GRAPH_H
#define XTRO_ZIP_PAIR_GRAPH_H

typedef struct xtro_pair_node {
  unsigned char id[16];
  struct zlist far *entry;
  unsigned char role;            /* 1=owner inline, 2=owner companion, 3=sidecar */
} xtro_pair_node;

static int xtro_pcmp(const void *ap, const void *bp)
{
  const xtro_pair_node *a = (const xtro_pair_node *)ap;
  const xtro_pair_node *b = (const xtro_pair_node *)bp;
  return memcmp(a->id, b->id, 16);
}

static int xtro_digit(unsigned char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static unsigned long xtro_le32(const unsigned char *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
         ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

/* Schema-compatible CRC32 for inline XTMD without a crypto/build dependency. */
static unsigned long xtro_crc_inline(const unsigned char *p, unsigned n)
{
  unsigned long c=0xffffffffUL;
  unsigned int i, j;
  for (i=0;i<n;i++) {
    c ^= p[i];
    for (j=0;j<8U;j++)
      c=(c&1UL)?(c>>1)^0xedb88320UL:(c>>1);
  }
  return (c^0xffffffffUL)&0xffffffffUL;
}

/* Return 0 if absent, 1 if valid one field, -1 for invalid or duplicate.
   Colliding third-party IDs without XTRO magic remain opaque. */
static int xtro_central_owner(struct zlist far *z, unsigned char id[16],
                              unsigned char *mode)
{
  const unsigned char *p = (const unsigned char *)z->cextra;
  unsigned int at = 0, size = z->cext;
  int seen = 0;
  if (size && !p) return -1;
  while (at < size) {
    unsigned int tag, n;
    unsigned int i, nz = 0;
    if (size - at < 4U) return -1;
    tag = (unsigned int)p[at] | ((unsigned int)p[at+1] << 8);
    n = (unsigned int)p[at+2] | ((unsigned int)p[at+3] << 8);
    if (n > size - at - 4U) return -1;
    if (tag == 0x5854U && n >= 4U && !memcmp(p + at + 4U, "XTRO", 4U)) {
      if (seen++ || n < 40U || p[at+8] != 1 || p[at+9] != 0 ||
          (p[at+10] != 1 && p[at+10] != 2) ||
          (p[at+11] & ~1U)) return -1;
      *mode = p[at+10];
      if (*mode == 1U) {
        const unsigned char *m=p+at+44U;
        if (p[at+11] || n < 76U ||
            xtro_le32(p+at+32U) != n-40U ||
            xtro_le32(p+at+36U) != 0UL ||
            memcmp(m,"XTMD\001\000\000\000",8U) ||
            memcmp(m+8U,p+at+12U,16U) ||
            xtro_le32(m+24U) != xtro_le32(p+at+28U) ||
            xtro_le32(m+28U) != n-76U ||
            xtro_le32(m+32U) != 0UL ||
            xtro_crc_inline(m,n-40U)!=xtro_le32(p+at+40U))
          return -1;
      } else if (n != (p[at+11] ? 40U : 72U)) return -1;
      if (*mode == 2U && p[at+11]) {
        unsigned int k;
        for (k=24U;k<40U;k++)
          if (p[at+4U+k]!=0U) return -1;
      }
      memcpy(id,p+at+12U,16U);
      for (i=0;i<16;i++) nz |= id[i];
      if (!nz) return -1;
    }
    at += 4U+n;
  }
  return seen;
}

/* An exact version-1 sidecar name supplies an identity but not proof of
 * authenticity. Other files under the reserved prefix reject when any
 * Xtro metadata is present; ordinary ZIP archives retain old behavior. */
static int xtro_sidecar_id(const char *name, unsigned char id[16])
{
  unsigned int i;
  if (!name || strlen(name) != 51U ||
      memcmp(name,"__XTRO_ZIP__/x/",15U) ||
      memcmp(name+47,".xtm",4U)) return 0;
  for (i=0;i<16;i++) {
    int a=xtro_digit((unsigned char)name[15U+2U*i]);
    int b=xtro_digit((unsigned char)name[16U+2U*i]);
    if (a < 0 || b < 0) return 0;
    id[i]=(unsigned char)((a<<4)|b);
  }
  return 1;
}

/* No cryptographic authentication is implied by these checks. This only
 * rejects accidental plaintext companion transport and forbidden FWKCS
 * disclosure before a ZIP rewrite. */
static int xtro_field_flags(const struct zlist far *z)
{
  const unsigned char *p=(const unsigned char *)z->cextra;
  unsigned int at=0;
  while (p && at <= z->cext && z->cext-at >= 4U) {
    unsigned int tag=(unsigned int)p[at]|((unsigned int)p[at+1U]<<8);
    unsigned int n=(unsigned int)p[at+2U]|((unsigned int)p[at+3U]<<8);
    if (n>z->cext-at-4U) return -1;
    if (tag==0x5854U && n>=40U && !memcmp(p+at+4U,"XTRO",4U))
      return p[at+11U];
    at+=4U+n;
  }
  return -1;
}
static int xtro_has_fwkcs(const struct zlist far *z)
{
  const unsigned char *p=(const unsigned char *)z->cextra;
  unsigned int at=0;
  while (p && at <= z->cext && z->cext-at >= 4U) {
    unsigned int tag=(unsigned int)p[at]|((unsigned int)p[at+1U]<<8);
    unsigned int n=(unsigned int)p[at+2U]|((unsigned int)p[at+3U]<<8);
    if (n>z->cext-at-4U) return 1;
    if (tag==0x4b46U) return 1;
    at+=4U+n;
  }
  return 0;
}

/* Validate the AES transport class as well as the general-purpose
 * encrypted bit. ZipCrypto and AES both set bit 0, but require different
 * decoding; silently pairing them would be invalid. AES compression method
 * is 99, and the original compression method lives in extra ID 0x9901.
 * This is central-header preflight only, not authentication. */
static int xtro_aes_extra(const struct zlist far *z,
                          unsigned char desc[7])
{
  const unsigned char *p=(const unsigned char *)z->cextra;
  unsigned at=0, seen=0;
  if (z->cext && !p) return -1;
  while (at<z->cext) {
    unsigned tag,n,version;
    if (z->cext-at<4U) return -1;
    tag=(unsigned)p[at]|((unsigned)p[at+1U]<<8);
    n=(unsigned)p[at+2U]|((unsigned)p[at+3U]<<8);
    if (n>z->cext-at-4U) return -1;
    if (tag==0x9901U) {
      if (seen++ || n<7U ||
          p[at+6U]!='A' || p[at+7U]!='E') return -1;
      version=(unsigned)p[at+4U]|((unsigned)p[at+5U]<<8);
      if ((version!=1U && version!=2U && version!=3U) ||
          n!=(version==3U?9U:7U) ||
          p[at+8U]<1U || p[at+8U]>3U) return -1;
      /* Five bytes of version, vendor and AES strength plus two AE-3
       * iteration bytes, if present; compression can legitimately differ
       * between the owner and metadata companion. */
      memcpy(desc,p+at+4U,5U);
      desc[5]=(unsigned char)(version==3U?p[at+11U]:0U);
      desc[6]=(unsigned char)(version==3U?p[at+12U]:0U);
    }
    at+=n+4U;
  }
  return (int)seen;
}

static int xtro_pair_crypto_valid(const struct zlist far *owner,
                                  const struct zlist far *side,
                                  int encrypted_dir_companion)
{
  unsigned char a[7],b[7];
  int oa=xtro_aes_extra(owner,a), sa=xtro_aes_extra(side,b);
  if (oa<0 || sa<0) return 0;
  if (!encrypted_dir_companion &&
      (owner->how==99U)!=(side->how==99U)) return 0;
  if ((owner->how==99U)!=(oa!=0) || (side->how==99U)!=(sa!=0))
    return 0;
  if (encrypted_dir_companion) {
    if (owner->how!=0U || oa || !(side->flg&1U)) return 0;
  } else if (oa && memcmp(a,b,7U)) return 0;
  /* Metadata sidecar is always STORE or Deflate internally. */
  if (side->how==99U) {
    const unsigned char *p=(const unsigned char *)side->cextra;
    unsigned at=0;
    while (at<side->cext) {
      unsigned tag=(unsigned)p[at]|((unsigned)p[at+1U]<<8);
      unsigned n=(unsigned)p[at+2U]|((unsigned)p[at+3U]<<8);
      if (tag==0x9901U) {
        unsigned method=(unsigned)p[at+9U]|((unsigned)p[at+10U]<<8);
        if (method!=0U && method!=8U) return 0;
        break;
      }
      at+=n+4U;
    }
  } else if (side->how!=0U && side->how!=8U) return 0;
  return 1;
}

/* Validate the entire archive identity graph and, for a selected copy or
 * deletion, include the companion whenever its owner is selected. Refuse
 * a sidecar-only selection. Called BEFORE marked entry sizes are counted.
 * action: 0 = validate only, 1 = selected delete, 2 = selected copy,
 *         3 = validate final marks after date filtering (no mark changes),
 *         4 = plan replacement by marking obsolete sidecars as 4.
 * 0 success, 1 malformed/ambiguous graph, 2 no memory, 3 orphaning request.
 * No changes to existing archive bytes on any failure. */
static int xtro_prepare_pairs(struct zlist far *head, int operation)
{
  struct zlist far *z;
  size_t cap=0, used=0, i, j;
  int have=0, bad=0;
  xtro_pair_node *nodes;
  unsigned char tmp[16], mode;
  for (z=head;z;z=z->nxt) {
    int rc;
    if (cap==(size_t)-1) return 2;
    cap++;
    rc=xtro_central_owner(z,tmp,&mode);
    if (rc<0) return 1;
    if (rc==1) have=1;
    if (z->iname && xtro_sidecar_id(z->iname,tmp)) have=1;
  }
  if (!have) return 0;
  if (!cap || cap > (size_t)-1/sizeof(*nodes)) return 2;
  nodes=(xtro_pair_node *)malloc(cap*sizeof(*nodes));
  if (!nodes) return 2;
  for (z=head;z;z=z->nxt) {
    int rc=xtro_central_owner(z,tmp,&mode);
    if (rc<0) {bad=1;break;}
    if (rc==1) {
      /* An owner cannot itself be inside the reserved namespace. */
      if (!z->iname || !strncmp(z->iname,"__XTRO_ZIP__/",13U))
        {bad=1;break;}
      memcpy(nodes[used].id,tmp,16U);
      nodes[used].entry=z;nodes[used].role=mode;used++;
    } else if (z->iname && !strncmp(z->iname,"__XTRO_ZIP__/",13U)) {
      if (!xtro_sidecar_id(z->iname,tmp)) {bad=1;break;}
      memcpy(nodes[used].id,tmp,16U);
      nodes[used].entry=z;nodes[used].role=3;used++;
    }
  }
  if (!bad) {
    qsort(nodes,used,sizeof(*nodes),xtro_pcmp);
    for (i=0;i<used;) {
      struct zlist far *owner=NULL,*side=NULL;
      unsigned char role=0;
      for (j=i;j<used && !memcmp(nodes[i].id,nodes[j].id,16U);j++) {
        if (nodes[j].role==3) {
          if (side) bad=1;
          side=nodes[j].entry;
        } else {
          if (owner) bad=1;
          owner=nodes[j].entry;role=nodes[j].role;
        }
      }
      if (!owner || (role==2 && !side) || (role==1 && side)) bad=1;
      if (!bad && role==1 && (owner->flg & 1U)) bad=1;
      if (!bad && role==2 && side) {
        int owner_crypto=(owner->flg & 1U)!=0U;
        int side_crypto=(side->flg & 1U)!=0U;
        int metadata_encrypted=xtro_field_flags(owner);
        size_t name_len=owner->iname?strlen(owner->iname):0U;
        int encrypted_dir_companion=0;
        if (name_len && owner->iname[name_len-1U]=='/' &&
            !owner_crypto && side_crypto && metadata_encrypted==1)
          encrypted_dir_companion=1;
        if ((name_len && owner->iname[name_len-1U]=='/' &&
             (owner_crypto || owner->len!=0)) ||
            (owner_crypto!=side_crypto && !encrypted_dir_companion) ||
            !xtro_pair_crypto_valid(owner,side,encrypted_dir_companion) ||
            metadata_encrypted != side_crypto ||
            (side_crypto && xtro_has_fwkcs(side))) bad=1;
      }
      if (!bad && operation==4 && side && side->mark) {
        /* A companion must never be supplied as an independent replacement.
         * It is exclusively owned by the old entry until a new metadata set
         * is emitted. */
        bad=3;
      }
      if (bad) break;
      /* Selection changes are safe only after all groups validate; the
       * second pass below modifies marks once preflight succeeds. */
      if (operation && side &&
          (operation == 3 ? ((side->mark != 0) != (owner->mark != 0)) :
           (side->mark && !owner->mark))) {bad=3;break;}
      i=j;
    }
  }
  if (!bad && (operation == 1 || operation == 2 || operation == 4)) {
    for (i=0;i<used;) {
      struct zlist far *owner=NULL,*side=NULL;
      for (j=i;j<used && !memcmp(nodes[i].id,nodes[j].id,16U);j++) {
        if (nodes[j].role==3) side=nodes[j].entry;
        else owner=nodes[j].entry;
      }
      if (side && owner && owner->mark) {
        if (operation==4) {
          if (owner->mark==1) side->mark=4;
        } else side->mark=1;
      }
      i=j;
    }
  }
  free(nodes);
  return bad;
}
#ifdef __ZIP_C
/* Verify and remove exactly one old XTRO field from an extra buffer.
 * In validation mode no bytes change. Once validation of both local and
 * central buffers succeeds, the caller may safely compact both in place.
 * Unknown fields, including third-party collisions on 0x5854, are retained.
 */
static int xtro_strip_old_field(char *data, unsigned *length,
                                 const unsigned char reference[40],
                                 int local_field, int commit)
{
  unsigned at=0, found=0, size=*length;
  unsigned char *p=(unsigned char *)data;
  if (size && !p) return 0;
  while (at<size) {
    unsigned tag,n;
    if (size-at<4U) return 0;
    tag=(unsigned)p[at]|((unsigned)p[at+1U]<<8);
    n=(unsigned)p[at+2U]|((unsigned)p[at+3U]<<8);
    if (n>size-at-4U) return 0;
    if (tag==0x5854U && n>=4U && !memcmp(p+at+4U,"XTRO",4U)) {
      if (++found!=1U || n<40U ||
          (local_field && n!=40U) ||
          memcmp(p+at+4U,reference,40U)) return 0;
      if (commit) {
        memmove(p+at,p+at+4U+n,size-at-4U-n);
        *length=size-4U-n;
        return 1;
      }
    }
    at+=4U+n;
  }
  return found==1U;
}

static int xtro_strip_replaced_owner(struct zlist far *z,
                                     const unsigned char expected_id[16])
{
  const unsigned char *p=(const unsigned char *)z->cextra;
  const unsigned char *ref=NULL;
  unsigned at=0, cn=(unsigned)z->cext, ln=(unsigned)z->ext;
  unsigned check_c=cn,check_l=ln;
  while (at<cn) {
    unsigned tag,n;
    if (!p || cn-at<4U) return 0;
    tag=(unsigned)p[at]|((unsigned)p[at+1U]<<8);
    n=(unsigned)p[at+2U]|((unsigned)p[at+3U]<<8);
    if (n>cn-at-4U) return 0;
    if (tag==0x5854U && n>=40U && !memcmp(p+at+4U,"XTRO",4U)) {
      if (ref) return 0;
      ref=p+at+4U;
    }
    at+=4U+n;
  }
  if (!ref || memcmp(ref+8U,expected_id,16U) ||
      !xtro_strip_old_field(z->extra,&check_l,ref,1,0) ||
      !xtro_strip_old_field(z->cextra,&check_c,ref,0,0))
    return 0;
  if (!xtro_strip_old_field(z->extra,&ln,ref,1,1) ||
      !xtro_strip_old_field(z->cextra,&cn,ref,0,1))
    return 0;
  z->ext=(ush)ln;
  z->cext=(ush)cn;
  return 1;
}
#endif /* __ZIP_C */
#endif /* XTRO_ZIP_PAIR_GRAPH_H */
