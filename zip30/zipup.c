/*
  zipup.c - Zip 3

  Copyright (c) 1990-2008 Info-ZIP.  All rights reserved.

  See the accompanying file LICENSE, version 2007-Mar-4 or later
  (the contents of which are also included in zip.h) for terms of use.
  If, for some reason, all these files are missing, the Info-ZIP license
  also may be found at:  ftp://ftp.info-zip.org/pub/infozip/license.html
*/
/*
 *  zipup.c by Mark Adler and Jean-loup Gailly.
 */
#define __ZIPUP_C

/* Found that for at least unix port zip.h has to be first or ctype.h will
   define off_t and when using 64-bit file environment off_t in other files
   is 8 bytes while off_t here is 4 bytes, and this makes the zlist struct
   different sizes and needless to say leads to segmentation faults.  Putting
   zip.h first seems to fix this.  8/14/04 EG */
#include "zip.h"
#ifndef NO_AES
#include "wzaes.h"
extern iz_wzaes iz_zip_aes_ctx;
extern iz_ae3 iz_zip_ae3_ctx;
extern int iz_zip_aes_active;
#endif
#include <ctype.h>
#include <errno.h>

#ifndef UTIL            /* This module contains no code for Zip Utilities */

#include "revision.h"
#include "crc32.h"
#include "crypt.h"
#include "pkdcl.h"

/* Keep the PKDCLX engine source unchanged and compile it with zipup.c */
#include "pkdcl.c"

/* Same with our custom ppmd */
#ifdef PPMD_SUPPORT
# include "ppmd8.c"
# include "ppmd8enc.c"
#endif

/* Our Zopfli is a self-contained amalgamation */
#ifdef ZOPFLI_SUPPORT
# include "zopfli.c"
#endif

/* PKZIP Shrink, method 1 */
#ifdef SHRINK_SUPPORT
# include "shrink.c"
#endif

/* PKZIP Reduce, methods 2-5 */
#ifdef REDUCE_SUPPORT
# include "reduce.c"
#endif

/* PKZIP Implode, method 6 */
#ifdef IMPLODE_SUPPORT
# include "implode6.c"
#endif

/* Deflate64, method 9 */
#ifdef DEFLATE64_SUPPORT
# include "deflate64.h"
# include "deflate64.c"
#endif

#ifdef USE_ZLIB
#  include "zlib.h"
#endif

#ifdef LZMA_SUPPORT
#  include "lzma.h"
#endif
#ifdef ZSTD_SUPPORT
#  include "zstd.h"
#endif

#ifdef BZIP2_SUPPORT
#  ifdef BZIP2_USEBZIP2DIR
#    include "bzip2/bzlib.h"
#  else
#    include "bzlib.h"
#  endif
#endif

#ifdef OS2
#  include "os2/os2zip.h"
#endif

#if defined(MMAP)
#  include <sys/mman.h>
#  ifndef PAGESIZE   /* used to be SYSV, what about pagesize on SVR3 ? */
#    define PAGESIZE getpagesize()
#  endif
#  if defined(NO_VALLOC) && !defined(valloc)
#    define valloc malloc
#  endif
#endif

/* Use the raw functions for MSDOS and Unix to save on buffer space.
   They're not used for VMS since it doesn't work (raw is weird on VMS).
 */

#ifdef AMIGA
#  include "amiga/zipup.h"
#endif /* AMIGA */

#ifdef AOSVS
#  include "aosvs/zipup.h"
#endif /* AOSVS */

#ifdef ATARI
#  include "atari/zipup.h"
#endif

#ifdef __BEOS__
#  include "beos/zipup.h"
#endif

#ifdef __ATHEOS__
#  include "atheos/zipup.h"
#endif /* __ATHEOS__ */

#ifdef __human68k__
#  include "human68k/zipup.h"
#endif /* __human68k__ */

#ifdef MACOS
#  include "macos/zipup.h"
#endif

#ifdef DOS
#  include "msdos/zipup.h"
#endif /* DOS */

#ifdef NLM
#  include "novell/zipup.h"
#  include <nwfattr.h>
#endif

#ifdef OS2
#  include "os2/zipup.h"
#endif /* OS2 */

#ifdef RISCOS
#  include "acorn/zipup.h"
#endif

#ifdef TOPS20
#  include "tops20/zipup.h"
#endif

#ifdef UNIX
#  include "unix/zipup.h"
#endif

#ifdef CMS_MVS
#  include "zipup.h"
#endif /* CMS_MVS */

#ifdef TANDEM
#  include "zipup.h"
#endif /* TANDEM */

#ifdef VMS
#  include "vms/zipup.h"
#endif /* VMS */

#ifdef QDOS
#  include "qdos/zipup.h"
#endif /* QDOS */

#ifdef WIN32
#  include "win32/zipup.h"
#endif

#ifdef THEOS
#  include "theos/zipup.h"
#endif

/* Local functions */
#ifndef RISCOS
   local int suffixes OF((char *, char *));
#else
   local int filetypes OF((char *, char *));
#endif
local unsigned file_read OF((char *buf, unsigned size));
#ifdef USE_ZLIB
  local int zl_deflate_init OF((int pack_level));
#else /* !USE_ZLIB */
# ifdef ZP_NEED_MEMCOMPR
    local unsigned mem_read OF((char *buf, unsigned size));
# endif
#endif /* ?USE_ZLIB */

/* zip64 support 08/29/2003 R.Nausedat */
local zoff_t filecompress OF((struct zlist far *z_entry, int *cmpr_method));
#ifdef SHRINK_SUPPORT
local zoff_t shrinkfilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
#ifdef REDUCE_SUPPORT
local zoff_t reducefilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
#ifdef IMPLODE_SUPPORT
local zoff_t implodefilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
#ifdef ZOPFLI_SUPPORT
local zoff_t zopflifilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
#ifdef DEFLATE64_SUPPORT
local zoff_t deflate64filecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
local zoff_t dclfilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#ifdef PPMD_SUPPORT
local zoff_t ppmdfilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
#ifdef LZMA_SUPPORT
local zoff_t lzmafilecompress OF((struct zlist far *z_entry, int *cmpr_method));
local zoff_t xzfilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif
#ifdef ZSTD_SUPPORT
local zoff_t zstdfilecompress OF((struct zlist far *z_entry, int *cmpr_method,
                                  zoff_t pledged_size));
#endif

#ifdef BZIP2_SUPPORT
local zoff_t bzfilecompress OF((struct zlist far *z_entry, int *cmpr_method));
#endif

/* Deflate "internal" global data (currently not in zip.h) */
#if defined(MMAP) || defined(BIG_MEM)
# ifdef USE_ZLIB
    local uch *window = NULL;   /* Used to read all input file at once */
    local ulg window_size;      /* size of said window */
# else /* !USE_ZLIB */
    extern uch *window;         /* Used to read all input file at once */
#endif /* ?USE_ZLIB */
#endif /* MMAP || BIG_MEM */
#ifndef USE_ZLIB
  extern ulg window_size;       /* size of said window */

  unsigned (*read_buf) OF((char *buf, unsigned size)) = file_read;
  /* Current input function. Set to mem_read for in-memory compression */
#endif /* !USE_ZLIB */

typedef struct fwkcs_md5_ctx {
  z_uint4 state[4];
  z_uint4 count[2];
  uch buffer[64];
} fwkcs_md5_ctx;

local void fwkcs_md5_transform OF((z_uint4 *, ZCONST uch *));
local void fwkcs_md5_init OF((fwkcs_md5_ctx *));
local void fwkcs_md5_update OF((fwkcs_md5_ctx *, ZCONST uch *, unsigned));
local void fwkcs_md5_final OF((uch *, fwkcs_md5_ctx *));
local void fwkcs_strip_extra OF((char *, ush *));
local int fwkcs_add_extra OF((struct zlist far *, ZCONST uch *));


#define FWKCS_MASK ((z_uint4)0xffffffffUL)
#define FWKCS_ROT(x,n) \
  ((z_uint4)(((((x) & FWKCS_MASK) << (n)) | \
               (((x) & FWKCS_MASK) >> (32-(n)))) & FWKCS_MASK))

local void fwkcs_md5_transform(state, block)
  z_uint4 *state;
  ZCONST uch *block;
{
  static ZCONST z_uint4 k[64] = {
    0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL,
    0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
    0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL,
    0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
    0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL,
    0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
    0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL,
    0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
    0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL,
    0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
    0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL,
    0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
    0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL,
    0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
    0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
    0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL
  };
  static ZCONST uch r[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  };
  z_uint4 a=state[0], b=state[1], c=state[2], d=state[3], x[16];
  z_uint4 f, t;
  unsigned i, g;

  for (i=0; i<16; ++i) {
    ZCONST uch *p = block + (i << 2);
    x[i] = (z_uint4)p[0] | ((z_uint4)p[1] << 8) |
           ((z_uint4)p[2] << 16) | ((z_uint4)p[3] << 24);
  }
  for (i=0; i<64; ++i) {
    if (i < 16) {
      f = ((b & c) | ((~b) & d)) & FWKCS_MASK; g = i;
    } else if (i < 32) {
      f = ((d & b) | ((~d) & c)) & FWKCS_MASK; g = (5*i + 1) & 15;
    } else if (i < 48) {
      f = (b ^ c ^ d) & FWKCS_MASK; g = (3*i + 5) & 15;
    } else {
      f = (c ^ (b | (~d))) & FWKCS_MASK; g = (7*i) & 15;
    }
    t = d; d = c; c = b;
    b = (b + FWKCS_ROT((a + f + k[i] + x[g]) & FWKCS_MASK, r[i])) & FWKCS_MASK;
    a = t;
  }
  state[0] = (state[0] + a) & FWKCS_MASK;
  state[1] = (state[1] + b) & FWKCS_MASK;
  state[2] = (state[2] + c) & FWKCS_MASK;
  state[3] = (state[3] + d) & FWKCS_MASK;
}

local void fwkcs_md5_init(ctx)
  fwkcs_md5_ctx *ctx;
{
  ctx->count[0] = ctx->count[1] = 0;
  ctx->state[0] = (z_uint4)0x67452301UL;
  ctx->state[1] = (z_uint4)0xefcdab89UL;
  ctx->state[2] = (z_uint4)0x98badcfeUL;
  ctx->state[3] = (z_uint4)0x10325476UL;
}

local void fwkcs_md5_update(ctx, data, len)
  fwkcs_md5_ctx *ctx;
  ZCONST uch *data;
  unsigned len;
{
  unsigned i, used = (unsigned)((ctx->count[0] >> 3) & 63);
  z_uint4 bits = (z_uint4)len << 3;

  {
    z_uint4 old = ctx->count[0];
    ctx->count[0] = (ctx->count[0] + bits) & FWKCS_MASK;
    if (ctx->count[0] < old) ctx->count[1] = (ctx->count[1] + 1) & FWKCS_MASK;
    ctx->count[1] = (ctx->count[1] + ((z_uint4)len >> 29)) & FWKCS_MASK;
  }
  if (used) {
    unsigned freeb = 64 - used;
    if (len < freeb) {
      memcpy(ctx->buffer + used, data, len);
      return;
    }
    memcpy(ctx->buffer + used, data, freeb);
    fwkcs_md5_transform(ctx->state, ctx->buffer);
    data += freeb; len -= freeb;
  }
  for (i = 0; i + 63 < len; i += 64)
    fwkcs_md5_transform(ctx->state, data + i);
  if (i < len) memcpy(ctx->buffer, data + i, len - i);
}

local void fwkcs_md5_final(digest, ctx)
  uch *digest;
  fwkcs_md5_ctx *ctx;
{
  static ZCONST uch pad[64] = { 0x80 };
  uch bits[8];
  unsigned i, used, padlen;

  for (i = 0; i < 4; ++i) {
    bits[i] = (uch)(ctx->count[0] >> (i << 3));
    bits[i+4] = (uch)(ctx->count[1] >> (i << 3));
  }
  used = (unsigned)((ctx->count[0] >> 3) & 63);
  padlen = (used < 56) ? 56 - used : 120 - used;
  fwkcs_md5_update(ctx, pad, padlen);
  fwkcs_md5_update(ctx, bits, 8);
  for (i = 0; i < 16; ++i)
    digest[i] = (uch)(ctx->state[i >> 2] >> ((i & 3) << 3));
}

local void fwkcs_strip_extra(extra, plen)
  char *extra;
  ush *plen;
{
  unsigned in = 0, out = 0, len = *plen;

  while (in < len) {
    unsigned data_size, size, tag;

    if (len - in < 4)
      ZIPERR(ZE_FORM, "malformed extra field");
    data_size = (unsigned)((uch)extra[in+2] |
                           ((unsigned)(uch)extra[in+3] << 8));
    if (data_size > len - in - 4)
      ZIPERR(ZE_FORM, "malformed extra field");
    size = data_size + 4;
    tag = (unsigned)((uch)extra[in] |
                     ((unsigned)(uch)extra[in+1] << 8));
    if (tag != EF_MD5) {
      if (out != in) memmove(extra + out, extra + in, size);
      out += size;
    }
    in += size;
  }
  *plen = (ush)out;
}

local int fwkcs_add_extra(z, digest)
  struct zlist far *z;
  ZCONST uch *digest;
{
  char *p;
  unsigned oldlen = z->cext;
  unsigned newlen = oldlen + 23;

  if (newlen > EF_SIZE_MAX) return ZE_BIG;
  if ((p = (char *)malloc(newlen)) == NULL) return ZE_MEM;
  if (oldlen) memcpy(p, z->cextra, oldlen);
  p[oldlen] = (char)(EF_MD5 & 0xff);
  p[oldlen+1] = (char)((EF_MD5 >> 8) & 0xff);
  p[oldlen+2] = 19; p[oldlen+3] = 0;
  p[oldlen+4] = 'M'; p[oldlen+5] = 'D'; p[oldlen+6] = '5';
  memcpy(p + oldlen + 7, digest, 16);
  if (z->cextra != z->extra) free(z->cextra);
  z->cextra = p;
  z->cext = (ush)newlen;
  return ZE_OK;
}


#ifndef NO_AES
/* Record the AE-1/AE-2/AE-3 vendor extension in both header extra areas.
 * The actual compressor method is carried within this field (not method 99).
 * In standard mode, WinZip 11+ uses AE-2 for inputs <20 bytes and BZIP2,
 * AE-1 otherwise.  For unknown input sizes (pipes), standard mode uses
 * AE-1 unless BZIP2; that decision cannot change in a nonseekable local
 * header.  "Quantum" mode always writes AE-3 (AES-256-GCM).
 */
local int iz_aes_append_extra(z, version, strength, method)
    struct zlist far *z;
    int version, strength, method;
{
    unsigned l = z->ext, c = z->cext;
    char *lp, *cp;
    unsigned char ef[13];
    unsigned field_len = version==3 ? 13U : 11U;
    if (l > EF_SIZE_MAX - field_len || c > EF_SIZE_MAX - field_len) return ZE_BIG;
    ef[0]=1; ef[1]=0x99; ef[2]=(unsigned char)(field_len-4); ef[3]=0;
    ef[4]=(unsigned char)version; ef[5]=0;
    ef[6]='A'; ef[7]='E';
    ef[8]=(unsigned char)(strength==128?1:strength==192?2:3);
    ef[9]=(unsigned char)method; ef[10]=(unsigned char)(method>>8);
    if (version==3) {
        unsigned units=(unsigned)(iz_aes_iterations/10000UL);
        ef[11]=(unsigned char)units;
        ef[12]=(unsigned char)(units>>8);
    }
    lp=(char *)malloc(l+field_len);if(!lp)return ZE_MEM;
    cp=(char *)malloc(c+field_len);if(!cp){free(lp);return ZE_MEM;}
    if(l)memcpy(lp,z->extra,l);
    if(c)memcpy(cp,z->cextra,c);
    memcpy(lp+l,ef,field_len);memcpy(cp+c,ef,field_len);
    if(z->extra!=z->cextra) {free(z->extra);free(z->cextra);}
    else free(z->extra);
    z->extra=lp;z->ext=(ush)(l+field_len);
    z->cextra=cp;z->cext=(ush)(c+field_len);
    return ZE_OK;
}
local void iz_aes_change_info(z, version, method)
    struct zlist far *z;
    unsigned version, method;
{
    unsigned i;
    char *ef[2];ush sz[2];int j;
    ef[0]=z->extra;ef[1]=z->cextra;
    sz[0]=z->ext;sz[1]=z->cext;
    for(j=0;j<2;j++)
      for(i=0;i+11<=sz[j];) {
        unsigned n=(unsigned)(unsigned char)ef[j][i+2]|
                   ((unsigned)(unsigned char)ef[j][i+3]<<8);
        if(n>(unsigned)sz[j]-i-4)break;
        if(ef[j][i]==1 && (unsigned char)ef[j][i+1]==0x99 && n>=7) {
            ef[j][i+4]=(char)version;
            ef[j][i+5]=0;
            ef[j][i+9]=(char)method;
            ef[j][i+10]=(char)(method>>8);
            break;
        }
        i+=n+4;
      }
}
local int iz_aes_write_initial(strength, password)
    int strength;
    const char *password;
{
    unsigned char salt[16],ver[4],ctr[4];
    unsigned n=iz_aes_quantum ? 16U : iz_aes_salt_size((unsigned)strength);
    if(!iz_aes_entropy(salt,n))return ZE_TEMP;
    if (iz_aes_quantum) {
        iz_ae3_salt_counter(salt,ctr);
        if (!iz_ae3_init(&iz_zip_ae3_ctx,password,salt,ctr,
                         iz_aes_iterations,ver)) {
            iz_aes_wipe(salt,sizeof(salt));return ZE_TEMP;
        }
        if (bfwrite(salt,1,16,BFWRITE_DATA)!=16 ||
            bfwrite(ver,1,4,BFWRITE_DATA)!=4 ||
            bfwrite(ctr,1,4,BFWRITE_DATA)!=4) {
            iz_aes_wipe(salt,sizeof(salt));
            iz_aes_wipe(&iz_zip_ae3_ctx,sizeof(iz_zip_ae3_ctx));
            return ZE_TEMP;
        }
        iz_zip_aes_active=3;
    } else {
        if(!iz_aes_init(&iz_zip_aes_ctx,password,salt,(unsigned)strength,ver)) {
            iz_aes_wipe(salt,sizeof(salt));return ZE_TEMP;
        }
        if (bfwrite(salt,1,(extent)n,BFWRITE_DATA)!=n ||
            bfwrite(ver,1,2,BFWRITE_DATA)!=2) {
            iz_aes_wipe(salt,sizeof(salt));
            iz_aes_wipe(&iz_zip_aes_ctx,sizeof(iz_zip_aes_ctx));
            return ZE_TEMP;
        }
        iz_zip_aes_active=1;
    }
    iz_aes_wipe(salt,sizeof(salt));
    return ZE_OK;
}
local int iz_aes_write_final()
{
    unsigned char auth[20],fin[4];
    unsigned n,quantum=(iz_zip_aes_active==3);
    iz_zip_aes_active=0;
    if (quantum) {
        iz_ae3_final(&iz_zip_ae3_ctx,auth,fin);
        n=bfwrite(auth,1,16,BFWRITE_DATA);
        if(n==16)n=bfwrite(fin,1,4,BFWRITE_DATA);
        iz_aes_wipe(&iz_zip_ae3_ctx,sizeof(iz_zip_ae3_ctx));
        iz_aes_wipe(auth,sizeof(auth));iz_aes_wipe(fin,sizeof(fin));
        return n==4?ZE_OK:ZE_TEMP;
    }
    iz_aes_auth(&iz_zip_aes_ctx,auth);
    n=bfwrite(auth,1,10,BFWRITE_DATA);
    iz_aes_wipe(auth,sizeof(auth));
    iz_aes_wipe(&iz_zip_aes_ctx,sizeof(iz_zip_aes_ctx));
    return n==10?ZE_OK:ZE_TEMP;
}
#endif

/* Local data */
local fwkcs_md5_ctx fwkcs_ctx;
local ush pkav_sum16 = 0;       /* PKAV sum of uncompressed stored bytes */
local uch pkav_xor8 = 0;        /* PKAV xor of uncompressed stored bytes */
local ulg crc;                  /* crc on uncompressed file data */
local ftype ifile;              /* file to compress */
#if defined(MMAP) || defined(BIG_MEM)
  local ulg remain;
  /* window bytes not yet processed.
   *  special value "(ulg)-1L" reserved to signal normal reads.
   */
#endif /* MMAP || BIG_MEM */
#ifdef USE_ZLIB
  local int deflInit = FALSE;   /* flag: zlib deflate is initialized */
  local z_stream zstrm;         /* zlib's data interface structure */
  local char *f_ibuf = NULL;
  local char *f_obuf = NULL;
#else /* !USE_ZLIB */
  local char file_outbuf[1024]; /* output buffer for compression to file */

# ifdef ZP_NEED_MEMCOMPR
    local char *in_buf;
    /* Current input buffer, in_buf is used only for in-memory compression. */
    local unsigned in_offset;
    /* Current offset in input buffer. in_offset is used only for in-memory
     * compression. On 16 bit machines, the buffer is limited to 64K.
     */
    local unsigned in_size;     /* size of current input buffer */
# endif /* ZP_NEED_MEMCOMPR */
#endif /* ?USE_ZLIB */

#ifdef BZIP2_SUPPORT
    local int bzipInit;         /* flag: bzip2lib is initialized */
    local bz_stream bstrm;      /* zlib's data interface structure */
# if !defined(USE_ZLIB)
    local char *f_ibuf = NULL;
    local char *f_obuf = NULL;
# endif /* !USE_ZLIB */
#endif /* BZIP2_SUPPORT */

#ifdef DEBUG
    zoff_t isize;               /* input file size. global only for debugging */
#else /* !DEBUG */
    local zoff_t isize;         /* input file size. global only for debugging */
#endif /* ?DEBUG */
  /* If file_read detects binary it sets this flag - 12/16/04 EG */
  local int file_binary = 0;        /* first buf */
  local int file_binary_final = 0;  /* for bzip2 for entire file.  assume text until find binary */


/* moved check to function 3/14/05 EG */
int is_seekable(y)
  FILE *y;
{
  zoff_t pos;

#ifdef BROKEN_FSEEK
  if (!fseekable(y)) {
    return 0;
  }
#endif

  pos = zftello(y);
  if (zfseeko(y, pos, SEEK_SET)) {
    return 0;
  }

  return 1;
}


int percent(n, m)
  uzoff_t n;
  uzoff_t m;                    /* n is the original size, m is the new size */
/* Return the percentage compression from n to m using only integer
   operations */
{
  zoff_t p;

#if 0
  if (n > 0xffffffL)            /* If n >= 16M */
  {                             /*  then divide n and m by 256 */
    n += 0x80;  n >>= 8;
    m += 0x80;  m >>= 8;
  }
  return n > m ? (int)(1 + (200 * (n - m)/n)) / 2 : 0;
#endif

/* 2004-12-01 SMS.
 * Changed to do big-n test only for small zoff_t.
 * Changed big-n arithmetic to accomodate apparently negative values
 * when a small zoff_t value exceeds 2G.
 * Increased the reduction divisor from 256 to 512 to avoid the sign bit
 * in a reduced intermediate, allowing signed arithmetic for the final
 * result (which is no longer artificially limited to non-negative
 * values).
 * Note that right shifts must be on unsigned values to avoid undesired
 * sign extension.
 */

/* Handle n = 0 case and account for int maybe being 16-bit.  12/28/2004 EG
 */

#define PC_MAX_SAFE 0x007fffffL    /* 9 clear bits at high end. */
#define PC_MAX_RND  0xffffff00L    /* 8 clear bits at low end. */

  if (sizeof(uzoff_t) < 8)          /* Don't fiddle with big zoff_t. */
  {
    if ((ulg)n > PC_MAX_SAFE)       /* Reduce large values.  (n > m) */
    {
      if ((ulg)n < PC_MAX_RND)      /* Divide n by 512 with rounding, */
        n = ((ulg)n + 0x100) >> 9;  /* if boost won't overflow. */
      else                          /* Otherwise, use max value. */
        n = PC_MAX_SAFE;

      if ((ulg)m < PC_MAX_RND)      /* Divide m by 512 with rounding, */
        m = ((ulg)m + 0x100) >> 9;  /* if boost won't overflow. */
      else                          /* Otherwise, use max value. */
        m = PC_MAX_SAFE;
    }
  }
  if (n != 0)
    p = ((200 * ((zoff_t)n - (zoff_t)m) / (zoff_t)n) + 1) / 2;
  else
    p = 0;
  return (int)p;  /* Return (rounded) % reduction. */
}


#ifndef RISCOS

local int suffixes(a, s)
  char *a;                      /* name to check suffix of */
  char *s;                      /* list of suffixes separated by : or ; */
/* Return true if a ends in any of the suffixes in the list s. */
{
  int m;                        /* true if suffix matches so far */
  char *p;                      /* pointer into special */
  char *q;                      /* pointer into name a */

#ifdef QDOS
  short dlen = devlen(a);
  a = a + dlen;
#endif

  m = 1;
#ifdef VMS
  if( (q = strrchr(a,';')) != NULL )    /* Cut out VMS file version */
    --q;
  else
    q = a + strlen(a) - 1;
#else /* !VMS */
  q = a + strlen(a) - 1;
#endif /* ?VMS */
  for (p = s + strlen(s) - 1; p >= s; p--)
    if (*p == ':' || *p == ';')
    {
      if (m)
        return 1;
      else
      {
        m = 1;
#ifdef VMS
        if( (q = strrchr(a,';')) != NULL )      /* Cut out VMS file version */
          --q;
        else
          q = a + strlen(a) - 1;
#else /* !VMS */
        q = a + strlen(a) - 1;
#endif /* ?VMS */
      }
    }
    else
    {
      m = m && q >= a && case_map(*p) == case_map(*q);
      q--;
    }
  return m;
}

#else /* RISCOS */

local int filetypes(a, s)
char *a;                        /* extra field of file to check filetype of */
char *s;                        /* list of filetypes separated by : or ; */
/* Return true if a is any of the filetypes in the list s. */
{
 char *p;                       /* pointer into special */
 char typestr[4];               /* filetype hex string taken from a */

 if ((((unsigned*)a)[2] & 0xFFF00000) != 0xFFF00000) {
 /* The file is not filestamped, always try to compress it */
   return 0;
 }

 sprintf(typestr,"%.3X",(((unsigned*)a)[2] & 0x000FFF00) >> 8);

 for (p=s;p<=s+strlen(s)-3;p+=3) { /* p+=3 to skip 3 hex type */
   while (*p==':' || *p==';')
     p++;

   if (typestr[0] == toupper(p[0]) &&
       typestr[1] == toupper(p[1]) &&
       typestr[2] == toupper(p[2]))
     return 1;
 }
 return 0;
}
#endif /* ?RISCOS */



/* Note: a zip "entry" includes a local header (which includes the file
   name), an encryption header if encrypting, the compressed data
   and possibly an extended local header. */

int zipup(z)
struct zlist far *z;    /* zip entry to compress */
/* Compress the file z->name into the zip entry described by *z and write
   it to the file *y. Encrypt if requested.  Return an error code in the
   ZE_ class.  Also, update tempzn by the number of bytes written. */
/* y is now global */
{
  iztimes f_utim;       /* UNIX GMT timestamps, filled by filetime() */
  ulg tim;              /* time returned by filetime() */
  ulg a = 0L;           /* attributes returned by filetime() */
  char *b;              /* malloc'ed file buffer */
  extent k = 0;         /* result of zread */
  int l = 0;            /* true if this file is a symbolic link */
  int m;                /* method for this entry */
#ifndef NO_AES
  int iz_aes_entry = 0;
  int iz_aes_version = 0;
  unsigned iz_aes_overhead = 0;
#endif

  zoff_t o = 0, p;      /* offsets in zip file */
  zoff_t q = (zoff_t) -3; /* size returned by filetime */
  uzoff_t uq;           /* unsigned q */
  zoff_t s = 0;         /* size of compressed data */

  int r;                /* temporary variable */
  int isdir;            /* set for a directory name */
  int set_type = 0;     /* set if file type (ascii/binary) unknown */
  zoff_t last_o;        /* used to detect wrap around */

  ush tempext = 0;      /* temp copies of extra fields */
  ush tempcext = 0;
  char *tempextra = NULL;
  char *tempcextra = NULL;


#ifdef WINDLL
# ifdef ZIP64_SUPPORT
  extern _int64 filesize64;
  extern unsigned long low;
  extern unsigned long high;
#  endif
#endif

  z->nam = strlen(z->iname);
  isdir = z->iname[z->nam-1] == (char)0x2f; /* ascii[(unsigned)('/')] */

  file_binary = -1;      /* not set, set after first read */
  file_binary_final = 0; /* not set, set after first read */

#if defined(UNICODE_SUPPORT) && defined(WIN32)
  if (!no_win32_wide)
    tim = filetimew(z->namew, &a, &q, &f_utim);
  else
    tim = filetime(z->name, &a, &q, &f_utim);
#else
  tim = filetime(z->name, &a, &q, &f_utim);
#endif
  if (tim == 0 || q == (zoff_t) -3)
    return ZE_OPEN;

  /* q is set to -1 if the input file is a device, -2 for a volume label */
  if (q == (zoff_t) -2) {
     isdir = 1;
     q = 0;
  } else if (isdir != ((a & MSDOS_DIR_ATTR) != 0)) {
     /* don't overwrite a directory with a file and vice-versa */
     return ZE_MISS;
  }
  /* reset dot_count for each file */
  if (!display_globaldots)
    dot_count = -1;

  /* display uncompressed size */
  uq = ((uzoff_t) q > (uzoff_t) -3) ? 0 : (uzoff_t) q;
  if (noisy && display_usize) {
    fprintf(mesg, " (");
    DisplayNumString( mesg, uq );
    fprintf(mesg, ")");
    mesg_line_started = 1;
    fflush(mesg);
  }
  if (logall && display_usize) {
    fprintf(logfile, " (");
    DisplayNumString( logfile, uq );
    fprintf(logfile, ")");
    logfile_line_started = 1;
    fflush(logfile);
  }

  /* initial z->len so if error later have something */
  z->len = uq;

  z->att = (ush)UNKNOWN; /* will be changed later */
  z->atx = 0; /* may be changed by set_extra_field() */

  /* Free the old extra fields which are probably obsolete */
  /* Should probably read these and keep any we don't update.  12/30/04 EG */
  if (extra_fields == 2) {
    /* If keeping extra fields, make copy before clearing for set_extra_field()
       A better approach is to modify the port code, but maybe later */
    if (z->ext) {
      if ((tempextra = malloc(z->ext)) == NULL) {
        ZIPERR(ZE_MEM, "extra fields copy");
      }
      memcpy(tempextra, z->extra, z->ext);
      tempext = z->ext;
      fwkcs_strip_extra(tempextra, &tempext);
    }
    if (z->cext) {
      if ((tempcextra = malloc(z->cext)) == NULL) {
        ZIPERR(ZE_MEM, "extra fields copy");
      }
      memcpy(tempcextra, z->cextra, z->cext);
      tempcext = z->cext;
      fwkcs_strip_extra(tempcextra, &tempcext);
    }
  }
  if (z->ext) {
    free((zvoid *)(z->extra));
  }
  if (z->cext && z->extra != z->cextra) {
    free((zvoid *)(z->cextra));
  }
  z->extra = z->cextra = NULL;
  z->ext = z->cext = 0;

#if defined(MMAP) || defined(BIG_MEM)
  remain = (ulg)-1L; /* changed only for MMAP or BIG_MEM */
#endif /* MMAP || BIG_MEM */
#if (!defined(USE_ZLIB) || defined(MMAP) || defined(BIG_MEM))
  window_size = 0L;
#endif /* !USE_ZLIB || MMAP || BIG_MEM */

  /* Select method based on the suffix and the global method */
#ifndef RISCOS
  m = special != NULL && suffixes(z->name, special) ? STORE : method;
#else /* RISCOS  must set m after setting extra field */
  m = method;
#endif /* ?RISCOS */

  /* For now force deflate if using descriptors.  Instead zip and unzip
     could check bytes read against compressed size in each data descriptor
     found and skip over any that don't match.  This is how at least one
     other zipper does it.  To be added later.  Until then it
     probably doesn't hurt to force deflation when streaming.  12/30/04 EG
  */

  /* Now is a good time.  For now allow storing for testing.  12/16/05 EG */
  /* By release need to force deflation based on reports some inflate
     streamed data to find the end of the data */
  /* Need to handle bzip2 */
#ifdef NO_STREAMING_STORE
  if (use_descriptors && m == STORE)
  {
      m = DEFLATE;
  }
#endif

  /* Open file to zip up unless it is stdin */
  if (strcmp(z->name, "-") == 0)
  {
    ifile = (ftype)zstdin;
#if defined(MSDOS) || defined(__human68k__)
    if (isatty(zstdin) == 0)  /* keep default mode if stdin is a terminal */
      setmode(zstdin, O_BINARY);
#endif
    z->tim = tim;
  }
  else
  {
#if !(defined(VMS) && defined(VMS_PK_EXTRA))
    if (extra_fields) {
      /* create extra field and change z->att and z->atx if desired */
      set_extra_field(z, &f_utim);
# ifdef QLZIP
      if(qlflag)
          a |= (S_IXUSR) << 16;   /* Cross compilers don't set this */
# endif
# ifdef RISCOS
      m = special != NULL && filetypes(z->extra, special) ? STORE : method;
# endif /* RISCOS */

      /* For now allow store for testing */
#ifdef NO_STREAMING_STORE
      /* For now force deflation if using data descriptors. */
      if (use_descriptors && m == STORE)
      {
        m = DEFLATE;
      }
#endif

    }
#endif /* !(VMS && VMS_PK_EXTRA) */
    l = issymlnk(a);
    if (pkav_enabled && l) {
      sprintf(errbuf, "PKAV cannot store symbolic link '%s'", z->oname);
      ZIPERR(ZE_PARMS, errbuf);
    }
    if (pkav_enabled && !isdir && q < 0 && strcmp(z->name, "-") != 0) {
      sprintf(errbuf, "PKAV cannot store special file '%s'", z->oname);
      ZIPERR(ZE_PARMS, errbuf);
    }
    if (l) {
      ifile = fbad;
      m = STORE;
    }
    else if (isdir) { /* directory */
      ifile = fbad;
      m = STORE;
      q = 0;
    }
#ifdef THEOS
    else if (((a >> 16) & S_IFMT) == S_IFLIB) {   /* library */
      ifile = fbad;
      m = STORE;
      q = 0;
    }
#endif
    else {
#ifdef CMS_MVS
      if (bflag) {
        if ((ifile = zopen(z->name, fhowb)) == fbad)
           return ZE_OPEN;
      }
      else
#endif /* CMS_MVS */
#if defined(UNICODE_SUPPORT) && defined(WIN32)
      if (!no_win32_wide) {
        if ((ifile = zwopen(z->namew, fhow)) == fbad)
          return ZE_OPEN;
      } else {
        if ((ifile = zopen(z->name, fhow)) == fbad)
          return ZE_OPEN;
      }
#else
      if ((ifile = zopen(z->name, fhow)) == fbad)
        return ZE_OPEN;
#endif
    }

    z->tim = tim;

#if defined(VMS) && defined(VMS_PK_EXTRA)
    /* vms_get_attributes must be called after vms_open() */
    if (extra_fields) {
      /* create extra field and change z->att and z->atx if desired */
      vms_get_attributes(ifile, z, &f_utim);
    }
#endif /* VMS && VMS_PK_EXTRA */

#if defined(MMAP) || defined(BIG_MEM)
    /* Map ordinary files but not devices. This code should go in fileio.c */
    if (!translate_eol && m != STORE && q != -1L && (ulg)q > 0 &&
        (ulg)q + MIN_LOOKAHEAD > (ulg)q) {
# ifdef MMAP
      /* Map the whole input file in memory */
      if (window != NULL)
        free(window);  /* window can't be a mapped file here */
      window_size = (ulg)q + MIN_LOOKAHEAD;
      remain = window_size & (PAGESIZE-1);
      /* If we can't touch the page beyond the end of file, we must
       * allocate an extra page.
       */
      if (remain > MIN_LOOKAHEAD) {
        window = (uch*)mmap(0, window_size, PROT_READ, MAP_PRIVATE, ifile, 0);
      } else {
        window = (uch*)valloc(window_size - remain + PAGESIZE);
        if (window != NULL) {
          window = (uch*)mmap((char*)window, window_size - remain, PROT_READ,
                        MAP_PRIVATE | MAP_FIXED, ifile, 0);
        } else {
          window = (uch*)(-1);
        }
      }
      if (window == (uch*)(-1)) {
        Trace((mesg, " mmap failure on %s\n", z->name));
        window = NULL;
        window_size = 0L;
        remain = (ulg)-1L;
      } else {
        remain = (ulg)q;
      }
# else /* !MMAP, must be BIG_MEM */
      /* Read the whole input file at once */
      window_size = (ulg)q + MIN_LOOKAHEAD;
      window = window ? (uch*) realloc(window, (unsigned)window_size)
                      : (uch*) malloc((unsigned)window_size);
      /* Just use normal code if big malloc or realloc fails: */
      if (window != NULL) {
        remain = (ulg)zread(ifile, (char*)window, q+1);
        if (remain != (ulg)q) {
          fprintf(mesg, " q=%lu, remain=%lu ", (ulg)q, remain);
          error("can't read whole file at once");
        }
      } else {
        window_size = 0L;
      }
# endif /* ?MMAP */
    }
#endif /* MMAP || BIG_MEM */

  } /* strcmp(z->name, "-") == 0 */

  if (extra_fields == 2) {
    unsigned len;
    char *p;

    /* step through old extra fields and copy over any not already
       in new extra fields */
    p = copy_nondup_extra_fields(tempextra, tempext, z->extra, z->ext, &len);
    free(z->extra);
    z->ext = len;
    z->extra = p;
    p = copy_nondup_extra_fields(tempcextra, tempcext, z->cextra, z->cext, &len);
    free(z->cextra);
    z->cext = len;
    z->cextra = p;

    if (tempext)
      free(tempextra);
    if (tempcext)
      free(tempcextra);
  }

  if (q == 0)
    m = STORE;
  if (m == BEST)
    m = DEFLATE;
#ifdef REDUCE_SUPPORT
  /* Resolve the selected factor BEFORE writing the local header.  A
   * data-descriptor/streamed archive cannot rewrite its method later. */
  if (m >= REDUCE1 && m <= REDUCE4)
    m = level >= 7 ? REDUCE4 : (level >= 5 ? REDUCE3 :
                               (level >= 3 ? REDUCE2 : REDUCE1));
#endif

  /* Do not create STORED files with extended local headers if the
   * input size is not known, because such files could not be extracted.
   * So if the zip file is not seekable and the input file is not
   * on disk, obey the -0 option by forcing deflation with stored block.
   * Note however that using "zip -0" as filter is not very useful...
   * ??? to be done.
   */

  /* An alternative used by others is to allow storing but on reading do
   * a second check when a signature is found.  This is simply to check
   * the compressed size to the bytes read since the start of the file data.
   * If this is the right signature then the compressed size should match
   * the size of the compressed data to that point.  If not look for the
   * next signature.  We should do this.  12/31/04 EG
   *
   * For reading and testing we should do this, but should not write
   * stored streamed data unless for testing as finding the end of
   * streamed deflated data can be done by inflating.  6/26/06 EG
   */

  /* Fill in header information and write local header to zip file.
   * This header will later be re-written since compressed length and
   * crc are not yet known.
   */

  /* (Assume ext, cext, com, and zname already filled in.) */
#if defined(OS2) || defined(WIN32)
# ifdef WIN32_OEM
  /* When creating OEM-coded names on Win32, the entries must always be marked
     as "created on MSDOS" (OS_CODE = 0), because UnZip needs to handle archive
     entry names just like those created by Zip's MSDOS port.
   */
  z->vem = (ush)(dosify ? 20 : 0 + Z_MAJORVER * 10 + Z_MINORVER);
# else
  z->vem = (ush)(z->dosflag ? (dosify ? 20 : /* Made under MSDOS by PKZIP 2.0 */
                               (0 + Z_MAJORVER * 10 + Z_MINORVER))
                 : OS_CODE + Z_MAJORVER * 10 + Z_MINORVER);
  /* For a plain old (8+3) FAT file system, we cheat and pretend that the file
   * was not made on OS2/WIN32 but under DOS. unzip is confused otherwise.
   */
# endif
#else /* !(OS2 || WIN32) */
  z->vem = (ush)(dosify ? 20 : OS_CODE + Z_MAJORVER * 10 + Z_MINORVER);
#endif /* ?(OS2 || WIN32) */

  if (pkav_enabled) {
    /* PKWARE AV archives ALWAYS use 'FAT/DOS' creator ID. */
    z->vem &= 0x00ff;
    if ((z->vem & 0xff) == 0)
      z->vem = (ush)(Z_MAJORVER * 10 + Z_MINORVER);
    z->dosflag = 1;
  }
  z->ver = (ush)(m == STORE || (m >= SHRINK && m <= IMPLODE) ? 10 : 20); /* legacy PKZIP 1.0 */
#ifdef DEFLATE64_SUPPORT
  if (method == DEFLATE64)
      z->ver = (ush)(m == STORE ? 10 : 21);
#endif
#ifdef BZIP2_SUPPORT
  if (method == BZIP2)
      z->ver = (ush)(m == STORE ? 10 : 46);
#endif
#ifdef PPMD_SUPPORT
  if (method == PPMD)
      z->ver = (ush)(m == STORE ? 10 : 63);
#endif
#ifdef LZMA_SUPPORT
  if (method == LZMA)
      z->ver = (ush)(m == STORE ? 10 : 63);
  if (method == XZ)
      z->ver = (ush)(m == STORE ? 10 : 20);
#endif
#ifdef ZSTD_SUPPORT
  /* WinZip-created method-93 archives use version-needed 2.0.  Python 3.14
   * writes 6.3 instead; follow the WinZip interoperability precedent here. */
  if (method == ZSTD)
      z->ver = (ush)(m == STORE ? 10 : 20);
#endif
  z->crc = 0;  /* to be updated later */
  /* Assume first that we will need an extended local header: */
  if (isdir)
    /* If dir then q = 0 and extended header not needed */
    z->flg = 0;
  else
    z->flg = 8;  /* to be updated later */
#ifdef LZMA_SUPPORT
  /* APPNOTE 5.8.9: bit 1 means that an LZMA EOS marker is present. */
  if (m == LZMA)
    z->flg |= 2;
#endif
#if CRYPT || !defined(NO_AES)
  if (!isdir && key != NULL) {
    z->flg |= 1;
    /* Since we do not yet know the crc here, we pretend that the crc
     * is the modification time:
     */
    z->crc = z->tim << 16;
    /* More than pretend.  File is encrypted using crypt header with that. */
  }
#endif /* CRYPT || AES */
  /* ZIP method 6: bit 1 selects 8K; bit 2 selects 3 trees. */
#ifdef IMPLODE_SUPPORT
  if (m == IMPLODE) {
    if (level >= 5) z->flg |= 2;
    if ((level >= 3 && level <= 4) || level >= 8) z->flg |= 4;
  }
#endif
  z->lflg = z->flg;
  z->how = (ush)m;                              /* may be changed later  */
  z->siz = (zoff_t)(m == STORE && q >= 0 ? q : 0); /* will be changed later */
  z->len = (zoff_t)(q != -1L ? q : 0);          /* may be changed later  */
#ifndef NO_AES
  iz_zip_aes_active = 0;
  if (!isdir && iz_aes_mode && key != NULL) {
      iz_aes_entry = 1;
      iz_aes_version = iz_aes_quantum ? 3 : (((q >= 0 && q < 20) || m == BZIP2) ? 2 : 1);
      iz_aes_overhead = iz_aes_quantum ? 44U : iz_aes_salt_size((unsigned)iz_aes_strength) + 12;
      if (iz_aes_quantum && z->ver < 20) z->ver = 20;
      if ((r=iz_aes_append_extra(z,iz_aes_version,iz_aes_strength,m))!=ZE_OK)
          return r;
      z->how = 99;
      /* WinZip AES never uses the traditional ZipCrypto timestamp value as
       * the local-header CRC placeholder.  Use zero until AE-1 can be
       * rewritten with the real CRC; AE-2 remains zero by definition. */
      z->crc = 0;
      /* The method-99 outer header is deliberately versioned according to
       * the actual compressor, not a fictitious AES version requirement. */
  }
#endif
  if (z->att == (ush)UNKNOWN) {
      z->att = BINARY;                    /* set sensible value in header */
      set_type = 1;
  }
  /* Attributes from filetime(), flag bits from set_extra_field(): */
#if defined(DOS) || defined(OS2) || defined(WIN32)
  z->atx = z->dosflag ? a & 0xff : a | (z->atx & 0x0000ff00);
#else
  z->atx = dosify ? a & 0xff : a | (z->atx & 0x0000ff00);
#endif /* DOS || OS2 || WIN32 */
  if (pkav_enabled)
    z->atx &= 0xffUL;

  if ((r = putlocal(z, PUTLOCAL_WRITE)) != ZE_OK) {
    if (ifile != fbad)
      zclose(ifile);
    return r;
  }

  /* now get split information set by bfwrite() */
  z->off = current_local_offset;

  /* disk local header was written to */
  z->dsk = current_local_disk;

  tempzn += 4 + LOCHEAD + z->nam + z->ext;


#if CRYPT || !defined(NO_AES)
  if (!isdir && key != NULL) {
#ifndef NO_AES
    if (iz_aes_entry) {
      if ((r=iz_aes_write_initial(iz_aes_strength,key))!=ZE_OK)
        return r;
      z->siz += iz_aes_overhead;
      tempzn += iz_aes_quantum ? 24 : iz_aes_salt_size((unsigned)iz_aes_strength) + 2;
    } else
#endif
    {
#if CRYPT
      crypthead(key, z->crc);
      z->siz += RAND_HEAD_LEN;  /* to be updated later */
      tempzn += RAND_HEAD_LEN;
#endif
    }
  }
#endif /* CRYPT || AES */
  if (ferror(y)) {
    if (ifile != fbad)
      zclose(ifile);
    ZIPERR(ZE_WRITE, "unexpected error on zip file");
  }

  last_o = o;
  o = zftello(y); /* for debugging only, ftell can fail on pipes */
  if (ferror(y))
    clearerr(y);

  if (o != -1 && last_o > o) {
    fprintf(mesg, "last %s o %s\n", zip_fzofft(last_o, NULL, NULL),
                                    zip_fzofft(o, NULL, NULL));
    ZIPERR(ZE_BIG, "seek wrap - zip file too big to write");
  }

  /* Write stored or deflated file to zip file */
  isize = 0L;
  crc = CRCVAL_INITIAL;
  pkav_sum16 = 0;
  pkav_xor8 = 0;

  if (fwkcs_md5) fwkcs_md5_init(&fwkcs_ctx);
  if (isdir) {
    /* nothing to write */
  }
  else if (m != STORE) {
    if (set_type) z->att = (ush)UNKNOWN;
    /* ... is finally set in file compression routine */
    if (m == DCLIMPLODE) {
      s = dclfilecompress(z, &m);
    }
#ifdef SHRINK_SUPPORT
    else if (m == SHRINK) {
      s = shrinkfilecompress(z, &m);
    }
#endif
#ifdef REDUCE_SUPPORT
    else if (m >= REDUCE1 && m <= REDUCE4) {
      s = reducefilecompress(z, &m);
    }
#endif
#ifdef IMPLODE_SUPPORT
    else if (m == IMPLODE) {
      s = implodefilecompress(z, &m);
    }
#endif
#ifdef DEFLATE64_SUPPORT
    else if (m == DEFLATE64) {
      s = deflate64filecompress(z, &m);
    }
#endif
#ifdef PPMD_SUPPORT
    else if (m == PPMD) {
      s = ppmdfilecompress(z, &m);
    }
#endif
#ifdef BZIP2_SUPPORT
    else if (m == BZIP2) {
      s = bzfilecompress(z, &m);
    }
#endif /* BZIP2_SUPPORT */
#ifdef LZMA_SUPPORT
    else if (m == LZMA) {
      s = lzmafilecompress(z, &m);
    }
    else if (m == XZ) {
      s = xzfilecompress(z, &m);
    }
#endif /* LZMA_SUPPORT */
#ifdef ZSTD_SUPPORT
    else if (m == ZSTD) {
      /* q is the original input size.  Pledge it only when no EOL
       * translation can alter the byte count; -1 means unknown/streamed. */
      s = zstdfilecompress(z, &m,
                          (q >= 0 && !translate_eol) ? q : (zoff_t)-1);
    }
#endif /* ZSTD_SUPPORT */
    else {
      s = filecompress(z, &m);
    }
#ifndef PGP
    if (z->att == (ush)BINARY && translate_eol && file_binary) {
      if (translate_eol == 1)
        zipwarn("has binary so -l ignored", "");
      else
        zipwarn("has binary so -ll ignored", "");
    }
    else if (z->att == (ush)BINARY && translate_eol) {
      if (translate_eol == 1)
        zipwarn("-l used on binary file - corrupted?", "");
      else
        zipwarn("-ll used on binary file - corrupted?", "");
    }
#endif
  }
  else
  {
    if ((b = malloc(SBSZ)) == NULL)
       return ZE_MEM;

    if (l) {
      k = rdsymlnk(z->name, b, SBSZ);
/*
 * compute crc first because zfwrite will alter the buffer b points to !!
 */
      crc = crc32(crc, (uch *) b, k);
      if (fwkcs_md5) fwkcs_md5_update(&fwkcs_ctx, (uch *)b, k);
      if (zfwrite(b, 1, k) != k)
      {
        free((zvoid *)b);
        return ZE_TEMP;
      }
      isize = k;

#ifdef MINIX
      q = k;
#endif /* MINIX */
    }
    else
    {
      while ((k = file_read(b, SBSZ)) > 0 && k != (extent) EOF)
      {
        if (zfwrite(b, 1, k) != k)
        {
          if (ifile != fbad)
            zclose(ifile);
          free((zvoid *)b);
          return ZE_TEMP;
        }
        if (!display_globaldots) {
          if (dot_size > 0) {
            /* initial space */
            if (noisy && dot_count == -1) {
#ifndef WINDLL
              putc(' ', mesg);
              fflush(mesg);
#else
              fprintf(stdout,"%c",' ');
#endif
              dot_count++;
            }
            dot_count++;
            if (dot_size <= (dot_count + 1) * SBSZ) dot_count = 0;
          }
          if ((verbose || noisy) && dot_size && !dot_count) {
#ifndef WINDLL
            putc('.', mesg);
            fflush(mesg);
#else
            fprintf(stdout,"%c",'.');
#endif
            mesg_line_started = 1;
          }
        }
      }
    }
    free((zvoid *)b);
    s = isize;
  }
  if (ifile != fbad && zerr(ifile)) {
    perror("\nzip warning");
    if (logfile)
      fprintf(logfile, "\nzip warning: %s\n", strerror(errno));
    zipwarn("could not read input file: ", z->oname);
  }
  if (ifile != fbad)
    zclose(ifile);
#ifdef MMAP
  if (remain != (ulg)-1L) {
    munmap((caddr_t) window, window_size);
    window = NULL;
  }
#endif /*MMAP */

#ifndef NO_AES
  if (iz_aes_entry) {
      unsigned final_aes_version = (unsigned)iz_aes_version;
      if ((r=iz_aes_write_final())!=ZE_OK) return r;
      /* A compressor may fall back to STORE after the initial AES choice.
       * Re-evaluate the WinZip AE-1/AE-2 policy when that happens.  Such
       * method fallback is seekable, so the local extra field can be rewritten. */
      if (m != method && !iz_aes_quantum)
        final_aes_version = ((isize < 20) || m == BZIP2) ? 2U : 1U;
      iz_aes_version = (int)final_aes_version;
      iz_aes_change_info(z,final_aes_version,(unsigned)m);
      tempzn += iz_aes_quantum ? 20 : 10;
  }
#endif
  tempzn += s;
  p = tempzn; /* save for future fseek() */

#if (!defined(MSDOS) || defined(OS2))
#if !defined(VMS) && !defined(CMS_MVS) && !defined(__mpexl)
  /* Check input size (but not in VMS -- variable record lengths mess it up)
   * and not on MSDOS -- diet in TSR mode reports an incorrect file size)
   */
#ifndef TANDEM /* Tandem EOF does not match byte count unless Unstructured */
  if (!translate_eol && q != -1L && isize != q)
  {
    Trace((mesg, " i=%lu, q=%lu ", isize, q));
    zipwarn(" file size changed while zipping ", z->name);
  }
#endif /* !TANDEM */
#endif /* !VMS && !CMS_MVS && !__mpexl */
#endif /* (!MSDOS || OS2) */

  if (fwkcs_md5) {
    uch digest[16];
    int fr;
    fwkcs_md5_final(digest, &fwkcs_ctx);
    if ((fr = fwkcs_add_extra(z, digest)) != ZE_OK)
      return fr;
  }

  if (isdir)
  {
    /* A directory */
    z->siz = 0;
    z->len = 0;
    z->how = STORE;
    z->ver = 10;
    /* never encrypt directory so don't need extended local header */
    z->flg &= ~8;
    z->lflg &= ~8;
  }
  else
  {
    /* Try to rewrite the local header with correct information */
#ifndef NO_AES
    z->crc = (iz_aes_entry && iz_aes_version!=1) ? 0 : crc;
#else
    z->crc = crc;
#endif
    z->siz = s;
#if CRYPT || !defined(NO_AES)
    if (!isdir && key != NULL) {
#ifndef NO_AES
      if (iz_aes_entry) z->siz += iz_aes_overhead;
#if CRYPT
      else
#endif
#endif
#if CRYPT
        z->siz += RAND_HEAD_LEN;
#endif
    }
#endif /* CRYPT || AES */
    z->len = isize;
#ifdef LZMA_SUPPORT
    /* small_store_finish() may have changed method 14 to STORE.  GPBF bit 1
     * has LZMA-specific EOS semantics, so it must not survive the fallback. */
    if (z->how == LZMA && m == STORE)
      z->flg &= ~2;
#endif
#ifndef NO_AES
    /* STORE carries no LZMA EOS information.  In AES members the outer
     * method is 99, so the normal method-14 check above cannot detect it. */
    if (iz_aes_entry && m == STORE) {
      z->flg &= ~2;
      z->lflg &= ~2;
    }
#endif
    if (pkav_enabled) {
      z->att |= 0x0004;
      z->atx = (((ulg)pkav_xor8 << 24) |
                ((ulg)pkav_sum16 << 8) |
                (z->atx & 0xffUL)) & 0xffffffffUL;
      z->vem &= 0x00ff;
      if ((z->vem & 0xff) == 0)
        z->vem = (ush)(Z_MAJORVER * 10 + Z_MINORVER);
      z->dosflag = 1;
    }
    /* if can seek back to local header */
#ifdef BROKEN_FSEEK
    if (use_descriptors || !fseekable(y) || zfseeko(y, z->off, SEEK_SET))
#else
    if (use_descriptors || zfseeko(y, z->off, SEEK_SET))
#endif
    {
#ifndef NO_AES
      if (!iz_aes_entry && z->how != (ush)m)
#else
      if (z->how != (ush)m)
#endif
         error("can't rewrite method");
      if (m == STORE && q < 0)
         ZIPERR(ZE_PARMS, "zip -0 not supported for I/O on pipes or devices");
      if ((r = putextended(z)) != ZE_OK)
        return r;
      /* if Zip64 and not seekable then Zip64 data descriptor */
#ifdef ZIP64_SUPPORT
      tempzn += (zip64_entry ? 24L : 16L);
#else
      tempzn += 16L;
#endif
      z->flg = z->lflg; /* if z->flg modified by deflate */
    } else {
      /* ftell() not as useful across splits */
#ifndef NO_AES
      if (bytes_this_entry != (uzoff_t)(s +
             (iz_aes_entry ? iz_aes_overhead : (key ? 12 : 0)))) {
#else
      if (bytes_this_entry != (uzoff_t)(key ? s + 12 : s)) {
#endif
        fprintf(mesg, " s=%s, actual=%s ",
                zip_fzofft(s, NULL, NULL), zip_fzofft(bytes_this_entry, NULL, NULL));
        error("incorrect compressed size");
      }
#if 0
       /* seek ok, ftell() should work, check compressed size */
# if !defined(VMS) && !defined(CMS_MVS)
      if (p - o != s) {
        fprintf(mesg, " s=%s, actual=%s ",
                zip_fzofft(s, NULL, NULL), zip_fzofft(p-o, NULL, NULL));
        error("incorrect compressed size");
      }
# endif /* !VMS && !CMS_MVS */
#endif /* 0 */
#ifndef NO_AES
      z->how = iz_aes_entry ? 99 : (ush)m;
#else
      z->how = (ush)m;
#endif
      switch (m)
      {
      case STORE:
      case SHRINK:
      case REDUCE1:
      case REDUCE2:
      case REDUCE3:
      case REDUCE4:
      case IMPLODE:
        z->ver = 10; break;
      /* Need PKUNZIP 2.0 for DEFLATE */
      case DEFLATE:
        z->ver = 20; break;
#ifdef DEFLATE64_SUPPORT
      case DEFLATE64:
        z->ver = 21; break;
#endif
      case DCLIMPLODE:
        z->ver = 20; break;
#ifdef BZIP2_SUPPORT
      case BZIP2:
        z->ver = 46; break;
#endif
#ifdef PPMD_SUPPORT
      case PPMD:
        z->ver = 63; break;
#endif
#ifdef LZMA_SUPPORT
      case LZMA:
        z->ver = 63; break;
      case XZ:
        z->ver = 20; break;
#endif
#ifdef ZSTD_SUPPORT
      case ZSTD:
        z->ver = 20; break;
#endif
      }
      /*
       * The encryption header needs the crc, but we don't have it
       * for a new file.  The file time is used instead and the encryption
       * header then used to encrypt the data.  The AppNote standard only
       * can be applied to a file that the crc is known, so that means
       * either an existing entry in an archive or get the crc before
       * creating the encryption header and then encrypt the data.
       */
      if ((z->flg & 1) == 0) {
        /* not encrypting so don't need extended local header */
        z->flg &= ~8;
      }
      /* deflate may have set compression level bit markers in z->flg,
         and we can't think of any reason central and local flags should
         be different. */
      z->lflg = z->flg;

      /* If not using descriptors, back up and rewrite local header. */
      if (split_method == 1 && current_local_file != y) {
        if (zfseeko(current_local_file, z->off, SEEK_SET))
          return ZE_READ;
      }

      /* if local header in another split, putlocal will close it */
      if ((r = putlocal(z, PUTLOCAL_REWRITE)) != ZE_OK)
        return r;

      if (zfseeko(y, bytes_this_split, SEEK_SET))
        return ZE_READ;

      if ((z->flg & 1) != 0) {
        /* encrypted file, extended header still required */
        if ((r = putextended(z)) != ZE_OK)
          return r;
#ifdef ZIP64_SUPPORT
        if (zip64_entry)
          tempzn += 24L;
        else
          tempzn += 16L;
#else
        tempzn += 16L;
#endif
      }
    }
  } /* isdir */
  /* Free the local extra field which is no longer needed */
  if (z->ext) {
    if (z->extra != z->cextra) {
      free((zvoid *)(z->extra));
      z->extra = NULL;
    }
    z->ext = 0;
  }

  /* Display statistics */
  if (noisy)
  {
    if (verbose) {
      fprintf( mesg, "\t(in=%s) (out=%s)",
               zip_fzofft(isize, NULL, "u"), zip_fzofft(s, NULL, "u"));
    }
#ifdef BZIP2_SUPPORT
    if (m == BZIP2)
      fprintf(mesg, " (bzip2ed %d%%)\n", percent(isize, s));
    else
#endif
    if (m == DEFLATE)
      fprintf(mesg, " (deflated %d%%)\n", percent(isize, s));
#ifdef SHRINK_SUPPORT
    else if (m == SHRINK)
      fprintf(mesg, " (shrunk %d%%)\n", percent(isize, s));
#endif
#ifdef REDUCE_SUPPORT
    else if (m >= REDUCE1 && m <= REDUCE4)
      fprintf(mesg, " (reduced factor %d, %d%%)\n", m - REDUCE1 + 1, percent(isize, s));
#endif
#ifdef DEFLATE64_SUPPORT
    else if (m == DEFLATE64)
      fprintf(mesg, " (deflate64 %d%%)\n", percent(isize, s));
#endif
    else if (m == IMPLODE)
      fprintf(mesg, " (imploded %d%%)\n", percent(isize, s));
    else if (m == DCLIMPLODE)
      fprintf(mesg, " (DCL imploded %d%%)\n", percent(isize, s));
#ifdef PPMD_SUPPORT
    else if (m == PPMD)
      fprintf(mesg, " (PPMd compressed %d%%)\n", percent(isize, s));
#endif
#ifdef LZMA_SUPPORT
    else if (m == LZMA)
      fprintf(mesg, " (LZMA compressed %d%%)\n", percent(isize, s));
    else if (m == XZ)
      fprintf(mesg, " (XZ compressed %d%%)\n", percent(isize, s));
#endif
#ifdef ZSTD_SUPPORT
    else if (m == ZSTD)
      fprintf(mesg, " (Zstd compressed %d%%)\n", percent(isize, s));
#endif
    else
      fprintf(mesg, " (stored 0%%)\n");
    mesg_line_started = 0;
    fflush(mesg);
  }
  if (logall)
  {
#ifdef BZIP2_SUPPORT
    if (m == BZIP2)
      fprintf(logfile, " (bzip2ed %d%%)\n", percent(isize, s));
    else
#endif
    if (m == DEFLATE)
      fprintf(logfile, " (deflated %d%%)\n", percent(isize, s));
#ifdef SHRINK_SUPPORT
    else if (m == SHRINK)
      fprintf(logfile, " (shrunk %d%%)\n", percent(isize, s));
#endif
#ifdef REDUCE_SUPPORT
    else if (m >= REDUCE1 && m <= REDUCE4)
      fprintf(logfile, " (reduced factor %d, %d%%)\n", m - REDUCE1 + 1, percent(isize, s));
#endif
#ifdef DEFLATE64_SUPPORT
    else if (m == DEFLATE64)
      fprintf(logfile, " (deflate64 %d%%)\n", percent(isize, s));
#endif
    else if (m == IMPLODE)
      fprintf(logfile, " (imploded %d%%)\n", percent(isize, s));
    else if (m == DCLIMPLODE)
      fprintf(logfile, " (DCL imploded %d%%)\n", percent(isize, s));
#ifdef PPMD_SUPPORT
    else if (m == PPMD)
      fprintf(logfile, " (PPMd compressed %d%%)\n", percent(isize, s));
#endif
#ifdef LZMA_SUPPORT
    else if (m == LZMA)
      fprintf(logfile, " (LZMA compressed %d%%)\n", percent(isize, s));
    else if (m == XZ)
      fprintf(logfile, " (XZ compressed %d%%)\n", percent(isize, s));
#endif
#ifdef ZSTD_SUPPORT
    else if (m == ZSTD)
      fprintf(logfile, " (Zstd compressed %d%%)\n", percent(isize, s));
#endif
    else
      fprintf(logfile, " (stored 0%%)\n");
    logfile_line_started = 0;
    fflush(logfile);
  }

#ifdef WINDLL
# ifdef ZIP64_SUPPORT
   /* The DLL api has been updated and uses a different
      interface.  7/24/04 EG */
   if (lpZipUserFunctions->ServiceApplication64 != NULL)
    {
    if ((*lpZipUserFunctions->ServiceApplication64)(z->zname, isize))
                ZIPERR(ZE_ABORT, "User terminated operation");
    }
  else
   {
   filesize64 = isize;
   low = (unsigned long)(filesize64 & 0x00000000FFFFFFFF);
   high = (unsigned long)((filesize64 >> 32) & 0x00000000FFFFFFFF);
   if (lpZipUserFunctions->ServiceApplication64_No_Int64 != NULL) {
    if ((*lpZipUserFunctions->ServiceApplication64_No_Int64)(z->zname, low, high))
                ZIPERR(ZE_ABORT, "User terminated operation");
    }
   }
# else
  if (lpZipUserFunctions->ServiceApplication != NULL)
  {
    if ((*lpZipUserFunctions->ServiceApplication)(z->zname, isize))
    {
      ZIPERR(ZE_ABORT, "User terminated operation");
    }
  }
# endif
#endif

  return ZE_OK;
}




local unsigned file_read(buf, size)
  char *buf;
  unsigned size;
/* Read a new buffer from the current input file, perform end-of-line
 * translation, and update the crc and input file size.
 * IN assertion: size >= 2 (for end-of-line translation)
 */
{
  unsigned len;
  char *b;
  zoff_t isize_prev;    /* Previous isize.  Used for overflow check. */

#if defined(MMAP) || defined(BIG_MEM)
  if (remain == 0L) {
    return 0;
  } else if (remain != (ulg)-1L) {
    /* The window data is already in place. We still compute the crc
     * by 32K blocks instead of once on whole file to keep a certain
     * locality of reference.
     */
    Assert(buf == (char*)window + isize, "are you lost?");
    if ((ulg)size > remain) size = (unsigned)remain;
    if (size > WSIZE) size = WSIZE; /* don't touch all pages at once */
    remain -= (ulg)size;
    len = size;
  } else
#endif /* MMAP || BIG_MEM */
  if (translate_eol == 0) {
    len = zread(ifile, buf, size);
    if (len == (unsigned)EOF || len == 0) return len;
#ifdef OS390
    b = buf;
    if (aflag == ASCII) {
      while (*b != '\0') {
        *b = (char)ascii[(uch)*b];
        b++;
      }
    }
#endif
  } else if (translate_eol == 1) {
    /* translate_eol == 1 */
    /* Transform LF to CR LF */
    size >>= 1;
    b = buf+size;
    size = len = zread(ifile, b, size);
    if (len == (unsigned)EOF || len == 0) return len;

    /* check buf for binary - 12/16/04 */
    if (file_binary == -1) {
      /* first read */
      file_binary = is_text_buf(b, size) ? 0 : 1;
    }

    if (file_binary != 1) {
#ifdef EBCDIC
      if (aflag == ASCII)
      {
         do {
            char c;

            if ((c = *b++) == '\n') {
               *buf++ = CR; *buf++ = LF; len++;
            } else {
              *buf++ = (char)ascii[(uch)c];
            }
         } while (--size != 0);
      }
      else
#endif /* EBCDIC */
      {
         do {
            if ((*buf++ = *b++) == '\n') *(buf-1) = CR, *buf++ = LF, len++;
         } while (--size != 0);
      }
      buf -= len;
    } else { /* do not translate binary */
      memcpy(buf, b, size);
    }

  } else {
    /* translate_eol == 2 */
    /* Transform CR LF to LF and suppress final ^Z */
    b = buf;
    size = len = zread(ifile, buf, size-1);
    if (len == (unsigned)EOF || len == 0) return len;

    /* check buf for binary - 12/16/04 */
    if (file_binary == -1) {
      /* first read */
      file_binary = is_text_buf(b, size) ? 0 : 1;
    }

    if (file_binary != 1) {
      buf[len] = '\n'; /* I should check if next char is really a \n */
#ifdef EBCDIC
      if (aflag == ASCII)
      {
         do {
            char c;

            if ((c = *b++) == '\r' && *b == '\n') {
               len--;
            } else {
               *buf++ = (char)(c == '\n' ? LF : ascii[(uch)c]);
            }
         } while (--size != 0);
      }
      else
#endif /* EBCDIC */
      {
         do {
            if (( *buf++ = *b++) == CR && *b == LF) buf--, len--;
         } while (--size != 0);
      }
      if (len == 0) {
         zread(ifile, buf, 1); len = 1; /* keep single \r if EOF */
#ifdef EBCDIC
         if (aflag == ASCII) {
            *buf = (char)(*buf == '\n' ? LF : ascii[(uch)(*buf)]);
         }
#endif
      } else {
         buf -= len;
         if (buf[len-1] == CTRLZ) len--; /* suppress final ^Z */
      }
    }
  }
  if (pkav_enabled) {
    unsigned pi;
    for (pi = 0; pi < len; pi++) {
      uch pc = (uch)buf[pi];
      pkav_sum16 = (ush)(pkav_sum16 + pc);
      pkav_xor8 ^= pc;
    }
  }
  if (fwkcs_md5) fwkcs_md5_update(&fwkcs_ctx, (uch *)buf, len);
  crc = crc32(crc, (uch *) buf, len);
  /* 2005-05-23 SMS.
     Increment file size.  A small-file program reading a large file may
     cause isize to overflow, so complain (and abort) if it goes
     negative or wraps around.  Awful things happen later otherwise.
  */
  isize_prev = isize;
  isize += (ulg)len;
  if (isize < isize_prev) {
    ZIPERR(ZE_BIG, "overflow in byte count");
  }
  return len;
}


/*
 * Keep a small input and compressed-output candidate until it is known
 * whether the whole input fits in memory.  This lets external compressors
 * make the same STORE-vs-compress decision which the traditional Deflate
 * paths make for small files, without writing candidate bytes to the archive
 * first.  Buffering is disabled when data descriptors are required because
 * the local-header method cannot then be rewritten safely.
 */
struct small_store_state {
    uch *input;
    size_t input_size;
    size_t input_limit;
    uch *output;
    size_t output_size;
    size_t output_alloc;
    int active;
};

local void small_store_init(s, limit)
    struct small_store_state *s;
    size_t limit;
{
    s->input = NULL;
    s->input_size = 0;
    s->input_limit = limit;
    s->output = NULL;
    s->output_size = 0;
    s->output_alloc = 0;
    s->active = FALSE;

    if (limit == 0 || use_descriptors || !fseekable(y))
        return;

    s->input = (uch *)malloc(limit);
    if (s->input != NULL)
        s->active = TRUE;
}

local void small_store_discard(s)
    struct small_store_state *s;
{
    free(s->input);
    free(s->output);
    s->input = NULL;
    s->output = NULL;
    s->input_size = 0;
    s->output_size = 0;
    s->output_alloc = 0;
    s->active = FALSE;
}

local void small_store_disable(s)
    struct small_store_state *s;
{
    if (!s->active)
        return;

    if (s->output_size != 0 &&
        zfwrite(s->output, 1, (extent)s->output_size) !=
            (extent)s->output_size) {
        small_store_discard(s);
        ziperr(ZE_TEMP, "error writing compressed data to zipfile");
    }
    small_store_discard(s);
}

local unsigned small_store_read(s, buf, size)
    struct small_store_state *s;
    char *buf;
    unsigned size;
{
    unsigned got;

    got = file_read(buf, size);
    if (s->active && got != (unsigned)EOF && got != 0) {
        if ((size_t)got > s->input_limit - s->input_size) {
            small_store_disable(s);
        } else {
            memcpy(s->input + s->input_size, buf, (size_t)got);
            s->input_size += (size_t)got;
        }
    }
    return got;
}

local unsigned small_store_write(s, buf, count)
    struct small_store_state *s;
    zvoid *buf;
    unsigned count;
{
    size_t needed;
    size_t alloc;
    uch *new_output;

    if (!s->active)
        return zfwrite(buf, 1, (extent)count);
    if (count == 0)
        return 0;

    needed = s->output_size + (size_t)count;
    if (needed < s->output_size) {
        small_store_disable(s);
        return zfwrite(buf, 1, (extent)count);
    }

    if (needed > s->output_alloc) {
        alloc = s->output_alloc == 0 ? 1024U : s->output_alloc;
        while (alloc < needed) {
            size_t next;
            next = alloc * 2U;
            if (next <= alloc) {
                alloc = needed;
                break;
            }
            alloc = next;
        }
        new_output = (uch *)realloc(s->output, alloc);
        if (new_output == NULL) {
            small_store_disable(s);
            return zfwrite(buf, 1, (extent)count);
        }
        s->output = new_output;
        s->output_alloc = alloc;
    }

    memcpy(s->output + s->output_size, buf, (size_t)count);
    s->output_size += (size_t)count;
    return count;
}

local zoff_t small_store_finish(s, cmpr_method, cmpr_size)
    struct small_store_state *s;
    int *cmpr_method;
    zoff_t cmpr_size;
{
    zoff_t result;

    if (!s->active)
        return cmpr_size;

    Assert(cmpr_size == (zoff_t)s->output_size,
           "small-store compressed byte count mismatch");

    if (cmpr_size >= (zoff_t)s->input_size) {
        if (s->input_size != 0 &&
            zfwrite(s->input, 1, (extent)s->input_size) !=
                (extent)s->input_size) {
            small_store_discard(s);
            ziperr(ZE_TEMP, "error writing stored data to zipfile");
        }
        *cmpr_method = STORE;
        result = (zoff_t)s->input_size;
    } else {
        if (s->output_size != 0 &&
            zfwrite(s->output, 1, (extent)s->output_size) !=
                (extent)s->output_size) {
            small_store_discard(s);
            ziperr(ZE_TEMP, "error writing compressed data to zipfile");
        }
        result = cmpr_size;
    }

    small_store_discard(s);
    return result;
}

struct dcl_zip_state {
    zoff_t output_size;
    int write_error;
    struct small_store_state *store_test;
};

static unsigned short dcl_zip_read(unsigned char *buffer,
                                   unsigned short *size, void *opaque)
{
    struct dcl_zip_state *s;
    unsigned got;

    s = (struct dcl_zip_state *)opaque;
    got = small_store_read(s->store_test, (char *)buffer, (unsigned)*size);
    if (got == (unsigned)EOF)
        return 0;

    if (got != 0 && file_binary_final == 0 &&
        !is_text_buf((char *)buffer, got))
        file_binary_final = 1;

    return (unsigned short)got;
}

static void dcl_zip_write(unsigned char *buffer, unsigned short *size,
                          void *opaque)
{
    struct dcl_zip_state *s;
    unsigned count;

    s = (struct dcl_zip_state *)opaque;
    count = (unsigned)*size;
    if (count == 0 || s->write_error)
        return;

    if (small_store_write(s->store_test, buffer, count) != count) {
        s->write_error = 1;
        return;
    }
    s->output_size += (zoff_t)count;
}

/*
 * PKWARE DCL Implode compression for ZIP method 10.  Binary literal coding
 * and automatic 1K/2K/4K dictionary selection are the defaults.  The command
 * line can select ASCII literals, a fixed dictionary, and the optimal parser.
 */
local zoff_t dclfilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    struct dcl_zip_state s;
    struct small_store_state store_test;
    unsigned short r;

    small_store_init(&store_test, (size_t)SBSZ);
    s.output_size = 0;
    s.write_error = 0;
    s.store_test = &store_test;

    r = pkdcl_implode_ex(dcl_zip_read, dcl_zip_write, &s,
                         dcl_implode_mode ? PKDCL_CMP_ASCII : PKDCL_CMP_BINARY,
                         dcl_implode_dict == 0 ? PKDCL_DICT_AUTO
                                               : (unsigned long)dcl_implode_dict,
                         PKDCL_FLAG_EXTRA |
                           (dcl_implode_optimal ? PKDCL_FLAG_OPTIMAL : 0U));

    if (s.write_error) {
        small_store_discard(&store_test);
        ziperr(ZE_TEMP, "error writing DCL implode data to zipfile");
    }
    if (r == PKDCL_CMP_ABORT) {
        small_store_discard(&store_test);
        ziperr(ZE_MEM, "DCL implode compression failed");
    }
    if (r != PKDCL_CMP_NO_ERROR) {
        small_store_discard(&store_test);
        ziperr(ZE_LOGIC, "DCL implode compression failed");
    }

    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    return small_store_finish(&store_test, cmpr_method, s.output_size);
}

#ifdef PPMD_SUPPORT
#define PPMD_ZIP_OUTBUF 16384U

typedef struct {
    IByteOut vt;
    Byte *buffer;
    unsigned used;
    zoff_t output_size;
    int write_error;
    struct small_store_state *store_test;
} ppmd_zip_out;

static void *ppmd_zip_alloc(ISzAllocPtr a, size_t size)
{
    (void)a;
    return malloc(size);
}

static void ppmd_zip_free(ISzAllocPtr a, void *address)
{
    (void)a;
    free(address);
}

static ISzAlloc ppmd_zip_allocator = { ppmd_zip_alloc, ppmd_zip_free };

static void ppmd_zip_flush_out(ppmd_zip_out *s)
{
    if (s->used == 0 || s->write_error)
        return;
    if (small_store_write(s->store_test, s->buffer, s->used) != s->used) {
        s->write_error = 1;
        return;
    }
    s->output_size += (zoff_t)s->used;
    s->used = 0;
}

static void ppmd_zip_write(IByteOutPtr stream, Byte b)
{
    ppmd_zip_out *s;

    s = (ppmd_zip_out *)stream;
    if (s->write_error)
        return;
    s->buffer[s->used++] = b;
    if (s->used == PPMD_ZIP_OUTBUF)
        ppmd_zip_flush_out(s);
}

typedef struct {
    unsigned order;
    unsigned mem_mb;
} ppmd_zip_level;

/* Map Zip's normal -1 .. -9 scale onto PPMdI model depth and memory.
 * Level 6 matches the APPNOTE's order-8 / 50-MiB nominal defaults; lower
 * levels trade model size for speed and memory, while -9 reaches PPMdI's
 * maximum order and memory field.  Restart restoration is used throughout
 * because it has the broadest interoperability. */
static ZCONST ppmd_zip_level ppmd_zip_levels[9] = {
    {  6U,   2U },
    {  7U,   4U },
    {  8U,   8U },
    {  8U,  16U },
    {  8U,  32U },
    {  8U,  50U },
    { 10U,  64U },
    { 12U, 128U },
    { 16U, 256U }
};

local zoff_t ppmdfilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    CPpmd8 model;
    struct small_store_state store_test;
    ppmd_zip_out output;
    Byte *inbuf;
    unsigned got, i, lev, props;
    unsigned order, mem_mb;

    lev = (level == 11) ? 9U :
          ((level >= 1 && level <= 9) ? (unsigned)level : 6U);
    order = ppmd_zip_levels[lev - 1U].order;
    mem_mb = ppmd_zip_levels[lev - 1U].mem_mb;

    small_store_init(&store_test, (size_t)SBSZ);
    output.vt.Write = ppmd_zip_write;
    output.buffer = (Byte *)malloc(PPMD_ZIP_OUTBUF);
    output.used = 0;
    output.output_size = 0;
    output.write_error = 0;
    output.store_test = &store_test;
    if (output.buffer == NULL) {
        small_store_discard(&store_test);
        ziperr(ZE_MEM, "PPMd output buffer allocation failed");
    }

    inbuf = (Byte *)malloc(SBSZ);
    if (inbuf == NULL) {
        free(output.buffer);
        small_store_discard(&store_test);
        ziperr(ZE_MEM, "PPMd input buffer allocation failed");
    }

    Ppmd8_Construct(&model);
    if (!Ppmd8_Alloc(&model, (UInt32)mem_mb << 20, &ppmd_zip_allocator)) {
        free(inbuf);
        free(output.buffer);
        small_store_discard(&store_test);
        ziperr(ZE_MEM, "PPMd model allocation failed");
    }

    /* ZIP method 98's little-endian two-byte properties word precedes the
     * range-coded bytes and is part of the compressed/encrypted data. */
    props = (order - 1U) | ((mem_mb - 1U) << 4);
    ppmd_zip_write(&output.vt, (Byte)props);
    ppmd_zip_write(&output.vt, (Byte)(props >> 8));

    model.Stream.Out = &output.vt;
    Ppmd8_Init_RangeEnc(&model);
    Ppmd8_Init(&model, order, PPMD8_RESTORE_METHOD_RESTART);

    while (!output.write_error) {
        got = small_store_read(&store_test, (char *)inbuf, SBSZ);
        if (got == (unsigned)EOF || got == 0)
            break;
        if (file_binary_final == 0 && !is_text_buf((char *)inbuf, got))
            file_binary_final = 1;
        for (i = 0; i < got; ++i)
            Ppmd8_EncodeSymbol(&model, (int)inbuf[i]);
    }

    if (!output.write_error) {
        Ppmd8_EncodeSymbol(&model, PPMD8_SYM_END);
        Ppmd8_Flush_RangeEnc(&model);
        ppmd_zip_flush_out(&output);
    }

    Ppmd8_Free(&model, &ppmd_zip_allocator);
    free(inbuf);
    free(output.buffer);

    if (output.write_error) {
        small_store_discard(&store_test);
        ziperr(ZE_TEMP, "error writing PPMd data to zipfile");
    }

    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    return small_store_finish(&store_test, cmpr_method, output.output_size);
}
#endif /* PPMD_SUPPORT */

#ifdef LZMA_SUPPORT
#define LZMA_ZIP_OUTBUF 16384U

/* ZIP method 14: a four-byte ZIP properties header followed by raw LZMA1.
 * liblzma's raw LZMA1 encoder always emits the EOS marker required by our
 * GPBF bit-1 policy. */
local zoff_t lzmafilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_options_lzma options;
    lzma_filter filters[2];
    struct small_store_state store_test;
    uint32_t props_size;
    uint8_t *props;
    uch *inbuf;
    uch *outbuf;
    unsigned lev;
    unsigned got;
    unsigned produced;
    zoff_t output_size;
    lzma_ret lr;
    int done;

    lev = (level == 11) ? 9U :
          ((level >= 1 && level <= 9) ? (unsigned)level : 6U);
    if (lzma_lzma_preset(&options, lev))
        ziperr(ZE_LOGIC, "unsupported liblzma compression preset");

    filters[0].id = LZMA_FILTER_LZMA1;
    filters[0].options = &options;
    filters[1].id = LZMA_VLI_UNKNOWN;
    filters[1].options = NULL;

    lr = lzma_properties_size(&props_size, &filters[0]);
    if (lr != LZMA_OK || props_size > 65535U)
        ziperr(ZE_LOGIC, "cannot encode LZMA properties");

    props = (uint8_t *)malloc((size_t)props_size);
    inbuf = (uch *)malloc((size_t)SBSZ);
    outbuf = (uch *)malloc((size_t)LZMA_ZIP_OUTBUF);
    if (props == NULL || inbuf == NULL || outbuf == NULL) {
        free(props);
        free(inbuf);
        free(outbuf);
        ziperr(ZE_MEM, "allocating LZMA compression buffers");
    }

    lr = lzma_properties_encode(&filters[0], props);
    if (lr != LZMA_OK) {
        free(props);
        free(inbuf);
        free(outbuf);
        ziperr(ZE_LOGIC, "cannot encode LZMA properties");
    }

    lr = lzma_raw_encoder(&strm, filters);
    if (lr != LZMA_OK) {
        free(props);
        free(inbuf);
        free(outbuf);
        if (lr == LZMA_MEM_ERROR)
            ziperr(ZE_MEM, "initializing LZMA compressor");
        ziperr(ZE_LOGIC, "initializing LZMA compressor");
    }

    small_store_init(&store_test, (size_t)SBSZ);
    output_size = 0;

    /* Interoperability convention used by established ZIP LZMA writers:
     * LZMA SDK version 9.4, then the little-endian property size. */
    outbuf[0] = 9;
    outbuf[1] = 4;
    outbuf[2] = (uch)(props_size & 0xffU);
    outbuf[3] = (uch)((props_size >> 8) & 0xffU);
    if (small_store_write(&store_test, outbuf, 4U) != 4U ||
        (props_size != 0 && small_store_write(&store_test, props,
          (unsigned)props_size) != (unsigned)props_size)) {
        lzma_end(&strm);
        small_store_discard(&store_test);
        free(props);
        free(inbuf);
        free(outbuf);
        ziperr(ZE_TEMP, "error writing LZMA data to zipfile");
    }
    output_size += (zoff_t)4 + (zoff_t)props_size;
    free(props);

    strm.next_out = (uint8_t *)outbuf;
    strm.avail_out = (size_t)LZMA_ZIP_OUTBUF;
    done = FALSE;
    while (!done) {
        got = small_store_read(&store_test, (char *)inbuf, SBSZ);
        if (got == (unsigned)EOF)
            got = 0;
        if (got != 0 && file_binary_final == 0 &&
            !is_text_buf((char *)inbuf, got))
            file_binary_final = 1;

        strm.next_in = (const uint8_t *)inbuf;
        strm.avail_in = (size_t)got;
        do {
            lr = lzma_code(&strm, got == 0 ? LZMA_FINISH : LZMA_RUN);
            if (lr != LZMA_OK && lr != LZMA_STREAM_END) {
                lzma_end(&strm);
                small_store_discard(&store_test);
                free(inbuf);
                free(outbuf);
                if (lr == LZMA_MEM_ERROR)
                    ziperr(ZE_MEM, "compressing with LZMA");
                ziperr(ZE_LOGIC, "liblzma compression failed");
            }

            produced = LZMA_ZIP_OUTBUF - (unsigned)strm.avail_out;
            if (produced != 0 &&
                (strm.avail_out == 0 || lr == LZMA_STREAM_END)) {
                if (small_store_write(&store_test, outbuf, produced) != produced) {
                    lzma_end(&strm);
                    small_store_discard(&store_test);
                    free(inbuf);
                    free(outbuf);
                    ziperr(ZE_TEMP, "error writing LZMA data to zipfile");
                }
                output_size += (zoff_t)produced;
                strm.next_out = (uint8_t *)outbuf;
                strm.avail_out = (size_t)LZMA_ZIP_OUTBUF;
            }
        } while ((got != 0 && strm.avail_in != 0) ||
                 (got == 0 && lr != LZMA_STREAM_END));

        if (got == 0)
            done = TRUE;
    }

    lzma_end(&strm);
    free(inbuf);
    free(outbuf);
    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    return small_store_finish(&store_test, cmpr_method, output_size);
}
/* ZIP method 95: one complete XZ stream per ZIP member.  XZ itself uses
 * LZMA2 for compression and supplies its own Stream Header, Block Header,
 * Index, and Stream Footer; unlike ZIP method 14 there is no ZIP-specific
 * LZMA properties prefix.
 *
 * Creation profile note: the available 7-Zip interoperability sample uses
 * the XZ CRC32 integrity check.  Pending a genuine WinZip-created method-95
 * reference archive, Zip deliberately emits LZMA_CHECK_NONE.  The enclosing
 * ZIP member already carries its normal CRC-32.  Revisit this choice when a
 * WinZip reference becomes available.  UnZip accepts every XZ check that
 * liblzma supports. */
local zoff_t xzfilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    lzma_stream strm = LZMA_STREAM_INIT;
    struct small_store_state store_test;
    uch *inbuf;
    uch *outbuf;
    unsigned lev;
    unsigned got;
    unsigned produced;
    zoff_t output_size;
    lzma_ret lr;
    int done;

    lev = (level == 11) ? 9U :
          ((level >= 1 && level <= 9) ? (unsigned)level : 6U);

    lr = lzma_easy_encoder(&strm, lev, LZMA_CHECK_NONE);
    if (lr != LZMA_OK) {
        if (lr == LZMA_MEM_ERROR)
            ziperr(ZE_MEM, "initializing XZ compressor");
        ziperr(ZE_LOGIC, "initializing XZ compressor");
    }

    inbuf = (uch *)malloc((size_t)SBSZ);
    outbuf = (uch *)malloc((size_t)LZMA_ZIP_OUTBUF);
    if (inbuf == NULL || outbuf == NULL) {
        lzma_end(&strm);
        free(inbuf);
        free(outbuf);
        ziperr(ZE_MEM, "allocating XZ compression buffers");
    }

    small_store_init(&store_test, (size_t)SBSZ);
    output_size = 0;
    strm.next_out = (uint8_t *)outbuf;
    strm.avail_out = (size_t)LZMA_ZIP_OUTBUF;
    done = FALSE;

    while (!done) {
        got = small_store_read(&store_test, (char *)inbuf, SBSZ);
        if (got == (unsigned)EOF)
            got = 0;
        if (got != 0 && file_binary_final == 0 &&
            !is_text_buf((char *)inbuf, got))
            file_binary_final = 1;

        strm.next_in = (const uint8_t *)inbuf;
        strm.avail_in = (size_t)got;
        do {
            lr = lzma_code(&strm, got == 0 ? LZMA_FINISH : LZMA_RUN);
            if (lr != LZMA_OK && lr != LZMA_STREAM_END) {
                lzma_end(&strm);
                small_store_discard(&store_test);
                free(inbuf);
                free(outbuf);
                if (lr == LZMA_MEM_ERROR)
                    ziperr(ZE_MEM, "compressing with XZ");
                ziperr(ZE_LOGIC, "liblzma XZ compression failed");
            }

            produced = LZMA_ZIP_OUTBUF - (unsigned)strm.avail_out;
            if (produced != 0 &&
                (strm.avail_out == 0 || lr == LZMA_STREAM_END)) {
                if (small_store_write(&store_test, outbuf, produced) != produced) {
                    lzma_end(&strm);
                    small_store_discard(&store_test);
                    free(inbuf);
                    free(outbuf);
                    ziperr(ZE_TEMP, "error writing XZ data to zipfile");
                }
                output_size += (zoff_t)produced;
                strm.next_out = (uint8_t *)outbuf;
                strm.avail_out = (size_t)LZMA_ZIP_OUTBUF;
            }
        } while (strm.avail_in != 0 ||
                 (got == 0 && lr != LZMA_STREAM_END));

        if (got == 0)
            done = TRUE;
    }

    lzma_end(&strm);
    free(inbuf);
    free(outbuf);
    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    return small_store_finish(&store_test, cmpr_method, output_size);
}

#endif /* LZMA_SUPPORT */

#ifdef ZSTD_SUPPORT
#define ZSTD_ZIP_OUTBUF 16384U

/* ZIP method 93: one standard Zstandard frame per ZIP member.  Deprecated
 * method 20 is accepted by UnZip but is never created by Zip.
 *
 * Interoperability profile: WinZip method-93 examples use version-needed 2.0
 * and omit the optional Zstd frame checksum.  Python 3.14 currently chooses
 * version-needed 6.3; this implementation deliberately follows WinZip and
 * documents that choice in the local-header setup above.  The ZIP member's
 * CRC-32 remains the outer integrity check.  Revisit these choices if future
 * interoperability evidence requires it.
 *
 * Generic Zip levels map directly: -1..-9 -> Zstd 1..9, while -11 maps to
 * native Zstd level 22 (Ultra).  --zstd-level 1..22 bypasses this mapping.
 * The mapping is explicit project policy and may be tuned later. */
local zoff_t zstdfilecompress(z_entry, cmpr_method, pledged_size)
    struct zlist far *z_entry;
    int *cmpr_method;
    zoff_t pledged_size;
{
    ZSTD_CCtx *cctx;
    ZSTD_inBuffer input;
    ZSTD_outBuffer output;
    struct small_store_state store_test;
    uch *inbuf;
    uch *outbuf;
    unsigned got;
    int lev;
    int done;
    size_t zr;
    zoff_t output_size;

    lev = zstd_level != 0 ? zstd_level :
          (level == 11 ? 22 :
           ((level >= 1 && level <= 9) ? level : 6));

    cctx = ZSTD_createCCtx();
    if (cctx == NULL)
        ziperr(ZE_MEM, "initializing Zstandard compressor");

    zr = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, lev);
    if (ZSTD_isError(zr)) {
        ZSTD_freeCCtx(cctx);
        ziperr(ZE_LOGIC, "setting Zstandard compression level");
    }
    zr = ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0);
    if (ZSTD_isError(zr)) {
        ZSTD_freeCCtx(cctx);
        ziperr(ZE_LOGIC, "disabling Zstandard frame checksum");
    }
    if (pledged_size >= 0) {
        zr = ZSTD_CCtx_setPledgedSrcSize(cctx,
                                         (unsigned long long)pledged_size);
        if (ZSTD_isError(zr)) {
            ZSTD_freeCCtx(cctx);
            ziperr(ZE_LOGIC, "setting Zstandard input size");
        }
    }

    inbuf = (uch *)malloc((size_t)SBSZ);
    outbuf = (uch *)malloc((size_t)ZSTD_ZIP_OUTBUF);
    if (inbuf == NULL || outbuf == NULL) {
        ZSTD_freeCCtx(cctx);
        free(inbuf);
        free(outbuf);
        ziperr(ZE_MEM, "allocating Zstandard compression buffers");
    }

    small_store_init(&store_test, (size_t)SBSZ);
    output_size = 0;
    done = FALSE;

    while (!done) {
        got = small_store_read(&store_test, (char *)inbuf, SBSZ);
        if (got == (unsigned)EOF)
            got = 0;
        if (got != 0 && file_binary_final == 0 &&
            !is_text_buf((char *)inbuf, got))
            file_binary_final = 1;

        input.src = (const void *)inbuf;
        input.size = (size_t)got;
        input.pos = 0;

        do {
            output.dst = (void *)outbuf;
            output.size = (size_t)ZSTD_ZIP_OUTBUF;
            output.pos = 0;
            zr = ZSTD_compressStream2(cctx, &output, &input,
                                      got == 0 ? ZSTD_e_end : ZSTD_e_continue);
            if (ZSTD_isError(zr)) {
                ZSTD_freeCCtx(cctx);
                small_store_discard(&store_test);
                free(inbuf);
                free(outbuf);
                ziperr(ZE_LOGIC, "libzstd compression failed");
            }
            if (output.pos != 0) {
                if (small_store_write(&store_test, outbuf,
                                      (unsigned)output.pos) !=
                    (unsigned)output.pos) {
                    ZSTD_freeCCtx(cctx);
                    small_store_discard(&store_test);
                    free(inbuf);
                    free(outbuf);
                    ziperr(ZE_TEMP, "error writing Zstandard data to zipfile");
                }
                output_size += (zoff_t)output.pos;
            }
        } while (input.pos != input.size || (got == 0 && zr != 0));

        if (got == 0)
            done = TRUE;
    }

    ZSTD_freeCCtx(cctx);
    free(inbuf);
    free(outbuf);
    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    return small_store_finish(&store_test, cmpr_method, output_size);
}
#endif /* ZSTD_SUPPORT */

#ifdef USE_ZLIB

local int zl_deflate_init(pack_level)
    int pack_level;
{
    unsigned i;
    int windowBits;
    int err = Z_OK;
    int zp_err = ZE_OK;

    if (zlib_version[0] != ZLIB_VERSION[0]) {
        sprintf(errbuf, "incompatible zlib version (expected %s, found %s)",
              ZLIB_VERSION, zlib_version);
        zp_err = ZE_LOGIC;
    } else if (strcmp(zlib_version, ZLIB_VERSION) != 0) {
        fprintf(mesg,
                "\twarning:  different zlib version (expected %s, using %s)\n",
                ZLIB_VERSION, zlib_version);
    }

    /* windowBits = log2(WSIZE) */
    for (i = ((unsigned)WSIZE), windowBits = 0; i != 1; i >>= 1, ++windowBits);

    zstrm.zalloc = (alloc_func)Z_NULL;
    zstrm.zfree = (free_func)Z_NULL;

    Trace((stderr, "initializing deflate()\n"));
    err = deflateInit2(&zstrm, pack_level, Z_DEFLATED, -windowBits, 8, 0);

    if (err == Z_MEM_ERROR) {
        sprintf(errbuf, "cannot initialize zlib deflate");
        zp_err = ZE_MEM;
    } else if (err != Z_OK) {
        sprintf(errbuf, "zlib deflateInit failure (%d)", err);
        zp_err = ZE_LOGIC;
    }

    deflInit = TRUE;
    return zp_err;
}


void zl_deflate_free()
{
    int err;

    if (f_obuf != NULL) {
        free(f_obuf);
        f_obuf = NULL;
    }
    if (f_ibuf != NULL) {
        free(f_ibuf);
        f_ibuf = NULL;
    }
    if (deflInit) {
        err = deflateEnd(&zstrm);
        if (err != Z_OK && err !=Z_DATA_ERROR) {
            ziperr(ZE_LOGIC, "zlib deflateEnd failed");
        }
        deflInit = FALSE;
    }
}

#else /* !USE_ZLIB */

# ifdef ZP_NEED_MEMCOMPR
/* ===========================================================================
 * In-memory read function. As opposed to file_read(), this function
 * does not perform end-of-line translation, and does not update the
 * crc and input size.
 *    Note that the size of the entire input buffer is an unsigned long,
 * but the size used in mem_read() is only an unsigned int. This makes a
 * difference on 16 bit machines. mem_read() may be called several
 * times for an in-memory compression.
 */
local unsigned mem_read(b, bsize)
     char *b;
     unsigned bsize;
{
    if (in_offset < in_size) {
        ulg block_size = in_size - in_offset;
        if (block_size > (ulg)bsize) block_size = (ulg)bsize;
        memcpy(b, in_buf + in_offset, (unsigned)block_size);
        in_offset += (unsigned)block_size;
        return (unsigned)block_size;
    } else {
        return 0; /* end of input */
    }
}
# endif /* ZP_NEED_MEMCOMPR */


/* ===========================================================================
 * Flush the current output buffer.
 */
void flush_outbuf(o_buf, o_idx)
    char *o_buf;
    unsigned *o_idx;
{
    if (y == NULL) {
        error("output buffer too small for in-memory compression");
    }
    /* Encrypt and write the output buffer: */
    if (*o_idx != 0) {
        zfwrite(o_buf, 1, (extent)*o_idx);
        if (ferror(y)) ziperr(ZE_WRITE, "write error on zip file");
    }
    *o_idx = 0;
}

/* ===========================================================================
 * Return true if the zip file can be seeked. This is used to check if
 * the local header can be re-rewritten. This function always returns
 * true for in-memory compression.
 * IN assertion: the local header has already been written (ftell() > 0).
 */
int seekable()
{
    return fseekable(y);
}
#endif /* ?USE_ZLIB */


#ifdef ZOPFLI_SUPPORT

/* Zopfli's raw Deflate part API can use at most the Deflate-standard 32 KiB
 * history window.  The 1,000,000-byte master chunk matches upstream Zopfli's
 * own large-input partitioning, while a full-read helper makes chunk
 * boundaries independent of short reads from pipes or devices. */
#define ZOPFLI_ZIP_HISTORY 32768U
#define ZOPFLI_ZIP_CHUNK   1000000UL

local size_t zopfli_read_chunk(store_test, buf, capacity, at_eof)
    struct small_store_state *store_test;
    uch *buf;
    size_t capacity;
    int *at_eof;
{
    size_t total;

    total = 0;
    *at_eof = 0;
    while (total < capacity) {
        unsigned want;
        unsigned got;

        want = (unsigned)(capacity - total);
        got = small_store_read(store_test, (char *)buf + total, want);
        if (got == (unsigned)EOF || got == 0) {
            *at_eof = 1;
            break;
        }
        if (file_binary_final == 0 &&
            !is_text_buf((char *)buf + total, got))
            file_binary_final = 1;
        total += (size_t)got;
    }
    return total;
}

local void zopfli_write_part(store_test, options, final, in, instart, inend,
                             bp, carry, total_out)
    struct small_store_state *store_test;
    ZopfliOptions *options;
    int final;
    ZCONST uch *in;
    size_t instart;
    size_t inend;
    uch *bp;
    uch *carry;
    zoff_t *total_out;
{
    uch *out;
    size_t outsize;
    size_t write_size;

    out = NULL;
    outsize = 0;

    /* If the preceding part ended in a partial byte, seed the new dynamic
     * output with that byte.  Zopfli then continues writing at *bp. */
    if (*bp != 0) {
        out = (uch *)malloc(1);
        if (out == NULL)
            ziperr(ZE_MEM, "allocating Zopfli output carry byte");
        out[0] = *carry;
        outsize = 1;
    }

    ZopfliDeflatePart(options, 2, final, in, instart, inend,
                      bp, &out, &outsize);

    if (final || *bp == 0) {
        write_size = outsize;
    } else {
        Assert(outsize != 0, "Zopfli partial output missing carry byte");
        write_size = outsize - 1;
        *carry = out[outsize - 1];
    }

    if (write_size != 0) {
        if (small_store_write(store_test, out, (unsigned)write_size) !=
            (unsigned)write_size) {
            free(out);
            ziperr(ZE_TEMP, "error writing Zopfli data to zipfile");
        }
        *total_out += (zoff_t)write_size;
    }
    free(out);
}

local zoff_t zopflifilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    ZopfliOptions options;
    struct small_store_state store_test;
    uch *work;
    uch *next;
    size_t history;
    size_t current_size;
    size_t next_size;
    int current_eof;
    int next_eof;
    uch bp;
    uch carry;
    zoff_t total_out;
    zoff_t processed;
    unsigned mrk_cnt;

    small_store_init(&store_test, (size_t)SBSZ);

    work = (uch *)malloc((size_t)ZOPFLI_ZIP_HISTORY +
                         (size_t)ZOPFLI_ZIP_CHUNK);
    next = (uch *)malloc((size_t)ZOPFLI_ZIP_CHUNK);
    if (work == NULL || next == NULL) {
        free(work);
        free(next);
        small_store_discard(&store_test);
        ziperr(ZE_MEM, "allocating Zopfli input buffers");
    }

    ZopfliInitOptions(&options);
    options.numiterations = zopfli_iterations;

    history = 0;
    bp = 0;
    carry = 0;
    total_out = 0;
    processed = 0;
    mrk_cnt = 1;

    current_size = zopfli_read_chunk(&store_test, work,
                                     (size_t)ZOPFLI_ZIP_CHUNK,
                                     &current_eof);
    next_size = 0;
    next_eof = 0;
    if (!current_eof)
        next_size = zopfli_read_chunk(&store_test, next,
                                      (size_t)ZOPFLI_ZIP_CHUNK,
                                      &next_eof);

    for (;;) {
        int final;

        final = current_eof || (next_eof && next_size == 0);
        zopfli_write_part(&store_test, &options, final, work, history,
                          history + current_size, &bp, &carry, &total_out);
        processed += (zoff_t)current_size;

        if (verbose || noisy) {
            while ((unsigned)(processed / (zoff_t)(ulg)WSIZE) > mrk_cnt) {
                mrk_cnt++;
                if (!display_globaldots) {
                    if (dot_size > 0) {
                        if (noisy && dot_count == -1) {
#ifndef WINDLL
                            putc(' ', mesg);
                            fflush(mesg);
#else
                            fprintf(stdout, "%c", ' ');
#endif
                            dot_count++;
                        }
                        dot_count++;
                        if (dot_size <= (dot_count + 1) * WSIZE)
                            dot_count = 0;
                    }
                    if (noisy && dot_size && !dot_count) {
#ifndef WINDLL
                        putc('.', mesg);
                        fflush(mesg);
#else
                        fprintf(stdout, "%c", '.');
#endif
                        mesg_line_started = 1;
                    }
                }
            }
        }

        if (final)
            break;

        {
            size_t keep;
            size_t available;

            available = history + current_size;
            keep = available < (size_t)ZOPFLI_ZIP_HISTORY ?
                   available : (size_t)ZOPFLI_ZIP_HISTORY;
            if (keep != 0)
                memmove(work, work + available - keep, keep);
            history = keep;
        }

        memcpy(work + history, next, next_size);
        current_size = next_size;
        current_eof = next_eof;

        next_size = 0;
        next_eof = 0;
        if (!current_eof)
            next_size = zopfli_read_chunk(&store_test, next,
                                          (size_t)ZOPFLI_ZIP_CHUNK,
                                          &next_eof);
    }

    free(next);
    free(work);

    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    z_entry->flg |= 2;               /* maximum-compression Deflate marker */
    return small_store_finish(&store_test, cmpr_method, total_out);
}
#endif /* ZOPFLI_SUPPORT */

#ifdef DEFLATE64_SUPPORT
struct d64_zip_state {
    struct small_store_state *store_test;
    zoff_t output_size;
    int write_error;
};

static unsigned d64_zip_read(void *opaque, unsigned char *buf, unsigned size)
{
    struct d64_zip_state *s;
    unsigned got;

    s = (struct d64_zip_state *)opaque;
    got = small_store_read(s->store_test, (char *)buf, size);
    if (got == (unsigned)EOF)
        return 0U;
    if (got != 0U && file_binary_final == 0 &&
        !is_text_buf((char *)buf, got))
        file_binary_final = 1;
    return got;
}

static int d64_zip_write(void *opaque, const unsigned char *buf, unsigned size)
{
    struct d64_zip_state *s;

    s = (struct d64_zip_state *)opaque;
    if (s->write_error)
        return 1;
    if (size != 0U && small_store_write(s->store_test, (zvoid *)buf, size) != size) {
        s->write_error = 1;
        return 1;
    }
    s->output_size += (zoff_t)size;
    return 0;
}

local zoff_t deflate64filecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    struct small_store_state store_test;
    struct d64_zip_state state;
    d64_stats stats;
    int lev;
    int r;
    zoff_t result;

    lev = level;
    if (lev < 1 || (lev > 9 && lev != 11))
        ziperr(ZE_LOGIC, "invalid Deflate64 compression level");

    small_store_init(&store_test, (size_t)SBSZ);
    state.store_test = &store_test;
    state.output_size = 0;
    state.write_error = 0;
    memset(&stats, 0, sizeof(stats));

    r = d64_encode(d64_zip_read, d64_zip_write, &state, lev, &stats);
    if (state.write_error || r == 2) {
        small_store_discard(&store_test);
        ziperr(ZE_TEMP, "error writing Deflate64 data to zipfile");
    }
    if (r == 1) {
        small_store_discard(&store_test);
        ziperr(ZE_MEM, "Deflate64 compression failed");
    }
    if (r != 0) {
        small_store_discard(&store_test);
        ziperr(ZE_LOGIC, "Deflate64 compression failed");
    }

    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    if (lev <= 2)
        z_entry->flg |= 4;
    else if (lev >= 8)
        z_entry->flg |= 2;

    result = small_store_finish(&store_test, cmpr_method, state.output_size);
    if (*cmpr_method == STORE)
        z_entry->flg &= ~6;
    return result;
}
#endif /* DEFLATE64_SUPPORT */

#ifdef SHRINK_SUPPORT
struct shk_zip_state {
    struct small_store_state *store_test;
    zoff_t written;
    int error;
};

static unsigned shk_zip_read(void *opaque, unsigned char *buf, unsigned size)
{
    struct shk_zip_state *s;
    unsigned n;
    s = (struct shk_zip_state *)opaque;
    n = small_store_read(s->store_test, (char *)buf, size);
    if (n != (unsigned)EOF && n != 0U && file_binary_final == 0 &&
        !is_text_buf((char *)buf, n)) file_binary_final = 1;
    return n;
}

static int shk_zip_write(void *opaque, const unsigned char *buf, unsigned n)
{
    struct shk_zip_state *s;
    s = (struct shk_zip_state *)opaque;
    if (s->error) return 1;
    if (n != 0U && small_store_write(s->store_test, (zvoid *)buf, n) != n) {
        s->error = 1;
        return 1;
    }
    s->written += (zoff_t)n;
    return 0;
}

local zoff_t shrinkfilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    struct small_store_state store_test;
    struct shk_zip_state state;
    int r;
    zoff_t result;

    small_store_init(&store_test, (size_t)SBSZ);
    state.store_test = &store_test;
    state.error = 0;
    state.written = 0;
    r = shk_encode(shk_zip_read, shk_zip_write, &state);
    if (r != 0 || state.error) {
        small_store_discard(&store_test);
        if (r == 1) ziperr(ZE_MEM, "allocating Shrink dictionary");
        ziperr(ZE_TEMP, "Shrink compression I/O failure");
    }
    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    result = small_store_finish(&store_test, cmpr_method, state.written);
    if (*cmpr_method == STORE) z_entry->flg &= ~6;
    return result;
}
#endif /* SHRINK_SUPPORT */

#ifdef REDUCE_SUPPORT
struct red_zip_state {
    struct small_store_state *store_test;
    zoff_t written;
    int error;
};

static unsigned red_zip_read(void *opaque, unsigned char *buf, unsigned size)
{
    struct red_zip_state *s;
    unsigned n;
    s = (struct red_zip_state *)opaque;
    n = small_store_read(s->store_test, (char *)buf, size);
    if (n != (unsigned)EOF && n != 0U && file_binary_final == 0 &&
        !is_text_buf((char *)buf, n)) file_binary_final = 1;
    return n;
}

static int red_zip_write(void *opaque, const unsigned char *buf, unsigned n)
{
    struct red_zip_state *s;
    s = (struct red_zip_state *)opaque;
    if (s->error) return 1;
    if (n != 0U && small_store_write(s->store_test, (zvoid *)buf, n) != n) {
        s->error = 1;
        return 1;
    }
    s->written += (zoff_t)n;
    return 0;
}

local zoff_t reducefilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    struct small_store_state store_test;
    struct red_zip_state state;
    int r;
    unsigned factor;
    zoff_t result;

    /* -1/-2 => 1, -3/-4 => 2, -5/-6 => 3, -7/-8/-9 => 4.
     * The extra -11 effort level uses factor 4, like other codecs. */
    factor = level >= 7 ? 4U : (level >= 5 ? 3U : (level >= 3 ? 2U : 1U));
    small_store_init(&store_test, (size_t)SBSZ);
    state.store_test = &store_test;
    state.written = 0;
    state.error = 0;
    r = red_encode(red_zip_read, red_zip_write, &state, factor);
    if (r != 0 || state.error) {
        small_store_discard(&store_test);
        if (r == 1) ziperr(ZE_TEMP, "allocating Reduce workspace or temporary file");
        ziperr(ZE_TEMP, "Reduce compression I/O failure");
    }
    *cmpr_method = (int)(REDUCE1 + factor - 1U);
    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    result = small_store_finish(&store_test, cmpr_method, state.written);
    if (*cmpr_method == STORE) z_entry->flg &= ~6;
    return result;
}
#endif /* REDUCE_SUPPORT */

#ifdef IMPLODE_SUPPORT
struct im6_zip_state {
    struct small_store_state *store_test;
    zoff_t written;
    int error;
};
static unsigned im6_zip_read(void *opaque, unsigned char *buf, unsigned n)
{
    struct im6_zip_state *s = (struct im6_zip_state *)opaque;
    unsigned got = small_store_read(s->store_test, (char *)buf, n);
    if (got != (unsigned)EOF && got != 0U && !file_binary_final &&
        !is_text_buf((char *)buf, got)) file_binary_final = 1;
    return got;
}
static int im6_zip_write(void *opaque, const unsigned char *buf, unsigned n)
{
    struct im6_zip_state *s = (struct im6_zip_state *)opaque;
    if (s->error) return 1;
    if (n && small_store_write(s->store_test, (zvoid *)buf, n) != n) {
        s->error = 1;
        return 1;
    }
    s->written += (zoff_t)n;
    return 0;
}
local zoff_t implodefilecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
    struct small_store_state store_test;
    struct im6_zip_state state;
    unsigned window = level >= 5 ? 8192U : 4096U;
    unsigned trees = ((level >= 3 && level <= 4) || level >= 8) ? 3U : 2U;
    int r;
    zoff_t result;
    small_store_init(&store_test, (size_t)SBSZ);
    state.store_test = &store_test;
    state.written = 0;
    state.error = 0;
    r = im6_encode(im6_zip_read, im6_zip_write, &state, window, trees);
    if (r != 0 || state.error) {
        small_store_discard(&store_test);
        if (r == 1) ziperr(ZE_TEMP, "allocating Implode workspace or temporary file");
        ziperr(ZE_TEMP, "Implode compression I/O failure");
    }
    z_entry->att = (ush)(file_binary_final ? BINARY : ASCII);
    result = small_store_finish(&store_test, cmpr_method, state.written);
    if (*cmpr_method == STORE) z_entry->flg &= ~6;
    return result;
}
#endif /* IMPLODE_SUPPORT */

/* ===========================================================================
 * Compression to archive file.
 */
local zoff_t filecompress(z_entry, cmpr_method)
    struct zlist far *z_entry;
    int *cmpr_method;
{
#ifdef ZOPFLI_SUPPORT
    if (level == 11)
        return zopflifilecompress(z_entry, cmpr_method);
#endif
#ifdef USE_ZLIB
    int err = Z_OK;
    unsigned mrk_cnt = 1;
    int maybe_stored = FALSE;
    ulg cmpr_size;
#if defined(MMAP) || defined(BIG_MEM)
    unsigned ibuf_sz = (unsigned)SBSZ;
#else
#   define ibuf_sz ((unsigned)SBSZ)
#endif
#ifndef OBUF_SZ
#  define OBUF_SZ ZBSZ
#endif
    unsigned u;

#if defined(MMAP) || defined(BIG_MEM)
    if (remain == (ulg)-1L && f_ibuf == NULL)
#else /* !(MMAP || BIG_MEM */
    if (f_ibuf == NULL)
#endif /* MMAP || BIG_MEM */
        f_ibuf = (char *)malloc(SBSZ);
    if (f_obuf == NULL)
        f_obuf = (char *)malloc(OBUF_SZ);
#if defined(MMAP) || defined(BIG_MEM)
    if ((remain == (ulg)-1L && f_ibuf == NULL) || f_obuf == NULL)
#else /* !(MMAP || BIG_MEM */
    if (f_ibuf == NULL || f_obuf == NULL)
#endif /* MMAP || BIG_MEM */
        ziperr(ZE_MEM, "allocating zlib file-I/O buffers");

    if (!deflInit) {
        err = zl_deflate_init(level);
        if (err != ZE_OK)
            ziperr(err, errbuf);
    }

    if (level <= 2) {
        z_entry->flg |= 4;
    } else if (level >= 8) {
        z_entry->flg |= 2;
    }
#if defined(MMAP) || defined(BIG_MEM)
    if (remain != (ulg)-1L) {
        zstrm.next_in = (Bytef *)window;
        ibuf_sz = (unsigned)WSIZE;
    } else
#endif /* MMAP || BIG_MEM */
    {
        zstrm.next_in = (Bytef *)f_ibuf;
    }
    zstrm.avail_in = file_read(zstrm.next_in, ibuf_sz);
    if (zstrm.avail_in < ibuf_sz) {
        unsigned more = file_read(zstrm.next_in + zstrm.avail_in,
                                  (ibuf_sz - zstrm.avail_in));
        if (more == EOF || more == 0) {
            maybe_stored = TRUE;
        } else {
            zstrm.avail_in += more;
        }
    }
    zstrm.next_out = (Bytef *)f_obuf;
    zstrm.avail_out = OBUF_SZ;

    if (!maybe_stored) while (zstrm.avail_in != 0 && zstrm.avail_in != EOF) {
        err = deflate(&zstrm, Z_NO_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) {
            sprintf(errbuf, "unexpected zlib deflate error %d", err);
            ziperr(ZE_LOGIC, errbuf);
        }
        if (zstrm.avail_out == 0) {
            if (zfwrite(f_obuf, 1, OBUF_SZ) != OBUF_SZ) {
                ziperr(ZE_TEMP, "error writing to zipfile");
            }
            zstrm.next_out = (Bytef *)f_obuf;
            zstrm.avail_out = OBUF_SZ;
        }
        if (zstrm.avail_in == 0) {
            if (verbose || noisy)
                while((unsigned)(zstrm.total_in / (uLong)WSIZE) > mrk_cnt) {
                    mrk_cnt++;
                    if (!display_globaldots) {
                      if (dot_size > 0) {
                        /* initial space */
                        if (noisy && dot_count == -1) {
#ifndef WINDLL
                          putc(' ', mesg);
                          fflush(mesg);
#else
                          fprintf(stdout,"%c",' ');
#endif
                          dot_count++;
                        }
                        dot_count++;
                        if (dot_size <= (dot_count + 1) * WSIZE) dot_count = 0;
                      }
                      if (noisy && dot_size && !dot_count) {
#ifndef WINDLL
                        putc('.', mesg);
                        fflush(mesg);
#else
                        fprintf(stdout,"%c",'.');
#endif
                        mesg_line_started = 1;
                      }
                    }
                }
#if defined(MMAP) || defined(BIG_MEM)
            if (remain == (ulg)-1L)
                zstrm.next_in = (Bytef *)f_ibuf;
#else
            zstrm.next_in = (Bytef *)f_ibuf;
#endif
            zstrm.avail_in = file_read(zstrm.next_in, ibuf_sz);
        }
    }

    do {
        err = deflate(&zstrm, Z_FINISH);
        if (maybe_stored) {
            if (err == Z_STREAM_END && zstrm.total_out >= zstrm.total_in &&
                fseekable(zipfile)) {
                /* deflation does not reduce size, switch to STORE method */
                unsigned len_out = (unsigned)zstrm.total_in;
                if (zfwrite(f_ibuf, 1, len_out) != len_out) {
                    ziperr(ZE_TEMP, "error writing to zipfile");
                }
                zstrm.total_out = (uLong)len_out;
                *cmpr_method = STORE;
                break;
            } else {
                maybe_stored = FALSE;
            }
        }
        if (zstrm.avail_out < OBUF_SZ) {
            unsigned len_out = OBUF_SZ - zstrm.avail_out;
            if (zfwrite(f_obuf, 1, len_out) != len_out) {
                ziperr(ZE_TEMP, "error writing to zipfile");
            }
            zstrm.next_out = (Bytef *)f_obuf;
            zstrm.avail_out = OBUF_SZ;
        }
    } while (err == Z_OK);

    if (err != Z_STREAM_END) {
        sprintf(errbuf, "unexpected zlib deflate error %d", err);
        ziperr(ZE_LOGIC, errbuf);
    }

    if (z_entry->att == (ush)UNKNOWN)
        z_entry->att = (ush)(zstrm.data_type == Z_ASCII ? ASCII : BINARY);
    cmpr_size = (ulg)zstrm.total_out;

    if ((err = deflateReset(&zstrm)) != Z_OK)
        ziperr(ZE_LOGIC, "zlib deflateReset failed");
    return cmpr_size;
#else /* !USE_ZLIB */

    /* Set the defaults for file compression. */
    read_buf = file_read;

    /* Initialize deflate's internals and execute file compression. */
    bi_init(file_outbuf, sizeof(file_outbuf), TRUE);
    ct_init(&z_entry->att, cmpr_method);
    lm_init(level, &z_entry->flg);
    return deflate();
#endif /* ?USE_ZLIB */
}

#ifdef ZP_NEED_MEMCOMPR
/* ===========================================================================
 * In-memory compression. This version can be used only if the entire input
 * fits in one memory buffer. The compression is then done in a single
 * call of memcompress(). (An extension to allow repeated calls would be
 * possible but is not needed here.)
 * The first two bytes of the compressed output are set to a short with the
 * method used (DEFLATE or STORE). The following four bytes contain the CRC.
 * The values are stored in little-endian order on all machines.
 * This function returns the byte size of the compressed output, including
 * the first six bytes (method and crc).
 */

ulg memcompress(tgt, tgtsize, src, srcsize)
    char *tgt, *src;       /* target and source buffers */
    ulg tgtsize, srcsize;  /* target and source sizes */
{
    ulg crc;
    unsigned out_total;
    int method   = DEFLATE;
    int mem_level = (level == 11 ? 9 : level);
#ifdef USE_ZLIB
    int err      = Z_OK;
#else
    ush att      = (ush)UNKNOWN;
    ush flags    = 0;
#endif

    if (tgtsize <= (ulg)6L) error("target buffer too small");
    out_total = 2 + 4;

#ifdef USE_ZLIB
    if (!deflInit) {
        err = zl_deflate_init(mem_level);
        if (err != ZE_OK)
            ziperr(err, errbuf);
    }

    zstrm.next_in = (Bytef *)src;
    zstrm.avail_in = (uInt)srcsize;
    zstrm.next_out = (Bytef *)(tgt + out_total);
    zstrm.avail_out = (uInt)tgtsize - (uInt)out_total;

    err = deflate(&zstrm, Z_FINISH);
    if (err != Z_STREAM_END)
        error("output buffer too small for in-memory compression");
    out_total += (unsigned)zstrm.total_out;

    if ((err = deflateReset(&zstrm)) != Z_OK)
        error("zlib deflateReset failed");
#else /* !USE_ZLIB */
    read_buf  = mem_read;
    in_buf    = src;
    in_size   = (unsigned)srcsize;
    in_offset = 0;
    window_size = 0L;

    bi_init(tgt + (2 + 4), (unsigned)(tgtsize - (2 + 4)), FALSE);
    ct_init(&att, &method);
    lm_init((mem_level != 0 ? mem_level : 1), &flags);
    out_total += (unsigned)deflate();
    window_size = 0L; /* was updated by lm_init() */
#endif /* ?USE_ZLIB */

    crc = CRCVAL_INITIAL;
    crc = crc32(crc, (uch *)src, (extent)srcsize);

    /* For portability, force little-endian order on all machines: */
    tgt[0] = (char)(method & 0xff);
    tgt[1] = (char)((method >> 8) & 0xff);
    tgt[2] = (char)(crc & 0xff);
    tgt[3] = (char)((crc >> 8) & 0xff);
    tgt[4] = (char)((crc >> 16) & 0xff);
    tgt[5] = (char)((crc >> 24) & 0xff);

    return (ulg)out_total;
}
#endif /* ZP_NEED_MEMCOMPR */

#ifdef BZIP2_SUPPORT

local int bz_compress_init(pack_level)
int pack_level;
{
    int err = BZ_OK;
    int zp_err = ZE_OK;
    const char *bzlibVer;

    bzlibVer = BZ2_bzlibVersion();

    /* $TODO - Check BZIP2 LIB version? */

    bstrm.bzalloc = NULL;
    bstrm.bzfree = NULL;
    bstrm.opaque = NULL;

    Trace((stderr, "initializing bzlib compress()\n"));
    err = BZ2_bzCompressInit(&bstrm, pack_level, 0, 30);

    if (err == BZ_MEM_ERROR) {
        sprintf(errbuf, "cannot initialize bzlib compress");
        zp_err = ZE_MEM;
    } else if (err != BZ_OK) {
        sprintf(errbuf, "bzlib bzCompressInit failure (%d)", err);
        zp_err = ZE_LOGIC;
    }

    bzipInit = TRUE;
    return zp_err;
}

void bz_compress_free()
{
    int err;

    if (f_obuf != NULL) {
        free(f_obuf);
        f_obuf = NULL;
    }
    if (f_ibuf != NULL) {
        free(f_ibuf);
        f_ibuf = NULL;
    }
    if (bzipInit) {
        err = BZ2_bzCompressEnd(&bstrm);
        if (err != BZ_OK && err != BZ_DATA_ERROR) {
            ziperr(ZE_LOGIC, "bzlib bzCompressEnd failed");
        }
        bzipInit = FALSE;
    }
}

/* ===========================================================================
 * BZIP2 Compression to archive file.
 */

local zoff_t bzfilecompress(z_entry, cmpr_method)
struct zlist far *z_entry;
int *cmpr_method;
{
    FILE *zipfile = y;

    int err = BZ_OK;
    unsigned mrk_cnt = 1;
    int maybe_stored = FALSE;
    zoff_t cmpr_size;
#if defined(MMAP) || defined(BIG_MEM)
    unsigned ibuf_sz = (unsigned)SBSZ;
#else
#   define ibuf_sz ((unsigned)SBSZ)
#endif
#ifndef OBUF_SZ
#  define OBUF_SZ ZBSZ
#endif

#if defined(MMAP) || defined(BIG_MEM)
    if (remain == (ulg)-1L && f_ibuf == NULL)
#else /* !(MMAP || BIG_MEM */
    if (f_ibuf == NULL)
#endif /* MMAP || BIG_MEM */
        f_ibuf = (char *)malloc(SBSZ);
    if (f_obuf == NULL)
        f_obuf = (char *)malloc(OBUF_SZ);
#if defined(MMAP) || defined(BIG_MEM)
    if ((remain == (ulg)-1L && f_ibuf == NULL) || f_obuf == NULL)
#else /* !(MMAP || BIG_MEM */
    if (f_ibuf == NULL || f_obuf == NULL)
#endif /* MMAP || BIG_MEM */
        ziperr(ZE_MEM, "allocating zlib/bzlib file-I/O buffers");

    if (!bzipInit) {
        err = bz_compress_init(level == 11 ? 9 : level);
        if (err != ZE_OK)
            ziperr(err, errbuf);
    }

#if defined(MMAP) || defined(BIG_MEM)
    if (remain != (ulg)-1L) {
        bstrm.next_in = (Bytef *)window;
        ibuf_sz = (unsigned)WSIZE;
    } else
#endif /* MMAP || BIG_MEM */
    {
        bstrm.next_in = (char *)f_ibuf;
    }
    bstrm.avail_in = file_read(bstrm.next_in, ibuf_sz);
    if (file_binary_final == 0) {
      /* check for binary as library does not */
      if (!is_text_buf(bstrm.next_in, ibuf_sz))
        file_binary_final = 1;
    }
    if (bstrm.avail_in < ibuf_sz) {
        unsigned more = file_read(bstrm.next_in + bstrm.avail_in,
                                  (ibuf_sz - bstrm.avail_in));
        if (more == (unsigned) EOF || more == 0) {
            maybe_stored = TRUE;
        } else {
            bstrm.avail_in += more;
        }
    }
    bstrm.next_out = (char *)f_obuf;
    bstrm.avail_out = OBUF_SZ;

    if (!maybe_stored) {
      while (bstrm.avail_in != 0 && bstrm.avail_in != (unsigned) EOF) {
        err = BZ2_bzCompress(&bstrm, BZ_RUN);
        if (err != BZ_RUN_OK && err != BZ_STREAM_END) {
            sprintf(errbuf, "unexpected bzlib compress error %d", err);
            ziperr(ZE_LOGIC, errbuf);
        }
        if (bstrm.avail_out == 0) {
            if (zfwrite(f_obuf, 1, OBUF_SZ) != OBUF_SZ) {
                ziperr(ZE_TEMP, "error writing to zipfile");
            }
            bstrm.next_out = (char *)f_obuf;
            bstrm.avail_out = OBUF_SZ;
        }
        /* $TODO what about high 32-bits of total-in??? */
        if (bstrm.avail_in == 0) {
            if (verbose || noisy)
#ifdef LARGE_FILE_SUPPORT
                while((unsigned)((bstrm.total_in_lo32
                                  + (((zoff_t)bstrm.total_in_hi32) << 32))
                                 / (zoff_t)(ulg)WSIZE) > mrk_cnt) {
#else
                while((unsigned)(bstrm.total_in_lo32 / (ulg)WSIZE) > mrk_cnt) {
#endif
                    mrk_cnt++;
                    if (!display_globaldots) {
                      if (dot_size > 0) {
                        /* initial space */
                        if (noisy && dot_count == -1) {
#ifndef WINDLL
                          putc(' ', mesg);
                          fflush(mesg);
#else
                          fprintf(stdout,"%c",' ');
#endif
                          dot_count++;
                        }
                        dot_count++;
                        if (dot_size <= (dot_count + 1) * WSIZE) dot_count = 0;
                      }
                      if (noisy && dot_size && !dot_count) {
#ifndef WINDLL
                        putc('.', mesg);
                        fflush(mesg);
#else
                        fprintf(stdout,"%c",'.');
#endif
                        mesg_line_started = 1;
                      }
                    }
                }
#if defined(MMAP) || defined(BIG_MEM)
            if (remain == (ulg)-1L)
                bstrm.next_in = (char *)f_ibuf;
#else
            bstrm.next_in = (char *)f_ibuf;
#endif
            bstrm.avail_in = file_read(bstrm.next_in, ibuf_sz);
            if (file_binary_final == 0) {
              /* check for binary as library does not */
              if (!is_text_buf(bstrm.next_in, ibuf_sz))
                file_binary_final = 1;
            }
        }
      }
    }

    /* binary or text */
    if (file_binary_final)
      /* found binary in file */
      z_entry->att = (ush)BINARY;
    else
      /* text file */
      z_entry->att = (ush)ASCII;

    do {
        err = BZ2_bzCompress(&bstrm, BZ_FINISH);
        if (maybe_stored) {
            /* This code is only executed when the complete data stream fits
               into the input buffer (see above where maybe_stored gets set).
               So, it is safe to assume that total_in_hi32 (and total_out_hi32)
               are 0, because the input buffer size is well below the 32-bit
               limit.
             */
            if (err == BZ_STREAM_END
                && bstrm.total_out_lo32 >= bstrm.total_in_lo32
                && fseekable(zipfile)) {
                /* BZIP2 compress does not reduce size,
                   switch to STORE method */
                unsigned len_out = (unsigned)bstrm.total_in_lo32;
                if (zfwrite(f_ibuf, 1, len_out) != len_out) {
                    ziperr(ZE_TEMP, "error writing to zipfile");
                }
                bstrm.total_out_lo32 = (ulg)len_out;
                *cmpr_method = STORE;
                break;
            } else {
                maybe_stored = FALSE;
            }
        }
        if (bstrm.avail_out < OBUF_SZ) {
            unsigned len_out = OBUF_SZ - bstrm.avail_out;
            if (zfwrite(f_obuf, 1, len_out) != len_out) {
                ziperr(ZE_TEMP, "error writing to zipfile");
            }
            bstrm.next_out = (char *)f_obuf;
            bstrm.avail_out = OBUF_SZ;
        }
    } while (err == BZ_FINISH_OK);

    if (err < BZ_OK) {
        sprintf(errbuf, "unexpected bzlib compress error %d", err);
        ziperr(ZE_LOGIC, errbuf);
    }

    if (z_entry->att == (ush)UNKNOWN)
        z_entry->att = (ush)BINARY;
#ifdef LARGE_FILE_SUPPORT
    cmpr_size = (zoff_t)bstrm.total_out_lo32
               + (((zoff_t)bstrm.total_out_hi32) << 32);
#else
    cmpr_size = (zoff_t)bstrm.total_out_lo32;
#endif

    if ((err = BZ2_bzCompressEnd(&bstrm)) != BZ_OK)
        ziperr(ZE_LOGIC, "zlib deflateReset failed");
    bzipInit = FALSE;
    return cmpr_size;
}

#endif /* BZIP2_SUPPORT */
#endif /* !UTIL */
