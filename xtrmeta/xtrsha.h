/* MIT-0. Pure ANSI C89 SHA-256 for XTRO manifest digests. */
#ifndef XTRSHA_H
# define XTRSHA_H
# include <stddef.h>
typedef struct xtr_sha256
{
  unsigned long h[8], bytes_lo, bytes_hi;
  unsigned char block[64];
  unsigned used;
} xtr_sha256;
void xtr_sha256_init (xtr_sha256 *s);
void xtr_sha256_update (xtr_sha256 *s, const unsigned char *p, size_t n);
void xtr_sha256_final (xtr_sha256 *s, unsigned char digest[32]);
#endif /* ifndef XTRSHA_H */
