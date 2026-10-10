#ifndef IZ_NATIVE_ZLIBNG_H
# define IZ_NATIVE_ZLIBNG_H
# include <zlib-ng.h>
typedef zng_stream z_stream;
typedef uint8_t Bytef;
typedef uint32_t uInt;
typedef unsigned long uLong;
# ifndef FAR
#  define FAR
# endif /* ifndef FAR */
# define zlib_version zlibng_version ()
# define ZLIB_VERSION ZLIBNG_VERSION
# define ZLIB_VERNUM 0x1300
# define zlibVersion zlibng_version
# define deflateInit2 zng_deflateInit2
# define deflate zng_deflate
# define deflateReset zng_deflateReset
# define deflateEnd zng_deflateEnd
# define inflateBackInit zng_inflateBackInit
# define inflateBack zng_inflateBack
# define inflateBackEnd zng_inflateBackEnd
# define inflateInit2 zng_inflateInit2
# define inflate zng_inflate
# define inflateEnd zng_inflateEnd
# define crc32(crc, buf, len) \
  zng_crc32_z ((uint32_t)(crc), (const uint8_t *)(buf), (size_t)(len))
#endif /* ifndef IZ_NATIVE_ZLIBNG_H */
