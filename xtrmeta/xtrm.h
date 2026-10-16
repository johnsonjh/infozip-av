/* Xtro-ZIP standalone M0/M1 wire-format experiment. NOT PRODUCTION FORMAT. */
/* SPDX-License-Identifier: MIT-0 */
#ifndef XTRM_H
# define XTRM_H
# include <stddef.h>

typedef struct xtr_u64
{
  unsigned long lo;
  unsigned long hi;
} xtr_u64;
typedef struct xtr_manifest
{
  unsigned char owner[16];
  unsigned long count;
  xtr_u64 records_len;
} xtr_manifest;
typedef struct xtr_record
{
  unsigned type;
  unsigned flags;
  unsigned origin;
  unsigned encoding;
  unsigned long ns_len;
  unsigned long name_len;
  unsigned long native_len;
  xtr_u64 value_len;
} xtr_record;
typedef struct xtr_extra
{
  unsigned char owner[16];
  unsigned mode;
  unsigned flags;
  unsigned long count;
  xtr_u64 manifest_len;
  unsigned long crc32;
} xtr_extra;
typedef size_t (*xtr_read_cb) (void *, unsigned char *, size_t);
/* field=0 namespace,1 name,2 platform-native TLVs,3 binary value */
typedef int (*xtr_data_cb) (void *, const xtr_record *, unsigned field,
                            const unsigned char *, size_t);
typedef int (*xtr_begin_cb) (void *, const xtr_record *);
typedef struct xtr_reader
{
  void *context;
  xtr_read_cb read;
  void *sink_context;
  xtr_begin_cb begin;
  xtr_data_cb data;
  unsigned long max_records;
  unsigned long max_field;
  xtr_u64 max_total;
} xtr_reader;
/* 0 success, 1 corrupt/truncated, 2 resource limit, 3 callback IO error,
 * 4 unsupported wire version or layout. No function exits/aborts/allocates. */
# define XTR_OK 0
# define XTR_CORRUPT 1
# define XTR_LIMIT 2
# define XTR_IO 3
# define XTR_UNSUPPORTED 4

int xtr_manifest_header (unsigned char out[36], const xtr_manifest *m);
int xtr_record_header (unsigned char out[28], const xtr_record *r);
int xtr_parse_manifest (xtr_reader *r, xtr_u64 total, xtr_manifest *m);
int xtr_extra_write (unsigned char out[], const xtr_extra *e, int central,
                     const unsigned char *inline_data, size_t inline_len,
                     size_t capacity, size_t *written);
int xtr_extra_read (const unsigned char *src, size_t size, int central,
                    xtr_extra *e);
unsigned long xtr_crc32_update (unsigned long crc, const unsigned char *p,
                                size_t n);
#endif /* ifndef XTRM_H */
