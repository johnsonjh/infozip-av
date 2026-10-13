/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#include <limits.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "zip_deflate.h"

#define deflate zo_legacy_deflate
#define lm_init zo_legacy_lm_init
#define lm_free zo_legacy_lm_free
#define longest_match zo_legacy_longest_match
#define ct_init zo_legacy_ct_init
#define ct_tally zo_legacy_ct_tally
#define flush_block zo_legacy_flush_block
#define bi_init zo_legacy_bi_init
#define strstart zo_legacy_strstart
#define match_start zo_legacy_match_start
#define prev_length zo_legacy_prev_length
#define max_chain_length zo_legacy_max_chain_length
#define nice_match zo_legacy_nice_match
#define good_match zo_legacy_good_match
#define window zo_legacy_window
#define head zo_legacy_head
#define prev zo_legacy_prev
#define window_size zo_legacy_window_size
#define block_start zo_legacy_block_start
#define read_buf zo_legacy_read_buf
#define flush_outbuf zo_legacy_flush_outbuf
#define seekable zo_legacy_seekable
#define error zo_legacy_error
#define level zo_legacy_level
#define noisy zo_legacy_noisy
#define verbose zo_legacy_verbose
#define mesg zo_legacy_mesg
#define dot_size zo_legacy_dot_size
#define dot_count zo_legacy_dot_count
#define mesg_line_started zo_legacy_mesg_line_started
#define key zo_legacy_key
#define use_descriptors zo_legacy_use_descriptors
#define disable_store_fallback zo_legacy_disable_store_fallback
#define display_globaldots zo_legacy_display_globaldots

#ifdef ASMV
# undef ASMV
#endif /* ifdef ASMV */

#ifdef DYN_ALLOC
# undef DYN_ALLOC
#endif /* ifdef DYN_ALLOC */

#ifdef USE_ZLIB
# undef USE_ZLIB
#endif /* ifdef USE_ZLIB */

#ifdef USE_ZLIB_NG
# undef USE_ZLIB_NG
#endif /* ifdef USE_ZLIB_NG */

#include "../zip30/deflate.c"
#include "../zip30/trees.c"
#include "../zip30/zip.h"

static jmp_buf zo_jump;
static unsigned (*zo_reader) (void *, unsigned char *, unsigned);
static int (*zo_writer) (void *, const unsigned char *, unsigned);
static void *zo_context;
static int zo_failure;

int zo_legacy_level = 0;
int zo_legacy_noisy = 0;
int zo_legacy_verbose = 0;
FILE *zo_legacy_mesg = NULL;
zoff_t zo_legacy_dot_size = 0;
zoff_t zo_legacy_dot_count = 0;
int zo_legacy_mesg_line_started = 0;
char *zo_legacy_key = NULL;
int zo_legacy_use_descriptors = 0;
int zo_legacy_disable_store_fallback = 1;
int zo_legacy_display_globaldots = 1;

unsigned (*zo_legacy_read_buf) (char *, unsigned) = NULL;

static unsigned
zo_legacy_read (char *p, unsigned length)
{
  return zo_reader (zo_context, (unsigned char *)p, length);
}

void
zo_legacy_flush_outbuf (char *p, unsigned *length)
{
  if (*length != 0U
      && zo_writer (zo_context, (const unsigned char *)p, *length))
    {
      zo_failure = 1;
      longjmp (zo_jump, 1);
    }

  *length = 0;
}

int
zo_legacy_seekable (void)
{
  return 0;
}

void
zo_legacy_error (const char *msg)
{
  (void)msg;
  zo_failure = 1;
  longjmp (zo_jump, 1);
}

int
zo_zip_internal_deflate (unsigned (*read_cb) (void *, unsigned char *,
                                              unsigned),
                         int (*write_cb) (void *, const unsigned char *,
                                          unsigned),
                         void *opaque, unsigned pack_level)
{
  ush attrs = UNKNOWN, flags = 0;
  int method = DEFLATE;
  char output_buffer[16384];

  if (pack_level < 1U || pack_level > 9U || !read_cb || !write_cb)
    {
      return 0;
    }

  zo_reader = read_cb;
  zo_writer = write_cb;
  zo_context = opaque;
  zo_failure = 0;
  zo_legacy_level = (int)pack_level;
  zo_legacy_read_buf = zo_legacy_read;
  zo_legacy_mesg = stderr;
  window_size = 0L;

  if (setjmp (zo_jump) != 0)
    {
      return 0;
    }

  bi_init (output_buffer, sizeof (output_buffer), 1);
  ct_init (&attrs, &method);
  init_block ();
  lm_init ((int)pack_level, &flags);
  (void)deflate ();
  lm_free ();

  return !zo_failure && method == DEFLATE;
}
