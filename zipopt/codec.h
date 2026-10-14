/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

/* zipopt integrated compression candidates */

#ifndef ZO_CODEC_H
# define ZO_CODEC_H

# include "archive.h"

typedef struct zo_candidate
{
  const char *name;
  unsigned method, parameter, flags;
} zo_candidate;

extern const zo_candidate zo_candidates[];
extern const unsigned zo_candidate_count;
int zo_candidate_available (unsigned);

/* 32 to allow more candidates later */
# define ZO_MAX_CANDIDATES 32U

typedef struct zo_settings
{
  unsigned zopfli_iterations; /* 1..10000, default 15 */
  int dcl_optimal;            /* default off; explicit level 11 enables */
  int disable_zopfli;
  unsigned levels[ZO_MAX_CANDIDATES]; /* candidate levels by registry order */
} zo_settings;

/* Return nonzero only if a complete, valid codec output stream was written. */
int zo_compress (unsigned candidate, FILE *in, FILE *out, zo_u64 *compressed,
                 const zo_settings *settings);

#endif /* ifndef ZO_CODEC_H */
