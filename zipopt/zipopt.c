/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#undef ZO_VER
#define ZO_VER "0.2"

#undef ZO_DATE
#define ZO_DATE "2026-01-12"

#include "archive.h"
#include "codec.h"
#include "display.h"
#include "extract.h"
#include "writer.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  zo_u64 size;
  unsigned code;
} zo_verbose_record;

static int
zo_verbose_descending (const void *left, const void *right)
{
  const zo_verbose_record *a = (const zo_verbose_record *)left;
  const zo_verbose_record *b = (const zo_verbose_record *)right;

  if (a->size > b->size)
    {
      return -1;
    }

  if (a->size < b->size)
    {
      return 1;
    }

  /* ties-breaker is original first then codec number */
  if (a->code < b->code)
    {
      return -1;
    }

  if (a->code > b->code)
    {
      return 1;
    }

  return 0;
}

typedef struct
{
  unsigned method;
  zo_u64 count;
} zo_method_tally;

static int
zo_tally_ascending (const void *left, const void *right)
{
  const zo_method_tally *a = (const zo_method_tally *)left;
  const zo_method_tally *b = (const zo_method_tally *)right;

  if (a->count < b->count)
    {
      return -1;
    }

  if (a->count > b->count)
    {
      return 1;
    }

  if (a->method < b->method)
    {
      return -1;
    }

  if (a->method > b->method)
    {
      return 1;
    }

  return 0;
}

/*
 * The original method is not necessarily one of the enabled encoders!
 * ZIP methods 6 and 10 have multiple stream variants and are labeled by
 * their method names rather than a particular encoder specific variant.
 */

static const char *
zo_method_name (unsigned method)
{
  unsigned i;

  switch (method)
    {
    case 6U:
      return "implode";

    case 10U:
      return "dcl-implode";

    case 16U:
      return "cmpsc";

    case 18U:
      return "method18-bwt-or-terse";

    case 20U:
      return "zstd-legacy";

    case 99U:
      return "lzfse";
    }

  for (i = 0; i < zo_candidate_count; i++)
    {
      if (zo_candidates[i].method == method)
        {
          return zo_candidates[i].name;
        }
    }

  return "unknown";
}

static void
zo_usage (void)
{
/******************************************************************************/
fprintf (stdout,
        "Xtro-ZIP - zipopt - Advanced ZIP archive optimizer\n"
        "Release %s - %s - https://github.com/johnsonjh/infozip-av\n"
        "Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com\n\n",
        ZO_VER, ZO_DATE);

  puts ("Usage: zipopt [-v|--verbose] [--methods=...] <in.zip> <out.zip>\n"
        "  --methods=<help|list|all>      specify methods (default: all)\n"
        "  --dcl-implode-optimal          enable DCL-Implode optimal parser");
  puts ("  --zopfli-iterations=N          Zopfli passes (1..10000; default 15)\n"
        "  -v, --verbose                  verbose output display mode\n"
        "  -h, --help                     display this help text");
/******************************************************************************/
}

static void
zo_methods_help (void)
{
  unsigned i;

  puts ("zipopt --methods=list: valid compression candidates:");
  puts ("  all                      all candidates (default)");
  puts ("  implode                  all four ZIP-Implode variants");
  puts ("  dcl-implode              both DCL-Implode modes");

  for (i = 0; i < zo_candidate_count; i++)
    {
      printf ("  %-24s (ZIP method %u)\n", zo_candidates[i].name,
              zo_candidates[i].method);
    }

  puts ("Separate multiple methods with commas; for example:");
  puts ("  --methods=store,deflate,ppmd");
}

static int
zo_iterations (const char *p, unsigned *out)
{
  unsigned long v;
  char *end;

  if (!p || !*p)
    {
      return 0;
    }

  /* Reject sign/whitespace/strtoul accepted extensions */
  if (*p < '0' || *p > '9')
    {
      return 0;
    }

  errno = 0;
  v = strtoul (p, &end, 10);

  if (errno == ERANGE || !end || *end || v < 1UL || v > 10000UL)
    {
      return 0;
    }

  *out = (unsigned)v;

  return 1;
}

static void
zo_log_name (const unsigned char *p, unsigned n)
{
  unsigned i;

  fputc ('"', stderr);

  for (i = 0; i < n; i++)
    {
      unsigned c = p[i];

      if (c >= 32U && c <= 126U && c != '"' && c != '\\')
        {
          fputc ((int)c, stderr);
        }
      else
        {
          fprintf (stderr, "\\x%02X", c);
        }
    }

  fputc ('"', stderr);
}

static int
zo_name (const char *p, size_t n, const char *name)
{
  return strlen (name) == n && memcmp (p, name, n) == 0;
}

static int
zo_selected_methods (const char *s, unsigned char *enabled)
{
  const char *p = s, *q;
  size_t n;
  unsigned i, matched;

  memset (enabled, 0, zo_candidate_count);

  if (!strcmp (s, "all"))
    {
      memset (enabled, 1, zo_candidate_count);

      return 1;
    }

  for (;;)
    {
      q = strchr (p, ',');
      n = q ? (size_t)(q - p) : strlen (p);

      if (n == 0)
        {
          return 0;
        }

      matched = 0;

      if (zo_name (p, n, "implode") || zo_name (p, n, "dcl-implode"))
        {
          unsigned wanted = zo_name (p, n, "implode") ? 6U : 10U;

          for (i = 0; i < zo_candidate_count; i++)
            {
              if (zo_candidates[i].method == wanted)
                {
                  enabled[i] = 1;
                  matched = 1;
                }
            }
        }
      else
        {
          for (i = 0; i < zo_candidate_count; i++)
            {
              if (zo_name (p, n, zo_candidates[i].name))
                {
                  enabled[i] = 1;
                  matched = 1;

                  break;
                }
            }
        }

      if (!matched)
        {
          return 0;
        }

      if (!q)
        {
          break;
        }

      p = q + 1;
    }

  return 1;
}

/* Selection tests METHOD not the ZIP-Implode or DCL variant */
static int
zo_original_allowed (unsigned method, const unsigned char *enabled)
{
  unsigned i;

  if (method == 20 || method == 16 || method == 99)
    {
      return 0;
    }

  for (i = 0; i < zo_candidate_count; i++)
    {
      if (enabled[i] && zo_candidates[i].method == method)
        {
          return 1;
        }
    }

  return 0;
}

static int
zo_equal (FILE *a, FILE *b)
{
  unsigned char x[32768], y[32768];
  size_t n, m;

  rewind (a);
  rewind (b);

  for (;;)
    {
      n = fread (x, 1, sizeof (x), a);
      m = fread (y, 1, sizeof (y), b);

      if (n != m || memcmp (x, y, n) != 0)
        {
          return 0;
        }

      if (n < sizeof (x))
        {
          return !ferror (a) && !ferror (b) && feof (a) && feof (b);
        }
    }
}

/* Compare byte ranges without allocating storage proportional to metadata. */
static int
zo_equal_records (zo_archive *a, zo_u64 ao, zo_archive *b, zo_u64 bo, zo_u64 n)
{
  unsigned char x[4096], y[4096];

  while (n)
    {
      size_t take = n > sizeof (x) ? sizeof (x) : (size_t)n;

      if (!zo_archive_at (a, ao, x, take) || !zo_archive_at (b, bo, y, take)
          || memcmp (x, y, take))
        {
          return 0;
        }

      ao += (zo_u64)take;
      bo += (zo_u64)take;
      n -= (zo_u64)take;
    }

  return 1;
}

static int
zo_verify_output (zo_archive *original, zo_writer *w, zo_u64 *verified_size)
{
  zo_archive output;
  zo_u64 i;
  FILE *a, *b;
  int ok = 1;
  unsigned char src[46], dst[46];

  if (!zo_archive_open (&output, w->temporary))
    {
      fprintf (stderr, "zipopt: output structural validation: %s\n",
               output.error);
      zo_archive_close (&output);

      return 0;
    }

  if (output.count != original->count
      || output.archive_comment_len != original->archive_comment_len
      || !zo_equal_records (original, original->eocd_offset + 22, &output,
                            output.eocd_offset + 22,
                            original->archive_comment_len))
    {
      ok = 0;
    }

  for (i = 0; i < original->count && ok; i++)
    {
      zo_entry *x = &original->entries[(size_t)i];
      zo_entry *y = &output.entries[(size_t)i];

      if (y->name_len != x->name_len || memcmp (y->name, x->name, x->name_len)
          || y->has_fwkcs || y->method != w->entries[(size_t)i].method
          || y->flags != w->entries[(size_t)i].flags
          || y->csize != w->entries[(size_t)i].csize || y->usize != x->usize
          || y->crc != x->crc
          || y->central_comment_len != x->central_comment_len
          || !zo_archive_at (original, x->central_offset, src, 46)
          || !zo_archive_at (&output, y->central_offset, dst, 46)
          || memcmp (src + 12, dst + 12, 4) || /* DOS timestamp */
          memcmp (src + 36, dst + 36, 6) || /* attrs and original OS flags */
          (src[5] != dst[5]) ||             /* version-made-by host OS */
          !zo_equal_records (
              original,
              x->central_offset + 46 + x->name_len + x->central_extra_len,
              &output,
              y->central_offset + 46 + y->name_len + y->central_extra_len,
              x->central_comment_len))
        {
          ok = 0;

          break;
        }

      a = tmpfile ();
      b = tmpfile ();

      if (!a || !b)
        {
          if (a)
            {
              fclose (a);
            }

          if (b)
            {
              fclose (b);
            }

          ok = 0;

          break;
        }

      if (!zo_extract_index (original, i, a)
          || !zo_extract_index (&output, i, b) || !zo_equal (a, b))
        {
          ok = 0;
        }

      fclose (a);
      fclose (b);
    }

  if (ok)
    {
      *verified_size = output.filesize;
    }

  zo_archive_close (&output);

  return ok;
}

int
main (int argc, char **argv)
{
  zo_archive a;
  zo_writer w;
  const char *input = NULL, *output = NULL, *method_arg = "all";
  unsigned char *enabled = NULL;
  zo_verbose_record *verbose_records = NULL;
  unsigned method, flags;
  zo_u64 i, compressed, best_size, total_uncompressed = 0,
                                   final_archive_size = 0;
  FILE *decoded = NULL, *best = NULL, *candidate = NULL;
  unsigned k, best_id = 0, selected_count = 0;
  unsigned size_width = 0, verbose_count = 0;
  unsigned member_width = 0;
  int rc = 1, verbose = 0, original_win, iterations_set = 0;
  zo_settings settings;
  int j;

  settings.zopfli_iterations = 15U;
  settings.dcl_optimal = 0;
  memset (&w, 0, sizeof (w));
  memset (&a, 0, sizeof (a));

  for (j = 1; j < argc; j++)
    {
      const char *arg = argv[j];

      if (!strcmp (arg, "-h") || !strcmp (arg, "--help"))
        {
          zo_usage ();
          return 0;
        }

      if (!strcmp (arg, "-v") || !strcmp (arg, "--verbose"))
        {
          verbose = 1;
        }
      else if (!strncmp (arg, "--methods=", 10))
        {
          method_arg = arg + 10;
        }
      else if (!strcmp (arg, "--dcl-implode-optimal"))
        {
          settings.dcl_optimal = 1;
        }
      else if (!strncmp (arg, "--zopfli-iterations=", 20))
        {
          if (!zo_iterations (arg + 20, &settings.zopfli_iterations))
            {
              fprintf (stderr,
                       "zipopt: --zopfli-iterations must be 1..10000\n");

              return 2;
            }

          iterations_set = 1;
        }
      else if (!strcmp (arg, "--zopfli-iterations"))
        {
          if (++j >= argc
              || !zo_iterations (argv[j], &settings.zopfli_iterations))
            {
              fprintf (stderr,
                       "zipopt: --zopfli-iterations must be 1..10000\n");

              return 2;
            }

          iterations_set = 1;
        }
      else if (arg[0] == '-')
        {
          zo_usage ();

          return 2;
        }
      else if (!input)
        {
          input = arg;
        }
      else if (!output)
        {
          output = arg;
        }
      else
        {
          zo_usage ();

          return 2;
        }
    }

  if (!strcmp (method_arg, "help"))
    {
      zo_methods_help ();

      return 0;
    }

  if (zo_candidate_count == 0)
    {
      zo_usage ();

      return 2;
    }

  enabled = (unsigned char *)malloc ((size_t)zo_candidate_count);

  if (!enabled)
    {
      fprintf (stderr, "zipopt: cannot allocate method selection\n");
      return 1;
    }

  if (!zo_selected_methods (method_arg, enabled))
    {
      fprintf (stderr, "zipopt: invalid --methods selection: %s\n",
               method_arg);
      zo_methods_help ();
      free (enabled);

      return 2;
    }

  for (k = 0; k < zo_candidate_count; k++)
    {
      if (enabled[k])
        {
          selected_count++;
        }
    }

  if (!input || !output)
    {
      zo_usage ();
      free (enabled);

      return 2;
    }

  if (iterations_set)
    {
      int deflate_present = 0;

      for (k = 0; k < zo_candidate_count; k++)
        {
          if (enabled[k] && zo_candidates[k].method == 8U)
            {
              deflate_present = 1;
            }
        }

      if (!deflate_present)
        {
          fprintf (
              stderr,
              "zipopt: --zopfli-iterations requires a Deflate candidate\n");
          free (enabled);

          return 2;
        }
    }

  if (settings.dcl_optimal)
    {
      int dcl_present = 0;

      for (k = 0; k < zo_candidate_count; k++)
        {
          if (enabled[k] && zo_candidates[k].method == 10U)
            {
              dcl_present = 1;
            }
        }

      if (!dcl_present)
        {
          fprintf (stderr,
                   "zipopt: --dcl-implode-optimal requires a DCL candidate\n");
          free (enabled);

          return 2;
        }
    }

  /* Reject the entire input before beginning output or compression. */
  if (!zo_archive_open (&a, input))
    {
      fprintf (stderr, "zipopt: input rejected: %s\n", a.error);
      zo_archive_close (&a);
      free (enabled);

      return 1;
    }

  /*
   * Member progress uses a one-based ordinal and the actual count of
   * central-directory entries (including directories). Keep the original
   * zero-based index alongside it for unambiguous member identification.
   */

  {
    char count_text[32];
    member_width = (unsigned)strlen (zo_decimal (a.count, count_text));
  }

  /*
   * Count logical member sizes separately from physical archive sizes.
   * Reject overflow rather than silently printing a wrapped ZIP64 total.
   */

  for (i = 0; i < a.count; i++)
    {
      zo_u64 usize = a.entries[(size_t)i].usize;

      if (usize > ((zo_u64)-1) - total_uncompressed)
        {
          fputs ("zipopt: uncompressed archive size total overflow\n", stderr);

          goto done;
        }

      total_uncompressed += usize;
    }

  if (verbose)
    {
      verbose_records = (zo_verbose_record *)calloc (
          (size_t)zo_candidate_count + 1U, sizeof (*verbose_records));

      if (!verbose_records)
        {
          fputs ("zipopt: cannot allocate compression statistics\n", stderr);

          goto done;
        }
    }

  if (!zo_writer_install_interrupts ())
    {
      fprintf (stderr, "zipopt: cannot install interrupt cleanup handlers\n");

      goto done;
    }

  if (!zo_writer_begin (&w, &a, output))
    {
      fprintf (stderr,
               "zipopt: output exists or temporary file unavailable\n");

      goto done;
    }

  for (i = 0; i < a.count; i++)
    {
      zo_entry *e = &a.entries[(size_t)i];

      /* Keep verbose records visually separated, including directories. */
      if (verbose && i != 0)
        {
          fputc ('\n', stderr);
        }

      /* Report the actual member name before any expensive encoding. */
      {
        char position[32], total[32];
        fprintf (stderr, "[member %*s/%s] ", (int)member_width,
                 zo_decimal (i + 1U, position), zo_decimal (a.count, total));
      }

      zo_log_name (e->name, e->name_len);

      if (e->name_len && e->name[e->name_len - 1] == '/')
        {
          fputs (": directory\n", stderr);
        }
      else
        {
          fputs (": optimizing", stderr);

          if (selected_count > 1)
            {
              fputc ('.', stderr);
            }
          else
            {
              fputc ('\n', stderr);
            }

          fflush (stderr);
        }

      decoded = tmpfile ();

      if (!decoded || !zo_extract_index (&a, i, decoded))
        {
          fprintf (
              stderr,
              "zipopt: member %lu failed input CRC/FWKCS/decoder validation\n",
              (unsigned long)i);

          goto done;
        }

      /*
       * Directory entries are structural records, not compression work.
       * Canonicalize them to empty stored members regardless of --methods.
       */

      if (e->name_len && e->name[e->name_len - 1] == '/')
        {
          if (e->usize != 0
              || !zo_writer_add (&w, i, decoded, 0, e->flags & 0x800U, 0))
            {
              fprintf (stderr,
                       "zipopt: invalid or unwritable directory member %lu\n",
                       (unsigned long)i);

              goto done;
            }

          fprintf (stderr, "  directory: stored (0 bytes)\n");

          if (e->has_fwkcs)
            {
              fputs ("  FWKCS input MD5 verified; omitted from output\n",
                     stderr);
            }

          fclose (decoded);
          decoded = NULL;

          continue;
        }

      original_win = zo_original_allowed (e->method, enabled);
      best_size = original_win ? e->csize : (zo_u64)-1;
      best_id = zo_candidate_count;

      if (verbose)
        {
          char size[32];
          /*
           * Buffer sizes only; candidate execution and selection order are
           * unchanged. Include the original in the later size sort.
           */

          verbose_records[0].size = e->csize;
          verbose_records[0].code = 0U;
          verbose_count = 1U;
          size_width = (unsigned)strlen (zo_byte_decimal (e->csize, size));
        }

      for (k = 0; k < zo_candidate_count; k++)
        {
          if (!enabled[k])
            {
              continue;
            }

          candidate = tmpfile ();

          if (!candidate
              || !zo_compress (k, decoded, candidate, &compressed, &settings))
            {
              fprintf (stderr, "zipopt: compressor %s failed on member %lu\n",
                       zo_candidates[k].name, (unsigned long)i);

              goto done;
            }

          if (verbose)
            {
              char size[32];
              unsigned width;
              verbose_records[verbose_count].size = compressed;
              verbose_records[verbose_count].code = k + 1U;
              verbose_count++;
              width = (unsigned)strlen (zo_byte_decimal (compressed, size));

              if (width > size_width)
                {
                  size_width = width;
                }
            }

          if (selected_count > 1)
            {
              fputc ('.', stderr);
              fflush (stderr);
            }

          /*
           * Same method-independent ZIP header cost for the current
           * candidate set, barring a ZIP64 threshold crossing.
           */

          if (compressed < best_size)
            {
              if (best)
                {
                  fclose (best);
                }

              best = candidate;
              candidate = NULL;
              best_size = compressed;
              best_id = k;
              original_win = 0;
            }

          if (candidate)
            {
              fclose (candidate);
              candidate = NULL;
            }
        }

      if (original_win)
        {
          method = e->method;
          flags = e->flags & ~8U;
        }
      else
        {
          if (best_id >= zo_candidate_count)
            {
              fprintf (stderr, "zipopt: no eligible encoder for member\n");

              goto done;
            }

          method = zo_candidates[best_id].method;
          flags = (e->flags & 0x800U) | zo_candidates[best_id].flags;
        }

      if (!zo_writer_add (&w, i, original_win ? NULL : best, method, flags,
                          best_size))
        {
          fprintf (stderr, "zipopt: failed writing member %lu\n",
                   (unsigned long)i);

          goto done;
        }

      {
        char unpacked[32], starting[32], final[32];

        if (selected_count > 1)
          {
            fputc ('\n', stderr);
          }

        if (verbose)
          {
            char size[32], ratio_text[64], change_text[64];
            char marker;
            unsigned ratio_width = 7U, change_width = 5U, width;
            qsort (verbose_records, (size_t)verbose_count,
                   sizeof (*verbose_records), zo_verbose_descending);

            /*
             * Determine both percentage-column widths before printing.
             * Large expansions can exceed the illustrative widths.
             */

            for (k = 0; k < verbose_count; k++)
              {
                zo_u64 packed = verbose_records[k].size;
                zo_ratio_text (e->usize, packed, ratio_text);
                zo_change_text (e->csize, packed, &marker, change_text);
                width = (unsigned)strlen (ratio_text);

                if (width > ratio_width)
                  {
                    ratio_width = width;
                  }

                width = (unsigned)strlen (change_text);

                if (width > change_width)
                  {
                    change_width = width;
                  }
              }

            for (k = 0; k < verbose_count; k++)
              {
                unsigned code = verbose_records[k].code;
                zo_u64 packed = verbose_records[k].size;
                const char *name
                    = code == 0U ? "original" : zo_candidates[code - 1U].name;
                zo_ratio_text (e->usize, packed, ratio_text);
                zo_change_text (e->csize, packed, &marker, change_text);
                fprintf (stderr, "  %-20s %*s bytes %*s   (%c%*s%c)", name,
                         (int)size_width, zo_byte_decimal (packed, size),
                         (int)ratio_width, ratio_text, marker,
                         (int)change_width, change_text,
                         marker == '?' ? ' ' : '%');

                if (code == 0U)
                  {
                    fprintf (stderr, " [%s, method %u",
                             zo_method_name (e->method), e->method);

                    if (!zo_original_allowed (e->method, enabled))
                      {
                        fputs (", excluded", stderr);
                      }

                    fputc (']', stderr);
                  }

                fputc ('\n', stderr);
              }
          }

        {
          char difference[32];
          int saved = e->csize >= best_size;
          zo_u64 delta = saved ? e->csize - best_size : best_size - e->csize;
          fprintf (
              stderr,
              "  selected: %s, %s bytes -> %s bytes -> %s bytes\n"
              "            (%.0f%% -> %.0f%% -> %.0f%%) "
              "[%s bytes %s]\n",
              original_win ? "original" : zo_candidates[best_id].name,
              zo_byte_decimal (e->usize, unpacked),
              zo_byte_decimal (e->csize, starting),
              zo_byte_decimal (best_size, final),
              zo_ratio (e->usize, e->csize), zo_ratio (e->csize, best_size),
              zo_ratio (e->usize, best_size),
              zo_byte_decimal (delta, difference), saved ? "saved" : "added");
        }

        if (e->has_fwkcs)
          {
            fputs ("  FWKCS input MD5 verified; omitted from output\n",
                   stderr);
          }
      }

      if (best)
        {
          fclose (best);
          best = NULL;
        }

      fclose (decoded);
      decoded = NULL;
    }

  if (!zo_archive_unchanged (&a))
    {
      fprintf (stderr, "zipopt: input changed before output validation: %s\n",
               a.error);

      goto done;
    }

  if (!zo_writer_complete (&w))
    {
      fprintf (stderr, "zipopt: failed finalizing ZIP headers\n");

      goto done;
    }

  if (!zo_verify_output (&a, &w, &final_archive_size))
    {
      fprintf (stderr,
               "zipopt: output validation or byte comparison failed\n");

      goto done;
    }

  if (!zo_archive_unchanged (&a))
    {
      fprintf (stderr, "zipopt: input changed before publication: %s\n",
               a.error);

      goto done;
    }

  if (!zo_writer_publish (&w))
    {
      fprintf (
          stderr,
          "zipopt: cannot atomically publish output (may already exist)\n");

      goto done;
    }

  rc = 0;
  {
    char members[32], unpacked[32], starting[32], final[32], difference[32];
    int saved = a.filesize >= final_archive_size;
    zo_u64 delta = saved ? a.filesize - final_archive_size
                         : final_archive_size - a.filesize;
    if (verbose)
      {
        fputc ('\n', stderr);
      }

    fprintf (stderr, "%s: complete [%s %s]\n", output,
             zo_decimal (a.count, members),
             a.count == 1 ? "member" : "members");
    if (verbose)
      {
        /*
         * Current output methods use ZIP IDs 0..98, but scan the actual
         * writer entries, never the chosen candidates or input methods.
         * At most 100 IDs exist in this range.
         */

        zo_method_tally tally[100];
        unsigned n = 0, m, width = 7U;

        for (i = 0; i < a.count; i++)
          {
            unsigned current = w.entries[(size_t)i].method;

            for (m = 0; m < n; m++)
              {
                if (tally[m].method == current)
                  {
                    break;
                  }
              }

            if (m == n)
              {
                tally[n].method = current;
                tally[n].count = 0;
                n++;
              }

            tally[m].count++;
          }

        qsort (tally, (size_t)n, sizeof (tally[0]), zo_tally_ascending);

        for (m = 0; m < n; m++)
          {
            char countbuf[32];
            unsigned digits
                = (unsigned)strlen (zo_decimal (tally[m].count, countbuf));

            if (digits > width)
              {
                width = digits;
              }
          }

        for (m = 0; m < n; m++)
          {
            char countbuf[32];
            fprintf (stderr, "  %*s %s\n", (int)width,
                     zo_decimal (tally[m].count, countbuf),
                     zo_method_name (tally[m].method));
          }
      }

    fprintf (stderr,
             "zipopt: %s bytes -> %s bytes -> %s bytes\n"
             "        (%.0f%% -> %.0f%% -> %.0f%%) [%s bytes %s]\n",
             zo_byte_decimal (total_uncompressed, unpacked),
             zo_byte_decimal (a.filesize, starting),
             zo_byte_decimal (final_archive_size, final),
             zo_ratio (total_uncompressed, a.filesize),
             zo_ratio (a.filesize, final_archive_size),
             zo_ratio (total_uncompressed, final_archive_size),
             zo_byte_decimal (delta, difference), saved ? "saved" : "added");
  }

done:
  if (candidate)
    {
      fclose (candidate);
    }

  if (best)
    {
      fclose (best);
    }

  if (decoded)
    {
      fclose (decoded);
    }

  zo_writer_abort (&w);
  zo_archive_close (&a);
  free (verbose_records);
  free (enabled);

  return rc;
}
