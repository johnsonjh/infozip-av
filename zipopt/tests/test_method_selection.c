/* SPDX-License-Identifier: MIT-0 */
/* Exercise the production --methods parser independently of compression.
 * ELF linker section GC discards the rest of the included ZipOpt program. */
#define main zo_unused_program_main_for_method_test
#include "../zipopt.c"
#undef main

/* Mirror the production registry, with one deliberately unavailable codec
 * and one optional codec available to exercise dynamic profile selection. */
const zo_candidate zo_candidates[] = {
  { "store", 0, 0, 0 }, { "shrink", 1, 0, 0 },
  { "reduce-l1", 2, 0, 0 }, { "reduce-l2", 3, 0, 0 },
  { "reduce-l3", 4, 0, 0 }, { "reduce-l4", 5, 0, 0 },
  { "implode-4k-2", 6, 0, 0 }, { "implode-4k-3", 6, 0, 0 },
  { "implode-8k-2", 6, 0, 0 }, { "implode-8k-3", 6, 0, 0 },
  { "deflate", 8, 0, 0 }, { "deflate64", 9, 0, 0 },
  { "dcl-implode-binary", 10, 0, 0 },
  { "dcl-implode-ascii", 10, 0, 0 },
  { "bzip2", 12, 0, 0 }, { "lzma", 14, 0, 0 },
  { "zstd", 93, 0, 0 }, { "xz", 95, 0, 0 },
  { "ppmd", 98, 0, 0 }, { "wavpack", 97, 0, 0 },
  { "libdeflate", 8, 0, 0 }
};
const unsigned zo_candidate_count = sizeof (zo_candidates) / sizeof (zo_candidates[0]);

int
zo_candidate_available (unsigned id)
{
  return id < zo_candidate_count && id != 14U && id != 19U;
}

#define M(n) (1UL << (n))
#define EVERY ((1UL << 21) - 1UL)
#define AVAILABLE (EVERY & ~M(14) & ~M(19))
#define PKZIP1 ((1UL << 10) - 1UL)
#define PKZIP2 (PKZIP1 | M(10))
#define REDUCE (M(2) | M(3) | M(4) | M(5))
#define IMPLODE (M(6) | M(7) | M(8) | M(9))
#define DCL (M(12) | M(13))
#define WINZIP (AVAILABLE & ~DCL)

static unsigned checks;

static int
check (const char *argument, int should_parse, unsigned long expected)
{
  unsigned char enabled[sizeof (zo_candidates) / sizeof (zo_candidates[0])];
  unsigned i;
  int parsed = zo_selected_methods (argument, enabled);

  checks++;
  if (parsed != should_parse)
    {
      fprintf (stderr, "--methods=%s: parse result %d, expected %d\n",
               argument, parsed, should_parse);
      return 0;
    }
  if (!parsed)
    return 1;
  for (i = 0; i < zo_candidate_count; i++)
    if (!!enabled[i] != !!(expected & M(i)))
      {
        fprintf (stderr, "--methods=%s: candidate %s is %u, expected %u\n",
                 argument, zo_candidates[i].name, (unsigned)enabled[i],
                 (unsigned)!!(expected & M(i)));
        return 0;
      }
  return 1;
}

#define OK(arg, mask) do { if (!check ((arg), 1, (mask))) return 1; } while (0)
#define BAD(arg) do { if (!check ((arg), 0, 0UL)) return 1; } while (0)

int
main (void)
{
  OK ("all", AVAILABLE);
  OK ("all,-bzip2", AVAILABLE);
  OK ("all,-bzip2,bzip2", AVAILABLE | M(14));
  OK ("all,-bzip2,bzip2,-bzip2", AVAILABLE);
  OK ("pkzip1", PKZIP1);
  OK ("pkzip2", PKZIP2);
  OK ("winzip", WINZIP);
  OK ("winzip,dcl-implode-binary", WINZIP | M(12));
  OK ("winzip,-deflate", WINZIP & ~M(10));
  OK ("all,-winzip", DCL);
  OK ("all,-pkzip2", AVAILABLE & ~PKZIP2);
  OK ("all,-libdeflate", AVAILABLE & ~M(20));
  OK ("pkzip2,-reduce", PKZIP2 & ~REDUCE);
  OK ("pkzip2,-implode", PKZIP2 & ~IMPLODE);
  OK ("pkzip2,-reduce,reduce-l4", (PKZIP2 & ~REDUCE) | M(5));
  OK ("pkzip1,-all,deflate", M(10));
  OK ("-all", 0UL);
  OK ("-all,all", AVAILABLE);
  OK ("-reduce,reduce", REDUCE);
  OK ("reduce,-reduce", 0UL);
  OK ("implode,-implode", 0UL);
  OK ("dcl-implode,-dcl-implode", 0UL);
  OK ("dcl-implode,-dcl-implode-ascii", M(12));
  OK ("all,-dcl-implode", AVAILABLE & ~DCL);
  BAD ("");
  BAD (",");
  BAD ("all,");
  BAD (",all");
  BAD ("all,,bzip2");
  BAD ("-");
  BAD ("--all");
  BAD ("bogus");
  BAD ("all,-bogus");
  BAD ("all,PKZIP1");
  BAD ("all, -deflate");

  printf ("zipopt method selection: %u checks PASS\n", checks);
  return 0;
}
