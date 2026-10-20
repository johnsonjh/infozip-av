/* SPDX-License-Identifier: MIT-0 */
/* Isolated archive-index regression for the Zip integration bridge. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define far
struct zlist
{
  struct zlist *nxt;
  char *iname;
  char *cextra;
  unsigned cext;
  unsigned flg;
  unsigned how;
  unsigned long len;
  int mark;
};
#include "../zip30/xtro_pairs.h"

static unsigned assertions;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      assertions++;                                                           \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "check failed on line %d: %s\n", __LINE__, #x);    \
          exit (1);                                                           \
        }                                                                     \
    }                                                                         \
  while (0)
static void
setup (struct zlist *o, struct zlist *c, char ef[44])
{
  unsigned i;

  memset (o, 0, sizeof (*o));
  memset (c, 0, sizeof (*c));
  memset (ef, 0, 44);
  ef[0] = 0x54;
  ef[1] = 0x58;
  ef[2] = 40;
  memcpy (ef + 4, "XTRO", 4);
  ef[8] = 1;
  ef[10] = 2;
  ef[11] = 1;
  for (i = 0; i < 16; i++)
    {
      ef[12 + i] = (char)(i + 1);
    }

  o->iname = "owner.dat";
  o->cextra = ef;
  o->cext = 44;
  o->nxt = c;
  o->flg = 1;
  c->flg = 1;
  c->iname = "__XTRO_ZIP__/x/0102030405060708090a0b0c0d0e0f10.xtm";
}
int
main (void)
{
  struct zlist o, c, d;
  char ef[44], second[44], aeowner[55], aeside[11];
  unsigned long rng = 0x9e3779b9UL;
  unsigned k, j;

  setup (&o, &c, ef);
  CHECK (xtro_prepare_pairs (&o, 0) == 0);
  o.mark = 1;
  CHECK (xtro_prepare_pairs (&o, 1) == 0 && c.mark == 1);
  o.mark = 0;
  c.mark = 1;
  CHECK (xtro_prepare_pairs (&o, 1) == 3);
  c.mark = 0;
  o.mark = 1;
  CHECK (xtro_prepare_pairs (&o, 2) == 0 && c.mark == 1);
  setup (&o, &c, ef);
  o.mark = 1;
  c.mark = 0;
  CHECK (xtro_prepare_pairs (&o, 3) == 3 && c.mark == 0);
  setup (&o, &c, ef);
  o.mark = 0;
  c.mark = 1;
  CHECK (xtro_prepare_pairs (&o, 3) == 3 && o.mark == 0);
  setup (&o, &c, ef);
  o.mark = 1;
  c.mark = 1;
  CHECK (xtro_prepare_pairs (&o, 3) == 0 && o.mark == 1 && c.mark == 1);
  setup (&o, &c, ef);
  o.mark = 0;
  c.mark = 0;
  CHECK (xtro_prepare_pairs (&o, 3) == 0);
  /* AES-2 transport matching: same version/strength; compression may
   * differ because companion is STORE or Deflate. */
  setup (&o, &c, ef);
  memcpy (aeowner, ef, 44);
  memset (aeside, 0, sizeof (aeside));
  aeside[0] = 1;
  aeside[1] = (char)0x99;
  aeside[2] = 7;
  aeside[4] = 2;
  aeside[6] = 'A';
  aeside[7] = 'E';
  aeside[8] = 3;
  aeside[9] = 8; /* companion's underlying compression method */
  memcpy (aeowner + 44, aeside, 11);
  aeowner[53] = 0; /* owner compressed using STORE */
  o.cextra = aeowner;
  o.cext = 55;
  o.how = 99;
  c.cextra = aeside;
  c.cext = 11;
  c.how = 99;
  CHECK (xtro_prepare_pairs (&o, 0) == 0);
  aeside[8] = 1;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  aeside[8] = 3;
  aeside[9] = 7;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  aeside[9] = 8;
  c.how = 8;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  c.how = 99;
  aeowner[50] = 'Z';
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  aeowner[50] = 'A';
  o.how = 8;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  c.how = 99;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  c.how = 93;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  /* B: unencrypted directory entry with encrypted sidecar is legitimate.
   * A regular file, plaintext flag, or absent encrypted companion is not. */
  setup (&o, &c, ef);
  o.iname = "directory/";
  o.flg = 0;
  c.flg = 1;
  o.how = 0;
  c.how = 8;
  CHECK (xtro_prepare_pairs (&o, 0) == 0);
  o.len = 1;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  o.len = 0;
  o.iname = "directory";
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  o.iname = "directory/";
  ef[11] = 0;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  ef[11] = 1;
  c.flg = 0;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  c.flg = 0;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  o.flg = 0;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  ef[11] = 0;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  o.nxt = NULL;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  c.nxt = &d;
  memset (&d, 0, sizeof (d));
  d.iname = c.iname;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  d.iname = "second.dat";
  d.cext = 44;
  memcpy (second, ef, 44);
  d.cextra = second;
  c.nxt = &d;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  ef[8] = 2;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  ef[10] = 3;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  memset (ef + 12, 0, 16);
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  o.iname = "__XTRO_ZIP__/owner.dat";
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  setup (&o, &c, ef);
  o.cextra = NULL;
  o.cext = 0;
  o.nxt = &c;
  CHECK (xtro_prepare_pairs (&o, 0) == 1);
  o.nxt = NULL;
  o.iname = "__XTRO_ZIP__/unrelated.dat";
  CHECK (xtro_prepare_pairs (&o, 0) == 0);
  /* Colliding extension ID without XTRO signature is not ours. */
  setup (&o, &c, ef);
  o.nxt = NULL;
  ef[2] = 4;
  ef[3] = 0;
  memcpy (ef + 4, "OTHER", 5);
  o.cext = 8;
  CHECK (xtro_prepare_pairs (&o, 0) == 0);
  /* Fixed-seed schema mutation test: zero-alloc, malformed lengths,
   * truncated descriptors, random IDs and unexpected tags. This
   * exercises checked bounds in the real production graph helper. */
  for (k = 0; k < 30000U; k++)
    {
      setup (&o, &c, ef);
      for (j = 0; j < sizeof (ef); j++)
        {
          rng = (rng * 1664525UL + 1013904223UL) & 0xffffffffUL;
          ef[j] = (char)(rng >> 24);
        }

      o.cext = (unsigned)(rng % ((unsigned)sizeof (ef) + 1U));
      CHECK (xtro_prepare_pairs (&o, 0) <= 2);
    }

  printf ("Xtro pair graph: %u C89 assertions, 0 failures\n", assertions);
  return 0;
}
