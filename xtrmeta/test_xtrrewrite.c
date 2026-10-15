/* SPDX-License-Identifier: MIT-0 */
/* Bounded deterministic malformed-list and association-graph regression. */
#define XTR_REWRITE_IMPLEMENTATION
#include "xtrrewrite.h"
#include <stdio.h>
static unsigned long seed = 0x17395eabUL;
static unsigned
rng (void)
{
  seed = (seed * 1664525UL + 1013904223UL) & 0xffffffffUL;
  return (unsigned)((seed >> 12) & 0xffffU);
}
static int
test (unsigned truth, const char *what, unsigned long *checks)
{
  (*checks)++;
  if (!truth)
    {
      fprintf (stderr, "FAIL: %s\n", what);
      return 0;
    }

  return 1;
}
int
main (void)
{
  xr_node nodes[10], out;
  unsigned char extras[256], name[64];
  unsigned long checks = 0;
  unsigned long i;
  int status;

  memset (nodes, 0, sizeof (nodes));
  nodes[0].role = 1;
  nodes[0].id[0] = 1;
  if (!test (xr_graph (nodes, 1), "inline owner alone", &checks))
    {
      return 1;
    }

  nodes[0].role = 2;
  if (!test (!xr_graph (nodes, 1), "missing companion", &checks))
    {
      return 1;
    }

  nodes[1].role = 3;
  nodes[1].id[0] = 1;
  if (!test (xr_graph (nodes, 2), "complete pair", &checks))
    {
      return 1;
    }

  nodes[2] = nodes[1];
  if (!test (!xr_graph (nodes, 3), "duplicate companion", &checks))
    {
      return 1;
    }

  nodes[2].role = 2;
  if (!test (!xr_graph (nodes, 3), "duplicate owner", &checks))
    {
      return 1;
    }

  nodes[2].role = 0;
  nodes[1].id[0] = 2;
  if (!test (!xr_graph (nodes, 2), "unmatched sidecar", &checks))
    {
      return 1;
    }

  nodes[1].id[0] = 1;
  memset (name, 'a', sizeof (name));
  memcpy (name, "__XTRO_ZIP__/x/", 15);
  for (i = 15; i < 47; i++)
    {
      name[i] = '0';
    }

  memcpy (name + 47, ".xtm", 4);
  status = xr_name (name, 51, out.id);
  if (!test (status == 1, "canonical companion name", &checks))
    {
      return 1;
    }

  name[18] = 'G';
  if (!test (xr_name (name, 51, out.id) == -1, "nonhex companion name",
             &checks))
    {
      return 1;
    }

  memset (extras, 0, sizeof (extras));
  extras[0] = 0x54;
  extras[1] = 0x58;
  extras[2] = 0xff;
  extras[3] = 0xff;
  memset (&out, 0, sizeof (out));
  if (!test (!xr_scan (extras, 64, 1, &out), "oversized extra", &checks))
    {
      return 1;
    }

  for (i = 0; i < 50000UL; i++)
    {
      unsigned len = rng () % sizeof (extras), j;
      int central = (int)(rng () & 1U);
      for (j = 0; j < len; j++)
        {
          extras[j] = (unsigned char)rng ();
        }

      memset (&out, 0, sizeof (out));
      (void)xr_scan (extras, len, central, &out);
      for (j = 0; j < 10; j++)
        {
          memset (&nodes[j], 0, sizeof (nodes[j]));
          nodes[j].id[0] = (unsigned char)rng ();
          nodes[j].id[1] = (unsigned char)rng ();
          nodes[j].role = rng () % 4;
        }

      (void)xr_graph (nodes, 10);
      checks++;
    }

  printf ("Xtro rewrite C89 graph validation: %lu checks, 0 failures\n",
          checks);
  return 0;
}
