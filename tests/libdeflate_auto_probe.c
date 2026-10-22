#define XLD_ENABLE_AUTO 1

#include "../common/xtrlibdeflate_size.h"
#include <stdio.h>

int
main (int argc, char **argv)
{
  size_t limit;

  if (argc != 2)
    {
      return 3;
    }

  if (strcmp (argv[1], "numeric") == 0)
    {
      if (!xld_parse_limit ("1MiB", &limit))
        {
          return 4;
        }
    }
  else if (strcmp (argv[1], "auto") == 0)
    {
      if (!xld_auto_supported () || !xld_auto_limit (&limit))
        {
          return 2;
        }
    }
  else
    {
      return 3;
    }

  printf ("%lu\n", (unsigned long)limit);

  return 0;
}
