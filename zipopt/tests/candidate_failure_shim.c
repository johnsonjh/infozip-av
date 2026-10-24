/*
 * SPDX-License-Identifier: MIT-0
 */

#include "../codec.h"

#include <stdlib.h>
#include <string.h>

int
zo_compress_test (unsigned id, FILE *in, FILE *out, zo_u64 *compressed,
                  const zo_settings *settings)
{
  const char *id_text = getenv ("ZO_TEST_FAIL_ID");
  char *end;
  unsigned long match;

  if (id_text && *id_text)
    {
      match = strtoul (id_text, &end, 10);

      if (*end == '\0' && match == (unsigned long)id)
        {
          if (getenv ("ZO_TEST_WRITE_PARTIAL"))
            {
              if (fwrite ("incomplete", 1, 10, out) != 10)
                {
                  return ZO_COMPRESS_FATAL;
                }
            }

          if (getenv ("ZO_TEST_FATAL"))
            {
              return ZO_COMPRESS_FATAL;
            }

          if (getenv ("ZO_TEST_INAPPLICABLE"))
            {
              return ZO_COMPRESS_INAPPLICABLE;
            }

          return ZO_COMPRESS_FAILED;
        }
    }

  return zo_compress (id, in, out, compressed, settings);
}
