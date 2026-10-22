/*
 * Optional libdeflate buffer limit parser.  ISO C89, locale independent.
 * An internally represented 64-bit byte count permits e.g. 1TB on 32-bit
 * targets.  The returned allocation limit saturates at SIZE_MAX there;
 * callers must separately verify that actual file lengths fit in size_t.
 */

#ifndef XTR_LIBDEFLATE_SIZE_H
# define XTR_LIBDEFLATE_SIZE_H

# include <stddef.h>
# include <string.h>

# define XLD_DEFAULT_LIMIT ((size_t)1048576UL)

static int
xld_parse_limit (const char *value, size_t *out)
{
  unsigned short words[4];
  unsigned long v, carry;
  unsigned i, n, exponent;
  char suffix[40];
  size_t result;
  const char *s;

  if (value == NULL || out == NULL || *value < '0' || *value > '9')
    {
      return 0;
    }

  for (i = 0; i < 4; i++)
    {
      words[i] = 0;
    }

  s = value;
  while (*s >= '0' && *s <= '9')
    {
      carry = (unsigned long)(*s++ - '0');
      for (i = 0; i < 4; i++)
        {
          v = (unsigned long)words[i] * 10UL + carry;
          words[i] = (unsigned short)(v & 65535UL);
          carry = v >> 16;
        }

      if (carry != 0UL)
        {
          return 0;
        }
    }
  if (words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0)
    {
      return 0;
    }

  n = 0;
  while (*s != '\0')
    {
      unsigned char c = (unsigned char)*s++;
      if (n >= sizeof (suffix) - 1U)
        {
          return 0;
        }

      if (c >= 'A' && c <= 'Z')
        {
          c = (unsigned char)(c + 'a' - 'A');
        }

      suffix[n++] = (char)c;
    }
  suffix[n] = '\0';

  if (n == 0 || strcmp (suffix, "b") == 0 || strcmp (suffix, "byte") == 0
      || strcmp (suffix, "bytes") == 0)
    {
      exponent = 0;
    }
  else if (strcmp (suffix, "k") == 0 || strcmp (suffix, "kb") == 0
           || strcmp (suffix, "kib") == 0 || strcmp (suffix, "kilobyte") == 0
           || strcmp (suffix, "kilobytes") == 0
           || strcmp (suffix, "kibibyte") == 0
           || strcmp (suffix, "kibibytes") == 0)
    {
      exponent = 1;
    }
  else if (strcmp (suffix, "m") == 0 || strcmp (suffix, "mb") == 0
           || strcmp (suffix, "mib") == 0 || strcmp (suffix, "megabyte") == 0
           || strcmp (suffix, "megabytes") == 0
           || strcmp (suffix, "mebibyte") == 0
           || strcmp (suffix, "mebibytes") == 0)
    {
      exponent = 2;
    }
  else if (strcmp (suffix, "g") == 0 || strcmp (suffix, "gb") == 0
           || strcmp (suffix, "gib") == 0 || strcmp (suffix, "gigabyte") == 0
           || strcmp (suffix, "gigabytes") == 0
           || strcmp (suffix, "gibibyte") == 0
           || strcmp (suffix, "gibibytes") == 0)
    {
      exponent = 3;
    }
  else if (strcmp (suffix, "t") == 0 || strcmp (suffix, "tb") == 0
           || strcmp (suffix, "tib") == 0 || strcmp (suffix, "terabyte") == 0
           || strcmp (suffix, "terabytes") == 0
           || strcmp (suffix, "tebibyte") == 0
           || strcmp (suffix, "tebibytes") == 0)
    {
      exponent = 4;
    }
  else
    {
      return 0;
    }

  while (exponent-- != 0)
    {
      carry = 0UL;
      for (i = 0; i < 4; i++)
        {
          v = (unsigned long)words[i] * 1024UL + carry;
          words[i] = (unsigned short)(v & 65535UL);
          carry = v >> 16;
        }

      if (carry != 0UL)
        {
          return 0;
        }
    }

  result = 0;
  for (i = 4; i != 0;)
    {
      --i;
      if (result > ((size_t)-1 - (size_t)words[i]) / 65536UL)
        {
          *out = (size_t)-1;
          return 1;
        }

      result = result * 65536UL + (size_t)words[i];
    }

  *out = result;
  return 1;
}

#endif /* ifndef XTR_LIBDEFLATE_SIZE_H */
