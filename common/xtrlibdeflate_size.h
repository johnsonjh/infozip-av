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

#if defined(XLD_ENABLE_AUTO)

# if defined(__linux__)
#  include <stdio.h>
#  define XLD_AUTO_AVAILABLE 1
# elif defined(_WIN32) || defined(WIN32)
#  include <windows.h>
#  define XLD_AUTO_AVAILABLE 1
# elif defined(__DJGPP__)
#  include <dpmi.h>
#  include <limits.h>
#  define XLD_AUTO_AVAILABLE 1
# else
#  define XLD_AUTO_AVAILABLE 0
# endif

static int
xld_auto_supported (void)
{
  return XLD_AUTO_AVAILABLE;
}

static int
xld_auto_limit (size_t *out)
{
  if (out == NULL)
    return 0;

# if defined(__linux__)
  {
    FILE *fp;
    char line[256];
    const char *s;
    size_t kb, digit, cap;
    int overflow;

#  ifndef XLD_MEMINFO_PATH
#   define XLD_MEMINFO_PATH "/proc/meminfo"
#  endif
    fp = fopen (XLD_MEMINFO_PATH, "r");
    if (fp == NULL)
      return 0;
    kb = 0;
    overflow = 0;
    cap = (size_t)-1;
    while (fgets (line, sizeof (line), fp) != NULL)
      {
        if (strncmp (line, "MemAvailable:", 13) != 0)
          continue;
        s = line + 13;
        while (*s == ' ' || *s == '\t')
          s++;
        if (*s < '0' || *s > '9')
          break;
        while (*s >= '0' && *s <= '9')
          {
            digit = (size_t)(*s++ - '0');
            if (!overflow)
              {
                if (kb > (cap - digit) / 10U)
                  {
                    kb = cap;
                    overflow = 1;
                  }
                else
                  kb = kb * 10U + digit;
              }
          }
        while (*s == ' ' || *s == '\t')
          s++;
        if (s[0] != 'k' || s[1] != 'B')
          break;
        s += 2;
        while (*s == ' ' || *s == '\t')
          s++;
        if (*s != '\0' && *s != '\n' && *s != '\r')
          break;
        if (kb == 0)
          break;
        /* MemAvailable is in KiB; half the available bytes is kb*512.
         * Saturation preserves the size_t allocation bound on 32-bit. */
        *out = kb > cap / 512U ? cap : kb * 512U;
        fclose (fp);
        return 1;
      }
    fclose (fp);
    return 0;
  }
# elif defined(_WIN32) || defined(WIN32)
  {
    HMODULE kernel;
    FARPROC symbol;
    BOOL (WINAPI *query)(LPMEMORYSTATUSEX);
    MEMORYSTATUSEX state;
    DWORDLONG available;

    /* Late lookup keeps Win9x binaries loadable when auto is not used;
     * the API itself is available on Windows XP and later. */
    kernel = GetModuleHandleA ("kernel32.dll");
    if (kernel == NULL)
      return 0;
    symbol = GetProcAddress (kernel, "GlobalMemoryStatusEx");
    if (symbol == NULL)
      return 0;
    query = (BOOL (WINAPI *)(LPMEMORYSTATUSEX))symbol;
    memset (&state, 0, sizeof (state));
    state.dwLength = sizeof (state);
    if (!query (&state))
      return 0;
    available = state.ullAvailPhys;
    if (state.ullAvailVirtual < available)
      available = state.ullAvailVirtual;
    if (state.ullAvailPageFile < available)
      available = state.ullAvailPageFile;
    available /= 2U;
    if (available == 0)
      return 0;
    *out = available > (DWORDLONG)(size_t)-1
           ? (size_t)-1 : (size_t)available;
    return 1;
  }
# elif defined(__DJGPP__)
  {
    __dpmi_free_mem_info info;
    unsigned long pagesize, freepages, largest;
    size_t available, cap;

    if (__dpmi_get_free_memory_information (&info) != 0 ||
        __dpmi_get_page_size (&pagesize) != 0 || pagesize == 0)
      return 0;
    freepages = info.total_number_of_free_pages;
    largest = info.largest_available_free_block_in_bytes;
    /* DPMI 0.9 allows unavailable fields to contain 0xffffffff.  Do not
     * mistake an unsupported counter for an enormous allocation budget. */
    if (freepages == 0xffffffffUL || freepages == 0 ||
        largest == 0xffffffffUL || largest == 0)
      return 0;
    cap = (size_t)-1;
    available = freepages > cap / pagesize
                ? cap : (size_t)freepages * (size_t)pagesize;
    if ((size_t)largest < available)
      available = (size_t)largest;
    *out = available / 2U;
    return *out != 0;
  }
# else
  return 0;
# endif
}
#endif /* XLD_ENABLE_AUTO */

#endif /* ifndef XTR_LIBDEFLATE_SIZE_H */
