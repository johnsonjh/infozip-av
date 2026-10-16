/* SPDX-License-Identifier: MIT-0 */
/* Strict C89 ABI/wire checks. These tests do NOT emulate an NTFS driver. */
#include "xtrwin_ea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long checks, failures;
#define CHECK(x)                                                              \
  do                                                                          \
    {                                                                         \
      checks++;                                                               \
      if (!(x))                                                               \
        {                                                                     \
          fprintf (stderr, "FAIL line %d: %s\n", __LINE__, #x);               \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)
static unsigned char bin[] = { 0, 1, 0, 255, 3 };
static unsigned char valbig[65535];
static xtr_win_ea entries[3];
static xtr_win_ea_list source;
static unsigned char owner[16];
static void
seed (void)
{
  unsigned i;

  for (i = 0; i < 16U; i++)
    {
      owner[i] = (unsigned char)(i + 1U);
    }

  for (i = 0; i < sizeof (valbig); i++)
    {
      valbig[i] = (unsigned char)(i * 31U + 7U);
    }

  memset (entries, 0, sizeof (entries));
  entries[0].name = (unsigned char *)"ZETA";
  entries[0].name_len = 4;
  entries[0].value = bin;
  entries[0].value_len = sizeof (bin);
  entries[0].flags = 128U;
  entries[1].name = (unsigned char *)"empty";
  entries[1].name_len = 5;
  entries[1].value = NULL;
  entries[1].value_len = 0;
  entries[2].name = (unsigned char *)"Big";
  entries[2].name_len = 3;
  entries[2].value = valbig;
  entries[2].value_len = sizeof (valbig);
  source.items = entries;
  source.count = 3;
}
static void
raw_roundtrip (void)
{
  unsigned char *buf = NULL, *again = NULL, *tmp;
  size_t n = 0, n2 = 0, i;
  xtr_win_ea_list parsed;
  int rc;

  CHECK (xtr_win_ea_pack (&source, &buf, &n) == XTR_OK);
  CHECK (buf != NULL && n > 65535U);
  rc = xtr_win_ea_parse (buf, n, &parsed);
  CHECK (rc == XTR_OK);
  if (rc == XTR_OK)
    {
      CHECK (parsed.count == 3);
      CHECK (parsed.items[0].name_len == 3
             && !memcmp (parsed.items[0].name, "Big", 3));
      CHECK (parsed.items[1].flags == 128U
             && parsed.items[1].value_len == sizeof (bin));
      CHECK (!memcmp (parsed.items[1].value, bin, sizeof (bin)));
      CHECK (parsed.items[2].value_len == 0);
      CHECK (parsed.items[0].value_len == sizeof (valbig));
      CHECK (!memcmp (parsed.items[0].value, valbig, sizeof (valbig)));
      CHECK (xtr_win_ea_pack (&parsed, &again, &n2) == XTR_OK);
      CHECK (n == n2 && !memcmp (buf, again, n));
      xtr_win_ea_free (&parsed);
    }

  /* Verify all rejection paths leave output empty and safe to free. */
  tmp = (unsigned char *)malloc (n + 4U);
  CHECK (tmp != NULL);
  if (tmp)
    {
      memcpy (tmp, buf, n + 0U);
      tmp[4] = 1;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      tmp[4] = 0;
      tmp[5] = 0;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      memcpy (tmp, buf, n);
      tmp[0] = 3;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      memcpy (tmp, buf, n);
      tmp[0] = 0xff;
      tmp[1] = 0xff;
      tmp[2] = 0xff;
      tmp[3] = 0x7f;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      memcpy (tmp, buf, n);
      tmp[8] = 0;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      memcpy (tmp, buf, n);
      tmp[n] = 1;
      CHECK (xtr_win_ea_parse (tmp, n + 1U, &parsed) != XTR_OK);
      memcpy (tmp, buf, n);
      tmp[0] = 1;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      memcpy (tmp, buf, n);
      tmp[0] = 0;
      tmp[1] = 0;
      tmp[2] = 0;
      tmp[3] = 0;
      CHECK (xtr_win_ea_parse (tmp, n, &parsed) != XTR_OK);
      for (i = 0; i < n; i++)
        {
          if (i % 211U == 0)
            {
              memcpy (tmp, buf, n);
              tmp[i] ^= 0x80;
              rc = xtr_win_ea_parse (tmp, n, &parsed);
              if (rc == XTR_OK)
                {
                  xtr_win_ea_free (&parsed);
                }

              CHECK (rc >= XTR_OK && rc <= XTR_UNSUPPORTED);
            }
        }

      free (tmp);
    }

  free (buf);
  free (again);
}
/* Deterministic hostile-input exercise under ASan/UBSan. The initial
 * buffer is valid; each iteration mutates a fresh copy or truncates it. */
static void
mutations (void)
{
  unsigned char *good = NULL, *trial;
  size_t used = 0, i;
  unsigned long random_state = 0x1f0033abUL;
  xtr_win_ea_list r;
  int rc;

  CHECK (xtr_win_ea_pack (&source, &good, &used) == XTR_OK);
  if (!good)
    {
      return;
    }

  trial = (unsigned char *)malloc (used + 1U);
  CHECK (trial != NULL);
  if (trial)
    {
      for (i = 0; i < 25000U; i++)
        {
          size_t pos, extent = used;
          memcpy (trial, good, used);
          random_state
              = (random_state * 1664525UL + 1013904223UL) & 0xffffffffUL;
          pos = (size_t)(random_state % used);
          if (i % 7U == 0U)
            {
              extent = pos;
            }
          else
            {
              trial[pos] ^= (unsigned char)(1U << (i % 8U));
            }

          rc = xtr_win_ea_parse (trial, extent, &r);
          CHECK (rc >= XTR_OK && rc <= XTR_UNSUPPORTED);
          if (rc == XTR_OK)
            {
              xtr_win_ea_free (&r);
            }
        }

      free (trial);
    }

  free (good);
}
static void
bad_names (void)
{
  unsigned char *raw = NULL;
  size_t n = 0;
  xtr_win_ea_list r;

  entries[1].name = (unsigned char *)"zeta";
  entries[1].name_len = 4;
  CHECK (xtr_win_ea_pack (&source, &raw, &n) == XTR_CORRUPT);
  CHECK (raw == NULL && n == 0);
  entries[1].name = (unsigned char *)"/bad";
  entries[1].name_len = 4;
  CHECK (xtr_win_ea_pack (&source, &raw, &n) == XTR_UNSUPPORTED);
  entries[1].name = (unsigned char *)"bad?";
  entries[1].name_len = 4;
  CHECK (xtr_win_ea_pack (&source, &raw, &n) == XTR_UNSUPPORTED);
  entries[1].name = (unsigned char *)"has space";
  entries[1].name_len = 9;
  CHECK (xtr_win_ea_pack (&source, &raw, &n) == XTR_OK);
  free (raw);
  raw = NULL;
  n = 0;
  entries[1].name = (unsigned char *)"empty";
  entries[1].name_len = 5;
  entries[0].flags = 1;
  CHECK (xtr_win_ea_pack (&source, &raw, &n) == XTR_UNSUPPORTED);
  entries[0].flags = 128;
  CHECK (xtr_win_ea_pack_set (&source, &raw, &n) == XTR_UNSUPPORTED);
  CHECK (raw == NULL && n == 0);
  CHECK (xtr_win_ea_parse (NULL, 0, &r) == XTR_OK && r.count == 0);
  xtr_win_ea_free (&r);
}
static xtr_extra
envelope (const xtr1_digest *d, int encrypted)
{
  xtr_extra e;

  memset (&e, 0, sizeof (e));
  memcpy (e.owner, owner, 16);
  e.mode = 2;
  if (encrypted)
    {
      e.flags = 1;
    }
  else
    {
      e.count = d->count;
      e.manifest_len = d->manifest_length;
      e.crc32 = d->crc32;
    }

  return e;
}
static void
manifests (int encrypted)
{
  xtr1_digest dig;
  xtr_extra e;
  xtr_win_ea_list out;
  xtr_u64 len;
  FILE *file = tmpfile ();
  unsigned char ch;
  int rc;

  CHECK (file != NULL);
  if (!file)
    {
      return;
    }

  rc = xtr_win_ea_to_manifest (&source, owner, file, encrypted, &dig);
  CHECK (rc == XTR_OK && dig.count == 3U);
  if (rc)
    {
      fclose (file);
      return;
    }

  e = envelope (&dig, encrypted);
  len = dig.manifest_length;
  if (encrypted)
    {
      len.lo += 36U;
    }

  rc = xtr_win_ea_from_manifest (file, len, &e, encrypted ? NULL : dig.sha256,
                                 &out);
  CHECK (rc == XTR_OK);
  if (!rc)
    {
      CHECK (out.count == 3);
      CHECK (out.items[0].value_len == sizeof (valbig));
      CHECK (!memcmp (out.items[0].value, valbig, sizeof (valbig)));
      CHECK (out.items[1].flags == 128U);
      CHECK (out.items[2].value_len == 0);
      xtr_win_ea_free (&out);
    }

  if (!encrypted)
    {
      unsigned char bad[32];
      memcpy (bad, dig.sha256, 32);
      bad[0] ^= 1;
      CHECK (xtr_win_ea_from_manifest (file, len, &e, bad, &out) != XTR_OK);
    }

  /* Corrupted body must be checked before conversion into native EAs. */
  CHECK (fseek (file, 60L, SEEK_SET) == 0);
  CHECK (fread (&ch, 1, 1, file) == 1);
  ch ^= 1;
  CHECK (fseek (file, 60L, SEEK_SET) == 0);
  CHECK (fwrite (&ch, 1, 1, file) == 1);
  CHECK (fflush (file) == 0);
  CHECK (xtr_win_ea_from_manifest (file, len, &e,
                                   encrypted ? NULL : dig.sha256, &out)
         != XTR_OK);
  fclose (file);
}
int
main (void)
{
  seed ();
  raw_roundtrip ();
  mutations ();
  bad_names ();
  manifests (0);
  manifests (1);
  printf ("Windows EA portable transport: %lu checks; %lu failed\n", checks,
          failures);
  return failures ? 1 : 0;
}
