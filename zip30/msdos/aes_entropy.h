/*
 * SPDX-License-Identifier: MIT-0
 */

#ifndef IZ_DOS16_AES_ENTROPY_H
# define IZ_DOS16_AES_ENTROPY_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>

static FILE *iz_dos_pool_fp;
static char iz_dos_pool_claim[FILENAME_MAX];
static int iz_dos_pool_state; /* 0 untried, 1 opened, -1 unavailable */
static int iz_dos_pool_reported;

static void
iz_dos_pool_close (void)
{
  if (iz_dos_pool_fp != NULL)
    {
      fclose (iz_dos_pool_fp);
      iz_dos_pool_fp = NULL;
    }

  if (iz_dos_pool_claim[0] != '\0')
    {
      /* The file is never restored or reused, including on failed jobs! */
      remove (iz_dos_pool_claim);
    }
}

static int
iz_dos_pool_open (void)
{
  const char *source = getenv ("XTR_AES_POOL");
  char *name, *dot, *p;
  FILE *existing;
  size_t length;

  if (iz_dos_pool_state != 0)
    {
      return iz_dos_pool_state == 1;
    }

  iz_dos_pool_state = -1;

  if (source == NULL || source[0] == '\0')
    {
      source = "XTRRND.BIN";
    }

  length = strlen (source);

  if (length == 0 || length + 4 >= sizeof (iz_dos_pool_claim))
    {
      return 0;
    }

  strcpy (iz_dos_pool_claim, source);
  name = iz_dos_pool_claim;

  for (p = iz_dos_pool_claim; *p != '\0'; ++p)
    {
      if (*p == '\\' || *p == '/' || *p == ':')
        {
          name = p + 1;
        }
    }

  if (*name == '\0')
    {
      return 0;
    }

  dot = strrchr (name, '.');

  if (dot != NULL)
    {
      *dot = '\0';
    }

  strcat (iz_dos_pool_claim, ".USE");

  if (strcmp (source, iz_dos_pool_claim) == 0)
    {
      return 0;
    }

  existing = fopen (iz_dos_pool_claim, "rb");

  if (existing != NULL)
    {
      fclose (existing);

      return 0;
    }

  if (rename (source, iz_dos_pool_claim) != 0)
    {
      return 0;
    }

  iz_dos_pool_fp = fopen (iz_dos_pool_claim, "rb");

  if (iz_dos_pool_fp == NULL)
    {
      return 0;
    }

  if (atexit (iz_dos_pool_close) != 0)
    {
      fclose (iz_dos_pool_fp);
      iz_dos_pool_fp = NULL;

      return 0;
    }

  iz_dos_pool_state = 1;

  return 1;
}

static int
iz_dos_salt_from_pool (unsigned char *out, size_t n)
{
  unsigned char slot[16];
  size_t got;

  if (out == NULL || (n != 8 && n != 12 && n != 16))
    {
      return 0;
    }

  if (!iz_dos_pool_open ())
    {
      goto fail;
    }

  got = fread (slot, 1, sizeof (slot), iz_dos_pool_fp);

  if (got != sizeof (slot))
    {
      goto fail;
    }

  memcpy (out, slot, n);
  iz_aes_wipe (slot, sizeof (slot));

  return 1;

fail:
  iz_aes_wipe (slot, sizeof (slot));
  if (!iz_dos_pool_reported)
    {
      fputs ("zip: DOS AES selected a salt pool but it is missing, "
             "invalid or exhausted (XTRRND.BIN or XTR_AES_POOL).\n",
             stderr);
      iz_dos_pool_reported = 1;
    }

  return 0;
}

#endif /* IZ_DOS16_AES_ENTROPY_H */
