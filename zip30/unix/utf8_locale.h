/*
 * Unix LC_CTYPE setup
 */

#ifndef ZIP_UNIX_UTF8_LOCALE_H
# define ZIP_UNIX_UTF8_LOCALE_H

static void
zip_init_unix_utf8_locale (void)
{
  wchar_t decoded[3];
  /* U+00E9 (C3 A9) followed by U+20AC (E2 82 AC), then NUL */
  static const char probe[] = "\303\251\342\202\254";
  size_t length;

  using_utf8 = 0;

  if (setlocale (LC_CTYPE, "") == NULL)
    {
      return;
    }

  length = mbstowcs (decoded, probe, sizeof (decoded) / sizeof (decoded[0]));

  if (length == 2 && decoded[0] == (wchar_t)0x00e9
      && decoded[1] == (wchar_t)0x20ac && decoded[2] == (wchar_t)0)
    {
      using_utf8 = 1;
    }
}

#endif /* ZIP_UNIX_UTF8_LOCALE_H */
