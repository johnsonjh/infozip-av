/* Windows UTF-8 paths for native Xtro Zip. MIT-0. */
#ifndef XTR_ZIP_UTF8_PATHS_H
#define XTR_ZIP_UTF8_PATHS_H
#if defined(XTR_WIN_NATIVE) && defined(WIN32) && defined(__MINGW32__) && !defined(UTIL) && !defined(WINDLL)
int xtr_zip_u8_argv(int *argc, char ***argv);
int xtr_zip_u8_active(void);
FILE *xtr_zip_u8_fopen(const char *path, const char *mode);
int xtr_zip_u8_stat(const char *path, z_stat *st);
int xtr_zip_u8_unlink(const char *path);
int xtr_zip_u8_rename(const char *from, const char *to);
char *xtr_zip_u8_tempname(const char *directory);
#endif
#endif
