/* Native Windows console argument conversion; MIT-0. */
#ifndef XTRWIN_UTF8ARGV_H
# define XTRWIN_UTF8ARGV_H
int xtr_win_utf8_argv (int *argc, char ***argv);
void xtr_win_utf8_free_argv (int argc, char **argv);
#endif /* ifndef XTRWIN_UTF8ARGV_H */
