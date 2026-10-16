/* SPDX-License-Identifier: MIT-0 */
/* One Windows EA/ADS manifest, streamed into a private ZIP staging file. */
#ifndef XTRWIN_MIXED_H
# define XTRWIN_MIXED_H
# include "xtrwin_nt.h"
# ifdef _WIN32
int xtr_win_mixed_capture (void *pinned, const unsigned char owner[16],
                           FILE *manifest, FILE *spool, int with_eas,
                           int encrypted, xtr1_digest *digest);
# endif /* ifdef _WIN32 */
#endif /* ifndef XTRWIN_MIXED_H */
