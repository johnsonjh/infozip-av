/* SPDX-License-Identifier: MIT-0 */
/* FreeBSD/NetBSD traditional EAs plus FreeBSD 15 named-stream adapter. */
#ifndef XTRBSD_H
# define XTRBSD_H
# include "xtrv1.h"
# include <stdio.h>
# include <time.h>
# if defined(__FreeBSD__) || defined(__NetBSD__) || defined(XTR_BSD_TEST)
/* All native operations use the caller's already-open fd.  This adapter
 * captures FreeBSD 15 O_NAMEDATTR streams when supported by the build
 * headers and filesystem, in addition to extattr(2). It does not capture
 * system-namespace EAs. Unknown native record origins fail closed. */
int xtr_bsd_capture_fd (int fd, const unsigned char owner[16], FILE *stage,
                        int encrypted, xtr1_digest *digest);
/* Only Zip sets this in reproducible archive mode; UnZip never enables it. */
void xtr_bsd_capture_set_epoch (time_t epoch);
int xtr_bsd_restore_fd (int fd, FILE *stage, xtr_u64 encoded_size,
                        const xtr_extra *outer, const unsigned char *sha32);
#  ifdef XTR_TEST_HOOKS
void xtr_bsd_test_fail_after (long writes);
#  endif /* ifdef XTR_TEST_HOOKS */
# endif /* if defined( __FreeBSD__ ) || defined( __NetBSD__ ) || defined(      \
          XTR_BSD_TEST ) */
#endif /* ifndef XTRBSD_H */
