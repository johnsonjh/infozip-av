/* SPDX-License-Identifier: MIT-0 */
/* Linux named-value adapter for Zip capture and UnZip restoration.
 * All APIs require an already-opened no-follow file descriptor. */
#ifndef XTRLINUX_H
# define XTRLINUX_H
# include "xtrv1.h"
# include <stdio.h>
# ifdef __linux__
/* The caller owns staging, owner ID, ZIP compression and encryption. Capture
 * stores an XTMD manifest in a seekable staging FILE, rewound on success.
 * Only user.* attributes are eligible by default. */
int xtr_linux_capture_fd (int fd, const unsigned char owner[16], FILE *stage,
                          int encrypted, xtr1_digest *digest);
/* Verify complete manifest SHA/CRC/schema BEFORE touching destination.
 * The encoded size and outer metadata must come from validated ZIP headers.
 * stage is a seekable, already decrypted/decompressed, private staging FILE.
 * Replaces the destination's eligible user.* namespace exactly. On native
 * write errors the old bounded snapshot is restored on a best-effort basis;
 * concurrent writes and native rollback failures are not atomic. */
int xtr_linux_restore_fd (int fd, FILE *stage, xtr_u64 encoded_size,
                          const xtr_extra *outer, const unsigned char *sha32);
#  ifdef XTR_TEST_HOOKS
/* Test-only injected error after N successful attribute writes. */
void xtr_linux_test_fail_after (long writes);
#  endif /* ifdef XTR_TEST_HOOKS */
# endif /* ifdef __linux__ */
#endif /* ifndef XTRLINUX_H */
