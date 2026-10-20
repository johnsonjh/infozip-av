/* SPDX-License-Identifier: MIT-0 */
#ifndef XTROS2_NLS_H
# define XTROS2_NLS_H
# include "xtros2_ea.h"
/* Pass to xtr_os2_ea_parse_ex / xtr_os2_ea_reconcile_ex on native OS/2. */
int xtr_os2_ea_native_equal (const unsigned char *, size_t,
                             const unsigned char *, size_t, void *);
#endif /* ifndef XTROS2_NLS_H */
