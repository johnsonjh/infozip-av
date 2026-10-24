/* SPDX-License-Identifier: MIT-0 */
/* Informational Xtro V1 archive-member association, independent of platform. */
#ifndef UZ_XTRO_ASSOC_H
#define UZ_XTRO_ASSOC_H
#include <stddef.h>

#define UZ_XTRO_ASSOC_COMPANION 1
#define UZ_XTRO_ASSOC_OWNER     2
#define UZ_XTRO_ASSOC_INLINE    4

typedef struct uz_xtro_assoc uz_xtro_assoc;
void uz_xtro_assoc_reset(void);
int uz_xtro_assoc_note(const char *name, const unsigned char *extra,
                       size_t extra_len);
void uz_xtro_assoc_select(const char *name, const unsigned char *extra,
                          size_t extra_len);
int uz_xtro_assoc_extra_kind(const unsigned char *extra, size_t extra_len);
int uz_xtro_assoc_is_companion(const char *name);
const char *uz_xtro_assoc_label(const char *name, char *buf, size_t cap);
const uz_xtro_assoc *uz_xtro_assoc_first(void);
const uz_xtro_assoc *uz_xtro_assoc_next(const uz_xtro_assoc *a);
const char *uz_xtro_assoc_owner(const uz_xtro_assoc *a);
void uz_xtro_assoc_member_name(const uz_xtro_assoc *a, char out[52]);
int uz_xtro_assoc_has_companion(const uz_xtro_assoc *a);
int uz_xtro_assoc_is_selected(const uz_xtro_assoc *a);
int uz_xtro_assoc_needs_followup(const uz_xtro_assoc *a);

#endif
