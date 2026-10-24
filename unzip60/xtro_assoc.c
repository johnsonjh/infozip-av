/* SPDX-License-Identifier: MIT-0 */
/* One C89-only implementation for UnZip test/extract and ZipInfo reporting.
 * Informational only: native EA restore and its validation are independent. */
#include "xtro_assoc.h"
#include <stdlib.h>
#include <string.h>

#define UZ_XTRO_BUCKETS 257U
#define UZ_XTRO_LIMIT 65536UL
struct uz_xtro_assoc {
    struct uz_xtro_assoc *hash_next, *all_next;
    unsigned char id[16];
    char *owner;
    unsigned owners, companions;
    int needs_followup, selected;
};
static uz_xtro_assoc *uz_xtro_hash[UZ_XTRO_BUCKETS];
static uz_xtro_assoc *uz_xtro_all, *uz_xtro_tail;
static unsigned long uz_xtro_count;

static unsigned uz_xtro_hash_id(const unsigned char id[16])
{
    unsigned i, h = 2166136261UL % UZ_XTRO_BUCKETS;
    for (i = 0; i < 16; ++i)
        h = (h * 33U + id[i]) % UZ_XTRO_BUCKETS;
    return h;
}

static int uz_xtro_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int uz_xtro_name_id(const char *name, unsigned char id[16])
{
    unsigned i;
    if (!name || strlen(name) != 51U ||
        memcmp(name, "__XTRO_ZIP__/x/", 15) ||
        strcmp(name + 47, ".xtm")) return 0;
    for (i = 0; i < 16; ++i) {
        int a = uz_xtro_nibble(name[15 + 2U * i]);
        int b = uz_xtro_nibble(name[16 + 2U * i]);
        if (a < 0 || b < 0) return 0;
        id[i] = (unsigned char)((a << 4) | b);
    }
    return 1;
}

/* Only metadata sufficient to identify an owner is interpreted here.
 * Never infer an association from an unrelated or malformed extra field. */
static int uz_xtro_extra(const unsigned char *p, size_t n,
                         unsigned char id[16])
{
    int found = 0, kind = 0;
    size_t at = 0;
    if (!p && n) return 0;
    while (at < n) {
        unsigned type, len;
        const unsigned char *v;
        if (n - at < 4U) return 0;
        type = (unsigned)p[at] | ((unsigned)p[at + 1] << 8);
        len = (unsigned)p[at + 2] | ((unsigned)p[at + 3] << 8);
        at += 4U;
        if ((size_t)len > n - at) return 0;
        v = p + at;
        if (type == 0x5854U) {
            unsigned i, zero = 1;
            if (found || len < 40U || memcmp(v, "XTRO\001\000", 6) ||
                (v[6] != 1U && v[6] != 2U) || (v[7] & ~1U)) return 0;
            found = 1;
            for (i = 8; i < 24; ++i)
                if (v[i]) zero = 0;
            if (zero) return 0;
            if (v[6] == 1U) {
                if (v[7] || len < 76U) return 0;
                kind = UZ_XTRO_ASSOC_INLINE;
            } else {
                if (len != (v[7] ? 40U : 72U)) return 0;
                kind = UZ_XTRO_ASSOC_OWNER;
            }
            memcpy(id, v + 8, 16);
        }
        at += len;
    }
    return kind;
}

static uz_xtro_assoc *uz_xtro_get(const unsigned char id[16], int create)
{
    unsigned bucket = uz_xtro_hash_id(id);
    uz_xtro_assoc *p;
    for (p = uz_xtro_hash[bucket]; p; p = p->hash_next)
        if (!memcmp(p->id, id, 16)) return p;
    if (!create || uz_xtro_count >= UZ_XTRO_LIMIT) return NULL;
    p = (uz_xtro_assoc *)calloc(1U, sizeof(*p));
    if (!p) return NULL;
    memcpy(p->id, id, 16);
    p->hash_next = uz_xtro_hash[bucket];
    uz_xtro_hash[bucket] = p;
    if (uz_xtro_tail) uz_xtro_tail->all_next = p;
    else uz_xtro_all = p;
    uz_xtro_tail = p;
    ++uz_xtro_count;
    return p;
}

void uz_xtro_assoc_reset(void)
{
    uz_xtro_assoc *p = uz_xtro_all;
    while (p) {
        uz_xtro_assoc *next = p->all_next;
        free(p->owner);
        free(p);
        p = next;
    }
    memset(uz_xtro_hash, 0, sizeof(uz_xtro_hash));
    uz_xtro_all = uz_xtro_tail = NULL;
    uz_xtro_count = 0;
}

int uz_xtro_assoc_note(const char *name, const unsigned char *extra,
                       size_t extra_len)
{
    unsigned char cid[16], oid[16];
    int companion, type;
    uz_xtro_assoc *p;
    if (!name) return 0;
    companion = uz_xtro_name_id(name, cid);
    type = uz_xtro_extra(extra, extra_len, oid);
    if (companion) {
        /* Reserved names must not also advertise an owner extra field. */
        if (type) return 0;
        p = uz_xtro_get(cid, 1);
        if (p && p->companions < 2U) ++p->companions;
        return UZ_XTRO_ASSOC_COMPANION;
    }
    if (type == UZ_XTRO_ASSOC_OWNER) {
        p = uz_xtro_get(oid, 1);
        if (p) {
            if (p->owners < 2U) ++p->owners;
            if (p->owners == 1U) {
                size_t n = strlen(name);
                p->owner = (char *)malloc(n + 1U);
                if (p->owner) memcpy(p->owner, name, n + 1U);
            }
        }
    }
    return type;
}

int uz_xtro_assoc_extra_kind(const unsigned char *extra, size_t extra_len)
{
    unsigned char id[16];
    return uz_xtro_extra(extra, extra_len, id);
}

void uz_xtro_assoc_select(const char *name, const unsigned char *extra,
                          size_t extra_len)
{
    unsigned char id[16];
    uz_xtro_assoc *p = NULL;
    if (uz_xtro_name_id(name, id) ||
        uz_xtro_extra(extra, extra_len, id) == UZ_XTRO_ASSOC_OWNER)
        p = uz_xtro_get(id, 0);
    if (p) p->selected = 1;
}

int uz_xtro_assoc_is_companion(const char *name)
{
    unsigned char id[16];
    return uz_xtro_name_id(name, id);
}

const char *uz_xtro_assoc_label(const char *name, char *buf, size_t cap)
{
    unsigned char id[16];
    uz_xtro_assoc *p;
    const char *owner;
    size_t n;
    if (!uz_xtro_name_id(name, id)) return name;
    p = uz_xtro_get(id, 0);
    owner = p && p->owners == 1U ? p->owner : NULL;
    if (!owner) {
        if (p) p->needs_followup = 1;
        if (p && p->owners > 1U)
            return "[Xtro: ambiguous owner]";
        return "[Xtro: owner not yet identified]";
    }
    n = strlen(owner);
    if (cap < 9U || n > cap - 9U) return "[Xtro: owner name too long]";
    memcpy(buf, "[Xtro: ", 7);
    memcpy(buf + 7, owner, n);
    buf[7 + n] = ']';
    buf[8 + n] = '\0';
    return buf;
}

const uz_xtro_assoc *uz_xtro_assoc_first(void) { return uz_xtro_all; }
const uz_xtro_assoc *uz_xtro_assoc_next(const uz_xtro_assoc *p)
{ return p ? p->all_next : NULL; }
const char *uz_xtro_assoc_owner(const uz_xtro_assoc *p)
{ return p && p->owners == 1U ? p->owner : NULL; }
int uz_xtro_assoc_has_companion(const uz_xtro_assoc *p)
{ return p && p->companions != 0; }
int uz_xtro_assoc_is_selected(const uz_xtro_assoc *p)
{ return p && p->selected; }
int uz_xtro_assoc_needs_followup(const uz_xtro_assoc *p)
{ return p && p->needs_followup && p->companions != 0; }
void uz_xtro_assoc_member_name(const uz_xtro_assoc *p, char out[52])
{
    static const char hexdigits[] = "0123456789abcdef";
    unsigned i;
    memcpy(out, "__XTRO_ZIP__/x/", 15);
    for (i = 0; i < 16; ++i) {
        out[15 + 2U * i] = hexdigits[(p->id[i] >> 4) & 15U];
        out[16 + 2U * i] = hexdigits[p->id[i] & 15U];
    }
    memcpy(out + 47, ".xtm", 5);
}
