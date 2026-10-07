/* WinZip AES (AE-1 and AE-2) primitives, C89, no external crypto library.
 * Internal to Info-ZIP; not PKWARE Strong Encryption.
 */
#ifndef IZ_WZAES_H
#define IZ_WZAES_H
#ifndef NO_AES
#include <stddef.h>
typedef struct {
    unsigned long h[5], low, high;
    unsigned char block[64];
    unsigned used;
} iz_sha1;
typedef struct {
    iz_sha1 inner, outer;
} iz_hmac;
typedef struct {
    unsigned char expanded[240];
    unsigned rounds;
    unsigned char counter[16], stream[16];
    unsigned stream_pos;
    iz_hmac mac;
} iz_wzaes;
unsigned iz_aes_salt_size(unsigned strength);
int iz_aes_init(iz_wzaes *ctx, const char *password,
                const unsigned char *salt, unsigned strength,
                unsigned char verifier[2]);
void iz_aes_encrypt(iz_wzaes *ctx, unsigned char *buf, size_t len);
void iz_aes_decrypt(iz_wzaes *ctx, unsigned char *buf, size_t len);
void iz_aes_auth(iz_wzaes *ctx, unsigned char tag[10]);
void iz_aes_mac_update(iz_wzaes *ctx, const unsigned char *ciphertext, size_t n);
void iz_aes_wipe(void *ptr, size_t n);
int iz_aes_entropy(unsigned char *salt, size_t length);
#endif
#endif
