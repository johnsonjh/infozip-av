/* Independently generated PBKDF2/AES-CTR/HMAC-SHA1 vectors for DOS AES.
 * C89 host-only test of shared core, not proof of DOS16 runtime operation.
 * Reference: PBKDF2-HMAC-SHA1 1000 iterations, AES-ECB(counter LE=1...),
 * HMAC-SHA1 over ciphertext truncated to 10 bytes.
 */
#include <stdio.h>
#include <string.h>
#include "../../zip30/wzaes.h"

static const unsigned char plain[] =
    "This is an AES interoperability test.";
static const struct {
    unsigned strength;
    const char *verifier;
    const char *cipher;
    const char *tag;
} vectors[] = {
    {128, "831e",
     "9a001a9264507eb4c80578aeb2acf74663264271134013069875e5979a8b4fc5415ef276f5",
     "57453efbfda93cf93a98"},
    {192, "a093",
     "7a037f8b31f15959be0cd748f5de6e40fd0014a649218a38e9f822351ef315a97e0629ef6c",
     "2394f1eefe4b28390d08"},
    {256, "d68d",
     "a0af28d2187c82b3f17fa42e74209e912d20c5f8db407321a9af1440853f456d8fc31ba86b",
     "4ffd3c1baaef040faeb4"}
};

static int nybble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static int match_hex(const unsigned char *bytes, unsigned count,
                     const char *hex)
{
    unsigned i;
    for (i = 0; i < count; ++i) {
        int a = nybble(hex[2 * i]), b = nybble(hex[2 * i + 1]);
        if (a < 0 || b < 0 || bytes[i] != (unsigned char)(a * 16 + b))
            return 0;
    }
    return hex[2 * count] == '\0';
}
int main(void)
{
    unsigned i, j;
    unsigned char salt[16], v[2], v2[2], tag[10], tag2[10];
    unsigned char ciphertext[sizeof(plain) - 1];
    iz_wzaes encrypt_ctx, decrypt_ctx;
    for (j = 0; j < 16; ++j) salt[j] = (unsigned char)j;
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        memcpy(ciphertext, plain, sizeof(ciphertext));
        if (!iz_aes_init(&encrypt_ctx, "testpass", salt,
                         vectors[i].strength, v)) return 1;
        if (!match_hex(v, 2, vectors[i].verifier)) return 2;
        iz_aes_encrypt(&encrypt_ctx, ciphertext, sizeof(ciphertext));
        iz_aes_auth(&encrypt_ctx, tag);
        if (!match_hex(ciphertext, sizeof(ciphertext), vectors[i].cipher))
            return 3;
        if (!match_hex(tag, sizeof(tag), vectors[i].tag)) return 4;
        if (!iz_aes_init(&decrypt_ctx, "testpass", salt,
                         vectors[i].strength, v2)) return 5;
        iz_aes_decrypt(&decrypt_ctx, ciphertext, sizeof(ciphertext));
        iz_aes_auth(&decrypt_ctx, tag2);
        if (memcmp(ciphertext, plain, sizeof(ciphertext)) != 0 ||
            memcmp(tag, tag2, 10) != 0 || memcmp(v, v2, 2) != 0)
            return 6;
        iz_aes_wipe(&encrypt_ctx, sizeof(encrypt_ctx));
        iz_aes_wipe(&decrypt_ctx, sizeof(decrypt_ctx));
    }
    puts("PASS: AES-128/192/256 verifier, ciphertext, tag and decrypt vectors");
    return 0;
}
