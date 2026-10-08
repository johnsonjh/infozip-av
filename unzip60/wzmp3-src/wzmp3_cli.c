/* SPDX-License-Identifier: MIT-0
 * Standalone WZ-MP3 / packMP3 Method 94 decoder.
 * Usage: wzmp3decode input.pmp output.mp3 expected_uncompressed_bytes
 * Does not depend on the original MP3, any reference implementation,
 * or a system MP3 decoder library.
 */
#include "wzmp3_decode.h"
#include "wzmp3_codebooks.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct wzmp3_file_s { FILE *fp; } wzmp3_file;
static int wzmp3_get(void *ctx, unsigned char *c)
{
    wzmp3_file *f = (wzmp3_file *)ctx;
    return f && f->fp && fread(c, 1U, 1U, f->fp) == 1U;
}
static int wzmp3_put(void *ctx, const unsigned char *buf, size_t count)
{
    wzmp3_file *f = (wzmp3_file *)ctx;
    return f && f->fp && (!count || fwrite(buf, 1U, count, f->fp) == count);
}
static int parse_size(const char *s, size_t *n)
{
    size_t value = 0U;
    if (!s || !*s || !n) return 0;
    while (*s) {
        unsigned int d;
        if (*s < '0' || *s > '9') return 0;
        d = (unsigned int)(*s++ - '0');
        if (value > (((size_t)-1) - d)/10U) return 0;
        value = value * 10U + d;
    }
    *n = value;
    return value > 0U;
}
int main(int argc, char **argv)
{
    wzmp3_file in, out;
    wzmp3_input reader;
    wzmp3_decode_options options;
    wzmp3_codebook *books = NULL;
    long compressed;
    int ok = 0;
    int created = 0;
    in.fp = NULL; out.fp = NULL;
    if (argc != 4 || !parse_size(argv[3], &options.maximum_output)) {
        fprintf(stderr, "usage: %s input.pmp output.mp3 expected_uncompressed_bytes\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], argv[2]) == 0) {
        fprintf(stderr, "Input and output paths must differ\n");
        return 2;
    }
    options.maximum_frames = 1000000UL;
    in.fp = fopen(argv[1], "rb");
    if (!in.fp) goto cleanup;
    if (fseek(in.fp, 0L, SEEK_END) || (compressed = ftell(in.fp)) < 0L ||
        fseek(in.fp, 0L, SEEK_SET)) goto cleanup;
    books = (wzmp3_codebook *)malloc(34U * sizeof(*books));
    if (!books) goto cleanup;
    wzmp3_codebooks_init(books);
    /* Open only after input validation; never use the original MP3. */
    out.fp = fopen(argv[2], "wb");
    if (!out.fp) goto cleanup;
    created = 1;
    wzmp3_input_init(&reader, wzmp3_get, &in, 0UL, (unsigned long)compressed);
    ok = wzmp3_decode(&reader, books, &options, wzmp3_put, &out);
    if (fclose(out.fp)) ok = 0;
    out.fp = NULL;
cleanup:
    if (out.fp) fclose(out.fp);
    if (in.fp) fclose(in.fp);
    free(books);
    if (!ok) {
        if (created) remove(argv[2]);
        fprintf(stderr, "WZ-MP3 decode failed\n");
        return 1;
    }
    return 0;
}
