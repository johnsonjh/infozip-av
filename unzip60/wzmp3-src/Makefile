# Standalone ANSI C89 WZ-MP3 decoder (no third-party libraries).
CC = cc
CFLAGS = -O2 -std=c89 -pedantic -Wall -Wextra -Werror
CORE = wzmp3_core.c wzmp3_ppm.c wzmp3_binary.c wzmp3_regions.c \
       wzmp3_granule.c wzmp3_spectral.c wzmp3_mpeg.c wzmp3_tail.c \
       wzmp3_make.c wzmp3_join.c wzmp3_decode.c wzmp3_codebooks.c

all: wzmp3decode

wzmp3decode: $(CORE) wzmp3_cli.c
	$(CC) $(CFLAGS) -o $@ $(CORE) wzmp3_cli.c

test_codebooks: wzmp3_codebooks.c test_codebooks.c
	$(CC) $(CFLAGS) -o $@ wzmp3_codebooks.c test_codebooks.c

test_core: wzmp3_core.c test_core.c
	$(CC) $(CFLAGS) -o $@ wzmp3_core.c test_core.c

test_join_reject: wzmp3_join.c test_join_reject.c
	$(CC) $(CFLAGS) -o $@ wzmp3_join.c test_join_reject.c

test: test_codebooks test_core test_join_reject
	./test_codebooks
	./test_core
	./test_join_reject

clean:
	rm -f wzmp3decode test_codebooks test_core test_join_reject

.PHONY: all test clean
