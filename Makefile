# Wrapper for generic UNIX builds only!
# SPDX-License-Identifier: MIT-0
# Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>

# Dependency tracking sort of sucks currently, so always clean first.
all:
	$${MAKE:-$(MAKE)} clean
	$${MAKE:-$(MAKE)} build

clean: clean.sh
	./clean.sh

build: build-unix.sh
	./build-unix.sh

.PHONY: all clean build
