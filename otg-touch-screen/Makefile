# Cross-compile example:
#   make CC=arm-linux-gnueabihf-gcc

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDFLAGS ?=

.PHONY: all clean install

all: touch-to-hidg

touch-to-hidg: touch-to-hidg.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

install: touch-to-hidg
	install -m 755 touch-to-hidg /usr/local/bin/
