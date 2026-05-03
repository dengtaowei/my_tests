CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: fb_painter

fb_painter: fb_painter.c
	$(CC) $(CFLAGS) -o $@ fb_painter.c

clean:
	rm -f fb_painter
