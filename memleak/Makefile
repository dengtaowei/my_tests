CC = gcc
CFLAGS = -Wall -Wextra -g -rdynamic  -ldl# -rdynamic 确保函数名可读
TARGET = memleakv1 memleakv2

all: $(TARGET)

memleakv1: memleakv1.c other_file.c
	$(CC) $(CFLAGS) $< -o $@

memleakv2: memleakv2.c other_file.c
	$(CC) $(CFLAGS) $< other_file.c -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean