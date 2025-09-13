CC = gcc
CFLAGS = -Wall -Wextra -g -rdynamic  # -rdynamic 确保函数名可读
TARGET = user_stack

all: $(TARGET)

$(TARGET): user_stack.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean