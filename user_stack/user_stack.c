#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

void print_stack_trace() {
    void *buffer[100];
    int size = backtrace(buffer, 100);
    char **symbols = backtrace_symbols(buffer, size);

    printf("Call stack:\n");
    for (int i = 0; i < size; i++) {
        printf("%s\n", symbols[i]);
    }

    free(symbols); // 释放内存
}

void foo() {
    print_stack_trace();
}

int main() {
    foo();
    return 0;
}