
#define _GNU_SOURCE
#include <execinfo.h>
#include <dlfcn.h>
#include <link.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void *ConvertToELF(void *addr)
{

    Dl_info info;
    struct link_map *link;

    dladdr1(addr, &info, (void **)&link, RTLD_DL_LINKMAP);

    return (void *)((size_t)addr - link->l_addr);
}

// main --> f1 --> f2 --> my_malloc

void *my_malloc(size_t size)
{

    void *p = NULL;

    p = malloc(size);
    if (!p)
    {
        return NULL;
    }

    // void *caller = __builtin_return_address(0);

    char buff[128] = {0};
    sprintf(buff, "./mem/%p.mem", p);

#if 0
		FILE *fp = fopen(buff, "w");
		if (!fp) {
			my_free(p);
			return NULL;
		}

		//fprintf(fp, "[+]%p, addr: %p, size: %ld\n", caller, p, size);
		fprintf(fp, "[+]%p, addr: %p, size: %ld\n", ConvertToELF(caller), p, size);
		fflush(fp);

#endif
    void *buffer[100];
    int nbt = backtrace(buffer, 100);
    int fd = open(buff, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        my_free(p);
        return NULL;
    }
    backtrace_symbols_fd(buffer, nbt, fd);
    close(fd);

    return p;
}

// addr2line
void my_free(void *ptr)
{
    char buff[128] = {0};
    snprintf(buff, 128, "./mem/%p.mem", ptr);

    if (unlink(buff) < 0)
    {
        printf("double my_free: %p", ptr);
        return;
    }

    free(ptr);

    return;
}

int main()
{
    void *p1 = my_malloc(5);
    void *p2 = my_malloc(10);
    void *p3 = my_malloc(35);
    void *p4 = my_malloc(10);

    my_free(p1);
    my_free(p3);
    my_free(p4);
    getchar();
}
