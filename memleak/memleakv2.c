
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

typedef void *(*malloc_t)(size_t size);
malloc_t malloc_f = NULL;

typedef void (*free_t)(void *ptr);
free_t free_f = NULL;

int enable_malloc = 1;
int enable_free = 1;



void *ConvertToELF(void *addr) {

	Dl_info info;
	struct link_map *link;
	
	dladdr1(addr, &info, (void **)&link, RTLD_DL_LINKMAP);

	return (void *)((size_t)addr - link->l_addr);
}

// main --> f1 --> f2 --> malloc

void *malloc(size_t size) {

	void *p = NULL;

	if (enable_malloc) {
		enable_malloc = 0;
        enable_free = 0;

		p = malloc_f(size);

		void *caller = __builtin_return_address(0);

		char buff[128] = {0};
		sprintf(buff, "./mem/%p.mem", p);

		void *buffer[100];
        int nbt = backtrace(buffer, 100);
        int fd = open(buff, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1)
        {
            free(p);
            enable_malloc = 1;
            enable_free = 1;
            return NULL;
        }
        backtrace_symbols_fd(buffer, nbt, fd);
        close(fd);
		
		enable_malloc = 1;
        enable_free = 1;
		
	} else {
		p = malloc_f(size);
	}


	return p;
}


// addr2line 
void free(void *ptr) {

	if (enable_free) {
		enable_free = 0;
        enable_malloc = 0;

		char buff[128] = {0};
		snprintf(buff, 128, "./mem/%p.mem", ptr);

		if (unlink(buff) < 0) {
			printf("double free: %p", ptr);
            enable_free = 1;
            enable_malloc = 1;
			return ;
		}

		free_f(ptr);

		enable_free = 1;
        enable_malloc = 1;
	} else {
		free_f(ptr);
	}

	return ;
}


void init_hook(void) {

	if (!malloc_f) {
		malloc_f = (malloc_t)dlsym(RTLD_NEXT, "malloc");
	}
	if (!free_f) {
		free_f = (free_t)dlsym(RTLD_NEXT, "free");
	}

}

int main() {

	init_hook();

	void *p1 = malloc(5);
	void *p2 = malloc(10);  
	void *p3 = malloc(35);
	void *p4 = malloc(10);

    other_file_malloc(16);
    other_file_malloc(17);
    other_file_malloc(18);
    other_file_malloc(19);

	free(p1);
	free(p3);
	free(p4);
	getchar();

} 



