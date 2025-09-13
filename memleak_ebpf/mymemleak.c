// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>  // 用于 struct timeval
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include "mymemleak.skel.h"
#include "mymemleak.h"
#include <assert.h>
#include "blazesym.h"



static struct env {
	int interval;
	int nr_intervals;
	pid_t pid;
	bool trace_all;
	bool show_allocs;
	bool combined_only;
	int min_age_ns;
	uint64_t sample_rate;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char object[32];

	bool wa_missing_free;
	bool percpu;
	int perf_max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool kernel_trace;
	bool verbose;
	char command[32];
    char folder[128];
} env = {
	.interval = 5, // posarg 1
	.nr_intervals = -1, // posarg 2
	.pid = -1, // -p --pid
	.trace_all = false, // -t --trace
	.show_allocs = false, // -a --show-allocs
	.combined_only = false, // --combined-only
	.min_age_ns = 500, // -o --older (arg * 1e6)
	.wa_missing_free = false, // --wa-missing-free
	.sample_rate = 1, // -s --sample-rate
	.top_stacks = 10, // -T --top
	.min_size = 0, // -z --min-size
	.max_size = -1, // -Z --max-size
	.object = {0}, // -O --obj
	.percpu = false, // --percpu
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.kernel_trace = true,
	.verbose = false,
	.command = {0}, // -c --command
    .folder = {0},
};

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = #sym_name, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				env.pid, \
				env.object, \
				0, \
				&uprobe_opts); \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name) \
	do { \
		if (!skel->links.prog_name) { \
			perror("no program attached for " #prog_name); \
			return -errno; \
		} \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do { \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
		__CHECK_PROGRAM(skel, prog_name); \
	} while (false)

/* ATTACH_UPROBE_CHECKED 和 ATTACH_UPROBE 宏的区别是:
 * ATTACH_UPROBE_CHECKED 会检查elf文件中(比如 libc.so)中是否存在 uprobe attach 的符号(比如malloc)
 * 如果不存在，返回错误；
 * ATTACH_UPROBE 发现符号不存在时不会返回错误，直接跳过这个符号的uprobe attach,继续往下执行；
 */
#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)


const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"modified from https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace outstanding memory allocations\n"
"\n"
"USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] [-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] [-f FOLDER] [-P] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"
"./memleak -p $(pidof allocs)\n"
"        Trace allocations and display a summary of 'leaked' (outstanding)\n"
"        allocations every 5 seconds\n"
"./memleak -p $(pidof allocs) -t\n"
"        Trace allocations and display each individual allocator function call\n"
"./memleak -ap $(pidof allocs) 10\n"
"        Trace allocations and display allocated addresses, sizes, and stacks\n"
"        every 10 seconds for outstanding allocations\n"
"./memleak -c './allocs'\n"
"        Run the specified command and trace its allocations\n"
"./memleak\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations every 5 seconds\n"
"./memleak -o 60000\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations that are at least one minute (60 seconds) old\n"
"./memleak -s 5\n"
"        Trace roughly every 5th allocation, to reduce overhead\n"
"";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "process ID to trace. if not specified, trace kernel allocs"},
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call" },
	{"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks"},
	{"older", 'o', "AGE_MS", 0, "prune allocations younger than this age in milliseconds"},
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command"},
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only"},
	{"wa-missing-free", 'F', 0, 0, "workaround to alleviate misjudgments when free is missing"},
	{"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead"},
	{"top", 'T', "TOP_STACKS", 0, "display only this many top allocating stacks (by size)"},
	{"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than this size"},
	{"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than this size"},
	{"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object"},
	{"percpu", 'P', NULL, 0, "trace percpu allocations"},
    {"folder", 'f', "FOLDER", 0, "print allocs to a folder"},
	{},
};

static const char default_object[] = "libc.so.6";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static struct blaze_symbolizer *symbolizer;

static void print_frame(char *buffer, int buflen, int *pos, const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
	/* If we have an input address  we have a new symbol. */
	if (input_addr != 0) {
		*pos += snprintf(buffer + *pos, buflen - *pos, "%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			*pos += snprintf(buffer + *pos, buflen - *pos, " %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			*pos += snprintf(buffer + *pos, buflen - *pos, " %s:%u\n", code_info->file, code_info->line);
		} else {
			*pos += snprintf(buffer + *pos, buflen - *pos, "\n");
		}
	} else {
		*pos += snprintf(buffer + *pos, buflen - *pos, "%16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			*pos += snprintf(buffer + *pos, buflen - *pos, "@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			*pos += snprintf(buffer + *pos, buflen - *pos, "@ %s:%u [inlined]\n", code_info->file, code_info->line);
		} else {
			*pos += snprintf(buffer + *pos, buflen - *pos, "[inlined]\n");
		}
	}
}

static void show_stack_trace(char *buffer, int buflen, int *pos, __u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *syms;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};

		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};

		syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	if (!syms) {
		*pos += snprintf(buffer + *pos, buflen - *pos, "  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
			*pos += snprintf(buffer + *pos, buflen - *pos, "%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &syms->syms[i];
		print_frame(buffer, buflen, pos, sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(buffer, buflen, pos, inlined->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_syms_free(syms);
}

int print_outstanding_combined_allocs(struct mymemleak_bpf * skel, pid_t pid)
{

	return 0;
}

int attach_uprobes(struct mymemleak_bpf *skel)
{
	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
	ATTACH_UPROBE_CHECKED(skel, free, free_enter);

	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

	ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
	ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

	// ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

	// the following probes are intentinally allowed to fail attachment

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, valloc, valloc_enter);
	ATTACH_URETPROBE(skel, valloc, valloc_exit);

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

	// added in C11
	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

void record_allocs(char *buffer, uint64_t addr)
{
    char buff[256] = {0};

    if (env.folder[0] == '\0')
    {
        printf("%s", buffer);
        return;
    }
    
    sprintf(buff, "%s/0x%016lx.mem", env.folder, addr);
    FILE *fp = fopen(buff, "w");
    if (!fp) {
        return;
    }

    //fprintf(fp, "[+]%p, addr: %p, size: %ld\n", caller, p, size);
    fprintf(fp, "%s", buffer);
    fflush(fp);
    fclose(fp);
    return;
}

void delete_allocs(char *buffer, uint64_t addr)
{
    char buff[256] = {0};

    if (env.folder[0] == '\0')
    {
        printf("%s", buffer);
        return;
    }
    
    sprintf(buff, "%s/0x%016lx.mem", env.folder, addr);
    if (unlink(buff) < 0)
    {
        printf("double my_free: 0x%016lx", addr);
        return;
    }
}

void format_nanosecond_timestamp(char *buffer, int buflen, int *pos, long long timestamp_ns) {
    // 1. 分离秒和纳秒部分
    time_t seconds = timestamp_ns / 1000000000;
    long nanoseconds = timestamp_ns % 1000000000;

    // 2. 转换为本地时间
    struct tm *timeinfo = localtime(&seconds);
    if (timeinfo == NULL) {
        return;
    }

    // 3. 格式化为字符串（精确到纳秒）
    char buff[80];
    strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", timeinfo);
    *pos += snprintf(buffer + *pos, buflen - *pos, "%s.%09ld\n", buff, nanoseconds);
}

time_t get_boot_time() {
    struct sysinfo info;
    sysinfo(&info);  // 获取系统信息（包括 uptime）
    return time(NULL) - info.uptime;  // boot_time = current_time - uptime
}

uint64_t convert_to_unix_time(uint64_t time_since_boot_ns) {
    time_t boot_time = get_boot_time();  // 系统启动时间（秒）
    return (uint64_t)boot_time * 1000000000ULL + time_since_boot_ns;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct stacktrace_event *event = data;

    static char buffer[2048] = { 0 };
    int pos = 0;

	time_t seconds = event->timestamp_ns / 1000000000;
    long nanoseconds = event->timestamp_ns % 1000000000;
	pos += snprintf(buffer + pos, sizeof(buffer) - pos, "[%ld.%ld]", seconds, nanoseconds);

	uint64_t unix_time_ns = convert_to_unix_time(event->timestamp_ns);

	format_nanosecond_timestamp(buffer, sizeof(buffer), &pos, unix_time_ns);

	pos += snprintf(buffer + pos, sizeof(buffer) - pos, "COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

    if (event->evt_id == EVT_ID_FREE_IN)
    {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "free: %p\n", (void *)event->address);
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n");
        delete_allocs(buffer, event->address);
        return 0;
    }

	if (event->ustack_sz > 0) {
		pos += snprintf(buffer + pos, sizeof(buffer) - pos, "alloc: %p, size: %llu\n", (void *)event->address, event->size);
		show_stack_trace(buffer, sizeof(buffer), &pos, event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	} else {
		pos += snprintf(buffer + pos, sizeof(buffer) - pos, "No Userspace Stack\n");
	}

	pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n");
    
    record_allocs(buffer, event->address);
	return 0;
}

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;

	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'a':
		env.show_allocs = true;
		break;
	case 'o':
		env.min_age_ns = 1e6 * atoi(arg);
		break;
	case 'c':
		strncpy(env.command, arg, sizeof(env.command) - 1);
		break;
    case 'f':
        strncpy(env.folder, arg, sizeof(env.folder) - 1);
        break;
	case 'C':
		env.combined_only = true;
		break;
	case 'F':
		env.wa_missing_free = true;
		break;
	case 's':
		env.sample_rate = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.top_stacks = atoi(arg);
		break;
	case 'z':
		env.min_size = argp_parse_long(key, arg, state);
		break;
	case 'Z':
		env.max_size = argp_parse_long(key, arg, state);
		break;
	case 'O':
		strncpy(env.object, arg, sizeof(env.object) - 1);
		break;
	case 'P':
		env.percpu = true;
		break;
	case ARGP_KEY_ARG:
		pos_args++;

		if (pos_args == 1) {
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			env.nr_intervals = argp_parse_long(key, arg, state);
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct mymemleak_bpf *skel;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
    struct ring_buffer *ring_buf = NULL;
    char cmd[256] = { 0 };

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

    // parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		goto cleanup;
	}

    if (!strlen(env.object)) {
		printf("using default object: %s\n", default_object);
		strncpy(env.object, default_object, sizeof(env.object) - 1);
	}

    if (env.folder[0] != '\0')
    {
        snprintf(cmd, sizeof(cmd), "mkdir -p %s", env.folder);
        system(cmd);
    }

    /* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = mymemleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    skel->rodata->trace_all = env.trace_all;

	err = mymemleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

    err = attach_uprobes(skel);
    if (err) {
        fprintf(stderr, "failed to attach uprobes\n");
        goto cleanup;
    }

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = mymemleak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

		/* Set up ring buffer polling */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(ring_buf, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
    ring_buffer__free(ring_buf);
	mymemleak_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	return -err;
}
