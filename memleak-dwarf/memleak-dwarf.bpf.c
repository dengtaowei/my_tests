// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "memleak-dwarf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define PT_REGS_PARM5_ARM(ctx) ({\
    u32 sp = (u32)PT_REGS_SP(ctx); \
    u32 arg5; \
    bpf_probe_read_kernel(&arg5, sizeof(arg5), (sp + 0x0)); \
    arg5; \
})

#define PT_REGS_PARM6_ARM(ctx) ({\
    u32 sp = (u32)PT_REGS_SP(ctx); \
    u32 arg6; \
    bpf_probe_read_kernel(&arg6, sizeof(arg6), (sp + 0x4)); \
    arg6; \
})

#define pt_regs_param_0 PT_REGS_PARM1
#define pt_regs_param_1 PT_REGS_PARM2
#define pt_regs_param_2 PT_REGS_PARM3
#define pt_regs_param_3 PT_REGS_PARM4
#if defined(__TARGET_ARCH_arm)
// arm32 前四个参数使用R0-R3寄存器，从第五个开始使用栈传递
#define pt_regs_param_4 PT_REGS_PARM5_ARM
#define pt_regs_param_5 PT_REGS_PARM6_ARM
#else
#define pt_regs_param_4 PT_REGS_PARM5
#endif

#if defined(__TARGET_ARCH_arm)
struct my_pt_regs {
	unsigned int uregs[18];
};
#define pt_regs my_pt_regs
#define ctx_get_arg(ctx, index) (u32)pt_regs_param_##index((struct my_pt_regs*)ctx)
#else
#define ctx_get_arg(ctx, index) (void *)pt_regs_param_##index((struct pt_regs*)ctx)
#endif


const volatile bool trace_all = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

static int gen_alloc_enter(size_t size)
{
    u64 m_size = (u64)size;
    const u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &pid_tgid, &m_size, BPF_ANY);
    if (trace_all)
	    bpf_printk("malloc_enter size=%d\n", size);
	return 0;
}

/* 通用的内存分配 uretprobe的处理逻辑
 * 内存分配接口(malloc, calloc等)返回时就会被调用
 * ctx: struct pt_regs 指针, 参考 BPF_KRETPROBE 的宏展开
 * address: 分配成功的内存指针, 比如 malloc 的返回值
 */
static int gen_alloc_exit2(void *ctx, u64 address)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *event;
	// int cp;

    const u64* size = bpf_map_lookup_elem(&sizes, &pid_tgid);
    // if (!size)
	// 	return 0; // missed alloc entry
    
    bpf_map_delete_elem(&sizes, &pid_tgid);
    


	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid_tgid >> 32;
	event->cpu_id = cpu_id;
    event->evt_id = EVT_ID_GEN_ALLOC_RET;
    event->address = (__u64)address;
	event->timestamp_ns = bpf_ktime_get_ns();
    if (size) {
        event->size = *size;
    }

	if (bpf_get_current_comm(event->comm, sizeof(event->comm))){
		event->comm[0] = 0;
    }

	event->ustack_sz =
		bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(event, 0);

    if (trace_all)
	    bpf_printk("malloc_exit address=%p\n", address);
	return 0;
}

/* 把 gen_alloc_exit2 接口中的2个参数精简为1个参数 
 * 参考 BPF_KRETPROBE 的宏展开过程
 */
static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

/* 通用的内存释放 uprobe的处理逻辑
 * 内存释放接口(free, munmap等)进入后就会被调用
 * address: 需要释放的内存指针, 比如 free 的第一个参数
 */
static int gen_free_enter(const void *address)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *event;
	// int cp;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid;
	event->cpu_id = cpu_id;
    event->evt_id = EVT_ID_FREE_IN;
    event->address = (__u64)address;
	event->timestamp_ns = bpf_ktime_get_ns();

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	// event->ustack_sz =
	// 	bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(event, 0);
    if (trace_all)
	    bpf_printk("free_enter address=%p\n", address);
	return 0;
}

/////////////////////////////////////////////////////////////////////

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void * address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
    const u64 memptr64 = (u64)(size_t)memptr;
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit)
{
    const u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *memptr64;
	void *addr;

	memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}