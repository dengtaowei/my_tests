CC = $(CROSS_COMPILE)gcc

TARGET = nettrace

BPF_FLAGS = -I$(ROOT)/third_party/vmlinux.h/include/$(ARCH) \
	-I$(ROOT)/third_party/install/$(ARCH)/include \
	-DBPF_NO_PRESERVE_ACCESS_INDEX

BPF_OBJ = ${TARGET:=.bpf.o}

USER_C = ${TARGET:=.c} \
	arg_parse.c \
	analysis.c \
	bpf_utils.c \
	dropreason.c \
	net_utils.c \
	output.c \
	parse_sym.c \
	rstreason.c \
	trace_probe.c \
	sys_utils.c \
	trace.c \
	trace_group.c \
	trace_tracing.c

USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

ifeq ($(ARCH), x86)
LDFLAGS=-L../third_party/install/$(ARCH)/lib -l:libbpf.a -ldw -llzma -lelf -lz
else ifeq ($(ARCH), arm64)
LDFLAGS=-L../third_party/install/$(ARCH)/lib -l:libbpf.a -ldw -lelf -lz
else ifeq ($(ARCH), arm)
LDFLAGS=-L../third_party/install/$(ARCH)/lib -l:libbpf.a -ldw -lelf -lz
endif

all: $(TARGET) $(BPF_OBJ)
.PHONY: app

$(TARGET): $(USER_C) $(USER_SKEL) $(COMMON_H)
	$(CC) -Wall -O0 -g3 -DBPF_DEBUG -DNO_BTF -DBPF_NO_GLOBAL_DATA -o $(TARGET) $(USER_C) --static $(LDFLAGS)

direct:
	cp ~/Desktop/nfs_share/$(USER_SKEL) ./
	$(CC) -Wall -O0 -g3 -DBPF_DEBUG -DNO_BTF -o $(TARGET) $(USER_C) --static $(LDFLAGS)
	cp $(TARGET) ~/Desktop/nfs_share

NOSTDINC_FLAGS	+= -nostdinc -isystem $(shell $(CC) -print-file-name=include)

%.bpf.o: %.bpf.c vmlinux.h $(COMMON_H)
	clang -target bpf -O2 -S -Wall -fno-asynchronous-unwind-tables              \
		-Wno-incompatible-pointer-types-discards-qualifiers             \
		$< -emit-llvm -Wno-unknown-attributes -I./ \
		$(BPF_FLAGS) \
		-g \
		-Wno-unused-function -Wno-compare-distinct-pointer-types -Wuninitialized \
		-D__TARGET_ARCH_$(ARCH) -DBPF_NO_PRESERVE_ACCESS_INDEX \
		-DBPF_NO_GLOBAL_DATA \
		-DNO_BTF \
		$(NOSTDINC_FLAGS)  \
		-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member \
		-Wno-tautological-compare -Wno-unknown-warning-option \
		-Wno-frame-address -DNT_DISABLE_IPV6 -Xclang        \
		-Wno-int-conversion \
		-disable-llvm-passes -o - |                                     \
		opt -O2 -mtriple=bpf-pc-linux |                                 \
		llvm-dis |                                                      \
		llc -march=bpf -filetype=obj -o $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
# 	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
	- rm $(USER_SKEL)