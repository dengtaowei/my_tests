clang -target bpf -O2 -S -Wall -fno-asynchronous-unwind-tables              \
	-Wno-incompatible-pointer-types-discards-qualifiers             \
	nettrace.bpf.c -emit-llvm -Wno-unknown-attributes -I./ \
	-D__F_STACK_TRACE -DBPF_NO_GLOBAL_DATA -DNT_DISABLE_IPV6 -D__F_NO_NF_HOOK_ENTRIES -DBPF_DEBUG -DNO_BTF -D__F_NFT_NAME_ARRAY -D__KERN_VER=6.6.23 -D__KERN_MAJOR=6 \
	-I/home/anlan/Desktop/my_tests/third_party/vmlinux.h/include/arm -I/home/anlan/Desktop/my_tests/third_party/install/arm/include -DBPF_NO_PRESERVE_ACCESS_INDEX \
	-g \
	-Wno-unused-function -Wno-compare-distinct-pointer-types -Wuninitialized \
	-D__TARGET_ARCH_arm -DBPF_NO_PRESERVE_ACCESS_INDEX \
	-nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabi/11/include  \
	-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member \
	-Wno-tautological-compare -Wno-unknown-warning-option \
	-Wno-frame-address -Xclang        \
	-Wno-int-conversion \
	-disable-llvm-passes -E -o nettrace.bpf.i