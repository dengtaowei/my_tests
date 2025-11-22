
#define NT_DISABLE_NFT 1
#if defined(__TARGET_ARCH_x86)
#include "./progs/kheaders/x86/kheaders_x86.h"
#elif defined(__TARGET_ARCH_arm)
#include "./kheaders/arm/kheaders_arm.h"
#elif defined(__TARGET_ARCH_arm64)
#include "./progs/kheaders/arm64/kstruct_offset.h"
#elif defined(__TARGET_ARCH_loongarch)
#include "./progs/vmlinux_loongarch64.h"
#endif
