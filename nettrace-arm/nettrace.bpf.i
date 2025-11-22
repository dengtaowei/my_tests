# 1 "nettrace.bpf.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 322 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "nettrace.bpf.c" 2

# 1 "./kheaders.h" 1

# 1 "././kheaders/arm/kheaders_arm.h" 1

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef __u16 __le16;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

typedef __u32 __wsum;

typedef __u16 __sum16;

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef _Bool bool;

enum
{
    false = 0,
    true = 1,
};

enum bpf_map_type
{
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
};

enum
{
    BPF_F_INDEX_MASK = 4294967295,
    BPF_F_CURRENT_CPU = 4294967295,
    BPF_F_CTXLEN_MASK = 0,
};

enum
{
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_MTP = 92,
    IPPROTO_BEETPH = 94,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_MPLS = 137,
    IPPROTO_RAW = 255,
    IPPROTO_MAX = 256,
};

struct list_head
{

    u32 next;
    u32 prev;
};

struct xt_table
{
    struct list_head list;
    unsigned int valid_hooks;
    struct xt_table_info *private;
    struct module *me;
    u8 af;
    int priority;

    u32 table_init;
    const char name[32];
};

struct iphdr
{
    __u8 ihl : 4;
    __u8 version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    union
    {
        struct
        {
            __be32 saddr;
            __be32 daddr;
        };
        struct
        {
            __be32 saddr;
            __be32 daddr;
        } addrs;
    };
} __attribute__((__packed__));

struct tcphdr
{
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4;
    __u16 doff : 4;
    __u16 fin : 1;
    __u16 syn : 1;
    __u16 rst : 1;
    __u16 psh : 1;
    __u16 ack : 1;
    __u16 urg : 1;
    __u16 ece : 1;
    __u16 cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((__packed__));

struct udphdr
{
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((__packed__));

struct icmphdr
{
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union
    {
        struct
        {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct
        {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
} __attribute__((__packed__));

struct in6_addr
{
    union
    {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((__packed__));

struct ipv6hdr
{
    __u8 priority : 4;
    __u8 version : 4;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    union
    {
        struct
        {
            struct in6_addr saddr;
            struct in6_addr daddr;
        };
        struct
        {
            struct in6_addr saddr;
            struct in6_addr daddr;
        } addrs;
    };
} __attribute__((__packed__));

struct tcp_sock
{
    unsigned char __padding1[1008];
    u32 rcv_nxt;
    unsigned char __padding2[40];
    u32 snd_una;
    unsigned char __padding3[196];
    u32 packets_out;
    u32 retrans_out;
    unsigned char __padding4[468];
} __attribute__((__packed__));

struct timer_list
{
    unsigned char __padding1[8];
    unsigned long expires;
    unsigned char __padding2[8];
} __attribute__((__packed__));

struct inet_connection_sock
{
    unsigned char __padding1[740];
    u32 icsk_timeout;
    struct timer_list icsk_retransmit_timer;
    unsigned char __padding2[61];
    u8 icsk_retransmits;
    u8 icsk_pending;
    unsigned char __padding3[157];
} __attribute__((__packed__));

struct sock_common
{
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    unsigned char __padding1[4];
    __be16 skc_dport;
    u16 skc_num;
    u16 skc_family;
    u8 skc_state;
    unsigned char __padding2[61];
} __attribute__((__packed__));

struct ip_esp_hdr
{
    __be32 spi;
    __be32 seq_no;
    __u8 enc_data[0];
};

struct tcp_skb_cb
{
    u32 seq;
    unsigned char __padding1[8];
    u8 tcp_flags;
    unsigned char __padding2[35];
} __attribute__((__packed__));

struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((__packed__));

struct __sk_buff
{
    unsigned char __padding1[76];
    u32 data;
    u32 data_end;
    unsigned char __padding2[108];
} __attribute__((__packed__));

struct netdev_queue
{
    unsigned char __padding1[72];
    unsigned long trans_start;
    unsigned long state;
    unsigned char __padding2[176];
} __attribute__((__packed__));

struct net_device
{
    unsigned char name[16];
    unsigned char __padding1[112];
    int ifindex;
    unsigned char __padding2[1276];
} __attribute__((__packed__));

struct nf_hook_state
{
    u8 hook;
    u8 pf;
} __attribute__((__packed__));

struct qdisc_skb_head
{
    unsigned char __padding1[8];
    unsigned int qlen;
    unsigned char __padding2[4];
} __attribute__((__packed__));

struct Qdisc
{
    unsigned char __padding1[8];
    unsigned int flags;
    unsigned char __padding2[28];
    u32 dev_queue;
    unsigned char __padding3[36];
    struct qdisc_skb_head q;
    unsigned char __padding4[160];
} __attribute__((__packed__));

typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);

struct nf_hook_entry
{

    u32 hook;
    u32 priv;
};

struct nf_hook_entries
{
    u16 num_hook_entries;
    struct nf_hook_entry hooks[0];
};

struct user_pt_regs
{
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct pt_regs
{

    unsigned int uregs[18];
};

struct sk_buff
{
    unsigned char __padding1[8];

    u32 dev;

    u32 sk;
    unsigned char __padding2[8];
    unsigned char cb[48];
    unsigned char __padding3[40];
    u32 skb_iif;
    unsigned char __padding4[24];
    __be16 protocol;
    u16 transport_header;
    u16 network_header;
    u16 mac_header;
    unsigned char __padding5[8];

    u32 head;
    unsigned char __padding6[16];
} __attribute__((__packed__));

struct sk_buff_head
{
    unsigned char __padding1[8];
    unsigned int qlen;
    unsigned char __padding2[4];
} __attribute__((__packed__));

struct sock;

struct socket
{
    unsigned char __padding1[16];

    u32 sk;
    unsigned char __padding2[108];
} __attribute__((__packed__));

struct sock_common;

struct sock
{
    struct sock_common __sk_common;
    unsigned char __padding1[56];
    struct sk_buff_head sk_receive_queue;
    unsigned char __padding2[76];
    struct sk_buff_head sk_write_queue;
    unsigned char __padding3[96];
    u16 sk_protocol;
    unsigned char __padding4[154];
} __attribute__((__packed__));
# 7 "./kheaders.h" 2
# 3 "nettrace.bpf.c" 2
# 1 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helpers.h" 1
# 11 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helpers.h"
# 1 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h" 1

struct bpf_fib_lookup;
struct bpf_sk_lookup;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_pidns_info;
struct bpf_redir_neigh;
struct bpf_sock;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct bpf_sock_tuple;
struct bpf_spin_lock;
struct bpf_sysctl;
struct bpf_tcp_sock;
struct bpf_tunnel_key;
struct bpf_xfrm_state;
struct linux_binprm;
struct pt_regs;
struct sk_reuseport_md;
struct sockaddr;
struct tcphdr;
struct seq_file;
struct tcp6_sock;
struct tcp_sock;
struct tcp_timewait_sock;
struct tcp_request_sock;
struct udp6_sock;
struct unix_sock;
struct task_struct;
struct cgroup;
struct __sk_buff;
struct sk_msg_md;
struct xdp_md;
struct path;
struct btf_ptr;
struct inode;
struct socket;
struct file;
struct bpf_timer;
struct mptcp_sock;
struct bpf_dynptr;
struct iphdr;
struct ipv6hdr;
# 64 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
# 86 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
# 96 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
# 110 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)4;
# 122 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)5;
# 185 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;
# 201 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u32 (*const bpf_get_prandom_u32)(void) = (void *)7;
# 214 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u32 (*const bpf_get_smp_processor_id)(void) = (void *)8;
# 235 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)9;
# 264 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *)10;
# 300 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *)11;
# 335 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)12;
# 365 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_clone_redirect)(struct __sk_buff *skb, __u32 ifindex, __u64 flags) = (void *)13;
# 378 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_current_pid_tgid)(void) = (void *)14;
# 389 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_current_uid_gid)(void) = (void *)15;
# 404 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
# 434 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u32 (*const bpf_get_cgroup_classid)(struct __sk_buff *skb) = (void *)17;
# 454 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_vlan_push)(struct __sk_buff *skb, __be16 vlan_proto, __u16 vlan_tci) = (void *)18;
# 470 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_vlan_pop)(struct __sk_buff *skb) = (void *)19;
# 525 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_get_tunnel_key)(struct __sk_buff *skb, struct bpf_tunnel_key *key, __u32 size, __u64 flags) = (void *)20;
# 569 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_set_tunnel_key)(struct __sk_buff *skb, struct bpf_tunnel_key *key, __u32 size, __u64 flags) = (void *)21;
# 602 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_perf_event_read)(void *map, __u64 flags) = (void *)22;
# 629 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
# 657 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u32 (*const bpf_get_route_realm)(struct __sk_buff *skb) = (void *)24;
# 706 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;
# 727 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
# 773 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *)27;
# 804 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __s64 (*const bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) = (void *)28;
# 826 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_get_tunnel_opt)(struct __sk_buff *skb, void *opt, __u32 size) = (void *)29;
# 840 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_set_tunnel_opt)(struct __sk_buff *skb, void *opt, __u32 size) = (void *)30;
# 871 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_change_proto)(struct __sk_buff *skb, __be16 proto, __u64 flags) = (void *)31;
# 902 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_change_type)(struct __sk_buff *skb, __u32 type) = (void *)32;
# 917 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_under_cgroup)(struct __sk_buff *skb, void *map, __u32 index) = (void *)33;
# 937 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u32 (*const bpf_get_hash_recalc)(struct __sk_buff *skb) = (void *)34;
# 947 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_current_task)(void) = (void *)35;
# 970 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_write_user)(void *dst, const void *src, __u32 len) = (void *)36;
# 986 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_current_task_under_cgroup)(void *map, __u32 index) = (void *)37;
# 1014 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)38;
# 1055 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *)39;
# 1071 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __s64 (*const bpf_csum_update)(struct __sk_buff *skb, __wsum csum) = (void *)40;
# 1085 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void (*const bpf_set_hash_invalid)(struct __sk_buff *skb) = (void *)41;
# 1100 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_numa_node_id)(void) = (void *)42;
# 1125 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_change_head)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)43;
# 1144 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_xdp_adjust_head)(struct xdp_md *xdp_md, int delta) = (void *)44;
# 1161 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_read_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)45;
# 1178 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_socket_cookie)(void *ctx) = (void *)46;
# 1192 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u32 (*const bpf_get_socket_uid)(struct __sk_buff *skb) = (void *)47;
# 1203 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_set_hash)(struct __sk_buff *skb, __u32 hash) = (void *)48;
# 1243 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_setsockopt)(void *bpf_socket, int level, int optname, void *optval, int optlen) = (void *)49;
# 1304 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)50;
# 1333 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_redirect_map)(void *map, __u64 key, __u64 flags) = (void *)51;
# 1348 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sk_redirect_map)(struct __sk_buff *skb, void *map, __u32 key, __u64 flags) = (void *)52;
# 1371 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sock_map_update)(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags) = (void *)53;
# 1404 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_xdp_adjust_meta)(struct xdp_md *xdp_md, int delta) = (void *)54;
# 1458 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_perf_event_read_value)(void *map, __u64 flags, struct bpf_perf_event_value *buf, __u32 buf_size) = (void *)55;
# 1473 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_perf_prog_read_value)(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, __u32 buf_size) = (void *)56;
# 1500 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_getsockopt)(void *bpf_socket, int level, int optname, void *optval, int optlen) = (void *)57;
# 1525 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_override_return)(struct pt_regs *regs, __u64 rc) = (void *)58;
# 1573 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *bpf_sock, int argval) = (void *)59;
# 1591 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_redirect_map)(struct sk_msg_md *msg, void *map, __u32 key, __u64 flags) = (void *)60;
# 1629 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_apply_bytes)(struct sk_msg_md *msg, __u32 bytes) = (void *)61;
# 1651 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_cork_bytes)(struct sk_msg_md *msg, __u32 bytes) = (void *)62;
# 1686 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_pull_data)(struct sk_msg_md *msg, __u32 start, __u32 end, __u64 flags) = (void *)63;
# 1708 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_bind)(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len) = (void *)64;
# 1726 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_xdp_adjust_tail)(struct xdp_md *xdp_md, int delta) = (void *)65;
# 1746 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_get_xfrm_state)(struct __sk_buff *skb, __u32 index, struct bpf_xfrm_state *xfrm_state, __u32 size, __u64 flags) = (void *)66;
# 1793 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_stack)(void *ctx, void *buf, __u32 size, __u64 flags) = (void *)67;
# 1819 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_load_bytes_relative)(const void *skb, __u32 offset, void *to, __u32 len, __u32 start_header) = (void *)68;
# 1875 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *)69;
# 1898 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sock_hash_update)(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags) = (void *)70;
# 1916 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_redirect_hash)(struct sk_msg_md *msg, void *map, void *key, __u64 flags) = (void *)71;
# 1934 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sk_redirect_hash)(struct __sk_buff *skb, void *map, void *key, __u64 flags) = (void *)72;
# 1975 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_lwt_push_encap)(struct __sk_buff *skb, __u32 type, void *hdr, __u32 len) = (void *)73;
# 1994 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_lwt_seg6_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len) = (void *)74;
# 2014 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_lwt_seg6_adjust_srh)(struct __sk_buff *skb, __u32 offset, __s32 delta) = (void *)75;
# 2047 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_lwt_seg6_action)(struct __sk_buff *skb, __u32 action, void *param, __u32 param_len) = (void *)76;
# 2070 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_rc_repeat)(void *ctx) = (void *)77;
# 2100 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_rc_keydown)(void *ctx, __u32 protocol, __u64 scancode, __u32 toggle) = (void *)78;
# 2120 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_skb_cgroup_id)(struct __sk_buff *skb) = (void *)79;
# 2132 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_current_cgroup_id)(void) = (void *)80;
# 2154 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_get_local_storage)(void *map, __u64 flags) = (void *)81;
# 2167 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sk_select_reuseport)(struct sk_reuseport_md *reuse, void *map, void *key, __u64 flags) = (void *)82;
# 2189 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_skb_ancestor_cgroup_id)(struct __sk_buff *skb, int ancestor_level) = (void *)83;
# 2230 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*const bpf_sk_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *)84;
# 2271 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*const bpf_sk_lookup_udp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *)85;
# 2283 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sk_release)(void *sock) = (void *)86;
# 2297 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_map_push_elem)(void *map, const void *value, __u64 flags) = (void *)87;
# 2307 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_map_pop_elem)(void *map, void *value) = (void *)88;
# 2317 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_map_peek_elem)(void *map, void *value) = (void *)89;
# 2337 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_push_data)(struct sk_msg_md *msg, __u32 start, __u32 len, __u64 flags) = (void *)90;
# 2353 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_msg_pop_data)(struct sk_msg_md *msg, __u32 start, __u32 len, __u64 flags) = (void *)91;
# 2371 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_rc_pointer_rel)(void *ctx, __s32 rel_x, __s32 rel_y) = (void *)92;
# 2423 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
# 2434 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;
# 2446 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*const bpf_sk_fullsock)(struct bpf_sock *sk) = (void *)95;
# 2458 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct bpf_tcp_sock *(*const bpf_tcp_sock)(struct bpf_sock *sk) = (void *)96;
# 2472 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_ecn_set_ce)(struct __sk_buff *skb) = (void *)97;
# 2484 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*const bpf_get_listener_sock)(struct bpf_sock *sk) = (void *)98;
# 2507 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*const bpf_skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *)99;
# 2527 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_tcp_check_syncookie)(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len) = (void *)100;
# 2547 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sysctl_get_name)(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len, __u64 flags) = (void *)101;
# 2570 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sysctl_get_current_value)(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len) = (void *)102;
# 2591 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sysctl_get_new_value)(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len) = (void *)103;
# 2612 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sysctl_set_new_value)(struct bpf_sysctl *ctx, const char *buf, unsigned long buf_len) = (void *)104;
# 2640 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_strtol)(const char *buf, unsigned long buf_len, __u64 flags, long *res) = (void *)105;
# 2667 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_strtoul)(const char *buf, unsigned long buf_len, __u64 flags, unsigned long *res) = (void *)106;
# 2702 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_sk_storage_get)(void *map, void *sk, void *value, __u64 flags) = (void *)107;
# 2715 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sk_storage_delete)(void *map, void *sk) = (void *)108;
# 2734 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_send_signal)(__u32 sig) = (void *)109;
# 2765 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __s64 (*const bpf_tcp_gen_syncookie)(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len) = (void *)110;
# 2793 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)111;
# 2804 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
# 2815 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
# 2863 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
# 2875 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)115;
# 2886 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_tcp_send_ack)(void *tp, __u32 rcv_nxt) = (void *)116;
# 2904 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_send_signal_thread)(__u32 sig) = (void *)117;
# 2914 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_jiffies64)(void) = (void *)118;
# 2937 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_read_branch_records)(struct bpf_perf_event_data *ctx, void *buf, __u32 size, __u64 flags) = (void *)119;
# 2953 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino, struct bpf_pidns_info *nsdata, __u32 size) = (void *)120;
# 2981 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_xdp_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)121;
# 2998 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_netns_cookie)(void *ctx) = (void *)122;
# 3020 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_current_ancestor_cgroup_id)(int ancestor_level) = (void *)123;
# 3052 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sk_assign)(void *ctx, void *sk, __u64 flags) = (void *)124;
# 3064 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_ktime_get_boot_ns)(void) = (void *)125;
# 3097 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_seq_printf)(struct seq_file *m, const char *fmt, __u32 fmt_size, const void *data, __u32 data_len) = (void *)126;
# 3111 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_seq_write)(struct seq_file *m, const void *data, __u32 len) = (void *)127;
# 3129 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_sk_cgroup_id)(void *sk) = (void *)128;
# 3151 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_sk_ancestor_cgroup_id)(void *sk, int ancestor_level) = (void *)129;
# 3172 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;
# 3184 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
# 3202 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void (*const bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
# 3220 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void (*const bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;
# 3241 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_ringbuf_query)(void *ringbuf, __u64 flags) = (void *)134;
# 3277 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_csum_level)(struct __sk_buff *skb, __u64 level) = (void *)135;
# 3287 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct tcp6_sock *(*const bpf_skc_to_tcp6_sock)(void *sk) = (void *)136;
# 3297 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct tcp_sock *(*const bpf_skc_to_tcp_sock)(void *sk) = (void *)137;
# 3307 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct tcp_timewait_sock *(*const bpf_skc_to_tcp_timewait_sock)(void *sk) = (void *)138;
# 3317 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct tcp_request_sock *(*const bpf_skc_to_tcp_request_sock)(void *sk) = (void *)139;
# 3327 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct udp6_sock *(*const bpf_skc_to_udp6_sock)(void *sk) = (void *)140;
# 3366 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_task_stack)(struct task_struct *task, void *buf, __u32 size, __u64 flags) = (void *)141;
# 3433 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_load_hdr_opt)(struct bpf_sock_ops *skops, void *searchby_res, __u32 len, __u64 flags) = (void *)142;
# 3470 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_store_hdr_opt)(struct bpf_sock_ops *skops, const void *from, __u32 len, __u64 flags) = (void *)143;
# 3496 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_reserve_hdr_opt)(struct bpf_sock_ops *skops, __u32 len, __u64 flags) = (void *)144;
# 3528 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_inode_storage_get)(void *map, void *inode, void *value, __u64 flags) = (void *)145;
# 3540 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static int (*const bpf_inode_storage_delete)(void *map, void *inode) = (void *)146;
# 3556 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_d_path)(struct path *path, char *buf, __u32 sz) = (void *)147;
# 3567 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_copy_from_user)(void *dst, __u32 size, const void *user_ptr) = (void *)148;
# 3607 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_snprintf_btf)(char *str, __u32 str_size, struct btf_ptr *ptr, __u32 btf_ptr_size, __u64 flags) = (void *)149;
# 3619 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_seq_printf_btf)(struct seq_file *m, struct btf_ptr *ptr, __u32 ptr_size, __u64 flags) = (void *)150;
# 3632 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_skb_cgroup_classid)(struct __sk_buff *skb) = (void *)151;
# 3657 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_redirect_neigh)(__u32 ifindex, struct bpf_redir_neigh *params, int plen, __u64 flags) = (void *)152;
# 3678 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_per_cpu_ptr)(const void *percpu_ptr, __u32 cpu) = (void *)153;
# 3694 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_this_cpu_ptr)(const void *percpu_ptr) = (void *)154;
# 3714 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_redirect_peer)(__u32 ifindex, __u64 flags) = (void *)155;
# 3746 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_task_storage_get)(void *map, struct task_struct *task, void *value, __u64 flags) = (void *)156;
# 3758 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_task_storage_delete)(void *map, struct task_struct *task) = (void *)157;
# 3770 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct task_struct *(*const bpf_get_current_task_btf)(void) = (void *)158;
# 3784 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_bprm_opts_set)(struct linux_binprm *bprm, __u64 flags) = (void *)159;
# 3798 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_ktime_get_coarse_ns)(void) = (void *)160;
# 3812 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_ima_inode_hash)(struct inode *inode, void *dst, __u32 size) = (void *)161;
# 3824 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct socket *(*const bpf_sock_from_file)(struct file *file) = (void *)162;
# 3895 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_check_mtu)(void *ctx, __u32 ifindex, __u32 *mtu_len, __s32 len_diff, __u64 flags) = (void *)163;
# 3928 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_for_each_map_elem)(void *map, void *callback_fn, void *callback_ctx, __u64 flags) = (void *)164;
# 3960 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_snprintf)(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len) = (void *)165;
# 3970 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sys_bpf)(__u32 cmd, void *attr, __u32 attr_size) = (void *)166;
# 3980 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_btf_find_by_name_kind)(char *name, int name_sz, __u32 kind, int flags) = (void *)167;
# 3990 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_sys_close)(__u32 fd) = (void *)168;
# 4011 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_timer_init)(struct bpf_timer *timer, void *map, __u64 flags) = (void *)169;
# 4026 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_timer_set_callback)(struct bpf_timer *timer, void *callback_fn) = (void *)170;
# 4064 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_timer_start)(struct bpf_timer *timer, __u64 nsecs, __u64 flags) = (void *)171;
# 4078 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_timer_cancel)(struct bpf_timer *timer) = (void *)172;
# 4094 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_func_ip)(void *ctx) = (void *)173;
# 4113 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_get_attach_cookie)(void *ctx) = (void *)174;
# 4123 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_task_pt_regs)(struct task_struct *task) = (void *)175;
# 4148 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_branch_snapshot)(void *entries, __u32 size, __u64 flags) = (void *)176;
# 4162 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_trace_vprintk)(const char *fmt, __u32 fmt_size, const void *data, __u32 data_len) = (void *)177;
# 4172 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct unix_sock *(*const bpf_skc_to_unix_sock)(void *sk) = (void *)178;
# 4191 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_kallsyms_lookup_name)(const char *name, int name_sz, int flags, __u64 *res) = (void *)179;
# 4214 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_find_vma)(struct task_struct *task, __u64 addr, void *callback_fn, void *callback_ctx, __u64 flags) = (void *)180;
# 4242 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *)181;
# 4256 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_strncmp)(const char *s1, __u32 s1_sz, const char *s2) = (void *)182;
# 4269 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_func_arg)(void *ctx, __u32 n, __u64 *value) = (void *)183;
# 4282 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_func_ret)(void *ctx, __u64 *value) = (void *)184;
# 4294 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_get_func_arg_cnt)(void *ctx) = (void *)185;
# 4307 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static int (*const bpf_get_retval)(void) = (void *)186;
# 4330 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static int (*const bpf_set_retval)(int retval) = (void *)187;
# 4340 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_xdp_get_buff_len)(struct xdp_md *xdp_md) = (void *)188;
# 4353 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_xdp_load_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *)189;
# 4364 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_xdp_store_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *)190;
# 4378 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_copy_from_user_task)(void *dst, __u32 size, const void *user_ptr, struct task_struct *tsk, __u64 flags) = (void *)191;
# 4412 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_skb_set_tstamp)(struct __sk_buff *skb, __u64 tstamp, __u32 tstamp_type) = (void *)192;
# 4426 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_ima_file_hash)(struct file *file, void *dst, __u32 size) = (void *)193;
# 4442 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_kptr_xchg)(void *dst, void *ptr) = (void *)194;
# 4454 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_map_lookup_percpu_elem)(void *map, const void *key, __u32 cpu) = (void *)195;
# 4464 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static struct mptcp_sock *(*const bpf_skc_to_mptcp_sock)(void *sk) = (void *)196;
# 4479 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)197;
# 4494 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_ringbuf_reserve_dynptr)(void *ringbuf, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *)198;
# 4509 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void (*const bpf_ringbuf_submit_dynptr)(struct bpf_dynptr *ptr, __u64 flags) = (void *)199;
# 4523 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void (*const bpf_ringbuf_discard_dynptr)(struct bpf_dynptr *ptr, __u64 flags) = (void *)200;
# 4537 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_dynptr_read)(void *dst, __u32 len, const struct bpf_dynptr *src, __u32 offset, __u64 flags) = (void *)201;
# 4562 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_dynptr_write)(const struct bpf_dynptr *dst, __u32 offset, void *src, __u32 len, __u64 flags) = (void *)202;
# 4580 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_dynptr_data)(const struct bpf_dynptr *ptr, __u32 offset, __u32 len) = (void *)203;
# 4604 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __s64 (*const bpf_tcp_raw_gen_syncookie_ipv4)(struct iphdr *iph, struct tcphdr *th, __u32 th_len) = (void *)204;
# 4630 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __s64 (*const bpf_tcp_raw_gen_syncookie_ipv6)(struct ipv6hdr *iph, struct tcphdr *th, __u32 th_len) = (void *)205;
# 4649 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_tcp_raw_check_syncookie_ipv4)(struct iphdr *iph, struct tcphdr *th) = (void *)206;
# 4670 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_tcp_raw_check_syncookie_ipv6)(struct ipv6hdr *iph, struct tcphdr *th) = (void *)207;
# 4685 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static __u64 (*const bpf_ktime_get_tai_ns)(void) = (void *)208;
# 4727 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_user_ringbuf_drain)(void *map, void *callback_fn, void *ctx, __u64 flags) = (void *)209;
# 4761 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static void *(*const bpf_cgrp_storage_get)(void *map, struct cgroup *cgroup, void *value, __u64 flags) = (void *)210;
# 4773 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helper_defs.h"
static long (*const bpf_cgrp_storage_delete)(void *map, struct cgroup *cgroup) = (void *)211;
# 12 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helpers.h" 2
# 142 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helpers.h"
static inline __attribute__((always_inline)) void
bpf_tail_call_static(void *ctx, const void *map, const __u32 slot)
{
    if (!__builtin_constant_p(slot))
        __builtin_trap();
# 161 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helpers.h"
    asm volatile("r1 = %[ctx]\n\t"
                 "r2 = %[map]\n\t"
                 "r3 = %[slot]\n\t"
                 "call 12" ::[ctx] "r"(ctx),
                 [map] "r"(map), [slot] "i"(slot)
                 : "r0", "r1", "r2", "r3", "r4", "r5");
}

enum libbpf_pin_type
{
    LIBBPF_PIN_NONE,

    LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate
{
    TRI_NO = 0,
    TRI_YES = 1,
    TRI_MODULE = 2,
};
# 321 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_helpers.h"
struct bpf_iter_num;

extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __attribute__((weak)) __attribute__((section(".ksyms")));
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __attribute__((weak)) __attribute__((section(".ksyms")));
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __attribute__((weak)) __attribute__((section(".ksyms")));
# 4 "nettrace.bpf.c" 2
# 1 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_endian.h" 1
# 5 "nettrace.bpf.c" 2
# 1 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_tracing.h" 1
# 455 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_tracing.h"
struct pt_regs;
# 793 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_tracing.h"
struct pt_regs;
# 6 "nettrace.bpf.c" 2

# 1 "./shared.h" 1

# 1 "./skb_shared.h" 1
# 59 "./skb_shared.h"
typedef struct
{
    u16 sport;
    u16 dport;
} l4_min_t;

typedef struct
{
    u64 ts;
    union
    {
        struct
        {
            u32 saddr;
            u32 daddr;
        } ipv4;

    } l3;
    union
    {
        struct
        {
            u16 sport;
            u16 dport;
            u32 seq;
            u32 ack;
            u8 flags;
        } tcp;
        struct
        {
            u16 sport;
            u16 dport;
        } udp;
        l4_min_t min;
        struct
        {
            u8 type;
            u8 code;
            u16 seq;
            u16 id;
        } icmp;
        struct
        {
            u16 op;
            u8 source[6];
            u8 dest[6];
        } arp_ext;
        struct
        {
            u32 spi;
            u32 seq;
        } espheader;

    } l4;
    u16 proto_l3;
    u8 proto_l4;
    u8 pad;
} packet_t;

typedef struct
{
    u64 ts;
    union
    {
        struct
        {
            u32 saddr;
            u32 daddr;
        } ipv4;

    } l3;
    union
    {
        struct
        {
            u16 sport;
            u16 dport;
            u32 packets_out;
            u32 retrans_out;
            u32 snd_una;
        } tcp;
        struct
        {
            u16 sport;
            u16 dport;
        } udp;
        l4_min_t min;
    } l4;
    u32 timer_out;
    u32 wqlen;
    u32 rqlen;
    u16 proto_l3;
    u8 proto_l4;
    u8 timer_pending;
    u8 state;
    u8 ca_state;
} sock_t;
# 169 "./skb_shared.h"
typedef struct
{
    u32 saddr;
    u32 daddr;
    u32 addr;
    u32 pkt_len_1;
    u32 pkt_len_2;
    u32 pad0;
    u32 saddr_v6[4];
    u32 daddr_v6[4];
    u32 addr_v6[4];
    u16 sport;
    u16 dport;
    u16 port;
    u32 icmpv6_type;
    u16 l3_proto;
    u8 l4_proto;
    u8 tcp_flags;
    u8 saddr_v6_enable : 1,
        daddr_v6_enable : 1,
        addr_v6_enable : 1;

    bool bpf_debug;

} __attribute__((__packed__)) pkt_args_t;
# 202 "./skb_shared.h"
typedef __u64 stack_trace_t[127];

enum
{
    BPF_LOCAL_FUNC_jiffies64,
    BPF_LOCAL_FUNC_get_func_ret,
    BPF_LOCAL_FUNC_MAX,
};
# 7 "./shared.h" 2

# 1 "./kprobe_trace.h" 1
# 9 "./shared.h" 2

typedef struct
{
    pkt_args_t pkt;
    u32 trace_mode;
    u32 pid;
    u32 netns;
    u32 max_event;
    bool drop_reason;
    bool detail;
    bool hooks;
    bool ready;
    bool stack;
    bool tiny_output;
    bool has_filter;
    bool latency_summary;
    bool func_stats;
    bool match_mode;
    bool latency_free;
    u32 first_rtt;
    u32 last_rtt;
    u32 rate_limit;
    u32 latency_min;
    int __rate_limit;
    u64 __last_update;
    u8 trace_status[162];
    u64 event_count;
} __attribute__((__packed__)) bpf_args_t;

typedef struct
{
    u16 meta;
    u16 func;
    u32 key;
    union
    {
        packet_t pkt;
        sock_t ske;
    };
    union
    {

        u64 retval;
        struct
        {
            u16 latency_func1;
            u16 latency_func2;
            u32 latency;
        };
    };

    u32 stack_id;

    u32 pid;
    int __event_filed[0];
} event_t;

typedef struct
{
    u16 meta;
    u16 func;
    u32 key;
    u64 ts;
} tiny_event_t;

typedef struct
{
    u16 meta;
    u16 func;
    u32 key;
    union
    {
        packet_t pkt;
        sock_t ske;
    };
    u64 retval;

    u32 stack_id;

    u32 pid;

    char task[16];
    char ifname[16];
    u32 ifindex;
    u32 netns;
    int __event_filed[0];
} detail_event_t;

typedef struct
{
} pure_event_t;

enum
{
    FUNC_TYPE_FUNC,
    FUNC_TYPE_RET,
    FUNC_TYPE_TINY,
    FUNC_TYPE_TRACING_RET,
    FUNC_TYPE_MAX,
};
# 127 "./shared.h"
typedef struct
{
    event_t event;
    int __event_filed[0];
    u64 location;
    u32 reason;
} drop_event_t;
typedef struct
{
    detail_event_t event;
    int __event_filed[0];
    u64 location;
    u32 reason;
} detail_drop_event_t;
typedef struct
{
    u64 location;
    u32 reason;
} pure_drop_event_t;

typedef struct
{
    event_t event;
    int __event_filed[0];
    unsigned char state;
    u32 reason;
} reset_event_t;
typedef struct
{
    detail_event_t event;
    int __event_filed[0];
    unsigned char state;
    u32 reason;
} detail_reset_event_t;
typedef struct
{
    unsigned char state;
    u32 reason;
} pure_reset_event_t;

typedef struct
{
    event_t event;
    int __event_filed[0];
    char table[8];
    char chain[8];
    u8 hook;
    u8 pf;
} nf_event_t;
typedef struct
{
    detail_event_t event;
    int __event_filed[0];
    char table[8];
    char chain[8];
    u8 hook;
    u8 pf;
} detail_nf_event_t;
typedef struct
{
    char table[8];
    char chain[8];
    u8 hook;
    u8 pf;
} pure_nf_event_t;

typedef struct
{
    event_t event;
    int __event_filed[0];
    char table[8];
    char chain[8];
    u8 hook;
    u8 pf;
    u64 hooks[6];
} nf_hooks_event_t;
typedef struct
{
    detail_event_t event;
    int __event_filed[0];
    char table[8];
    char chain[8];
    u8 hook;
    u8 pf;
    u64 hooks[6];
} detail_nf_hooks_event_t;
typedef struct
{
    char table[8];
    char chain[8];
    u8 hook;
    u8 pf;
    u64 hooks[6];
} pure_nf_hooks_event_t;

typedef struct
{
    event_t event;
    int __event_filed[0];
    u64 last_update;
    u32 state;
    u32 qlen;
    u32 flags;
} qdisc_event_t;
typedef struct
{
    detail_event_t event;
    int __event_filed[0];
    u64 last_update;
    u32 state;
    u32 qlen;
    u32 flags;
} detail_qdisc_event_t;
typedef struct
{
    u64 last_update;
    u32 state;
    u32 qlen;
    u32 flags;
} pure_qdisc_event_t;

typedef struct
{
    event_t event;
    int __event_filed[0];
    u32 first_rtt;
    u32 last_rtt;
} rtt_event_t;
typedef struct
{
    detail_event_t event;
    int __event_filed[0];
    u32 first_rtt;
    u32 last_rtt;
} detail_rtt_event_t;
typedef struct
{
    u32 first_rtt;
    u32 last_rtt;
} pure_rtt_event_t;

typedef struct __attribute__((__packed__))
{
    u16 meta;
    u16 func;
    u32 pid;
    u64 ts;
    u64 val;
} retevent_t;

typedef enum trace_mode
{
    TRACE_MODE_BASIC,
    TRACE_MODE_DROP,
    TRACE_MODE_TIMELINE,
    TRACE_MODE_DIAG,
    TRACE_MODE_SOCK,
    TRACE_MODE_MONITOR,
    TRACE_MODE_RTT,
    TRACE_MODE_LATENCY,

    TRACE_MODE_TINY = 16,
} trace_mode_t;

enum rule_type
{

    RULE_RETURN_EQ = 1,

    RULE_RETURN_NE,

    RULE_RETURN_LT,

    RULE_RETURN_GT,

    RULE_RETURN_RANGE,

    RULE_RETURN_ANY,
};

typedef struct
{
    int expected[8];
    int op[8];
} rules_ret_t;
# 8 "nettrace.bpf.c" 2
# 1 "./core.h" 1

# 1 "./skb_parse.h" 1
# 10 "./skb_parse.h"
# 1 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_core_read.h" 1
# 15 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_core_read.h"
enum bpf_field_info_kind
{
    BPF_FIELD_BYTE_OFFSET = 0,
    BPF_FIELD_BYTE_SIZE = 1,
    BPF_FIELD_EXISTS = 2,
    BPF_FIELD_SIGNED = 3,
    BPF_FIELD_LSHIFT_U64 = 4,
    BPF_FIELD_RSHIFT_U64 = 5,
};

enum bpf_type_id_kind
{
    BPF_TYPE_ID_LOCAL = 0,
    BPF_TYPE_ID_TARGET = 1,
};

enum bpf_type_info_kind
{
    BPF_TYPE_EXISTS = 0,
    BPF_TYPE_SIZE = 1,
    BPF_TYPE_MATCHES = 2,
};

enum bpf_enum_value_kind
{
    BPF_ENUMVAL_EXISTS = 0,
    BPF_ENUMVAL_VALUE = 1,
};
# 329 "/home/anlan/Desktop/my_tests/third_party/install/arm/include/bpf/bpf_core_read.h"
extern void *bpf_rdonly_cast(const void *obj, __u32 btf_id) __attribute__((section(".ksyms"))) __attribute__((weak));
# 11 "./skb_parse.h" 2

# 1 "./skb_macro.h" 1
# 13 "./skb_parse.h" 2

struct
{
    int (*type)[BPF_MAP_TYPE_PERF_EVENT_ARRAY];
    int (*key_size)[sizeof(int)];
    int (*value_size)[sizeof(u32)];
    int (*max_entries)[256];
} m_event
# 23 "./skb_parse.h"
#pragma GCC diagnostic push
# 23 "./skb_parse.h"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 23 "./skb_parse.h"
    __attribute__((section(".maps"), used))
# 23 "./skb_parse.h"
#pragma GCC diagnostic pop
# 23 "./skb_parse.h"
    ;

struct
{
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int (*key_size)[sizeof(int)];
    int (*value_size)[1024];
    int (*max_entries)[1];
} m_config
# 30 "./skb_parse.h"
#pragma GCC diagnostic push
# 30 "./skb_parse.h"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 30 "./skb_parse.h"
    __attribute__((section(".maps"), used))
# 30 "./skb_parse.h"
#pragma GCC diagnostic pop
# 30 "./skb_parse.h"
    ;
# 100 "./skb_parse.h"
typedef struct
{
    u64 pad;
    u64 skb;
    u64 location;
    u16 prot;
    u32 reason;
} kfree_skb_t;

typedef struct
{
    void *data;
    u16 mac_header;
    u16 network_header;
} parse_ctx_t;
# 143 "./skb_parse.h"
static inline u8 get_ip_header_len(u8 h)
{
    u8 len = (h & 0x0F) * 4;
    return len > (sizeof(struct iphdr)) ? len : (sizeof(struct iphdr));
}

static inline bool skb_l4_was_set(u16 transport_header)
{
    return transport_header != (typeof(transport_header))~0U;
}

static inline bool skb_l2_check(u16 header)
{
    return !header || header == (u16)~0U;
}

static inline bool skb_l4_check(u16 l4, u16 l3)
{
    return !skb_l4_was_set(l4) || l4 <= l3;
}
# 174 "./skb_parse.h"
static inline bool is_ipv6_equal(void *addr1, void *addr2)
{
    return *(u64 *)addr1 == *(u64 *)addr2 &&
           *(u64 *)(addr1 + 8) == *(u64 *)(addr2 + 8);
}

static inline int filter_ipv6_check(pkt_args_t *args, void *saddr, void *daddr)
{
    if (!args)
        return 0;

    return (args->saddr_v6_enable && !is_ipv6_equal(args->saddr_v6, saddr)) ||
           (args->daddr_v6_enable && !is_ipv6_equal(args->daddr_v6, daddr)) ||
           (args->addr_v6_enable && !is_ipv6_equal(args->addr_v6, daddr) &&
            !is_ipv6_equal(args->addr_v6, saddr));
}

static inline int filter_ipv4_check(pkt_args_t *args, u32 saddr,
                                    u32 daddr)
{
    if (!args)
        return 0;

    return (args->saddr && args->saddr != saddr) ||
           (args->daddr && args->daddr != daddr) ||
           (args->addr && args->addr != daddr && args->addr != saddr);
}

static inline int filter_port(pkt_args_t *args, u32 sport, u32 dport)
{
    if (!args)
        return 0;

    return (args->sport && args->sport != sport) ||
           (args->dport && args->dport != dport) ||
           (args->port && args->port != dport && args->port != sport);
}

static inline int filter_icmpv6_type(pkt_args_t *args, u8 type)
{
    if (!args || !args->icmpv6_type)
        return 0;

    return ((args->icmpv6_type & 0xFF) != type) &&
           (((args->icmpv6_type >> 8) & 0xFF) != type) &&
           (((args->icmpv6_type >> 16) & 0xFF) != type) &&
           (((args->icmpv6_type >> 24) & 0xFF) != type);
}

struct arphdr_all
{
    __be16 ar_hrd;
    __be16 ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    __be16 ar_op;

    unsigned char ar_sha[6];
    unsigned char ar_sip[4];
    unsigned char ar_tha[6];
    unsigned char ar_tip[4];
};

static inline int probe_parse_arp(void *l3, packet_t *pkt, pkt_args_t *args)
{
    struct arphdr_all *arp = l3;

    pkt->l4.arp_ext.op = (__builtin_constant_p(({ typeof(arp->ar_op) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&arp->ar_op), &arp->ar_op); ____tmp; })) ? ((__u16)(((__u16)(({ typeof(arp->ar_op) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&arp->ar_op), &arp->ar_op); ____tmp; })) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(({ typeof(arp->ar_op) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&arp->ar_op), &arp->ar_op); ____tmp; })) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(({ typeof(arp->ar_op) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&arp->ar_op), &arp->ar_op); ____tmp; })));
    if (pkt->l4.arp_ext.op != 1 && pkt->l4.arp_ext.op != 2)
        return 0;

    bpf_probe_read_kernel(&pkt->l3.ipv4.saddr, 4, arp->ar_sip);
    bpf_probe_read_kernel(&pkt->l3.ipv4.daddr, 4, arp->ar_tip);

    if (filter_ipv4_check(args, pkt->l3.ipv4.saddr, pkt->l3.ipv4.daddr))
        return -1;

    bpf_probe_read_kernel(pkt->l4.arp_ext.source, 6, arp->ar_sha);
    bpf_probe_read_kernel(pkt->l4.arp_ext.dest, 6, arp->ar_tha);

    return 0;
}

static inline int probe_parse_l4(void *l4, packet_t *pkt, pkt_args_t *args)
{
    switch (pkt->proto_l4)
    {
    case IPPROTO_IP:
    case IPPROTO_TCP:
    {
        struct tcphdr *tcp = l4;
        u16 sport = ({ typeof(tcp->source) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->source), &tcp->source); ____tmp; });
        u16 dport = ({ typeof(tcp->dest) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->dest), &tcp->dest); ____tmp; });
        u8 flags;

        if (filter_port(args, sport, dport))
            return -1;

        flags = ({ typeof(((u8 *)tcp)[13]) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&((u8 *)tcp)[13]), &((u8 *)tcp)[13]); ____tmp; });
        if ((args && args->tcp_flags) &&
            !(flags & args->tcp_flags))
            return -1;

        pkt->l4.tcp.sport = sport;
        pkt->l4.tcp.dport = dport;
        pkt->l4.tcp.flags = flags;
        pkt->l4.tcp.seq = (__builtin_constant_p(({ typeof(tcp->seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->seq), &tcp->seq); ____tmp; })) ? ((__u32)(((__u32)(({ typeof(tcp->seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->seq), &tcp->seq); ____tmp; })) << (32 - (0 + 1) * 8) >> (32 - 8) << (3 * 8)) | ((__u32)(({ typeof(tcp->seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->seq), &tcp->seq); ____tmp; })) << (32 - (1 + 1) * 8) >> (32 - 8) << (2 * 8)) | ((__u32)(({ typeof(tcp->seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->seq), &tcp->seq); ____tmp; })) << (32 - (2 + 1) * 8) >> (32 - 8) << (1 * 8)) | ((__u32)(({ typeof(tcp->seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->seq), &tcp->seq); ____tmp; })) << (32 - (3 + 1) * 8) >> (32 - 8) << (0 * 8)))) : __builtin_bswap32(({ typeof(tcp->seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->seq), &tcp->seq); ____tmp; })));
        pkt->l4.tcp.ack = (__builtin_constant_p(({ typeof(tcp->ack_seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->ack_seq), &tcp->ack_seq); ____tmp; })) ? ((__u32)(((__u32)(({ typeof(tcp->ack_seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->ack_seq), &tcp->ack_seq); ____tmp; })) << (32 - (0 + 1) * 8) >> (32 - 8) << (3 * 8)) | ((__u32)(({ typeof(tcp->ack_seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->ack_seq), &tcp->ack_seq); ____tmp; })) << (32 - (1 + 1) * 8) >> (32 - 8) << (2 * 8)) | ((__u32)(({ typeof(tcp->ack_seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->ack_seq), &tcp->ack_seq); ____tmp; })) << (32 - (2 + 1) * 8) >> (32 - 8) << (1 * 8)) | ((__u32)(({ typeof(tcp->ack_seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->ack_seq), &tcp->ack_seq); ____tmp; })) << (32 - (3 + 1) * 8) >> (32 - 8) << (0 * 8)))) : __builtin_bswap32(({ typeof(tcp->ack_seq) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tcp->ack_seq), &tcp->ack_seq); ____tmp; })));
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = l4;
        u16 sport = ({ typeof(udp->source) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&udp->source), &udp->source); ____tmp; });
        u16 dport = ({ typeof(udp->dest) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&udp->dest), &udp->dest); ____tmp; });

        if (filter_port(args, sport, dport))
            return -1;

        pkt->l4.udp.sport = sport;
        pkt->l4.udp.dport = dport;
        break;
    }
    case 58:
    case IPPROTO_ICMP:
    {
        struct icmphdr *icmp = l4;
        if ((args && (args->port || args->sport || args->dport)))
            return -1;
        u8 type = ({ typeof(icmp->type) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&icmp->type), &icmp->type); ____tmp; });
        if (filter_icmpv6_type(args, type))
            return -1;
        pkt->l4.icmp.code = ({ typeof(icmp->code) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&icmp->code), &icmp->code); ____tmp; });
        pkt->l4.icmp.type = ({ typeof(icmp->type) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&icmp->type), &icmp->type); ____tmp; });
        pkt->l4.icmp.seq = ({ typeof(icmp->un.echo.sequence) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&icmp->un.echo.sequence), &icmp->un.echo.sequence); ____tmp; });
        pkt->l4.icmp.id = ({ typeof(icmp->un.echo.id) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&icmp->un.echo.id), &icmp->un.echo.id); ____tmp; });
        break;
    }
    case IPPROTO_ESP:
    {
        struct ip_esp_hdr *esp_hdr = l4;
        if ((args && (args->port || args->sport || args->dport)))
            return -1;
        pkt->l4.espheader.seq = ({ typeof(esp_hdr->seq_no) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&esp_hdr->seq_no), &esp_hdr->seq_no); ____tmp; });
        pkt->l4.espheader.spi = ({ typeof(esp_hdr->spi) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&esp_hdr->spi), &esp_hdr->spi); ____tmp; });
        break;
    }
    default:
        if ((args && (args->port || args->sport || args->dport)))
            return -1;
    }
    return 0;
}

static inline int probe_parse_l3(struct sk_buff *skb, pkt_args_t *args,
                                 packet_t *pkt, void *l3,
                                 parse_ctx_t *ctx)
{
    u16 trans_header;
    void *l4 = ((void *)0);

    trans_header = ({ typeof((skb)->transport_header) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->transport_header); }); __r; });
    if (!skb_l4_check(trans_header, ctx->network_header))
        l4 = ctx->data + trans_header;

    if (pkt->proto_l3 == 0x86DD)
    {
        struct ipv6hdr *ipv6 = l3;

        if ((args && (args->addr || args->saddr || args->daddr)))
            return -1;
# 347 "./skb_parse.h"
        pkt->proto_l4 = ({ typeof(ipv6->nexthdr) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&ipv6->nexthdr), &ipv6->nexthdr); ____tmp; });
        l4 = l4 ?: l3 + sizeof(*ipv6);
    }
    else
    {
        struct iphdr *ipv4 = l3;
        u32 saddr, daddr, len;

        len = (__builtin_constant_p(({ typeof((ipv4)->tot_len) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((ipv4))))(((ipv4))))->tot_len); }); __r; })) ? ((__u16)(((__u16)(({ typeof((ipv4)->tot_len) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((ipv4))))(((ipv4))))->tot_len); }); __r; })) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(({ typeof((ipv4)->tot_len) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((ipv4))))(((ipv4))))->tot_len); }); __r; })) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(({ typeof((ipv4)->tot_len) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((ipv4))))(((ipv4))))->tot_len); }); __r; })));
        if (args && (args->pkt_len_1 || args->pkt_len_2))
        {
            if (len < args->pkt_len_1 || len > args->pkt_len_2)
                return -1;
        }

        if ((args && (args->addr_v6[0] || args->saddr_v6[0] || args->daddr_v6[0])))
            return -1;

        l4 = l4 ?: l3 + get_ip_header_len(({ typeof(((u8 *)l3)[0]) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&((u8 *)l3)[0]), &((u8 *)l3)[0]); ____tmp; }));
        saddr = ({ typeof(ipv4->saddr) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&ipv4->saddr), &ipv4->saddr); ____tmp; });
        daddr = ({ typeof(ipv4->daddr) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&ipv4->daddr), &ipv4->daddr); ____tmp; });

        if (filter_ipv4_check(args, saddr, daddr))
            return -1;

        pkt->proto_l4 = ({ typeof(ipv4->protocol) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&ipv4->protocol), &ipv4->protocol); ____tmp; });
        pkt->l3.ipv4.saddr = saddr;
        pkt->l3.ipv4.daddr = daddr;
    }

    if (((args && args->l4_proto) && args->l4_proto != pkt->proto_l4))
        return -1;

    return probe_parse_l4(l4, pkt, args);
}
# 398 "./skb_parse.h"
static inline int probe_parse_sk(struct sock *sk, sock_t *ske,
                                 pkt_args_t *args)
{
    struct inet_connection_sock *icsk;
    struct sock_common *skc;
    u8 saddr[16], daddr[16];
    unsigned long tmo;
    u16 l3_proto;
    u8 l4_proto;

    skc = (struct sock_common *)sk;
    switch (({ typeof((skc)->skc_family) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_family); }); __r; }))
    {
    case 2:
        l3_proto = 0x0800;
        ske->l3.ipv4.saddr = ({ typeof((skc)->skc_rcv_saddr) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_rcv_saddr); }); __r; });
        ske->l3.ipv4.daddr = ({ typeof((skc)->skc_daddr) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_daddr); }); __r; });
        if (filter_ipv4_check(args, ske->l3.ipv4.saddr,
                              ske->l3.ipv4.daddr))
            goto err;
        break;
    case 10:

        if (filter_ipv6_check(args, saddr, daddr))
            goto err;
        l3_proto = 0x86DD;
        break;
    default:

        goto err;
    }
    if (((args && args->l3_proto) && args->l3_proto != l3_proto))
        goto err;

    l4_proto = ({ typeof((sk)->sk_protocol) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->sk_protocol); }); __r; });
# 447 "./skb_parse.h"
    if (l4_proto == IPPROTO_IP)
        l4_proto = IPPROTO_TCP;

    if (((args && args->l4_proto) && args->l4_proto != l4_proto))
        goto err;

    switch (l4_proto)
    {
    case IPPROTO_TCP:
    {
        struct tcp_sock *tp = (void *)sk;

        if (false)
        {
            ske->l4.tcp.packets_out = ({ typeof((tp)->packets_out) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((tp))))(((tp))))->packets_out); }); __r; });
            ske->l4.tcp.retrans_out = ({ typeof((tp)->retrans_out) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((tp))))(((tp))))->retrans_out); }); __r; });
            ske->l4.tcp.snd_una = ({ typeof((tp)->snd_una) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((tp))))(((tp))))->snd_una); }); __r; });
        }
        else
        {
            ske->l4.tcp.packets_out = ({ typeof(tp->packets_out) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tp->packets_out), &tp->packets_out); ____tmp; });
            ske->l4.tcp.retrans_out = ({ typeof(tp->retrans_out) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tp->retrans_out), &tp->retrans_out); ____tmp; });
            ske->l4.tcp.snd_una = ({ typeof(tp->snd_una) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tp->snd_una), &tp->snd_una); ____tmp; });
        }
    }
    case IPPROTO_UDP:
        ske->l4.min.sport = (__builtin_constant_p(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })) ? ((__u16)(((__u16)(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })));
        ske->l4.min.dport = ({ typeof((skc)->skc_dport) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_dport); }); __r; });
        break;
    default:
        break;
    }

    if (filter_port(args, ske->l4.tcp.sport, ske->l4.tcp.dport))
        goto err;

    ske->rqlen = ({ typeof((sk)->sk_receive_queue.qlen) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->sk_receive_queue.qlen); }); __r; });
    ske->wqlen = ({ typeof((sk)->sk_write_queue.qlen) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->sk_write_queue.qlen); }); __r; });

    ske->proto_l3 = l3_proto;
    ske->proto_l4 = l4_proto;
    ske->state = ({ typeof((skc)->skc_state) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_state); }); __r; });

    if (!false)
        return 0;

    icsk = (void *)sk;
    bpf_probe_read_kernel(&ske->ca_state, sizeof(u8),
                          (u8 *)icsk +
                              ((unsigned long)&((struct inet_connection_sock *)0)->icsk_retransmits) -

                              1);

    if (false)
    {
        if (false)
            tmo = ({ typeof((icsk)->icsk_timeout) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((icsk))))(((icsk))))->icsk_timeout); }); __r; });
        else
            tmo = ({ typeof((icsk)->icsk_retransmit_timer.expires) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((icsk))))(((icsk))))->icsk_retransmit_timer.expires); }); __r; });
        ske->timer_out = tmo - (unsigned long)bpf_jiffies64();
    }

    ske->timer_pending = ({ typeof((icsk)->icsk_pending) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((icsk))))(((icsk))))->icsk_pending); }); __r; });

    return 0;
err:
    return -1;
}

static inline int probe_parse_skb_sk(struct sock *sk, struct sk_buff *skb,
                                     packet_t *pkt, pkt_args_t *args,
                                     parse_ctx_t *ctx)
{
    u16 l3_proto, trans_header;
    struct sock_common *skc;
    u8 l4_proto;

    skc = (struct sock_common *)sk;
    switch (({ typeof((skc)->skc_family) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_family); }); __r; }))
    {
    case 2:
        l3_proto = 0x0800;
        pkt->l3.ipv4.saddr = ({ typeof((skc)->skc_rcv_saddr) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_rcv_saddr); }); __r; });
        pkt->l3.ipv4.daddr = ({ typeof((skc)->skc_daddr) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_daddr); }); __r; });
        if (filter_ipv4_check(args, pkt->l3.ipv4.saddr,
                              pkt->l3.ipv4.daddr))
            return -1;
        break;
    case 10:

        l3_proto = 0x86DD;
        break;
    default:

        return -1;
    }
    if (((args && args->l3_proto) && args->l3_proto != l3_proto))
        return -1;

    l4_proto = ({ typeof((sk)->sk_protocol) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->sk_protocol); }); __r; });
# 563 "./skb_parse.h"
    if (l4_proto == IPPROTO_IP)
        l4_proto = IPPROTO_TCP;

    if (((args && args->l4_proto) && args->l4_proto != l4_proto))
        return -1;

    pkt->proto_l3 = l3_proto;
    pkt->proto_l4 = l4_proto;

    trans_header = ({ typeof((skb)->transport_header) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->transport_header); }); __r; });
    if (skb_l4_was_set(trans_header))
    {
        return probe_parse_l4(({ typeof((skb)->head) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->head); }); __r; }) + trans_header,
                              pkt, args);
    }

    switch (l4_proto)
    {
    case IPPROTO_TCP:
    {
        struct tcp_sock *tp = (void *)sk;
        struct tcp_skb_cb *cb;

        cb = ((void *)(skb) + ((unsigned long)&((typeof(*skb) *)0)->cb));
        pkt->l4.tcp.seq = ({ typeof((cb)->seq) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((cb))))(((cb))))->seq); }); __r; });
        pkt->l4.tcp.flags = ({ typeof((cb)->tcp_flags) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((cb))))(((cb))))->tcp_flags); }); __r; });
        if (false)
            pkt->l4.tcp.ack = ({ typeof((tp)->rcv_nxt) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((tp))))(((tp))))->rcv_nxt); }); __r; });
        else
            pkt->l4.tcp.ack = ({ typeof(tp->rcv_nxt) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&tp->rcv_nxt), &tp->rcv_nxt); ____tmp; });
    }
    case IPPROTO_UDP:
        pkt->l4.min.sport = (__builtin_constant_p(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })) ? ((__u16)(((__u16)(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(({ typeof((skc)->skc_num) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_num); }); __r; })));
        pkt->l4.min.dport = ({ typeof((skc)->skc_dport) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skc))))(((skc))))->skc_dport); }); __r; });
        break;
    default:
        break;
    }

    return filter_port(args, pkt->l4.tcp.sport, pkt->l4.tcp.dport);
}
# 619 "./skb_parse.h"
static inline __attribute__((always_inline)) int probe_parse_skb(struct sk_buff *skb, struct sock *sk,
                                                                 packet_t *pkt, pkt_args_t *args)
{
    parse_ctx_t __ctx, *ctx = &__ctx;
    u16 l3_proto;
    void *l3;
    {
        if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
            ({ char ____fmt[] = "nettrace: ""skb=%llx, ""dtwdebug""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), (u64)(void *)skb); });
    };
    return -1;
    ctx->network_header = ({ typeof((skb)->network_header) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->network_header); }); __r; });
    ctx->mac_header = ({ typeof((skb)->mac_header) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->mac_header); }); __r; });
    ctx->data = ({ typeof((skb)->head) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->head); }); __r; });

    {
        if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
            ({ char ____fmt[] = "nettrace: ""skb=%llx, ""begin to parse, nh=%d mh=%d""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), (u64)(void *)skb, ctx->network_header, ctx->mac_header); });
    };

    if (skb_l2_check(ctx->mac_header))
    {
        int family;

        sk = sk ?: ({ typeof((skb)->sk) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->sk); }); __r; });
# 648 "./skb_parse.h"
        if (!ctx->network_header)
        {
            if (!sk)
                return -1;
            return probe_parse_skb_sk(sk, skb, pkt, args, ctx);
        }

        l3_proto = (__builtin_constant_p(({ typeof((skb)->protocol) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->protocol); }); __r; })) ? ((__u16)(((__u16)(({ typeof((skb)->protocol) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->protocol); }); __r; })) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(({ typeof((skb)->protocol) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->protocol); }); __r; })) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(({ typeof((skb)->protocol) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->protocol); }); __r; })));
        if (!l3_proto)
        {

            if (!sk)
                return -1;
            family = ({ typeof(((struct sock_common *)sk)->skc_family) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof((((struct sock_common *)sk))))((((struct sock_common *)sk))))->skc_family); }); __r; });
            if (family == 2)
                l3_proto = 0x0800;
            else if (family == 10)
                l3_proto = 0x86DD;
            else
                return -1;
        }
        l3 = ctx->data + ctx->network_header;
    }
    else if (ctx->network_header && ctx->mac_header >= ctx->network_header)
    {

        l3 = ctx->data + ctx->network_header;
        l3_proto = 0x0800;
    }
    else
    {

        struct ethhdr *eth = ctx->data + ctx->mac_header;

        l3 = (void *)eth + 14;
        l3_proto = (__builtin_constant_p(({ typeof(eth->h_proto) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&eth->h_proto), &eth->h_proto); ____tmp; })) ? ((__u16)(((__u16)(({ typeof(eth->h_proto) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&eth->h_proto), &eth->h_proto); ____tmp; })) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(({ typeof(eth->h_proto) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&eth->h_proto), &eth->h_proto); ____tmp; })) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(({ typeof(eth->h_proto) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&eth->h_proto), &eth->h_proto); ____tmp; })));
    }

    if (args)
    {
        if (args->l3_proto)
        {
            if (args->l3_proto != l3_proto)
                return -1;
        }
        else if (args->l4_proto)
        {

            if (l3_proto != 0x0800 && l3_proto != 0x86DD)
                return -1;
        }
    }

    pkt->proto_l3 = l3_proto;
    {
        if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
            ({ char ____fmt[] = "nettrace: ""skb=%llx, ""l3=%d""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), (u64)(void *)skb, l3_proto); });
    };

    switch (l3_proto)
    {
    case 0x86DD:
    case 0x0800:
        return probe_parse_l3(skb, args, pkt, l3, ctx);
    case 0x0806:
        return probe_parse_arp(l3, pkt, args);
    default:
        return 0;
    }
}

static inline int direct_parse_skb(struct __sk_buff *skb, packet_t *pkt,
                                   pkt_args_t *bpf_args)
{
    struct ethhdr *eth = ((void *)(long)skb->data);
    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)ip > ((void *)(long)skb->data_end))
        goto err;

    if (bpf_args && (bpf_args->l3_proto && bpf_args->l3_proto != eth->h_proto))
        goto err;

    pkt->proto_l3 = (__builtin_constant_p(eth->h_proto) ? ((__u16)(((__u16)(eth->h_proto) << (16 - (0 + 1) * 8) >> (16 - 8) << (1 * 8)) | ((__u16)(eth->h_proto) << (16 - (1 + 1) * 8) >> (16 - 8) << (0 * 8)))) : __builtin_bswap16(eth->h_proto));
    if ((((void *)(long)skb->data) + ((sizeof(struct ethhdr)) + (sizeof(struct iphdr))) > ((void *)(long)skb->data_end)))
        goto err;

    if (bpf_args && ((bpf_args->l4_proto && bpf_args->l4_proto != ip->protocol) ||
                     (bpf_args->saddr && bpf_args->saddr != ip->saddr) ||
                     (bpf_args->daddr && bpf_args->daddr != ip->daddr)))
        goto err;

    l4_min_t *l4_p = (void *)(ip + 1);
    struct tcphdr *tcp = (void *)l4_p;

    switch (ip->protocol)
    {
    case IPPROTO_UDP:
        if ((((void *)(long)skb->data) + (((sizeof(struct ethhdr)) + (sizeof(struct iphdr))) + (sizeof(struct udphdr))) > ((void *)(long)skb->data_end)))
            goto err;
        goto fill_port;
    case IPPROTO_TCP:
        if ((((void *)(long)skb->data) + (((sizeof(struct ethhdr)) + (sizeof(struct iphdr))) + (sizeof(struct tcphdr))) > ((void *)(long)skb->data_end)))
            goto err;

        pkt->l4.tcp.flags = ((u8 *)tcp)[13];
        pkt->l4.tcp.ack = (__builtin_constant_p(tcp->ack_seq) ? ((__u32)(((__u32)(tcp->ack_seq) << (32 - (0 + 1) * 8) >> (32 - 8) << (3 * 8)) | ((__u32)(tcp->ack_seq) << (32 - (1 + 1) * 8) >> (32 - 8) << (2 * 8)) | ((__u32)(tcp->ack_seq) << (32 - (2 + 1) * 8) >> (32 - 8) << (1 * 8)) | ((__u32)(tcp->ack_seq) << (32 - (3 + 1) * 8) >> (32 - 8) << (0 * 8)))) : __builtin_bswap32(tcp->ack_seq));
        pkt->l4.tcp.seq = (__builtin_constant_p(tcp->seq) ? ((__u32)(((__u32)(tcp->seq) << (32 - (0 + 1) * 8) >> (32 - 8) << (3 * 8)) | ((__u32)(tcp->seq) << (32 - (1 + 1) * 8) >> (32 - 8) << (2 * 8)) | ((__u32)(tcp->seq) << (32 - (2 + 1) * 8) >> (32 - 8) << (1 * 8)) | ((__u32)(tcp->seq) << (32 - (3 + 1) * 8) >> (32 - 8) << (0 * 8)))) : __builtin_bswap32(tcp->seq));
    fill_port:
        pkt->l4.min = *l4_p;
        break;
    case IPPROTO_ICMP:
    {
        struct icmphdr *icmp = (void *)l4_p;
        if ((((void *)(long)skb->data) + (((sizeof(struct ethhdr)) + (sizeof(struct iphdr))) + (sizeof(struct icmphdr))) > ((void *)(long)skb->data_end)))
            goto err;

        pkt->l4.icmp.code = icmp->code;
        pkt->l4.icmp.type = icmp->type;
        pkt->l4.icmp.seq = icmp->un.echo.sequence;
        pkt->l4.icmp.id = icmp->un.echo.id;
    }
    default:
        goto out;
    }

    if (bpf_args && ((bpf_args->sport && bpf_args->sport != l4_p->sport) ||
                     (bpf_args->dport && bpf_args->dport != l4_p->dport)))
        return 1;

    pkt->l3.ipv4.saddr = ip->saddr;
    pkt->l3.ipv4.daddr = ip->daddr;
    pkt->proto_l4 = ip->protocol;
    pkt->proto_l3 = 0x0800;
    pkt->ts = bpf_ktime_get_ns();

out:
    return 0;
err:
    return 1;
}
# 5 "./core.h" 2

typedef struct
{
    u16 func1;
    u16 func2;
    u32 ts1;
    u32 ts2;
} match_val_t;

typedef struct
{

    void *ctx;
    struct sk_buff *skb;
    struct sock *sk;
    event_t *e;

    bpf_args_t *args;
    union
    {

        u64 retval;

        match_val_t match_val;
        u32 matched;
    };
    u16 func;
    u8 func_status;

    u8 no_event : 1;
} context_info_t;
# 9 "nettrace.bpf.c" 2

# 1 "./kprobe_trace.h" 1
# 11 "nettrace.bpf.c" 2
# 91 "nettrace.bpf.c"
static inline int handle_exit(struct pt_regs *ctx, int func);
static inline void get_ret(context_info_t *info);
static inline int default_handle_entry(context_info_t *info);

# 1 "./core.c" 1

# 1 "./kheaders.h" 1
# 3 "./core.c" 2

# 1 "./kprobe_trace.h" 1
# 10 "./core.c" 2

struct
{

    int (*type)[BPF_MAP_TYPE_HASH];

    int (*key_size)[sizeof(u64)];
    int (*value_size)[sizeof(int)];
    int (*max_entries)[1024];
} m_ret
# 25 "./core.c"
#pragma GCC diagnostic push
# 25 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 25 "./core.c"
    __attribute__((section(".maps"), used))
# 25 "./core.c"
#pragma GCC diagnostic pop
# 25 "./core.c"
    ;

struct
{
    int (*type)[BPF_MAP_TYPE_STACK_TRACE];
    int (*max_entries)[16384];
    int (*key_size)[sizeof(__u32)];
    int (*value_size)[sizeof(stack_trace_t)];
} m_stack
# 33 "./core.c"
#pragma GCC diagnostic push
# 33 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 33 "./core.c"
    __attribute__((section(".maps"), used))
# 33 "./core.c"
#pragma GCC diagnostic pop
# 33 "./core.c"
    ;

struct
{

    int (*type)[BPF_MAP_TYPE_HASH];

    int (*max_entries)[102400];
    int (*key_size)[sizeof(u64)];
    int (*value_size)[sizeof(match_val_t)];
} m_matched
# 45 "./core.c"
#pragma GCC diagnostic push
# 45 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 45 "./core.c"
    __attribute__((section(".maps"), used))
# 45 "./core.c"
#pragma GCC diagnostic pop
# 45 "./core.c"
    ;

struct
{
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int (*key_size)[sizeof(int)];
    int (*value_size)[sizeof(__u64)];
    int (*max_entries)[512];
} m_stats
# 52 "./core.c"
#pragma GCC diagnostic push
# 52 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 52 "./core.c"
    __attribute__((section(".maps"), used))
# 52 "./core.c"
#pragma GCC diagnostic pop
# 52 "./core.c"
    ;

static inline void try_trace_stack(context_info_t *info)
{
    if (!info->args->stack || !(info->func_status & (1 << 4)))
        return;

    info->e->stack_id = bpf_get_stackid(info->ctx, &m_stack, 0);
}

static inline int filter_by_netns(context_info_t *info)
{
    return 0;
}

static inline __attribute__((always_inline)) void do_event_output(context_info_t *info,
                                                                  const int size)
{
    bpf_perf_event_output(info->ctx, &m_event, BPF_F_CURRENT_CPU, info->e, size);
}

static inline __attribute__((always_inline)) int check_rate_limit(bpf_args_t *args)
{
    u64 last_ts = args->__last_update, ts = 0;
    int budget = args->__rate_limit;
    int limit = args->rate_limit;

    if (!limit)
        return 0;

    if (!last_ts)
    {
        last_ts = bpf_ktime_get_ns();
        args->__last_update = last_ts;
    }

    if (budget <= 0)
    {
        ts = bpf_ktime_get_ns();
        budget = (((ts - last_ts) / 1000000) * limit) / 1000;
        budget = budget < limit ? budget : limit;
        if (budget <= 0)
            return -1;
        args->__last_update = ts;
    }

    budget--;
    args->__rate_limit = budget;

    return 0;
}

static inline void handle_tiny_output(context_info_t *info)
{
    tiny_event_t e = {
        .func = info->func,
        .meta = FUNC_TYPE_TINY,

        .key = (u64)(void *)info->skb,

        .ts = bpf_ktime_get_ns(),
    };

    bpf_perf_event_output(info->ctx, &m_event, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

static inline bool mode_has_context(bpf_args_t *args)
{
    return args->trace_mode & ((1 << TRACE_MODE_DIAG) | (1 << TRACE_MODE_TIMELINE) | (1 << TRACE_MODE_LATENCY));
}

static inline __attribute__((always_inline)) u8 get_func_status(bpf_args_t *args, u16 func)
{
    if (func >= 162)
        return 0;

    return args->trace_status[func];
}

static inline bool func_is_free(u8 status)
{
    return status & ((1 << 0) | (1 << 6));
}

static inline bool func_is_cfree(u8 status)
{
    return status & (1 << 6);
}

static inline void consume_map_ctx(bpf_args_t *args, void *key)
{
    bpf_map_delete_elem(&m_matched, key);
    args->event_count++;
}

static inline void free_map_ctx(bpf_args_t *args, void *key)
{
    bpf_map_delete_elem(&m_matched, key);
}

static inline void init_ctx_match(void *skb, u16 func, bool ts)
{
    match_val_t matched = {
        .ts1 = ts ? bpf_ktime_get_ns() / 1000 : 0,
        .func1 = func,
    };

    bpf_map_update_elem(&m_matched, &skb, &matched, 0);
}

static inline __attribute__((always_inline)) void update_stats_key(u32 key)
{
    u64 *stats = bpf_map_lookup_elem(&m_stats, &key);

    if (stats)
        (*stats)++;
}

static inline __attribute__((always_inline)) void update_stats_log(u32 val)
{
    u32 key = 0, i = 0, tmp = 2;

#pragma clang loop unroll_count(16)
    for (; i < 16; i++)
    {
        if (val < tmp)
            break;
        tmp <<= 1;
        key++;
    }

    update_stats_key(key);
}

static inline int pre_tiny_output(context_info_t *info)
{
    handle_tiny_output(info);
    if (func_is_free(info->func_status))
        consume_map_ctx(info->args, &info->skb);
    else
        get_ret(info);
    return 1;
}

static inline int pre_handle_latency(context_info_t *info,
                                     match_val_t *match_val)
{
    bpf_args_t *args = (void *)info->args;
    u32 delta;

    if (match_val)
    {
        if (args->latency_free || !func_is_free(info->func_status) ||
            func_is_cfree(info->func_status))
        {
            match_val->ts2 = bpf_ktime_get_ns() / 1000;
            match_val->func2 = info->func;
        }

        if (info->func_status & (1 << 3) &&
            match_val->func1 == info->func)
            match_val->ts1 = bpf_ktime_get_ns() / 1000;

        if (func_is_free(info->func_status))
        {
            delta = match_val->ts2 - match_val->ts1;

            if (!match_val->func2 || delta < args->latency_min)
            {
                free_map_ctx(info->args, &info->skb);
                return 1;
            }
            if (args->latency_summary)
            {
                update_stats_log(delta);
                consume_map_ctx(info->args, &info->skb);
                return 1;
            }
            info->match_val = *match_val;
            return 0;
        }
        return 1;
    }
    else
    {

        if (func_is_free(info->func_status))
            return 1;

        if (!args->has_filter)
        {
            init_ctx_match(info->skb, info->func, true);
            return 1;
        }
    }
    info->no_event = true;
    return 0;
}

static inline bool trace_mode_latency(bpf_args_t *args)
{
    return args->trace_mode & (1 << TRACE_MODE_LATENCY);
}

static inline int pre_handle_entry(context_info_t *info, u16 func)
{
    bpf_args_t *args = (void *)info->args;
    int ret = 0;

    if (!args->ready || check_rate_limit(args))
        return -1;

    if (args->max_event && args->event_count >= args->max_event)
        return -1;

    info->func_status = get_func_status(info->args, func);
    if (mode_has_context(args))
    {
        match_val_t *match_val = bpf_map_lookup_elem(&m_matched,
                                                     &info->skb);

        if (!match_val)
        {

            if (args->match_mode &&
                !(info->func_status & (1 << 3)))
                return -1;

            if (func_is_free(info->func_status))
                return -1;
        }

        if (match_val && args->tiny_output)
            ret = pre_tiny_output(info);
        else if (trace_mode_latency(args))
            ret = pre_handle_latency(info, match_val);
        else if (match_val)
            info->match_val = *match_val;
    }

    if (args->func_stats)
    {
        if (ret)
        {
            update_stats_key(func);
        }
        else if (!args->has_filter)
        {
            update_stats_key(func);
            args->event_count++;
            ret = 1;
        }
        else
        {
            info->no_event = true;
        }
    }

    return ret;
}

static inline void handle_entry_finish(context_info_t *info, int err)
{
    if (err < 0)
        return;

    if (mode_has_context(info->args))
    {
        if (func_is_free(info->func_status))
        {
            if (info->matched)
                consume_map_ctx(info->args, &info->skb);
        }
        else if (!info->matched)
        {
            init_ctx_match(info->skb, info->func,
                           trace_mode_latency(info->args));
        }
    }
    else
    {
        info->args->event_count++;
    }

    if (info->args->func_stats)
        update_stats_key(info->func);
}

static inline void try_set_latency(bpf_args_t *args, event_t *e,
                                   match_val_t *val)
{
    if (!val->func1 || !trace_mode_latency(args))
        return;

    e->latency = val->ts2 - val->ts1;
    e->latency_func1 = val->func1;
    e->latency_func2 = val->func2;
}

static int handle_entry(context_info_t *info)
{
    bpf_args_t *args = (void *)info->args;
    struct sk_buff *skb = info->skb;
    struct net_device *dev;
    detail_event_t *detail;
    event_t *e = info->e;
    pkt_args_t *pkt_args;
    bool mode_ctx, filter;
    packet_t *pkt;
    u32 pid;
    int err;

    {
        if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
            ({ char ____fmt[] = "nettrace: ""skb=%llx, ""begin to handle, func=%d""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), (u64)(void *)skb, info->func); });
    };
    pid = (u32)bpf_get_current_pid_tgid();
    mode_ctx = mode_has_context(args);
    filter = !info->matched;
    pkt_args = &args->pkt;
    pkt = &e->pkt;

    if (filter && (args->pid && args->pid != pid))
        goto err;

    if (!filter)
    {
        if (!skb)
        {
            {
                if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
                    ({ char ____fmt[] = "nettrace: ""no skb available, func=%d""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), info->func); });
            };
            goto err;
        }
        probe_parse_skb(skb, info->sk, pkt, ((void *)0));
        goto no_filter;
    }

    if (info->func_status & (1 << 1))
    {
        if (!info->sk)
        {
            {
                if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
                    ({ char ____fmt[] = "nettrace: ""no sock available, func=%d""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), info->func); });
            };
            goto err;
        }
        err = probe_parse_sk(info->sk, &e->ske, pkt_args);
    }
    else
    {
        if (!skb)
        {
            {
                if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
                    ({ char ____fmt[] = "nettrace: ""no skb available, func=%d""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), info->func); });
            };
            goto err;
        }
        err = probe_parse_skb(skb, info->sk, pkt, pkt_args);
    }

    if (err)
        goto err;

no_filter:
    if (filter_by_netns(info) && filter)
        goto err;

    if (info->no_event)
        return 1;

    if (!args->detail)
        goto out;

    dev = ({ typeof((skb)->dev) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->dev); }); __r; });
    detail = (void *)e;

    bpf_get_current_comm(detail->task, sizeof(detail->task));
    if (dev)
    {
        bpf_probe_read_kernel_str(detail->ifname, sizeof(detail->ifname) - 1,
                                  &dev->name);
        detail->ifindex = ({ typeof((dev)->ifindex) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((dev))))(((dev))))->ifindex); }); __r; });
    }
    else
    {
        detail->ifindex = ({ typeof((skb)->skb_iif) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->skb_iif); }); __r; });
        detail->ifname[0] = '\0';
    }

out:
{
    if (({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; })->bpf_debug)
        ({ char ____fmt[] = "nettrace: ""skb=%llx, ""pkt matched""\n"; bpf_trace_printk(____fmt, sizeof(____fmt), (u64)(void *)skb); });
};
    try_trace_stack(info);
    pkt->ts = bpf_ktime_get_ns();

    e->key = (u64)(void *)skb;

    e->func = info->func;
    e->pid = pid;

    try_set_latency(args, e, &info->match_val);

    if (mode_ctx)
        get_ret(info);
    return 0;
err:
    return -1;
}

static inline int default_handle_entry(context_info_t *info)
{
    bool detail = info->args->detail;
    detail_event_t __e;

    int size;

    int err;

    info->e = (void *)&__e;

    if (!detail)
    {
        size = sizeof(event_t);
        __builtin_memset(&__e, 0, size);
    }
    else
    {
        size = sizeof(__e);
        __builtin_memset(&__e, 0, size);
    }

    err = handle_entry(info);
    if (!err)
    {
# 491 "./core.c"
        do_event_output(info, size);
    }

    return err;
}
# 509 "./core.c"
static inline int fake__napi_gro_receive_entry(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("tp/"
                       "net"
                       "/"
                       "napi_gro_receive_entry"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_napi_gro_receive_entry(void *ctx)
{
    context_info_t info = {.func = 1, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 24))};
    if (pre_handle_entry(&info, 1))
        return 0;
    handle_entry_finish(&info, fake__napi_gro_receive_entry(&info));
    return 0;
}
static inline int fake__napi_gro_receive_entry(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__dev_gro_receive(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "dev_gro_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_dev_gro_receive(struct pt_regs *ctx)
{
    return handle_exit(ctx, 2);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "dev_gro_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_dev_gro_receive(struct pt_regs *ctx)
{
    context_info_t info = {.func = 2, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 2))
        return 0;
    handle_entry_finish(&info, fake__dev_gro_receive(&info));
    return 0;
}
static inline int fake__dev_gro_receive(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__enqueue_to_backlog(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "enqueue_to_backlog"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_enqueue_to_backlog(struct pt_regs *ctx)
{
    return handle_exit(ctx, 3);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "enqueue_to_backlog"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_enqueue_to_backlog(struct pt_regs *ctx)
{
    context_info_t info = {.func = 3, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 3))
        return 0;
    handle_entry_finish(&info, fake__enqueue_to_backlog(&info));
    return 0;
}
static inline int fake__enqueue_to_backlog(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__netif_receive_generic_xdp(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "netif_receive_generic_xdp"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_netif_receive_generic_xdp(struct pt_regs *ctx)
{
    return handle_exit(ctx, 4);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "netif_receive_generic_xdp"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_netif_receive_generic_xdp(struct pt_regs *ctx)
{
    context_info_t info = {.func = 4, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 4))
        return 0;
    handle_entry_finish(&info, fake__netif_receive_generic_xdp(&info));
    return 0;
}
static inline int fake__netif_receive_generic_xdp(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xdp_do_generic_redirect(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xdp_do_generic_redirect"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xdp_do_generic_redirect(struct pt_regs *ctx)
{
    return handle_exit(ctx, 5);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xdp_do_generic_redirect"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xdp_do_generic_redirect(struct pt_regs *ctx)
{
    context_info_t info = {.func = 5, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 5))
        return 0;
    handle_entry_finish(&info, fake__xdp_do_generic_redirect(&info));
    return 0;
}
static inline int fake__xdp_do_generic_redirect(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____netif_receive_skb_core(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("tp/"
                       "net"
                       "/"
                       "netif_receive_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___netif_receive_skb_core(void *ctx)
{
    context_info_t info = {.func = 6, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 8))};
    if (pre_handle_entry(&info, 6))
        return 0;
    handle_entry_finish(&info, fake____netif_receive_skb_core(&info));
    return 0;
}
static inline int fake____netif_receive_skb_core(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__RtmpOsPktRcvHandle(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "RtmpOsPktRcvHandle"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_RtmpOsPktRcvHandle(struct pt_regs *ctx)
{
    return handle_exit(ctx, 7);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "RtmpOsPktRcvHandle"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_RtmpOsPktRcvHandle(struct pt_regs *ctx)
{
    context_info_t info = {.func = 7, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 7))
        return 0;
    handle_entry_finish(&info, fake__RtmpOsPktRcvHandle(&info));
    return 0;
}
static inline int fake__RtmpOsPktRcvHandle(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____dev_queue_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__dev_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___dev_queue_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 8);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__dev_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___dev_queue_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 8, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 8))
        return 0;
    handle_entry_finish(&info, fake____dev_queue_xmit(&info));
    return 0;
}
static inline int fake____dev_queue_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__dev_hard_start_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "dev_hard_start_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_dev_hard_start_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 9);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "dev_hard_start_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_dev_hard_start_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 9, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 9))
        return 0;
    handle_entry_finish(&info, fake__dev_hard_start_xmit(&info));
    return 0;
}
static inline int fake__dev_hard_start_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__fp_send_data_pkt(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "fp_send_data_pkt"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_fp_send_data_pkt(struct pt_regs *ctx)
{
    return handle_exit(ctx, 10);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "fp_send_data_pkt"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_fp_send_data_pkt(struct pt_regs *ctx)
{
    context_info_t info = {.func = 10, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 10))
        return 0;
    handle_entry_finish(&info, fake__fp_send_data_pkt(&info));
    return 0;
}
static inline int fake__fp_send_data_pkt(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcf_classify(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcf_classify"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcf_classify(struct pt_regs *ctx)
{
    return handle_exit(ctx, 11);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcf_classify"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcf_classify(struct pt_regs *ctx)
{
    context_info_t info = {.func = 11, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 11))
        return 0;
    handle_entry_finish(&info, fake__tcf_classify(&info));
    return 0;
}
static inline int fake__tcf_classify(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__cls_bpf_classify(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "cls_bpf_classify"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_cls_bpf_classify(struct pt_regs *ctx)
{
    return handle_exit(ctx, 12);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "cls_bpf_classify"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_cls_bpf_classify(struct pt_regs *ctx)
{
    context_info_t info = {.func = 12, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 12))
        return 0;
    handle_entry_finish(&info, fake__cls_bpf_classify(&info));
    return 0;
}
static inline int fake__cls_bpf_classify(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcf_bpf_act(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcf_bpf_act"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcf_bpf_act(struct pt_regs *ctx)
{
    return handle_exit(ctx, 13);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcf_bpf_act"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcf_bpf_act(struct pt_regs *ctx)
{
    context_info_t info = {.func = 13, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 13))
        return 0;
    handle_entry_finish(&info, fake__tcf_bpf_act(&info));
    return 0;
}
static inline int fake__tcf_bpf_act(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipvlan_queue_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipvlan_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipvlan_queue_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 16);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipvlan_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipvlan_queue_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 16, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 16))
        return 0;
    handle_entry_finish(&info, fake__ipvlan_queue_xmit(&info));
    return 0;
}
static inline int fake__ipvlan_queue_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipvlan_handle_frame(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipvlan_handle_frame"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipvlan_handle_frame(struct pt_regs *ctx)
{
    return handle_exit(ctx, 17);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipvlan_handle_frame"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipvlan_handle_frame(struct pt_regs *ctx)
{
    context_info_t info = {.func = 17, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 17))
        return 0;
    handle_entry_finish(&info, fake__ipvlan_handle_frame(&info));
    return 0;
}
static inline int fake__ipvlan_handle_frame(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipvlan_rcv_frame(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipvlan_rcv_frame"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipvlan_rcv_frame(struct pt_regs *ctx)
{
    return handle_exit(ctx, 18);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipvlan_rcv_frame"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipvlan_rcv_frame(struct pt_regs *ctx)
{
    context_info_t info = {.func = 18, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 18))
        return 0;
    handle_entry_finish(&info, fake__ipvlan_rcv_frame(&info));
    return 0;
}
static inline int fake__ipvlan_rcv_frame(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipvlan_xmit_mode_l3(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipvlan_xmit_mode_l3"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipvlan_xmit_mode_l3(struct pt_regs *ctx)
{
    return handle_exit(ctx, 19);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipvlan_xmit_mode_l3"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipvlan_xmit_mode_l3(struct pt_regs *ctx)
{
    context_info_t info = {.func = 19, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 19))
        return 0;
    handle_entry_finish(&info, fake__ipvlan_xmit_mode_l3(&info));
    return 0;
}
static inline int fake__ipvlan_xmit_mode_l3(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipvlan_process_v4_outbound(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipvlan_process_v4_outbound"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipvlan_process_v4_outbound(struct pt_regs *ctx)
{
    return handle_exit(ctx, 20);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipvlan_process_v4_outbound"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipvlan_process_v4_outbound(struct pt_regs *ctx)
{
    context_info_t info = {.func = 20, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 20))
        return 0;
    handle_entry_finish(&info, fake__ipvlan_process_v4_outbound(&info));
    return 0;
}
static inline int fake__ipvlan_process_v4_outbound(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__br_nf_pre_routing(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "br_nf_pre_routing"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_br_nf_pre_routing(struct pt_regs *ctx)
{
    return handle_exit(ctx, 21);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "br_nf_pre_routing"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_br_nf_pre_routing(struct pt_regs *ctx)
{
    context_info_t info = {.func = 21, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 21))
        return 0;
    handle_entry_finish(&info, fake__br_nf_pre_routing(&info));
    return 0;
}
static inline int fake__br_nf_pre_routing(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__br_nf_forward_ip(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "br_nf_forward_ip"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_br_nf_forward_ip(struct pt_regs *ctx)
{
    return handle_exit(ctx, 22);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "br_nf_forward_ip"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_br_nf_forward_ip(struct pt_regs *ctx)
{
    context_info_t info = {.func = 22, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 22))
        return 0;
    handle_entry_finish(&info, fake__br_nf_forward_ip(&info));
    return 0;
}
static inline int fake__br_nf_forward_ip(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__br_nf_forward_arp(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "br_nf_forward_arp"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_br_nf_forward_arp(struct pt_regs *ctx)
{
    return handle_exit(ctx, 23);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "br_nf_forward_arp"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_br_nf_forward_arp(struct pt_regs *ctx)
{
    context_info_t info = {.func = 23, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 23))
        return 0;
    handle_entry_finish(&info, fake__br_nf_forward_arp(&info));
    return 0;
}
static inline int fake__br_nf_forward_arp(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__br_nf_post_routing(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "br_nf_post_routing"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_br_nf_post_routing(struct pt_regs *ctx)
{
    return handle_exit(ctx, 24);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "br_nf_post_routing"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_br_nf_post_routing(struct pt_regs *ctx)
{
    context_info_t info = {.func = 24, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 24))
        return 0;
    handle_entry_finish(&info, fake__br_nf_post_routing(&info));
    return 0;
}
static inline int fake__br_nf_post_routing(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__arp_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "arp_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_arp_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 25);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "arp_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_arp_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 25, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 25))
        return 0;
    handle_entry_finish(&info, fake__arp_rcv(&info));
    return 0;
}
static inline int fake__arp_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__bond_dev_queue_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "bond_dev_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_bond_dev_queue_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 27);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "bond_dev_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_bond_dev_queue_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 27, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 27))
        return 0;
    handle_entry_finish(&info, fake__bond_dev_queue_xmit(&info));
    return 0;
}
static inline int fake__bond_dev_queue_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____iptunnel_pull_header(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__iptunnel_pull_header"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___iptunnel_pull_header(struct pt_regs *ctx)
{
    return handle_exit(ctx, 28);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__iptunnel_pull_header"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___iptunnel_pull_header(struct pt_regs *ctx)
{
    context_info_t info = {.func = 28, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 28))
        return 0;
    handle_entry_finish(&info, fake____iptunnel_pull_header(&info));
    return 0;
}
static inline int fake____iptunnel_pull_header(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__vxlan_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "vxlan_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_vxlan_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 29);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "vxlan_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_vxlan_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 29, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 29))
        return 0;
    handle_entry_finish(&info, fake__vxlan_rcv(&info));
    return 0;
}
static inline int fake__vxlan_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__vxlan_xmit_one(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "vxlan_xmit_one"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_vxlan_xmit_one(struct pt_regs *ctx)
{
    return handle_exit(ctx, 30);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "vxlan_xmit_one"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_vxlan_xmit_one(struct pt_regs *ctx)
{
    context_info_t info = {.func = 30, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 30))
        return 0;
    handle_entry_finish(&info, fake__vxlan_xmit_one(&info));
    return 0;
}
static inline int fake__vxlan_xmit_one(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__vlan_do_receive(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "vlan_do_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_vlan_do_receive(struct pt_regs *ctx)
{
    return handle_exit(ctx, 31);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "vlan_do_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_vlan_do_receive(struct pt_regs *ctx)
{
    context_info_t info = {.func = 31, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 31))
        return 0;
    handle_entry_finish(&info, fake__vlan_do_receive(&info));
    return 0;
}
static inline int fake__vlan_do_receive(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__vlan_dev_hard_start_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "vlan_dev_hard_start_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_vlan_dev_hard_start_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 32);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "vlan_dev_hard_start_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_vlan_dev_hard_start_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 32, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 32))
        return 0;
    handle_entry_finish(&info, fake__vlan_dev_hard_start_xmit(&info));
    return 0;
}
static inline int fake__vlan_dev_hard_start_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__netdev_port_receive(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "netdev_port_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_netdev_port_receive(struct pt_regs *ctx)
{
    return handle_exit(ctx, 33);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "netdev_port_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_netdev_port_receive(struct pt_regs *ctx)
{
    context_info_t info = {.func = 33, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 33))
        return 0;
    handle_entry_finish(&info, fake__netdev_port_receive(&info));
    return 0;
}
static inline int fake__netdev_port_receive(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ovs_vport_receive(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ovs_vport_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ovs_vport_receive(struct pt_regs *ctx)
{
    return handle_exit(ctx, 34);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ovs_vport_receive"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ovs_vport_receive(struct pt_regs *ctx)
{
    context_info_t info = {.func = 34, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 34))
        return 0;
    handle_entry_finish(&info, fake__ovs_vport_receive(&info));
    return 0;
}
static inline int fake__ovs_vport_receive(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ovs_dp_process_packet(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ovs_dp_process_packet"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ovs_dp_process_packet(struct pt_regs *ctx)
{
    return handle_exit(ctx, 35);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ovs_dp_process_packet"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ovs_dp_process_packet(struct pt_regs *ctx)
{
    context_info_t info = {.func = 35, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 35))
        return 0;
    handle_entry_finish(&info, fake__ovs_dp_process_packet(&info));
    return 0;
}
static inline int fake__ovs_dp_process_packet(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__packet_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "packet_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_packet_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 36);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "packet_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_packet_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 36, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 36))
        return 0;
    handle_entry_finish(&info, fake__packet_rcv(&info));
    return 0;
}
static inline int fake__packet_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tpacket_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tpacket_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tpacket_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 37);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tpacket_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tpacket_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 37, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 37))
        return 0;
    handle_entry_finish(&info, fake__tpacket_rcv(&info));
    return 0;
}
static inline int fake__tpacket_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__packet_direct_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "packet_direct_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_packet_direct_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 38);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "packet_direct_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_packet_direct_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 38, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 38))
        return 0;
    handle_entry_finish(&info, fake__packet_direct_xmit(&info));
    return 0;
}
static inline int fake__packet_direct_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__nf_nat_manip_pkt(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "nf_nat_manip_pkt"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_nf_nat_manip_pkt(struct pt_regs *ctx)
{
    return handle_exit(ctx, 40);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "nf_nat_manip_pkt"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_nf_nat_manip_pkt(struct pt_regs *ctx)
{
    context_info_t info = {.func = 40, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 40))
        return 0;
    handle_entry_finish(&info, fake__nf_nat_manip_pkt(&info));
    return 0;
}
static inline int fake__nf_nat_manip_pkt(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipv4_confirm(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipv4_confirm"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipv4_confirm(struct pt_regs *ctx)
{
    return handle_exit(ctx, 44);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipv4_confirm"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipv4_confirm(struct pt_regs *ctx)
{
    context_info_t info = {.func = 44, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 44))
        return 0;
    handle_entry_finish(&info, fake__ipv4_confirm(&info));
    return 0;
}
static inline int fake__ipv4_confirm(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__nf_confirm(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "nf_confirm"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_nf_confirm(struct pt_regs *ctx)
{
    return handle_exit(ctx, 45);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "nf_confirm"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_nf_confirm(struct pt_regs *ctx)
{
    context_info_t info = {.func = 45, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 45))
        return 0;
    handle_entry_finish(&info, fake__nf_confirm(&info));
    return 0;
}
static inline int fake__nf_confirm(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipv4_conntrack_in(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipv4_conntrack_in"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipv4_conntrack_in(struct pt_regs *ctx)
{
    return handle_exit(ctx, 46);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipv4_conntrack_in"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipv4_conntrack_in(struct pt_regs *ctx)
{
    context_info_t info = {.func = 46, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 46))
        return 0;
    handle_entry_finish(&info, fake__ipv4_conntrack_in(&info));
    return 0;
}
static inline int fake__ipv4_conntrack_in(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__nf_conntrack_in(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "nf_conntrack_in"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_nf_conntrack_in(struct pt_regs *ctx)
{
    return handle_exit(ctx, 47);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "nf_conntrack_in"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_nf_conntrack_in(struct pt_regs *ctx)
{
    context_info_t info = {.func = 47, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[3]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 47))
        return 0;
    handle_entry_finish(&info, fake__nf_conntrack_in(&info));
    return 0;
}
static inline int fake__nf_conntrack_in(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipv4_pkt_to_tuple(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipv4_pkt_to_tuple"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipv4_pkt_to_tuple(struct pt_regs *ctx)
{
    return handle_exit(ctx, 48);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipv4_pkt_to_tuple"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipv4_pkt_to_tuple(struct pt_regs *ctx)
{
    context_info_t info = {.func = 48, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 48))
        return 0;
    handle_entry_finish(&info, fake__ipv4_pkt_to_tuple(&info));
    return 0;
}
static inline int fake__ipv4_pkt_to_tuple(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_new(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_new"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_new(struct pt_regs *ctx)
{
    return handle_exit(ctx, 49);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_new"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_new(struct pt_regs *ctx)
{
    context_info_t info = {.func = 49, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 49))
        return 0;
    handle_entry_finish(&info, fake__tcp_new(&info));
    return 0;
}
static inline int fake__tcp_new(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_pkt_to_tuple(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_pkt_to_tuple"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_pkt_to_tuple(struct pt_regs *ctx)
{
    return handle_exit(ctx, 50);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_pkt_to_tuple"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_pkt_to_tuple(struct pt_regs *ctx)
{
    context_info_t info = {.func = 50, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 50))
        return 0;
    handle_entry_finish(&info, fake__tcp_pkt_to_tuple(&info));
    return 0;
}
static inline int fake__tcp_pkt_to_tuple(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__resolve_normal_ct(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "resolve_normal_ct"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_resolve_normal_ct(struct pt_regs *ctx)
{
    return handle_exit(ctx, 51);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "resolve_normal_ct"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_resolve_normal_ct(struct pt_regs *ctx)
{
    context_info_t info = {.func = 51, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 51))
        return 0;
    handle_entry_finish(&info, fake__resolve_normal_ct(&info));
    return 0;
}
static inline int fake__resolve_normal_ct(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_packet(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_packet"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_packet(struct pt_regs *ctx)
{
    return handle_exit(ctx, 52);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_packet"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_packet(struct pt_regs *ctx)
{
    context_info_t info = {.func = 52, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 52))
        return 0;
    handle_entry_finish(&info, fake__tcp_packet(&info));
    return 0;
}
static inline int fake__tcp_packet(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____nf_ct_refresh_acct(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__nf_ct_refresh_acct"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___nf_ct_refresh_acct(struct pt_regs *ctx)
{
    return handle_exit(ctx, 54);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__nf_ct_refresh_acct"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___nf_ct_refresh_acct(struct pt_regs *ctx)
{
    context_info_t info = {.func = 54, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 54))
        return 0;
    handle_entry_finish(&info, fake____nf_ct_refresh_acct(&info));
    return 0;
}
static inline int fake____nf_ct_refresh_acct(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 55);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 55, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 55))
        return 0;
    handle_entry_finish(&info, fake__ip_rcv(&info));
    return 0;
}
static inline int fake__ip_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_rcv_core(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_rcv_core"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_rcv_core(struct pt_regs *ctx)
{
    return handle_exit(ctx, 56);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_rcv_core"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_rcv_core(struct pt_regs *ctx)
{
    context_info_t info = {.func = 56, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 56))
        return 0;
    handle_entry_finish(&info, fake__ip_rcv_core(&info));
    return 0;
}
static inline int fake__ip_rcv_core(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_rcv_finish(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_rcv_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_rcv_finish(struct pt_regs *ctx)
{
    return handle_exit(ctx, 57);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_rcv_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_rcv_finish(struct pt_regs *ctx)
{
    context_info_t info = {.func = 57, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 57))
        return 0;
    handle_entry_finish(&info, fake__ip_rcv_finish(&info));
    return 0;
}
static inline int fake__ip_rcv_finish(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_local_deliver(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_local_deliver"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_local_deliver(struct pt_regs *ctx)
{
    return handle_exit(ctx, 58);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_local_deliver"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_local_deliver(struct pt_regs *ctx)
{
    context_info_t info = {.func = 58, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 58))
        return 0;
    handle_entry_finish(&info, fake__ip_local_deliver(&info));
    return 0;
}
static inline int fake__ip_local_deliver(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_local_deliver_finish(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_local_deliver_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_local_deliver_finish(struct pt_regs *ctx)
{
    return handle_exit(ctx, 59);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_local_deliver_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_local_deliver_finish(struct pt_regs *ctx)
{
    context_info_t info = {.func = 59, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 59))
        return 0;
    handle_entry_finish(&info, fake__ip_local_deliver_finish(&info));
    return 0;
}
static inline int fake__ip_local_deliver_finish(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_forward(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_forward"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_forward(struct pt_regs *ctx)
{
    return handle_exit(ctx, 60);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_forward"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_forward(struct pt_regs *ctx)
{
    context_info_t info = {.func = 60, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 60))
        return 0;
    handle_entry_finish(&info, fake__ip_forward(&info));
    return 0;
}
static inline int fake__ip_forward(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_forward_finish(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_forward_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_forward_finish(struct pt_regs *ctx)
{
    return handle_exit(ctx, 61);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_forward_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_forward_finish(struct pt_regs *ctx)
{
    context_info_t info = {.func = 61, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 61))
        return 0;
    handle_entry_finish(&info, fake__ip_forward_finish(&info));
    return 0;
}
static inline int fake__ip_forward_finish(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_forward(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_forward"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_forward(struct pt_regs *ctx)
{
    return handle_exit(ctx, 62);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_forward"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_forward(struct pt_regs *ctx)
{
    context_info_t info = {.func = 62, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 62))
        return 0;
    handle_entry_finish(&info, fake__ip6_forward(&info));
    return 0;
}
static inline int fake__ip6_forward(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_rcv_finish(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_rcv_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_rcv_finish(struct pt_regs *ctx)
{
    return handle_exit(ctx, 63);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_rcv_finish"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_rcv_finish(struct pt_regs *ctx)
{
    context_info_t info = {.func = 63, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 63))
        return 0;
    handle_entry_finish(&info, fake__ip6_rcv_finish(&info));
    return 0;
}
static inline int fake__ip6_rcv_finish(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_rcv_core(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_rcv_core"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_rcv_core(struct pt_regs *ctx)
{
    return handle_exit(ctx, 64);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_rcv_core"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_rcv_core(struct pt_regs *ctx)
{
    context_info_t info = {.func = 64, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 64))
        return 0;
    handle_entry_finish(&info, fake__ip6_rcv_core(&info));
    return 0;
}
static inline int fake__ip6_rcv_core(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ipv6_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ipv6_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ipv6_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 65);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ipv6_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ipv6_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 65, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 65))
        return 0;
    handle_entry_finish(&info, fake__ipv6_rcv(&info));
    return 0;
}
static inline int fake__ipv6_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____ip_queue_xmit(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__ip_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___ip_queue_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 66);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__ip_queue_xmit"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___ip_queue_xmit(struct pt_regs *ctx)
{
    context_info_t info = {.func = 66, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 66))
        return 0;
    handle_entry_finish(&info, fake____ip_queue_xmit(&info));
    return 0;
}
static inline int fake____ip_queue_xmit(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____ip_local_out(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__ip_local_out"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___ip_local_out(struct pt_regs *ctx)
{
    return handle_exit(ctx, 67);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__ip_local_out"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___ip_local_out(struct pt_regs *ctx)
{
    context_info_t info = {.func = 67, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[1])};
    if (pre_handle_entry(&info, 67))
        return 0;
    handle_entry_finish(&info, fake____ip_local_out(&info));
    return 0;
}
static inline int fake____ip_local_out(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 68);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 68, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 68))
        return 0;
    handle_entry_finish(&info, fake__ip_output(&info));
    return 0;
}
static inline int fake__ip_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_finish_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_finish_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_finish_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 69);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_finish_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_finish_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 69, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 69))
        return 0;
    handle_entry_finish(&info, fake__ip_finish_output(&info));
    return 0;
}
static inline int fake__ip_finish_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_finish_output_gso(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_finish_output_gso"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_finish_output_gso(struct pt_regs *ctx)
{
    return handle_exit(ctx, 70);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_finish_output_gso"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_finish_output_gso(struct pt_regs *ctx)
{
    context_info_t info = {.func = 70, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 70))
        return 0;
    handle_entry_finish(&info, fake__ip_finish_output_gso(&info));
    return 0;
}
static inline int fake__ip_finish_output_gso(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_finish_output2(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_finish_output2"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_finish_output2(struct pt_regs *ctx)
{
    return handle_exit(ctx, 71);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_finish_output2"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_finish_output2(struct pt_regs *ctx)
{
    context_info_t info = {.func = 71, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 71))
        return 0;
    handle_entry_finish(&info, fake__ip_finish_output2(&info));
    return 0;
}
static inline int fake__ip_finish_output2(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 72);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 72, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 72))
        return 0;
    handle_entry_finish(&info, fake__ip6_output(&info));
    return 0;
}
static inline int fake__ip6_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_finish_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_finish_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_finish_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 73);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_finish_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_finish_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 73, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 73))
        return 0;
    handle_entry_finish(&info, fake__ip6_finish_output(&info));
    return 0;
}
static inline int fake__ip6_finish_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_finish_output2(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_finish_output2"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_finish_output2(struct pt_regs *ctx)
{
    return handle_exit(ctx, 74);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_finish_output2"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_finish_output2(struct pt_regs *ctx)
{
    context_info_t info = {.func = 74, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 74))
        return 0;
    handle_entry_finish(&info, fake__ip6_finish_output2(&info));
    return 0;
}
static inline int fake__ip6_finish_output2(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_send_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_send_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_send_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 75);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_send_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_send_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 75, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 75))
        return 0;
    handle_entry_finish(&info, fake__ip6_send_skb(&info));
    return 0;
}
static inline int fake__ip6_send_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip6_local_out(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip6_local_out"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip6_local_out(struct pt_regs *ctx)
{
    return handle_exit(ctx, 76);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip6_local_out"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip6_local_out(struct pt_regs *ctx)
{
    context_info_t info = {.func = 76, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 76))
        return 0;
    handle_entry_finish(&info, fake__ip6_local_out(&info));
    return 0;
}
static inline int fake__ip6_local_out(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 77);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 77, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 77))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_output(&info));
    return 0;
}
static inline int fake__xfrm4_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 78);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 78, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 78))
        return 0;
    handle_entry_finish(&info, fake__xfrm_output(&info));
    return 0;
}
static inline int fake__xfrm_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm_output2(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm_output2"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm_output2(struct pt_regs *ctx)
{
    return handle_exit(ctx, 79);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm_output2"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm_output2(struct pt_regs *ctx)
{
    context_info_t info = {.func = 79, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 79))
        return 0;
    handle_entry_finish(&info, fake__xfrm_output2(&info));
    return 0;
}
static inline int fake__xfrm_output2(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm_output_gso(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm_output_gso"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm_output_gso(struct pt_regs *ctx)
{
    return handle_exit(ctx, 80);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm_output_gso"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm_output_gso(struct pt_regs *ctx)
{
    context_info_t info = {.func = 80, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 80))
        return 0;
    handle_entry_finish(&info, fake__xfrm_output_gso(&info));
    return 0;
}
static inline int fake__xfrm_output_gso(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm_output_resume(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm_output_resume"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm_output_resume(struct pt_regs *ctx)
{
    return handle_exit(ctx, 81);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm_output_resume"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm_output_resume(struct pt_regs *ctx)
{
    context_info_t info = {.func = 81, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 81))
        return 0;
    handle_entry_finish(&info, fake__xfrm_output_resume(&info));
    return 0;
}
static inline int fake__xfrm_output_resume(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_transport_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_transport_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_transport_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 82);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_transport_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_transport_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 82, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 82))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_transport_output(&info));
    return 0;
}
static inline int fake__xfrm4_transport_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_prepare_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_prepare_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_prepare_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 83);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_prepare_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_prepare_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 83, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 83))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_prepare_output(&info));
    return 0;
}
static inline int fake__xfrm4_prepare_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_policy_check(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_policy_check"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_policy_check(struct pt_regs *ctx)
{
    return handle_exit(ctx, 84);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_policy_check"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_policy_check(struct pt_regs *ctx)
{
    context_info_t info = {.func = 84, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 84))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_policy_check(&info));
    return 0;
}
static inline int fake__xfrm4_policy_check(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 85);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 85, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 85))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_rcv(&info));
    return 0;
}
static inline int fake__xfrm4_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm_input(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm_input(struct pt_regs *ctx)
{
    return handle_exit(ctx, 86);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm_input(struct pt_regs *ctx)
{
    context_info_t info = {.func = 86, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 86))
        return 0;
    handle_entry_finish(&info, fake__xfrm_input(&info));
    return 0;
}
static inline int fake__xfrm_input(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_transport_input(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_transport_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_transport_input(struct pt_regs *ctx)
{
    return handle_exit(ctx, 87);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_transport_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_transport_input(struct pt_regs *ctx)
{
    context_info_t info = {.func = 87, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 87))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_transport_input(&info));
    return 0;
}
static inline int fake__xfrm4_transport_input(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ah_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ah_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ah_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 88);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ah_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ah_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 88, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 88))
        return 0;
    handle_entry_finish(&info, fake__ah_output(&info));
    return 0;
}
static inline int fake__ah_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__esp_output(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "esp_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_esp_output(struct pt_regs *ctx)
{
    return handle_exit(ctx, 89);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "esp_output"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_esp_output(struct pt_regs *ctx)
{
    context_info_t info = {.func = 89, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 89))
        return 0;
    handle_entry_finish(&info, fake__esp_output(&info));
    return 0;
}
static inline int fake__esp_output(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__esp_output_tail(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "esp_output_tail"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_esp_output_tail(struct pt_regs *ctx)
{
    return handle_exit(ctx, 90);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "esp_output_tail"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_esp_output_tail(struct pt_regs *ctx)
{
    context_info_t info = {.func = 90, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 90))
        return 0;
    handle_entry_finish(&info, fake__esp_output_tail(&info));
    return 0;
}
static inline int fake__esp_output_tail(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ah_input(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ah_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ah_input(struct pt_regs *ctx)
{
    return handle_exit(ctx, 91);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ah_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ah_input(struct pt_regs *ctx)
{
    context_info_t info = {.func = 91, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 91))
        return 0;
    handle_entry_finish(&info, fake__ah_input(&info));
    return 0;
}
static inline int fake__ah_input(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__esp_input(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "esp_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_esp_input(struct pt_regs *ctx)
{
    return handle_exit(ctx, 92);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "esp_input"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_esp_input(struct pt_regs *ctx)
{
    context_info_t info = {.func = 92, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 92))
        return 0;
    handle_entry_finish(&info, fake__esp_input(&info));
    return 0;
}
static inline int fake__esp_input(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__fib_validate_source(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "fib_validate_source"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_fib_validate_source(struct pt_regs *ctx)
{
    return handle_exit(ctx, 93);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "fib_validate_source"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_fib_validate_source(struct pt_regs *ctx)
{
    context_info_t info = {.func = 93, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 93))
        return 0;
    handle_entry_finish(&info, fake__fib_validate_source(&info));
    return 0;
}
static inline int fake__fib_validate_source(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ip_route_input_slow(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ip_route_input_slow"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ip_route_input_slow(struct pt_regs *ctx)
{
    return handle_exit(ctx, 94);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ip_route_input_slow"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ip_route_input_slow(struct pt_regs *ctx)
{
    context_info_t info = {.func = 94, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 94))
        return 0;
    handle_entry_finish(&info, fake__ip_route_input_slow(&info));
    return 0;
}
static inline int fake__ip_route_input_slow(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_v4_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v4_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_v4_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 95);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v4_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_v4_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 95, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 95))
        return 0;
    handle_entry_finish(&info, fake__tcp_v4_rcv(&info));
    return 0;
}
static inline int fake__tcp_v4_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_v6_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v6_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_v6_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 96);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v6_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_v6_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 96, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 96))
        return 0;
    handle_entry_finish(&info, fake__tcp_v6_rcv(&info));
    return 0;
}
static inline int fake__tcp_v6_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_filter(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_filter"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_filter(struct pt_regs *ctx)
{
    return handle_exit(ctx, 97);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_filter"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_filter(struct pt_regs *ctx)
{
    context_info_t info = {.func = 97, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 97))
        return 0;
    handle_entry_finish(&info, fake__tcp_filter(&info));
    return 0;
}
static inline int fake__tcp_filter(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_child_process(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_child_process"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_child_process(struct pt_regs *ctx)
{
    return handle_exit(ctx, 98);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_child_process"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_child_process(struct pt_regs *ctx)
{
    context_info_t info = {.func = 98, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 98))
        return 0;
    handle_entry_finish(&info, fake__tcp_child_process(&info));
    return 0;
}
static inline int fake__tcp_child_process(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_v4_do_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v4_do_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_v4_do_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 101);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v4_do_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_v4_do_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 101, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 101))
        return 0;
    handle_entry_finish(&info, fake__tcp_v4_do_rcv(&info));
    return 0;
}
static inline int fake__tcp_v4_do_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_v6_do_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v6_do_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_v6_do_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 102);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v6_do_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_v6_do_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 102, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 102))
        return 0;
    handle_entry_finish(&info, fake__tcp_v6_do_rcv(&info));
    return 0;
}
static inline int fake__tcp_v6_do_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_rcv_established(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_rcv_established"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_rcv_established(struct pt_regs *ctx)
{
    return handle_exit(ctx, 103);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_rcv_established"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_rcv_established(struct pt_regs *ctx)
{
    context_info_t info = {.func = 103, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 103))
        return 0;
    handle_entry_finish(&info, fake__tcp_rcv_established(&info));
    return 0;
}
static inline int fake__tcp_rcv_established(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_rcv_state_process(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_rcv_state_process"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_rcv_state_process(struct pt_regs *ctx)
{
    return handle_exit(ctx, 104);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_rcv_state_process"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_rcv_state_process(struct pt_regs *ctx)
{
    context_info_t info = {.func = 104, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 104))
        return 0;
    handle_entry_finish(&info, fake__tcp_rcv_state_process(&info));
    return 0;
}
static inline int fake__tcp_rcv_state_process(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_queue_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_queue_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_queue_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 105);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_queue_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_queue_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 105, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 105))
        return 0;
    handle_entry_finish(&info, fake__tcp_queue_rcv(&info));
    return 0;
}
static inline int fake__tcp_queue_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_data_queue_ofo(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_data_queue_ofo"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_data_queue_ofo(struct pt_regs *ctx)
{
    return handle_exit(ctx, 106);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_data_queue_ofo"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_data_queue_ofo(struct pt_regs *ctx)
{
    context_info_t info = {.func = 106, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 106))
        return 0;
    handle_entry_finish(&info, fake__tcp_data_queue_ofo(&info));
    return 0;
}
static inline int fake__tcp_data_queue_ofo(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_ack_probe(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_ack_probe"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_ack_probe(struct pt_regs *ctx)
{
    return handle_exit(ctx, 107);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_ack_probe"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_ack_probe(struct pt_regs *ctx)
{
    context_info_t info = {.func = 107, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 107))
        return 0;
    handle_entry_finish(&info, fake__tcp_ack_probe(&info));
    return 0;
}
static inline int fake__tcp_ack_probe(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_ack(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_ack"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_ack(struct pt_regs *ctx)
{
    return handle_exit(ctx, 108);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_ack"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_ack(struct pt_regs *ctx)
{
    context_info_t info = {.func = 108, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 108))
        return 0;
    handle_entry_finish(&info, fake__tcp_ack(&info));
    return 0;
}
static inline int fake__tcp_ack(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_probe_timer(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_probe_timer"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_probe_timer(struct pt_regs *ctx)
{
    return handle_exit(ctx, 109);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_probe_timer"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_probe_timer(struct pt_regs *ctx)
{
    context_info_t info = {.func = 109, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 109))
        return 0;
    handle_entry_finish(&info, fake__tcp_probe_timer(&info));
    return 0;
}
static inline int fake__tcp_probe_timer(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_send_probe0(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_send_probe0"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_send_probe0(struct pt_regs *ctx)
{
    return handle_exit(ctx, 110);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_send_probe0"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_send_probe0(struct pt_regs *ctx)
{
    context_info_t info = {.func = 110, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 110))
        return 0;
    handle_entry_finish(&info, fake__tcp_send_probe0(&info));
    return 0;
}
static inline int fake__tcp_send_probe0(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____inet_lookup_listener(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__inet_lookup_listener"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___inet_lookup_listener(struct pt_regs *ctx)
{
    return handle_exit(ctx, 111);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__inet_lookup_listener"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___inet_lookup_listener(struct pt_regs *ctx)
{
    context_info_t info = {.func = 111, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 111))
        return 0;
    handle_entry_finish(&info, fake____inet_lookup_listener(&info));
    return 0;
}
static inline int fake____inet_lookup_listener(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__inet6_lookup_listener(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "inet6_lookup_listener"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_inet6_lookup_listener(struct pt_regs *ctx)
{
    return handle_exit(ctx, 112);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "inet6_lookup_listener"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_inet6_lookup_listener(struct pt_regs *ctx)
{
    context_info_t info = {.func = 112, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[2]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 112))
        return 0;
    handle_entry_finish(&info, fake__inet6_lookup_listener(&info));
    return 0;
}
static inline int fake__inet6_lookup_listener(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_bad_csum(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("tp/"
                       "tcp"
                       "/"
                       "tcp_bad_csum"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_bad_csum(void *ctx)
{
    context_info_t info = {.func = 113, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 8))};
    if (pre_handle_entry(&info, 113))
        return 0;
    handle_entry_finish(&info, fake__tcp_bad_csum(&info));
    return 0;
}
static inline int fake__tcp_bad_csum(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_sendmsg_locked(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_sendmsg_locked"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_sendmsg_locked(struct pt_regs *ctx)
{
    return handle_exit(ctx, 114);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_sendmsg_locked"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_sendmsg_locked(struct pt_regs *ctx)
{
    context_info_t info = {.func = 114, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 114))
        return 0;
    handle_entry_finish(&info, fake__tcp_sendmsg_locked(&info));
    return 0;
}
static inline int fake__tcp_sendmsg_locked(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_skb_entail(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_skb_entail"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_skb_entail(struct pt_regs *ctx)
{
    return handle_exit(ctx, 115);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_skb_entail"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_skb_entail(struct pt_regs *ctx)
{
    context_info_t info = {.func = 115, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 115))
        return 0;
    handle_entry_finish(&info, fake__tcp_skb_entail(&info));
    return 0;
}
static inline int fake__tcp_skb_entail(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__skb_entail(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "skb_entail"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_skb_entail(struct pt_regs *ctx)
{
    return handle_exit(ctx, 116);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "skb_entail"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_skb_entail(struct pt_regs *ctx)
{
    context_info_t info = {.func = 116, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 116))
        return 0;
    handle_entry_finish(&info, fake__skb_entail(&info));
    return 0;
}
static inline int fake__skb_entail(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____tcp_push_pending_frames(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__tcp_push_pending_frames"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___tcp_push_pending_frames(struct pt_regs *ctx)
{
    return handle_exit(ctx, 117);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__tcp_push_pending_frames"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___tcp_push_pending_frames(struct pt_regs *ctx)
{
    context_info_t info = {.func = 117, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 117))
        return 0;
    handle_entry_finish(&info, fake____tcp_push_pending_frames(&info));
    return 0;
}
static inline int fake____tcp_push_pending_frames(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____tcp_transmit_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__tcp_transmit_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___tcp_transmit_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 118);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__tcp_transmit_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___tcp_transmit_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 118, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 118))
        return 0;
    handle_entry_finish(&info, fake____tcp_transmit_skb(&info));
    return 0;
}
static inline int fake____tcp_transmit_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____tcp_retransmit_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__tcp_retransmit_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___tcp_retransmit_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 119);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__tcp_retransmit_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___tcp_retransmit_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 119, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 119))
        return 0;
    handle_entry_finish(&info, fake____tcp_retransmit_skb(&info));
    return 0;
}
static inline int fake____tcp_retransmit_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_rate_skb_delivered(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_rate_skb_delivered"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_rate_skb_delivered(struct pt_regs *ctx)
{
    return handle_exit(ctx, 120);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_rate_skb_delivered"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_rate_skb_delivered(struct pt_regs *ctx)
{
    context_info_t info = {.func = 120, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 120))
        return 0;
    handle_entry_finish(&info, fake__tcp_rate_skb_delivered(&info));
    return 0;
}
static inline int fake__tcp_rate_skb_delivered(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__udp_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "udp_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_udp_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 121);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "udp_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_udp_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 121, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 121))
        return 0;
    handle_entry_finish(&info, fake__udp_rcv(&info));
    return 0;
}
static inline int fake__udp_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__udp_unicast_rcv_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "udp_unicast_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_udp_unicast_rcv_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 122);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "udp_unicast_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_udp_unicast_rcv_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 122, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 122))
        return 0;
    handle_entry_finish(&info, fake__udp_unicast_rcv_skb(&info));
    return 0;
}
static inline int fake__udp_unicast_rcv_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__udp_queue_rcv_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "udp_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_udp_queue_rcv_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 123);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "udp_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_udp_queue_rcv_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 123, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 123))
        return 0;
    handle_entry_finish(&info, fake__udp_queue_rcv_skb(&info));
    return 0;
}
static inline int fake__udp_queue_rcv_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_udp_encap_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_udp_encap_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_udp_encap_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 124);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_udp_encap_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_udp_encap_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 124, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 124))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_udp_encap_rcv(&info));
    return 0;
}
static inline int fake__xfrm4_udp_encap_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__xfrm4_rcv_encap(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "xfrm4_rcv_encap"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_xfrm4_rcv_encap(struct pt_regs *ctx)
{
    return handle_exit(ctx, 125);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "xfrm4_rcv_encap"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_xfrm4_rcv_encap(struct pt_regs *ctx)
{
    context_info_t info = {.func = 125, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 125))
        return 0;
    handle_entry_finish(&info, fake__xfrm4_rcv_encap(&info));
    return 0;
}
static inline int fake__xfrm4_rcv_encap(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____udp_queue_rcv_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__udp_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___udp_queue_rcv_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 126);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__udp_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___udp_queue_rcv_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 126, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 126))
        return 0;
    handle_entry_finish(&info, fake____udp_queue_rcv_skb(&info));
    return 0;
}
static inline int fake____udp_queue_rcv_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____udp_enqueue_schedule_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__udp_enqueue_schedule_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___udp_enqueue_schedule_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 127);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__udp_enqueue_schedule_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___udp_enqueue_schedule_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 127, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 127))
        return 0;
    handle_entry_finish(&info, fake____udp_enqueue_schedule_skb(&info));
    return 0;
}
static inline int fake____udp_enqueue_schedule_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__icmp_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "icmp_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_icmp_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 128);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "icmp_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_icmp_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 128, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 128))
        return 0;
    handle_entry_finish(&info, fake__icmp_rcv(&info));
    return 0;
}
static inline int fake__icmp_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__icmp_echo(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "icmp_echo"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_icmp_echo(struct pt_regs *ctx)
{
    return handle_exit(ctx, 129);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "icmp_echo"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_icmp_echo(struct pt_regs *ctx)
{
    context_info_t info = {.func = 129, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 129))
        return 0;
    handle_entry_finish(&info, fake__icmp_echo(&info));
    return 0;
}
static inline int fake__icmp_echo(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__icmp_reply(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "icmp_reply"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_icmp_reply(struct pt_regs *ctx)
{
    return handle_exit(ctx, 130);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "icmp_reply"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_icmp_reply(struct pt_regs *ctx)
{
    context_info_t info = {.func = 130, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 130))
        return 0;
    handle_entry_finish(&info, fake__icmp_reply(&info));
    return 0;
}
static inline int fake__icmp_reply(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__icmpv6_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "icmpv6_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_icmpv6_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 131);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "icmpv6_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_icmpv6_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 131, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 131))
        return 0;
    handle_entry_finish(&info, fake__icmpv6_rcv(&info));
    return 0;
}
static inline int fake__icmpv6_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__icmpv6_echo_reply(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "icmpv6_echo_reply"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_icmpv6_echo_reply(struct pt_regs *ctx)
{
    return handle_exit(ctx, 132);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "icmpv6_echo_reply"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_icmpv6_echo_reply(struct pt_regs *ctx)
{
    context_info_t info = {.func = 132, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 132))
        return 0;
    handle_entry_finish(&info, fake__icmpv6_echo_reply(&info));
    return 0;
}
static inline int fake__icmpv6_echo_reply(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ping_rcv(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ping_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ping_rcv(struct pt_regs *ctx)
{
    return handle_exit(ctx, 133);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ping_rcv"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ping_rcv(struct pt_regs *ctx)
{
    context_info_t info = {.func = 133, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 133))
        return 0;
    handle_entry_finish(&info, fake__ping_rcv(&info));
    return 0;
}
static inline int fake__ping_rcv(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____ping_queue_rcv_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__ping_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___ping_queue_rcv_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 134);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__ping_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___ping_queue_rcv_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 134, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 134))
        return 0;
    handle_entry_finish(&info, fake____ping_queue_rcv_skb(&info));
    return 0;
}
static inline int fake____ping_queue_rcv_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ping_queue_rcv_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ping_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ping_queue_rcv_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 135);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ping_queue_rcv_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ping_queue_rcv_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 135, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 135))
        return 0;
    handle_entry_finish(&info, fake__ping_queue_rcv_skb(&info));
    return 0;
}
static inline int fake__ping_queue_rcv_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__ping_lookup(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "ping_lookup"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_ping_lookup(struct pt_regs *ctx)
{
    return handle_exit(ctx, 136);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "ping_lookup"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_ping_lookup(struct pt_regs *ctx)
{
    context_info_t info = {.func = 136, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 136))
        return 0;
    handle_entry_finish(&info, fake__ping_lookup(&info));
    return 0;
}
static inline int fake__ping_lookup(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_v4_destroy_sock(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v4_destroy_sock"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_v4_destroy_sock(struct pt_regs *ctx)
{
    return handle_exit(ctx, 138);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v4_destroy_sock"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_v4_destroy_sock(struct pt_regs *ctx)
{
    context_info_t info = {.func = 138, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 138))
        return 0;
    handle_entry_finish(&info, fake__tcp_v4_destroy_sock(&info));
    return 0;
}
static inline int fake__tcp_v4_destroy_sock(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_close(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_close"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_close(struct pt_regs *ctx)
{
    return handle_exit(ctx, 139);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_close"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_close(struct pt_regs *ctx)
{
    context_info_t info = {.func = 139, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 139))
        return 0;
    handle_entry_finish(&info, fake__tcp_close(&info));
    return 0;
}
static inline int fake__tcp_close(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_write_timer_handler(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_write_timer_handler"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_write_timer_handler(struct pt_regs *ctx)
{
    return handle_exit(ctx, 142);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_write_timer_handler"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_write_timer_handler(struct pt_regs *ctx)
{
    context_info_t info = {.func = 142, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 142))
        return 0;
    handle_entry_finish(&info, fake__tcp_write_timer_handler(&info));
    return 0;
}
static inline int fake__tcp_write_timer_handler(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_retransmit_timer(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_retransmit_timer"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_retransmit_timer(struct pt_regs *ctx)
{
    return handle_exit(ctx, 143);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_retransmit_timer"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_retransmit_timer(struct pt_regs *ctx)
{
    context_info_t info = {.func = 143, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 143))
        return 0;
    handle_entry_finish(&info, fake__tcp_retransmit_timer(&info));
    return 0;
}
static inline int fake__tcp_retransmit_timer(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_enter_recovery(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_enter_recovery"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_enter_recovery(struct pt_regs *ctx)
{
    return handle_exit(ctx, 144);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_enter_recovery"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_enter_recovery(struct pt_regs *ctx)
{
    context_info_t info = {.func = 144, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 144))
        return 0;
    handle_entry_finish(&info, fake__tcp_enter_recovery(&info));
    return 0;
}
static inline int fake__tcp_enter_recovery(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_enter_loss(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_enter_loss"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_enter_loss(struct pt_regs *ctx)
{
    return handle_exit(ctx, 145);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_enter_loss"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_enter_loss(struct pt_regs *ctx)
{
    context_info_t info = {.func = 145, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 145))
        return 0;
    handle_entry_finish(&info, fake__tcp_enter_loss(&info));
    return 0;
}
static inline int fake__tcp_enter_loss(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_try_keep_open(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_try_keep_open"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_try_keep_open(struct pt_regs *ctx)
{
    return handle_exit(ctx, 146);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_try_keep_open"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_try_keep_open(struct pt_regs *ctx)
{
    context_info_t info = {.func = 146, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 146))
        return 0;
    handle_entry_finish(&info, fake__tcp_try_keep_open(&info));
    return 0;
}
static inline int fake__tcp_try_keep_open(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_enter_cwr(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_enter_cwr"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_enter_cwr(struct pt_regs *ctx)
{
    return handle_exit(ctx, 147);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_enter_cwr"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_enter_cwr(struct pt_regs *ctx)
{
    context_info_t info = {.func = 147, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 147))
        return 0;
    handle_entry_finish(&info, fake__tcp_enter_cwr(&info));
    return 0;
}
static inline int fake__tcp_enter_cwr(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_fastretrans_alert(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_fastretrans_alert"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_fastretrans_alert(struct pt_regs *ctx)
{
    return handle_exit(ctx, 148);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_fastretrans_alert"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_fastretrans_alert(struct pt_regs *ctx)
{
    context_info_t info = {.func = 148, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 148))
        return 0;
    handle_entry_finish(&info, fake__tcp_fastretrans_alert(&info));
    return 0;
}
static inline int fake__tcp_fastretrans_alert(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_rearm_rto(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_rearm_rto"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_rearm_rto(struct pt_regs *ctx)
{
    return handle_exit(ctx, 149);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_rearm_rto"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_rearm_rto(struct pt_regs *ctx)
{
    context_info_t info = {.func = 149, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 149))
        return 0;
    handle_entry_finish(&info, fake__tcp_rearm_rto(&info));
    return 0;
}
static inline int fake__tcp_rearm_rto(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_event_new_data_sent(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_event_new_data_sent"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_event_new_data_sent(struct pt_regs *ctx)
{
    return handle_exit(ctx, 150);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_event_new_data_sent"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_event_new_data_sent(struct pt_regs *ctx)
{
    context_info_t info = {.func = 150, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 150))
        return 0;
    handle_entry_finish(&info, fake__tcp_event_new_data_sent(&info));
    return 0;
}
static inline int fake__tcp_event_new_data_sent(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_schedule_loss_probe(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_schedule_loss_probe"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_schedule_loss_probe(struct pt_regs *ctx)
{
    return handle_exit(ctx, 151);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_schedule_loss_probe"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_schedule_loss_probe(struct pt_regs *ctx)
{
    context_info_t info = {.func = 151, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 151))
        return 0;
    handle_entry_finish(&info, fake__tcp_schedule_loss_probe(&info));
    return 0;
}
static inline int fake__tcp_schedule_loss_probe(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_rtx_synack(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_rtx_synack"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_rtx_synack(struct pt_regs *ctx)
{
    return handle_exit(ctx, 152);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_rtx_synack"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_rtx_synack(struct pt_regs *ctx)
{
    context_info_t info = {.func = 152, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 152))
        return 0;
    handle_entry_finish(&info, fake__tcp_rtx_synack(&info));
    return 0;
}
static inline int fake__tcp_rtx_synack(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_retransmit_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_retransmit_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_retransmit_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 153);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_retransmit_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_retransmit_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 153, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 153))
        return 0;
    handle_entry_finish(&info, fake__tcp_retransmit_skb(&info));
    return 0;
}
static inline int fake__tcp_retransmit_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_rcv_spurious_retrans(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_rcv_spurious_retrans"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_rcv_spurious_retrans(struct pt_regs *ctx)
{
    return handle_exit(ctx, 154);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_rcv_spurious_retrans"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_rcv_spurious_retrans(struct pt_regs *ctx)
{
    context_info_t info = {.func = 154, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1]), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 154))
        return 0;
    handle_entry_finish(&info, fake__tcp_rcv_spurious_retrans(&info));
    return 0;
}
static inline int fake__tcp_rcv_spurious_retrans(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__tcp_dsack_set(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_dsack_set"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_tcp_dsack_set(struct pt_regs *ctx)
{
    return handle_exit(ctx, 155);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_dsack_set"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_tcp_dsack_set(struct pt_regs *ctx)
{
    context_info_t info = {.func = 155, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = ((void *)0), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 155))
        return 0;
    handle_entry_finish(&info, fake__tcp_dsack_set(&info));
    return 0;
}
static inline int fake__tcp_dsack_set(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__skb_clone(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "skb_clone"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_skb_clone(struct pt_regs *ctx)
{
    return handle_exit(ctx, 156);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "skb_clone"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_skb_clone(struct pt_regs *ctx)
{
    context_info_t info = {.func = 156, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 156))
        return 0;
    handle_entry_finish(&info, fake__skb_clone(&info));
    return 0;
}
static inline int fake__skb_clone(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__consume_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("tp/"
                       "skb"
                       "/"
                       "consume_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_consume_skb(void *ctx)
{
    context_info_t info = {.func = 157, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 8))};
    if (pre_handle_entry(&info, 157))
        return 0;
    handle_entry_finish(&info, fake__consume_skb(&info));
    return 0;
}
static inline int fake__consume_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake____kfree_skb(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "__kfree_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace___kfree_skb(struct pt_regs *ctx)
{
    return handle_exit(ctx, 159);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "__kfree_skb"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace___kfree_skb(struct pt_regs *ctx)
{
    context_info_t info = {.func = 159, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 159))
        return 0;
    handle_entry_finish(&info, fake____kfree_skb(&info));
    return 0;
}
static inline int fake____kfree_skb(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__kfree_skb_partial(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "kfree_skb_partial"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_kfree_skb_partial(struct pt_regs *ctx)
{
    return handle_exit(ctx, 160);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "kfree_skb_partial"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_kfree_skb_partial(struct pt_regs *ctx)
{
    context_info_t info = {.func = 160, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 160))
        return 0;
    handle_entry_finish(&info, fake__kfree_skb_partial(&info));
    return 0;
}
static inline int fake__kfree_skb_partial(context_info_t *info) { return default_handle_entry(info); }
static inline int fake__skb_attempt_defer_free(context_info_t *info);
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kretprobe/"
                       "skb_attempt_defer_free"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int ret__trace_skb_attempt_defer_free(struct pt_regs *ctx)
{
    return handle_exit(ctx, 161);
}
# 509 "./core.c"
#pragma GCC diagnostic push
# 509 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 509 "./core.c"
__attribute__((section("kprobe/"
                       "skb_attempt_defer_free"),
               used))
# 509 "./core.c"
#pragma GCC diagnostic pop
# 509 "./core.c"
int __trace_skb_attempt_defer_free(struct pt_regs *ctx)
{
    context_info_t info = {.func = 161, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0]), .sk = ((void *)0)};
    if (pre_handle_entry(&info, 161))
        return 0;
    handle_entry_finish(&info, fake__skb_attempt_defer_free(&info));
    return 0;
}
static inline int fake__skb_attempt_defer_free(context_info_t *info) { return default_handle_entry(info); }
# 518 "./core.c"
static inline int fake__kfree_skb(context_info_t *info);
# 518 "./core.c"
#pragma GCC diagnostic push
# 518 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 518 "./core.c"
__attribute__((section("tp/"
                       "skb"
                       "/"
                       "kfree_skb"),
               used))
# 518 "./core.c"
#pragma GCC diagnostic pop
# 518 "./core.c"
int __trace_kfree_skb(void *ctx)
{
    context_info_t info = {.func = 158, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 8))};
    if (pre_handle_entry(&info, 158))
        return 0;
    handle_entry_finish(&info, fake__kfree_skb(&info));
    return 0;
}
static inline int fake__kfree_skb(context_info_t *info)
{
    int reason = 0;

    if (false)
    {
        if (false)
            reason = *(int *)((void *)(info->ctx) + 36);
        else
            reason = *(int *)((void *)(info->ctx) + 28);
    }
    else if (info->args->drop_reason)
    {

        reason = ({ typeof(*(int *)((void *)(info->ctx) + 28)) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&*(int *)((void *)(info->ctx) + 28)), &*(int *)((void *)(info->ctx) + 28)); ____tmp; });
    }

    pure_drop_event_t __attribute__((__unused__)) * e;
    drop_event_t __attribute__((__unused__)) __e;
    detail_drop_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_drop_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((drop_event_t *)0)->__event_filed));
    }

    e->location = *(u64 *)((void *)(info->ctx) + 16);
    e->reason = reason;

    return ({ int err = handle_entry(info); if (!err) do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); err; });
}

static inline int bpf_ipt_do_table(context_info_t *info, struct xt_table *table,
                                   u32 hook)
{
    char *table_name;
    pure_nf_event_t __attribute__((__unused__)) * e;
    nf_event_t __attribute__((__unused__)) __e;
    detail_nf_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_nf_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((nf_event_t *)0)->__event_filed));
    }

    e->hook = hook;
    if (false)
        table_name = ({ typeof((table)->name) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((table))))(((table))))->name); }); __r; });
    else
        table_name = ({ typeof(table->name) ____tmp; bpf_probe_read_kernel(&____tmp, sizeof(*&table->name), &table->name); ____tmp; });

    bpf_probe_read(e->table, sizeof(e->table) - 1, table_name);
    return ({ int err = handle_entry(info); if (!err) do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); err; });
}
# 566 "./core.c"
static inline int fake__ipt_do_table_legacy(context_info_t *info);
# 566 "./core.c"
#pragma GCC diagnostic push
# 566 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 566 "./core.c"
__attribute__((section("kretprobe/"
                       "ipt_do_table"),
               used))
# 566 "./core.c"
#pragma GCC diagnostic pop
# 566 "./core.c"
int ret__trace_ipt_do_table_legacy(struct pt_regs *ctx)
{
    return handle_exit(ctx, 43);
}
# 566 "./core.c"
#pragma GCC diagnostic push
# 566 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 566 "./core.c"
__attribute__((section("kprobe/"
                       "ipt_do_table"),
               used))
# 566 "./core.c"
#pragma GCC diagnostic pop
# 566 "./core.c"
int __trace_ipt_do_table_legacy(struct pt_regs *ctx)
{
    context_info_t info = {.func = 43, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 43))
        return 0;
    handle_entry_finish(&info, fake__ipt_do_table_legacy(&info));
    return 0;
}
static inline int fake__ipt_do_table_legacy(context_info_t *info)

{
    struct nf_hook_state *state = (u32)(((struct pt_regs *)info->ctx)->uregs[1]);
    struct xt_table *table = (u32)(((struct pt_regs *)info->ctx)->uregs[2]);

    return bpf_ipt_do_table(info, table, ({ typeof((state)->hook) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((state))))(((state))))->hook); }); __r; }));
}

static inline int fake__ipt_do_table(context_info_t *info);
# 576 "./core.c"
#pragma GCC diagnostic push
# 576 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 576 "./core.c"
__attribute__((section("kretprobe/"
                       "ipt_do_table"),
               used))
# 576 "./core.c"
#pragma GCC diagnostic pop
# 576 "./core.c"
int ret__trace_ipt_do_table(struct pt_regs *ctx)
{
    return handle_exit(ctx, 42);
}
# 576 "./core.c"
#pragma GCC diagnostic push
# 576 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 576 "./core.c"
__attribute__((section("kprobe/"
                       "ipt_do_table"),
               used))
# 576 "./core.c"
#pragma GCC diagnostic pop
# 576 "./core.c"
int __trace_ipt_do_table(struct pt_regs *ctx)
{
    context_info_t info = {.func = 42, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1])};
    if (pre_handle_entry(&info, 42))
        return 0;
    handle_entry_finish(&info, fake__ipt_do_table(&info));
    return 0;
}
static inline int fake__ipt_do_table(context_info_t *info)
{
    struct nf_hook_state *state = (u32)(((struct pt_regs *)info->ctx)->uregs[2]);
    struct xt_table *table = (u32)(((struct pt_regs *)info->ctx)->uregs[0]);

    return bpf_ipt_do_table(info, table, ({ typeof((state)->hook) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((state))))(((state))))->hook); }); __r; }));
}

static inline int fake__nf_hook_slow(context_info_t *info);
# 584 "./core.c"
#pragma GCC diagnostic push
# 584 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 584 "./core.c"
__attribute__((section("kretprobe/"
                       "nf_hook_slow"),
               used))
# 584 "./core.c"
#pragma GCC diagnostic pop
# 584 "./core.c"
int ret__trace_nf_hook_slow(struct pt_regs *ctx)
{
    return handle_exit(ctx, 41);
}
# 584 "./core.c"
#pragma GCC diagnostic push
# 584 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 584 "./core.c"
__attribute__((section("kprobe/"
                       "nf_hook_slow"),
               used))
# 584 "./core.c"
#pragma GCC diagnostic pop
# 584 "./core.c"
int __trace_nf_hook_slow(struct pt_regs *ctx)
{
    context_info_t info = {.func = 41, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 41))
        return 0;
    handle_entry_finish(&info, fake__nf_hook_slow(&info));
    return 0;
}
static inline int fake__nf_hook_slow(context_info_t *info)
{
    struct nf_hook_state *state;
    int err;

    state = (u32)(((struct pt_regs *)info->ctx)->uregs[1]);
    if (!info->args->hooks)
    {
        pure_nf_event_t __attribute__((__unused__)) * e;
        nf_event_t __attribute__((__unused__)) __e;
        detail_nf_event_t __detail_e = {0};
        info->e = (void *)&__detail_e;
        if (info->args->detail)
        {
            (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_nf_event_t *)0)->__event_filed));
        }
        else
        {
            (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((nf_event_t *)0)->__event_filed));
        }

        err = handle_entry(info);
        if (err)
            return err;

        e->hook = ({ typeof((state)->hook) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((state))))(((state))))->hook); }); __r; });
        e->pf = ({ typeof((state)->pf) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((state))))(((state))))->pf); }); __r; });
        do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e)));
        return 0;
    }
# 622 "./core.c"
    return 0;
}

static inline __attribute__((always_inline)) int
bpf_qdisc_handle(context_info_t *info, struct Qdisc *q)
{
    struct netdev_queue *txq;
    unsigned long start;
    pure_qdisc_event_t __attribute__((__unused__)) * e;
    qdisc_event_t __attribute__((__unused__)) __e;
    detail_qdisc_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_qdisc_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((qdisc_event_t *)0)->__event_filed));
    }

    txq = ({ typeof((q)->dev_queue) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((q))))(((q))))->dev_queue); }); __r; });

    if (false)
    {
        start = ({ typeof((txq)->trans_start) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((txq))))(((txq))))->trans_start); }); __r; });
        if (start)
            e->last_update = bpf_jiffies64() - start;
    }

    e->qlen = ({ typeof((&(q->q))->qlen) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((&(q->q)))))(((&(q->q)))))->qlen); }); __r; });
    e->state = ({ typeof((txq)->state) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((txq))))(((txq))))->state); }); __r; });
    e->flags = ({ typeof((q)->flags) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((q))))(((q))))->flags); }); __r; });

    return ({ int err = handle_entry(info); if (!err) do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); err; });
}

static inline int fake__qdisc_dequeue(context_info_t *info);
# 647 "./core.c"
#pragma GCC diagnostic push
# 647 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 647 "./core.c"
__attribute__((section("tp/"
                       "qdisc"
                       "/"
                       "qdisc_dequeue"),
               used))
# 647 "./core.c"
#pragma GCC diagnostic pop
# 647 "./core.c"
int __trace_qdisc_dequeue(void *ctx)
{
    context_info_t info = {.func = 14, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 32))};
    if (pre_handle_entry(&info, 14))
        return 0;
    handle_entry_finish(&info, fake__qdisc_dequeue(&info));
    return 0;
}
static inline int fake__qdisc_dequeue(context_info_t *info)
{
    struct Qdisc *q = *(struct Qdisc **)((void *)(info->ctx) + 8);
    return bpf_qdisc_handle(info, q);
}

static inline int fake__qdisc_enqueue(context_info_t *info);
# 653 "./core.c"
#pragma GCC diagnostic push
# 653 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 653 "./core.c"
__attribute__((section("tp/"
                       "qdisc"
                       "/"
                       "qdisc_enqueue"),
               used))
# 653 "./core.c"
#pragma GCC diagnostic pop
# 653 "./core.c"
int __trace_qdisc_enqueue(void *ctx)
{
    context_info_t info = {.func = 15, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .skb = (u32)(*(void **)(ctx + 24))};
    if (pre_handle_entry(&info, 15))
        return 0;
    handle_entry_finish(&info, fake__qdisc_enqueue(&info));
    return 0;
}
static inline int fake__qdisc_enqueue(context_info_t *info)
{
    struct Qdisc *q = *(struct Qdisc **)((void *)(info->ctx) + 8);
    return bpf_qdisc_handle(info, q);
}
# 722 "./core.c"
static inline int fake__tcp_v4_send_reset(context_info_t *info);
# 722 "./core.c"
#pragma GCC diagnostic push
# 722 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 722 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v4_send_reset"),
               used))
# 722 "./core.c"
#pragma GCC diagnostic pop
# 722 "./core.c"
int ret__trace_tcp_v4_send_reset(struct pt_regs *ctx)
{
    return handle_exit(ctx, 99);
}
# 722 "./core.c"
#pragma GCC diagnostic push
# 722 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 722 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v4_send_reset"),
               used))
# 722 "./core.c"
#pragma GCC diagnostic pop
# 722 "./core.c"
int __trace_tcp_v4_send_reset(struct pt_regs *ctx)
{
    context_info_t info = {.func = 99, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0]), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1])};
    if (pre_handle_entry(&info, 99))
        return 0;
    handle_entry_finish(&info, fake__tcp_v4_send_reset(&info));
    return 0;
}
static inline int fake__tcp_v4_send_reset(context_info_t *info)

{
    struct sock *sk = (u32)(((struct pt_regs *)info->ctx)->uregs[0]);
    struct sock_common skc_common = (
        {
            typeof((sk)->__sk_common) __r;
            ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->__sk_common); });
            __r;
        });
    pure_reset_event_t __attribute__((__unused__)) * e;
    reset_event_t __attribute__((__unused__)) __e;
    detail_reset_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_reset_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((reset_event_t *)0)->__event_filed));
    }

    e->state = skc_common.skc_state;
    e->reason = (u64)(u32)(((struct pt_regs *)info->ctx)->uregs[2]);

    return ({ int err = handle_entry(info); if (!err) do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); err; });
}

static inline int fake__tcp_v6_send_reset(context_info_t *info);
# 736 "./core.c"
#pragma GCC diagnostic push
# 736 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 736 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_v6_send_reset"),
               used))
# 736 "./core.c"
#pragma GCC diagnostic pop
# 736 "./core.c"
int ret__trace_tcp_v6_send_reset(struct pt_regs *ctx)
{
    return handle_exit(ctx, 100);
}
# 736 "./core.c"
#pragma GCC diagnostic push
# 736 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 736 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_v6_send_reset"),
               used))
# 736 "./core.c"
#pragma GCC diagnostic pop
# 736 "./core.c"
int __trace_tcp_v6_send_reset(struct pt_regs *ctx)
{
    context_info_t info = {.func = 100, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0]), .skb = (u32)(((struct pt_regs *)ctx)->uregs[1])};
    if (pre_handle_entry(&info, 100))
        return 0;
    handle_entry_finish(&info, fake__tcp_v6_send_reset(&info));
    return 0;
}
static inline int fake__tcp_v6_send_reset(context_info_t *info)

{
    struct sock *sk = (u32)(((struct pt_regs *)info->ctx)->uregs[0]);
    struct sock_common skc_common = (
        {
            typeof((sk)->__sk_common) __r;
            ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->__sk_common); });
            __r;
        });
    pure_reset_event_t __attribute__((__unused__)) * e;
    reset_event_t __attribute__((__unused__)) __e;
    detail_reset_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_reset_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((reset_event_t *)0)->__event_filed));
    }

    e->state = skc_common.skc_state;
    e->reason = (u64)(u32)(((struct pt_regs *)info->ctx)->uregs[2]);

    return ({ int err = handle_entry(info); if (!err) do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); err; });
}

static inline int fake__tcp_send_active_reset(context_info_t *info);
# 750 "./core.c"
#pragma GCC diagnostic push
# 750 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 750 "./core.c"
__attribute__((section("kretprobe/"
                       "tcp_send_active_reset"),
               used))
# 750 "./core.c"
#pragma GCC diagnostic pop
# 750 "./core.c"
int ret__trace_tcp_send_active_reset(struct pt_regs *ctx)
{
    return handle_exit(ctx, 140);
}
# 750 "./core.c"
#pragma GCC diagnostic push
# 750 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 750 "./core.c"
__attribute__((section("kprobe/"
                       "tcp_send_active_reset"),
               used))
# 750 "./core.c"
#pragma GCC diagnostic pop
# 750 "./core.c"
int __trace_tcp_send_active_reset(struct pt_regs *ctx)
{
    context_info_t info = {.func = 140, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .sk = (u32)(((struct pt_regs *)ctx)->uregs[0])};
    if (pre_handle_entry(&info, 140))
        return 0;
    handle_entry_finish(&info, fake__tcp_send_active_reset(&info));
    return 0;
}
static inline int fake__tcp_send_active_reset(context_info_t *info)

{
    struct sock *sk = (u32)(((struct pt_regs *)info->ctx)->uregs[0]);
    struct sock_common skc_common = (
        {
            typeof((sk)->__sk_common) __r;
            ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof(((sk))))(((sk))))->__sk_common); });
            __r;
        });
    pure_reset_event_t __attribute__((__unused__)) * e;
    reset_event_t __attribute__((__unused__)) __e;
    detail_reset_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_reset_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((reset_event_t *)0)->__event_filed));
    }

    e->state = skc_common.skc_state;
    e->reason = (u64)(u32)(((struct pt_regs *)info->ctx)->uregs[2]);

    return ({ int err = handle_entry(info); if (!err) do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); err; });
}

static inline int fake__inet_listen(context_info_t *info);
# 769 "./core.c"
#pragma GCC diagnostic push
# 769 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 769 "./core.c"
__attribute__((section("kretprobe/"
                       "inet_listen"),
               used))
# 769 "./core.c"
#pragma GCC diagnostic pop
# 769 "./core.c"
int ret__trace_inet_listen(struct pt_regs *ctx)
{
    return handle_exit(ctx, 137);
}
# 769 "./core.c"
#pragma GCC diagnostic push
# 769 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 769 "./core.c"
__attribute__((section("kprobe/"
                       "inet_listen"),
               used))
# 769 "./core.c"
#pragma GCC diagnostic pop
# 769 "./core.c"
int __trace_inet_listen(struct pt_regs *ctx)
{
    context_info_t info = {.func = 137, .ctx = ctx, .args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; }), .sk = ({ typeof(((struct socket *)(u32)(((struct pt_regs*)ctx)->uregs[0]))->sk) __r; ({ bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), &((typeof((((struct socket *)(u32)(((struct pt_regs*)ctx)->uregs[0])))))((((struct socket *)(u32)(((struct pt_regs*)ctx)->uregs[0])))))->sk); }); __r; })};
    if (pre_handle_entry(&info, 137))
        return 0;
    handle_entry_finish(&info, fake__inet_listen(&info));
    return 0;
}
static inline int fake__inet_listen(context_info_t *info)

{
    return default_handle_entry(info);
}
# 815 "./core.c"
char _license[]
# 815 "./core.c"
#pragma GCC diagnostic push
# 815 "./core.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 815 "./core.c"
    __attribute__((section("license"), used))
# 815 "./core.c"
#pragma GCC diagnostic pop
# 815 "./core.c"
    = "GPL";
# 96 "nettrace.bpf.c" 2

static inline __attribute__((always_inline)) u64 get_ret_key(int func)
{
    return (bpf_get_current_pid_tgid() << 32) + func;
}

static inline void get_ret(context_info_t *info)
{
    int *ref;
    u64 key;

    if (!(info->func_status & (1 << 5)))
        return;

    key = get_ret_key(info->func);
    ref = bpf_map_lookup_elem(&m_ret, &key);
    if (!ref)
    {
        int v = 1;

        bpf_map_update_elem(&m_ret, &key, &v, 0);
        return;
    }
    (*ref)++;
}

static inline int put_ret(bpf_args_t *args, int func)
{
    int *ref;
    u64 key;

    if (!(get_func_status(args, func) & (1 << 5)))
        return 1;

    key = get_ret_key(func);
    ref = bpf_map_lookup_elem(&m_ret, &key);
    if (!ref || *ref <= 0)
    {
        bpf_map_delete_elem(&m_ret, &key);
        return 1;
    }
    (*ref)--;
    return 0;
}

static inline int handle_exit(struct pt_regs *ctx, int func)
{
    bpf_args_t *args = (void *)({ int _key = 0; void * _v = bpf_map_lookup_elem(&m_config, &_key); if (!_v) return 0; (pkt_args_t *)_v; });
    retevent_t event;

    if (!args->ready || put_ret(args, func))
        return 0;

    event = (retevent_t){
        .ts = bpf_ktime_get_ns(),
        .func = func,
        .meta = FUNC_TYPE_RET,
        .val = ((ctx)->uregs[0]),
        .pid = (u32)bpf_get_current_pid_tgid(),
    };

    if (func == 156)
        init_ctx_match((void *)event.val, func, false);

    bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
