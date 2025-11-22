#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

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

// typedef enum { false, true } bool;

enum {
	false = 0,
	true = 1,
};


enum bpf_map_type {
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

enum {
	BPF_F_INDEX_MASK = 4294967295,
	BPF_F_CURRENT_CPU = 4294967295,
	BPF_F_CTXLEN_MASK = 0,
};

enum {
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

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct xt_table {
	struct list_head list;
	unsigned int valid_hooks;
	struct xt_table_info *private;
	struct module *me;
	u8 af;
	int priority;
	int (*table_init)(struct net *);
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
    char fill_1[1496];
    u32 rcv_nxt; // dtwdebug /*  1496     4 */
    char fill_2[40];
    u32 snd_una; // dtwdebug /*  1540     4 */
    char fill_3[212];
    u32 packets_out; // dtwdebug /*  1756     4 */
    char fill_4[0];
    u32 retrans_out; // dtwdebug /*  1760     4 */
    char fill_5[540];
} __attribute__((__packed__));  // 2304

struct timer_list
{
    char fill_1[16];
    unsigned long		expires; // /*  16    8 */
    char fill_2[16];
} __attribute__((__packed__));  // 40

struct inet_connection_sock
{
    char fill_1[1160];
    unsigned long icsk_timeout;             /*  1160 8 */
    struct timer_list icsk_retransmit_timer; /*  1168 40 */
    char fill_2[105];
    __u8 icsk_retransmits; /*  1313 1 */
    __u8 icsk_pending;     /*  1314 1 */
    char fill_3[157];
} __attribute__((__packed__));  // 1472

struct sock_common
{
    union
    {
        __addrpair skc_addrpair; /*     0     4 */
        struct
        {
            __be32 skc_daddr;     /*     0     4 */
            __be32 skc_rcv_saddr; /*     4     4 */
        };
    };
    char fill_1[4];
    union
    {
        __portpair skc_portpair; /*    12     2 */
        struct
        {
            __be16 skc_dport; /*    12     2 */
            __u16 skc_num;    /*    14     2 */
        };
    };
    short unsigned int skc_family;    /*    16     2 */
    volatile unsigned char skc_state; /*    18     1 */
    char fill_2[37];
    struct in6_addr skc_v6_daddr;     /*    56    16 */
    struct in6_addr skc_v6_rcv_saddr; /*    72    16 */
    char fill_3[48];
} __attribute__((__packed__));  // 136

struct ip_esp_hdr
{
    __be32 spi;
    __be32 seq_no;
    __u8 enc_data[0];
};


struct tcp_skb_cb
{
    __u32 seq; /*     0     4 */
    char fill_1[8];
    __u8 tcp_flags; /*    12     1 */
    char fill_2[35];
} __attribute__((__packed__));  // 48

struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((__packed__));

struct __sk_buff
{
    char fill_1[76];
    __u32 data;     /*    76     4 */
    __u32 data_end; /*    80     4 */
    char fill_2[108];
} __attribute__((__packed__));  // 192

struct netdev_queue
{
    char fill_1[136];
    unsigned long trans_start; /*   136     8 */
    unsigned long state;       /*   144     8 */
    char fill_2[168];
} __attribute__((__packed__));  // 320

struct net_device
{
    char name[16]; /*   0    16 */
    char fill_1[208];
    int ifindex; /*   224     4 */
    char fill_2[2204];
} __attribute__((__packed__));  // 2432

struct nf_hook_state
{
    u8 hook; /*     0     1 */
    u8 pf;   /*     1     1 */
} __attribute__((__packed__));

struct qdisc_skb_head
{
    char fill_1[16];
    __u32 qlen; /*    16     4 */
    char fill_2[4];
} __attribute__((__packed__));  // 24

struct Qdisc
{
    char fill_1[16];
    unsigned int flags; /*    16     4 */
    char fill_2[44];
    struct netdev_queue *dev_queue; /*    64     8 */
    char fill_3[80];
    struct qdisc_skb_head q; /*   152    24 */
    char fill_4[208];
} __attribute__((__packed__));  // 384

typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);

struct nf_hook_entry {
	nf_hookfn			*hook;
	void				*priv;
};

struct nf_hook_entries
{
    u16 num_hook_entries;
    struct nf_hook_entry hooks[0];
} ;

struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct pt_regs {
	long unsigned int uregs[18];
};

struct sk_buff
{
    union
    {
        struct
        {
            struct sk_buff *next;
            struct sk_buff *prev;
            union
            {
                struct net_device *dev; /*    16     8 */
            };
        };
    };
    struct sock *sk; /*    24     8 */
    char fill_0[8];
    char cb[48]; /*    40    48 */
    char fill_1[56];
    union
    {
        struct
        {
            // char fill_2[20];
            int skb_iif; /*   144     4 */
            char fill_3[24];
            __be16 protocol;        /*   172     2 */
            __u16 transport_header; /*   174     2 */
            __u16 network_header;   /*   176     2 */
            __u16 mac_header;       /*   178     2 */
        };
        struct
        {
            // char fill_2[20];
            int skb_iif; /*   144     4 */
            char fill_3[24];
            __be16 protocol;        /*   172     2 */
            __u16 transport_header; /*   174     2 */
            __u16 network_header;   /*   176     2 */
            __u16 mac_header;       /*   178     2 */
        } headers;
    };
    char fill_4[204];
    unsigned char *head; /*   384     8 */
    char fill_5[24];
} __attribute__((__packed__));  // 416

struct sk_buff_head
{
    char fill_1[16];
    __u32 qlen; /*    16     4 */
    char fill_2[4];
} __attribute__((__packed__));  // 24

struct sock;

struct socket
{
    char fill_1[24];
    struct sock *sk; /*    24     8 */
    char fill_2[96];
} __attribute__((__packed__));  // 128

struct sock_common;

struct sock
{
    struct sock_common __sk_common; /*     0   136 */
    char fill_1[80];
    struct sk_buff_head sk_receive_queue; /*   216    24 */
    char fill_2[120];
    struct sk_buff_head sk_write_queue; /*   360    24 */
    char fill_3[132];
    u16 sk_protocol; /*   516    2 */
    char fill_4[322];
} __attribute__((__packed__));  // 840

#endif