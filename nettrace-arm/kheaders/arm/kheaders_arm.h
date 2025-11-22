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
	// struct list_head *next;
	// struct list_head *prev;
	u32 next;
	u32 prev;
};

struct xt_table {
	struct list_head list;
	unsigned int valid_hooks;
	struct xt_table_info *private;
	struct module *me;
	u8 af;
	int priority;
	// int (*table_init)(struct net *);
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

struct tcp_sock {
    unsigned char __padding1[1008]; /* [0-1007] 1008 bytes */
    u32 rcv_nxt; /* [1008-1011] 4 bytes */
    unsigned char __padding2[40]; /* [1012-1051] 40 bytes */
    u32 snd_una; /* [1052-1055] 4 bytes */
    unsigned char __padding3[196]; /* [1056-1251] 196 bytes */
    u32 packets_out; /* [1252-1255] 4 bytes */
    u32 retrans_out; /* [1256-1259] 4 bytes */
    unsigned char __padding4[468]; /* [1260-1727] 468 bytes */
} __attribute__((__packed__)); /* total size: 1728 bytes */

struct timer_list {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned long expires; /* [8-11] 4 bytes */
    unsigned char __padding2[8]; /* [12-19] 8 bytes */
} __attribute__((__packed__)); /* total size: 20 bytes */

struct inet_connection_sock {
    unsigned char __padding1[740]; /* [0-739] 740 bytes */
    u32 icsk_timeout; /* [740-743] 4 bytes */
    struct timer_list icsk_retransmit_timer; /* [744-763] 20 bytes */
    unsigned char __padding2[61]; /* [764-824] 61 bytes */
    u8 icsk_retransmits; /* [825-825] 1 bytes */
    u8 icsk_pending; /* [826-826] 1 bytes */
    unsigned char __padding3[157]; /* [827-983] 157 bytes */
} __attribute__((__packed__)); /* total size: 984 bytes */

struct sock_common {
    __be32 skc_daddr; /* [0-3] 4 bytes */
    __be32 skc_rcv_saddr; /* [4-7] 4 bytes */
    unsigned char __padding1[4]; /* [8-11] 4 bytes */
    __be16 skc_dport; /* [12-13] 2 bytes */
    u16 skc_num; /* [14-15] 2 bytes */
    u16 skc_family; /* [16-17] 2 bytes */
    u8 skc_state; /* [18-18] 1 bytes */
    unsigned char __padding2[61]; /* [19-79] 61 bytes */
} __attribute__((__packed__)); /* total size: 80 bytes */

struct ip_esp_hdr
{
    __be32 spi;
    __be32 seq_no;
    __u8 enc_data[0];
};


struct tcp_skb_cb {
    u32 seq; /* [0-3] 4 bytes */
    unsigned char __padding1[8]; /* [4-11] 8 bytes */
    u8 tcp_flags; /* [12-12] 1 bytes */
    unsigned char __padding2[35]; /* [13-47] 35 bytes */
} __attribute__((__packed__)); /* total size: 48 bytes */

struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((__packed__));

struct __sk_buff {
    unsigned char __padding1[76]; /* [0-75] 76 bytes */
    u32 data; /* [76-79] 4 bytes */
    u32 data_end; /* [80-83] 4 bytes */
    unsigned char __padding2[108]; /* [84-191] 108 bytes */
} __attribute__((__packed__)); /* total size: 192 bytes */

struct netdev_queue {
    unsigned char __padding1[72]; /* [0-71] 72 bytes */
    unsigned long trans_start; /* [72-75] 4 bytes */
    unsigned long state; /* [76-79] 4 bytes */
    unsigned char __padding2[176]; /* [80-255] 176 bytes */
} __attribute__((__packed__)); /* total size: 256 bytes */

struct net_device {
    unsigned char  name[16]; /* [0-15] 16 bytes */
    unsigned char __padding1[112]; /* [16-127] 112 bytes */
    int ifindex; /* [128-131] 4 bytes */
    unsigned char __padding2[1276]; /* [132-1407] 1276 bytes */
} __attribute__((__packed__)); /* total size: 1408 bytes */

struct nf_hook_state
{
    u8 hook; /*     0     1 */
    u8 pf;   /*     1     1 */
} __attribute__((__packed__));

struct qdisc_skb_head {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int qlen; /* [8-11] 4 bytes */
    unsigned char __padding2[4]; /* [12-15] 4 bytes */
} __attribute__((__packed__)); /* total size: 16 bytes */

struct Qdisc {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int flags; /* [8-11] 4 bytes */
    unsigned char __padding2[28]; /* [12-39] 28 bytes */
    u32 dev_queue; /* [40-43] 4 bytes */
    unsigned char __padding3[36]; /* [44-79] 36 bytes */
    struct qdisc_skb_head q; /* [80-95] 16 bytes */
    unsigned char __padding4[160]; /* [96-255] 160 bytes */
} __attribute__((__packed__)); /* total size: 256 bytes */

typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);

struct nf_hook_entry {
	// nf_hookfn			*hook;
	// void				*priv;
	u32 hook;
	u32 priv;
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
	// long unsigned int uregs[18];
	unsigned int uregs[18];
};

struct sk_buff {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    // struct net_device * dev; /* [8-11] 4 bytes */
	u32 dev;
    // struct sock * sk; /* [12-15] 4 bytes */
	u32 sk;
    unsigned char __padding2[8]; /* [16-23] 8 bytes */
    unsigned char  cb[48]; /* [24-71] 48 bytes */
    unsigned char __padding3[40]; /* [72-111] 40 bytes */
    u32 skb_iif; /* [112-115] 4 bytes */
    unsigned char __padding4[24]; /* [116-139] 24 bytes */
    __be16 protocol; /* [140-141] 2 bytes */
    u16 transport_header; /* [142-143] 2 bytes */
    u16 network_header; /* [144-145] 2 bytes */
    u16 mac_header; /* [146-147] 2 bytes */
    unsigned char __padding5[8]; /* [148-155] 8 bytes */
    // void * head; /* [156-159] 4 bytes */
	u32 head;
    unsigned char __padding6[16]; /* [160-175] 16 bytes */
} __attribute__((__packed__)); /* total size: 176 bytes */

struct sk_buff_head {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int qlen; /* [8-11] 4 bytes */
    unsigned char __padding2[4]; /* [12-15] 4 bytes */
} __attribute__((__packed__)); /* total size: 16 bytes */

struct sock;

struct socket {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    // struct sock * sk; /* [16-19] 4 bytes */
	u32 sk;
    unsigned char __padding2[108]; /* [20-127] 108 bytes */
} __attribute__((__packed__)); /* total size: 128 bytes */

struct sock_common;

struct sock {
    struct sock_common __sk_common; /* [0-79] 80 bytes */
    unsigned char __padding1[56]; /* [80-135] 56 bytes */
    struct sk_buff_head sk_receive_queue; /* [136-151] 16 bytes */
    unsigned char __padding2[76]; /* [152-227] 76 bytes */
    struct sk_buff_head sk_write_queue; /* [228-243] 16 bytes */
    unsigned char __padding3[96]; /* [244-339] 96 bytes */
    u16 sk_protocol; /* [340-341] 2 bytes */
    unsigned char __padding4[154]; /* [342-495] 154 bytes */
} __attribute__((__packed__)); /* total size: 496 bytes */

#endif