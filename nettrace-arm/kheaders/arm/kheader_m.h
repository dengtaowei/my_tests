#ifndef __GENERATED_STRUCTS_H__
#define __GENERATED_STRUCTS_H__

/*
 * 自动生成的结构体定义
 * 注释格式: [起始偏移-结束偏移] 大小
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/timer.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

struct tcp_sock {
    unsigned char __padding1[1136]; /* [0-1135] 1136 bytes */
    u32 rcv_nxt; /* [1136-1139] 4 bytes */
    unsigned char __padding2[40]; /* [1140-1179] 40 bytes */
    u32 snd_una; /* [1180-1183] 4 bytes */
    unsigned char __padding3[196]; /* [1184-1379] 196 bytes */
    u32 packets_out; /* [1380-1383] 4 bytes */
    u32 retrans_out; /* [1384-1387] 4 bytes */
    unsigned char __padding4[476]; /* [1388-1863] 476 bytes */
} __attribute__((__packed__)); /* total size: 1864 bytes */

struct timer_list {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned long expires; /* [8-11] 4 bytes */
    unsigned char __padding2[8]; /* [12-19] 8 bytes */
} __attribute__((__packed__)); /* total size: 20 bytes */

struct inet_connection_sock {
    unsigned char __padding1[868]; /* [0-867] 868 bytes */
    u32 icsk_timeout; /* [868-871] 4 bytes */
    struct timer_list icsk_retransmit_timer; /* [872-891] 20 bytes */
    unsigned char __padding2[61]; /* [892-952] 61 bytes */
    u8 icsk_retransmits; /* [953-953] 1 bytes */
    u8 icsk_pending; /* [954-954] 1 bytes */
    unsigned char __padding3[157]; /* [955-1111] 157 bytes */
} __attribute__((__packed__)); /* total size: 1112 bytes */

struct sock_common {
    __be32 skc_daddr; /* [0-3] 4 bytes */
    __be32 skc_rcv_saddr; /* [4-7] 4 bytes */
    unsigned char __padding1[4]; /* [8-11] 4 bytes */
    __be16 skc_dport; /* [12-13] 2 bytes */
    u16 skc_num; /* [14-15] 2 bytes */
    u16 skc_family; /* [16-17] 2 bytes */
    u8 skc_state; /* [18-18] 1 bytes */
    unsigned char __padding2[21]; /* [19-39] 21 bytes */
    struct in6_addr skc_v6_daddr; /* [40-55] 16 bytes */
    struct in6_addr skc_v6_rcv_saddr; /* [56-71] 16 bytes */
    unsigned char __padding3[40]; /* [72-111] 40 bytes */
} __attribute__((__packed__)); /* total size: 112 bytes */

struct tcp_skb_cb {
    u32 seq; /* [0-3] 4 bytes */
    unsigned char __padding1[8]; /* [4-11] 8 bytes */
    u8 tcp_flags; /* [12-12] 1 bytes */
    unsigned char __padding2[35]; /* [13-47] 35 bytes */
} __attribute__((__packed__)); /* total size: 48 bytes */

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
    unsigned char __padding2[1468]; /* [132-1599] 1468 bytes */
} __attribute__((__packed__)); /* total size: 1600 bytes */

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

struct sk_buff {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    struct net_device * dev; /* [8-11] 4 bytes */
    struct sock * sk; /* [12-15] 4 bytes */
    unsigned char __padding2[8]; /* [16-23] 8 bytes */
    unsigned char  cb[48]; /* [24-71] 48 bytes */
    unsigned char __padding3[44]; /* [72-115] 44 bytes */
    u32 skb_iif; /* [116-119] 4 bytes */
    unsigned char __padding4[24]; /* [120-143] 24 bytes */
    __be16 protocol; /* [144-145] 2 bytes */
    u16 transport_header; /* [146-147] 2 bytes */
    u16 network_header; /* [148-149] 2 bytes */
    u16 mac_header; /* [150-151] 2 bytes */
    unsigned char __padding5[168]; /* [152-319] 168 bytes */
    void * head; /* [320-323] 4 bytes */
    unsigned char __padding6[20]; /* [324-343] 20 bytes */
} __attribute__((__packed__)); /* total size: 344 bytes */

struct sk_buff_head {
    unsigned char __padding1[8]; /* [0-7] 8 bytes */
    unsigned int qlen; /* [8-11] 4 bytes */
    unsigned char __padding2[4]; /* [12-15] 4 bytes */
} __attribute__((__packed__)); /* total size: 16 bytes */

struct socket {
    unsigned char __padding1[16]; /* [0-15] 16 bytes */
    struct sock * sk; /* [16-19] 4 bytes */
    unsigned char __padding2[108]; /* [20-127] 108 bytes */
} __attribute__((__packed__)); /* total size: 128 bytes */

struct sock {
    struct sock_common __sk_common; /* [0-111] 112 bytes */
    unsigned char __padding1[56]; /* [112-167] 56 bytes */
    struct sk_buff_head sk_receive_queue; /* [168-183] 16 bytes */
    unsigned char __padding2[84]; /* [184-267] 84 bytes */
    struct sk_buff_head sk_write_queue; /* [268-283] 16 bytes */
    unsigned char __padding3[96]; /* [284-379] 96 bytes */
    u16 sk_protocol; /* [380-381] 2 bytes */
    unsigned char __padding4[226]; /* [382-607] 226 bytes */
} __attribute__((__packed__)); /* total size: 608 bytes */

#endif /* __GENERATED_STRUCTS_H__ */