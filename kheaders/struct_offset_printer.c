#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <net/inet_connection_sock.h>
#include <net/sock.h>
#include <uapi/linux/bpf.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <net/sch_generic.h>
#include <net/tcp.h>

#define PRINT_STRUCT_FIELD(struct_type, field) \
    pr_info("FIELD: " #field " offset=%zu size=%zu\n", \
            offsetof(struct_type, field), \
            sizeof(((struct_type *)0)->field))

#define PRINT_STRUCT_BEGIN(struct_type) \
    pr_info("# STRUCT_BEGIN " #struct_type " %zu\n", sizeof(struct_type))

#define PRINT_STRUCT_END(struct_type) \
    pr_info("# STRUCT_END " #struct_type "\n\n")

static void print_tcp_sock_fields(void)
{
    PRINT_STRUCT_BEGIN(struct tcp_sock);
    PRINT_STRUCT_FIELD(struct tcp_sock, retrans_out);
    PRINT_STRUCT_FIELD(struct tcp_sock, rcv_nxt);
    PRINT_STRUCT_FIELD(struct tcp_sock, snd_una);
    PRINT_STRUCT_FIELD(struct tcp_sock, packets_out);
    PRINT_STRUCT_END(struct tcp_sock);
}

static void print_timer_list_fields(void)
{
    PRINT_STRUCT_BEGIN(struct timer_list);
    PRINT_STRUCT_FIELD(struct timer_list, expires);
    PRINT_STRUCT_END(struct timer_list);
}

static void print_connection_sock_fields(void)
{
    PRINT_STRUCT_BEGIN(struct inet_connection_sock);
    PRINT_STRUCT_FIELD(struct inet_connection_sock, icsk_timeout);
    pr_info("FIELD: icsk_retransmit_timer offset=%zu size=%zu type=timer_list\n",
            offsetof(struct inet_connection_sock, icsk_retransmit_timer),
            sizeof(((struct inet_connection_sock *)0)->icsk_retransmit_timer));
    PRINT_STRUCT_FIELD(struct inet_connection_sock, icsk_retransmits);
    PRINT_STRUCT_FIELD(struct inet_connection_sock, icsk_pending);
    PRINT_STRUCT_END(struct inet_connection_sock);
}

static void print_sock_common_fields(void)
{
    PRINT_STRUCT_BEGIN(struct sock_common);
    PRINT_STRUCT_FIELD(struct sock_common, skc_daddr);
    PRINT_STRUCT_FIELD(struct sock_common, skc_rcv_saddr);
    PRINT_STRUCT_FIELD(struct sock_common, skc_dport);
    PRINT_STRUCT_FIELD(struct sock_common, skc_num);
    PRINT_STRUCT_FIELD(struct sock_common, skc_family);
    PRINT_STRUCT_FIELD(struct sock_common, skc_state);
    PRINT_STRUCT_END(struct sock_common);
}

static void print_tcp_skb_cb_fields(void)
{
    PRINT_STRUCT_BEGIN(struct tcp_skb_cb);
    PRINT_STRUCT_FIELD(struct tcp_skb_cb, seq);
    PRINT_STRUCT_FIELD(struct tcp_skb_cb, tcp_flags);
    PRINT_STRUCT_END(struct tcp_skb_cb);
}

static void print___sk_buff_fields(void)
{
    PRINT_STRUCT_BEGIN(struct __sk_buff);
    PRINT_STRUCT_FIELD(struct __sk_buff, data);
    PRINT_STRUCT_FIELD(struct __sk_buff, data_end);
    PRINT_STRUCT_END(struct __sk_buff);
}

static void print_netdev_queue_fields(void)
{
    PRINT_STRUCT_BEGIN(struct netdev_queue);
    PRINT_STRUCT_FIELD(struct netdev_queue, trans_start);
    PRINT_STRUCT_FIELD(struct netdev_queue, state);
    PRINT_STRUCT_END(struct netdev_queue);
}

static void print_net_device_fields(void)
{
    PRINT_STRUCT_BEGIN(struct net_device);
    PRINT_STRUCT_FIELD(struct net_device, ifindex);
    PRINT_STRUCT_FIELD(struct net_device, name);
    PRINT_STRUCT_END(struct net_device);
}

static void print_qdisc_skb_head_fields(void)
{
    PRINT_STRUCT_BEGIN(struct qdisc_skb_head);
    PRINT_STRUCT_FIELD(struct qdisc_skb_head, qlen);
    PRINT_STRUCT_END(struct qdisc_skb_head);
}

static void print_Qdisc_fields(void)
{
    PRINT_STRUCT_BEGIN(struct Qdisc);
    PRINT_STRUCT_FIELD(struct Qdisc, flags);
    PRINT_STRUCT_FIELD(struct Qdisc, dev_queue);
    // PRINT_STRUCT_FIELD(struct Qdisc, q); qdisc_skb_head
    pr_info("FIELD: q offset=%zu size=%zu type=qdisc_skb_head\n",
            offsetof(struct Qdisc, q),
            sizeof(((struct Qdisc *)0)->q));
    PRINT_STRUCT_END(struct Qdisc);
}

static void print_sk_buff_fields(void)
{
    PRINT_STRUCT_BEGIN(struct sk_buff);
    PRINT_STRUCT_FIELD(struct sk_buff, dev);
    PRINT_STRUCT_FIELD(struct sk_buff, sk);
    PRINT_STRUCT_FIELD(struct sk_buff, cb);
    PRINT_STRUCT_FIELD(struct sk_buff, skb_iif);
    PRINT_STRUCT_FIELD(struct sk_buff, protocol);
    PRINT_STRUCT_FIELD(struct sk_buff, transport_header);
    PRINT_STRUCT_FIELD(struct sk_buff, network_header);
    PRINT_STRUCT_FIELD(struct sk_buff, mac_header);
    PRINT_STRUCT_FIELD(struct sk_buff, head);
    PRINT_STRUCT_END(struct sk_buff);
}

static void print_sk_buff_head_fields(void)
{
    PRINT_STRUCT_BEGIN(struct sk_buff_head);
    PRINT_STRUCT_FIELD(struct sk_buff_head, qlen);
    PRINT_STRUCT_END(struct sk_buff_head);
}

static void print_socket_fields(void)
{
    PRINT_STRUCT_BEGIN(struct socket);
    PRINT_STRUCT_FIELD(struct socket, sk);
    PRINT_STRUCT_END(struct socket);
}

static void print_sock_fields(void)
{
    PRINT_STRUCT_BEGIN(struct sock);
    // PRINT_STRUCT_FIELD(struct sock, __sk_common); struct sock_common __sk_common;
    pr_info("FIELD: __sk_common offset=%zu size=%zu type=sock_common\n",
            offsetof(struct sock, __sk_common),
            sizeof(((struct sock *)0)->__sk_common));
    // PRINT_STRUCT_FIELD(struct sock, sk_receive_queue);  struct sk_buff_head sk_receive_queue;
    pr_info("FIELD: sk_receive_queue offset=%zu size=%zu type=sk_buff_head\n",
            offsetof(struct sock, sk_receive_queue),
            sizeof(((struct sock *)0)->sk_receive_queue));
    // PRINT_STRUCT_FIELD(struct sock, sk_write_queue);  
    pr_info("FIELD: sk_write_queue offset=%zu size=%zu type=sk_buff_head\n",
            offsetof(struct sock, sk_write_queue),
            sizeof(((struct sock *)0)->sk_write_queue));
    PRINT_STRUCT_FIELD(struct sock, sk_protocol);
    PRINT_STRUCT_END(struct sock);
}

static int __init struct_printer_init(void)
{
    pr_info("Structure Offset Printer Module Loaded\n");
    print_tcp_sock_fields();
    print_timer_list_fields();
    print_connection_sock_fields();
    print_sock_common_fields();
    print_tcp_skb_cb_fields();
    print___sk_buff_fields();
    print_netdev_queue_fields();
    print_net_device_fields();
    print_qdisc_skb_head_fields();
    print_Qdisc_fields();
    print_sk_buff_fields();
    print_sk_buff_head_fields();
    print_socket_fields();
    print_sock_fields();
    return 0;
}

static void __exit struct_printer_exit(void)
{
    pr_info("Structure Offset Printer Module Unloaded\n");
}

module_init(struct_printer_init);
module_exit(struct_printer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to print structure offsets");
MODULE_VERSION("0.1");