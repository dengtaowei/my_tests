#include "trace.h"
#include "kprobe_trace.h"
#include "analysis.h"

trace_group_t root_group = {
	.name = "all",
	.desc = "trace the whole kernel network stack",
	.children = LIST_HEAD_INIT(root_group.children),
	.traces = LIST_HEAD_INIT(root_group.traces),
	.list = LIST_HEAD_INIT(root_group.list),
};
trace_group_t group_link = {
	.name = "link",
	.desc = "link layer (L2) of the network stack",
	.children = LIST_HEAD_INIT(group_link.children),
	.traces = LIST_HEAD_INIT(group_link.traces),
	.list = LIST_HEAD_INIT(group_link.list),
};
trace_group_t group_link_in = {
	.name = "link-in",
	.desc = "link layer (L2) of packet in",
	.children = LIST_HEAD_INIT(group_link_in.children),
	.traces = LIST_HEAD_INIT(group_link_in.traces),
	.list = LIST_HEAD_INIT(group_link_in.list),
};
trace_t trace_napi_gro_receive_entry = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "napi_gro_receive_entry",
	.skb = 4,
	.skboffset = 24,
	.custom = false,
	.tp = "net/napi_gro_receive_entry",
	.def = true,
	.index = INDEX_napi_gro_receive_entry,
	.prog = "__trace_napi_gro_receive_entry",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace_napi_gro_receive_entry.rules),
};
trace_list_t trace_napi_gro_receive_entry_list = {
	.trace = &trace_napi_gro_receive_entry,
	.list = LIST_HEAD_INIT(trace_napi_gro_receive_entry_list.list)
};

trace_t trace_dev_gro_receive = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "dev_gro_receive",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_dev_gro_receive,
	.prog = "__trace_dev_gro_receive",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace_dev_gro_receive.rules),
};
trace_list_t trace_dev_gro_receive_list = {
	.trace = &trace_dev_gro_receive,
	.list = LIST_HEAD_INIT(trace_dev_gro_receive_list.list)
};
rule_t rule_trace_dev_gro_receive_0 = {	.level = RULE_ERROR,
	.expected = 4,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_ERROR"packet is dropped by GRO"PFMT_END,
};

trace_t trace_enqueue_to_backlog = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.arg_count = 3,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "enqueue_to_backlog",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_enqueue_to_backlog,
	.prog = "__trace_enqueue_to_backlog",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace_enqueue_to_backlog.rules),
};
trace_list_t trace_enqueue_to_backlog_list = {
	.trace = &trace_enqueue_to_backlog,
	.list = LIST_HEAD_INIT(trace_enqueue_to_backlog_list.list)
};
rule_t rule_trace_enqueue_to_backlog_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_NE,
	.adv = "increase the /proc/sys/net/core/netdev_max_backlog",
	.msg = PFMT_ERROR"failed to enqeueu to CPU backlog"PFMT_END,
};

trace_t trace_netif_receive_generic_xdp = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.is_backup = false,
	.probe = false,
	.name = "netif_receive_generic_xdp",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_netif_receive_generic_xdp,
	.prog = "__trace_netif_receive_generic_xdp",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace_netif_receive_generic_xdp.rules),
};
trace_list_t trace_netif_receive_generic_xdp_list = {
	.trace = &trace_netif_receive_generic_xdp,
	.list = LIST_HEAD_INIT(trace_netif_receive_generic_xdp_list.list)
};
rule_t rule_trace_netif_receive_generic_xdp_0 = {	.level = RULE_ERROR,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.adv = "check your XDP eBPF program",
	.msg = PFMT_ERROR"packet is dropped by XDP program"PFMT_END,
};
rule_t rule_trace_netif_receive_generic_xdp_1 = {	.level = RULE_INFO,
	.expected = 3,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is transmited by XDP program"PFMT_END,
};
rule_t rule_trace_netif_receive_generic_xdp_2 = {	.level = RULE_INFO,
	.expected = 4,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is redirected by XDP program"PFMT_END,
};

trace_t trace_xdp_do_generic_redirect = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.arg_count = 4,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "xdp_do_generic_redirect",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xdp_do_generic_redirect,
	.prog = "__trace_xdp_do_generic_redirect",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace_xdp_do_generic_redirect.rules),
};
trace_list_t trace_xdp_do_generic_redirect_list = {
	.trace = &trace_xdp_do_generic_redirect,
	.list = LIST_HEAD_INIT(trace_xdp_do_generic_redirect_list.list)
};
rule_t rule_trace_xdp_do_generic_redirect_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_NE,
	.adv = "check if the target ifindex exist",
	.msg = PFMT_ERROR"XDP failed to redirect skb"PFMT_END,
};

trace_t trace___netif_receive_skb_core = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__netif_receive_skb_core",
	.skb = 1,
	.skboffset = 8,
	.custom = false,
	.tp = "net/netif_receive_skb",
	.def = true,
	.index = INDEX___netif_receive_skb_core,
	.prog = "__trace___netif_receive_skb_core",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace___netif_receive_skb_core.rules),
};
trace_list_t trace___netif_receive_skb_core_list = {
	.trace = &trace___netif_receive_skb_core,
	.list = LIST_HEAD_INIT(trace___netif_receive_skb_core_list.list)
};

trace_t trace_RtmpOsPktRcvHandle = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "RtmpOsPktRcvHandle",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_RtmpOsPktRcvHandle,
	.prog = "__trace_RtmpOsPktRcvHandle",
	.parent = &group_link_in,
	.rules = LIST_HEAD_INIT(trace_RtmpOsPktRcvHandle.rules),
};
trace_list_t trace_RtmpOsPktRcvHandle_list = {
	.trace = &trace_RtmpOsPktRcvHandle,
	.list = LIST_HEAD_INIT(trace_RtmpOsPktRcvHandle_list.list)
};

trace_group_t group_link_out = {
	.name = "link-out",
	.desc = "link layer (L2) of packet out",
	.children = LIST_HEAD_INIT(group_link_out.children),
	.traces = LIST_HEAD_INIT(group_link_out.traces),
	.list = LIST_HEAD_INIT(group_link_out.list),
};
trace_t trace___dev_queue_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.arg_count = 2,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "__dev_queue_xmit",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX___dev_queue_xmit,
	.prog = "__trace___dev_queue_xmit",
	.parent = &group_link_out,
	.rules = LIST_HEAD_INIT(trace___dev_queue_xmit.rules),
};
trace_list_t trace___dev_queue_xmit_list = {
	.trace = &trace___dev_queue_xmit,
	.list = LIST_HEAD_INIT(trace___dev_queue_xmit_list.list)
};
rule_t rule_trace___dev_queue_xmit_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_NE,
	.adv = "too complex to say",
	.msg = PFMT_ERROR"failed to queue packet to qdisc"PFMT_END,
};

trace_t trace_dev_hard_start_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "dev_hard_start_xmit",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_dev_hard_start_xmit,
	.prog = "__trace_dev_hard_start_xmit",
	.parent = &group_link_out,
	.rules = LIST_HEAD_INIT(trace_dev_hard_start_xmit.rules),
};
trace_list_t trace_dev_hard_start_xmit_list = {
	.trace = &trace_dev_hard_start_xmit,
	.list = LIST_HEAD_INIT(trace_dev_hard_start_xmit_list.list)
};
rule_t rule_trace_dev_hard_start_xmit_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"skb is successfully sent to the NIC driver"PFMT_END,
};

trace_t trace_fp_send_data_pkt = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "fp_send_data_pkt",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_fp_send_data_pkt,
	.prog = "__trace_fp_send_data_pkt",
	.parent = &group_link_out,
	.rules = LIST_HEAD_INIT(trace_fp_send_data_pkt.rules),
};
trace_list_t trace_fp_send_data_pkt_list = {
	.trace = &trace_fp_send_data_pkt,
	.list = LIST_HEAD_INIT(trace_fp_send_data_pkt_list.list)
};
rule_t rule_trace_fp_send_data_pkt_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"skb is successfully sent to the WiFi driver"PFMT_END,
};

trace_group_t group_sched = {
	.name = "sched",
	.desc = "TC(traffic control) module",
	.children = LIST_HEAD_INIT(group_sched.children),
	.traces = LIST_HEAD_INIT(group_sched.traces),
	.list = LIST_HEAD_INIT(group_sched.list),
};
trace_t trace_tcf_classify = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcf_classify",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcf_classify,
	.prog = "__trace_tcf_classify",
	.parent = &group_sched,
	.rules = LIST_HEAD_INIT(trace_tcf_classify.rules),
};
trace_list_t trace_tcf_classify_list = {
	.trace = &trace_tcf_classify,
	.list = LIST_HEAD_INIT(trace_tcf_classify_list.list)
};

trace_t trace_cls_bpf_classify = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "cls_bpf_classify",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_cls_bpf_classify,
	.prog = "__trace_cls_bpf_classify",
	.parent = &group_sched,
	.rules = LIST_HEAD_INIT(trace_cls_bpf_classify.rules),
};
trace_list_t trace_cls_bpf_classify_list = {
	.trace = &trace_cls_bpf_classify,
	.list = LIST_HEAD_INIT(trace_cls_bpf_classify_list.list)
};

trace_t trace_tcf_bpf_act = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcf_bpf_act",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcf_bpf_act,
	.prog = "__trace_tcf_bpf_act",
	.parent = &group_sched,
	.rules = LIST_HEAD_INIT(trace_tcf_bpf_act.rules),
};
trace_list_t trace_tcf_bpf_act_list = {
	.trace = &trace_tcf_bpf_act,
	.list = LIST_HEAD_INIT(trace_tcf_bpf_act_list.list)
};

trace_t trace_qdisc_dequeue = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(qdisc),
	.is_backup = false,
	.probe = false,
	.name = "qdisc_dequeue",
	.skb = 4,
	.skboffset = 32,
	.custom = true,
	.tp = "qdisc/qdisc_dequeue",
	.def = true,
	.index = INDEX_qdisc_dequeue,
	.prog = "__trace_qdisc_dequeue",
	.parent = &group_sched,
	.rules = LIST_HEAD_INIT(trace_qdisc_dequeue.rules),
};
trace_list_t trace_qdisc_dequeue_list = {
	.trace = &trace_qdisc_dequeue,
	.list = LIST_HEAD_INIT(trace_qdisc_dequeue_list.list)
};

trace_t trace_qdisc_enqueue = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(qdisc),
	.is_backup = false,
	.probe = false,
	.name = "qdisc_enqueue",
	.skb = 3,
	.skboffset = 24,
	.custom = true,
	.tp = "qdisc/qdisc_enqueue",
	.def = true,
	.index = INDEX_qdisc_enqueue,
	.prog = "__trace_qdisc_enqueue",
	.parent = &group_sched,
	.rules = LIST_HEAD_INIT(trace_qdisc_enqueue.rules),
};
trace_list_t trace_qdisc_enqueue_list = {
	.trace = &trace_qdisc_enqueue,
	.list = LIST_HEAD_INIT(trace_qdisc_enqueue_list.list)
};

trace_group_t group_ipvlan = {
	.name = "ipvlan",
	.desc = "ipvlan network interface",
	.children = LIST_HEAD_INIT(group_ipvlan.children),
	.traces = LIST_HEAD_INIT(group_ipvlan.traces),
	.list = LIST_HEAD_INIT(group_ipvlan.list),
};
trace_t trace_ipvlan_queue_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipvlan_queue_xmit",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_ipvlan_queue_xmit,
	.prog = "__trace_ipvlan_queue_xmit",
	.parent = &group_ipvlan,
	.rules = LIST_HEAD_INIT(trace_ipvlan_queue_xmit.rules),
};
trace_list_t trace_ipvlan_queue_xmit_list = {
	.trace = &trace_ipvlan_queue_xmit,
	.list = LIST_HEAD_INIT(trace_ipvlan_queue_xmit_list.list)
};

trace_t trace_ipvlan_handle_frame = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipvlan_handle_frame",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_ipvlan_handle_frame,
	.prog = "__trace_ipvlan_handle_frame",
	.parent = &group_ipvlan,
	.rules = LIST_HEAD_INIT(trace_ipvlan_handle_frame.rules),
};
trace_list_t trace_ipvlan_handle_frame_list = {
	.trace = &trace_ipvlan_handle_frame,
	.list = LIST_HEAD_INIT(trace_ipvlan_handle_frame_list.list)
};

trace_t trace_ipvlan_rcv_frame = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipvlan_rcv_frame",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_ipvlan_rcv_frame,
	.prog = "__trace_ipvlan_rcv_frame",
	.parent = &group_ipvlan,
	.rules = LIST_HEAD_INIT(trace_ipvlan_rcv_frame.rules),
};
trace_list_t trace_ipvlan_rcv_frame_list = {
	.trace = &trace_ipvlan_rcv_frame,
	.list = LIST_HEAD_INIT(trace_ipvlan_rcv_frame_list.list)
};

trace_t trace_ipvlan_xmit_mode_l3 = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipvlan_xmit_mode_l3",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_ipvlan_xmit_mode_l3,
	.prog = "__trace_ipvlan_xmit_mode_l3",
	.parent = &group_ipvlan,
	.rules = LIST_HEAD_INIT(trace_ipvlan_xmit_mode_l3.rules),
};
trace_list_t trace_ipvlan_xmit_mode_l3_list = {
	.trace = &trace_ipvlan_xmit_mode_l3,
	.list = LIST_HEAD_INIT(trace_ipvlan_xmit_mode_l3_list.list)
};

trace_t trace_ipvlan_process_v4_outbound = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipvlan_process_v4_outbound",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_ipvlan_process_v4_outbound,
	.prog = "__trace_ipvlan_process_v4_outbound",
	.parent = &group_ipvlan,
	.rules = LIST_HEAD_INIT(trace_ipvlan_process_v4_outbound.rules),
};
trace_list_t trace_ipvlan_process_v4_outbound_list = {
	.trace = &trace_ipvlan_process_v4_outbound,
	.list = LIST_HEAD_INIT(trace_ipvlan_process_v4_outbound_list.list)
};

trace_group_t group_bridge = {
	.name = "bridge",
	.desc = "bridge network interface",
	.children = LIST_HEAD_INIT(group_bridge.children),
	.traces = LIST_HEAD_INIT(group_bridge.traces),
	.list = LIST_HEAD_INIT(group_bridge.list),
};
trace_t trace_br_nf_pre_routing = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.msg = "ebtable in PREROUTING",
	.is_backup = false,
	.probe = false,
	.name = "br_nf_pre_routing",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_br_nf_pre_routing,
	.prog = "__trace_br_nf_pre_routing",
	.parent = &group_bridge,
	.rules = LIST_HEAD_INIT(trace_br_nf_pre_routing.rules),
};
trace_list_t trace_br_nf_pre_routing_list = {
	.trace = &trace_br_nf_pre_routing,
	.list = LIST_HEAD_INIT(trace_br_nf_pre_routing_list.list)
};
rule_t rule_trace_br_nf_pre_routing_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your netfilter rule",
	.msg = PFMT_ERROR"packet is dropped"PFMT_END,
};
rule_t rule_trace_br_nf_pre_routing_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_t trace_br_nf_forward_ip = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.msg = "ebtable in FORWARD",
	.is_backup = false,
	.probe = false,
	.name = "br_nf_forward_ip",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_br_nf_forward_ip,
	.prog = "__trace_br_nf_forward_ip",
	.parent = &group_bridge,
	.rules = LIST_HEAD_INIT(trace_br_nf_forward_ip.rules),
};
trace_list_t trace_br_nf_forward_ip_list = {
	.trace = &trace_br_nf_forward_ip,
	.list = LIST_HEAD_INIT(trace_br_nf_forward_ip_list.list)
};
rule_t rule_trace_br_nf_forward_ip_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your netfilter rule",
	.msg = PFMT_ERROR"packet is dropped"PFMT_END,
};
rule_t rule_trace_br_nf_forward_ip_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_t trace_br_nf_forward_arp = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.msg = "ebtable in FORWARD",
	.is_backup = false,
	.probe = false,
	.name = "br_nf_forward_arp",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_br_nf_forward_arp,
	.prog = "__trace_br_nf_forward_arp",
	.parent = &group_bridge,
	.rules = LIST_HEAD_INIT(trace_br_nf_forward_arp.rules),
};
trace_list_t trace_br_nf_forward_arp_list = {
	.trace = &trace_br_nf_forward_arp,
	.list = LIST_HEAD_INIT(trace_br_nf_forward_arp_list.list)
};
rule_t rule_trace_br_nf_forward_arp_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your netfilter rule",
	.msg = PFMT_ERROR"packet is dropped"PFMT_END,
};
rule_t rule_trace_br_nf_forward_arp_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_t trace_br_nf_post_routing = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.msg = "ebtable in POST_ROUTING",
	.is_backup = false,
	.probe = false,
	.name = "br_nf_post_routing",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_br_nf_post_routing,
	.prog = "__trace_br_nf_post_routing",
	.parent = &group_bridge,
	.rules = LIST_HEAD_INIT(trace_br_nf_post_routing.rules),
};
trace_list_t trace_br_nf_post_routing_list = {
	.trace = &trace_br_nf_post_routing,
	.list = LIST_HEAD_INIT(trace_br_nf_post_routing_list.list)
};
rule_t rule_trace_br_nf_post_routing_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your netfilter rule",
	.msg = PFMT_ERROR"packet is dropped"PFMT_END,
};
rule_t rule_trace_br_nf_post_routing_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_group_t group_arp = {
	.name = "arp",
	.desc = "arp protocol",
	.children = LIST_HEAD_INIT(group_arp.children),
	.traces = LIST_HEAD_INIT(group_arp.traces),
	.list = LIST_HEAD_INIT(group_arp.list),
};
trace_t trace_arp_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "arp_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_arp_rcv,
	.prog = "__trace_arp_rcv",
	.parent = &group_arp,
	.rules = LIST_HEAD_INIT(trace_arp_rcv.rules),
};
trace_list_t trace_arp_rcv_list = {
	.trace = &trace_arp_rcv,
	.list = LIST_HEAD_INIT(trace_arp_rcv_list.list)
};

trace_t trace_arp_process = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "arp_process",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_arp_process,
	.prog = "__trace_arp_process",
	.parent = &group_arp,
	.rules = LIST_HEAD_INIT(trace_arp_process.rules),
};
trace_list_t trace_arp_process_list = {
	.trace = &trace_arp_process,
	.list = LIST_HEAD_INIT(trace_arp_process_list.list)
};

trace_group_t group_bonding = {
	.name = "bonding",
	.desc = "bonding netdevice",
	.children = LIST_HEAD_INIT(group_bonding.children),
	.traces = LIST_HEAD_INIT(group_bonding.traces),
	.list = LIST_HEAD_INIT(group_bonding.list),
};
trace_t trace_bond_dev_queue_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "bond_dev_queue_xmit",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_bond_dev_queue_xmit,
	.prog = "__trace_bond_dev_queue_xmit",
	.parent = &group_bonding,
	.rules = LIST_HEAD_INIT(trace_bond_dev_queue_xmit.rules),
};
trace_list_t trace_bond_dev_queue_xmit_list = {
	.trace = &trace_bond_dev_queue_xmit,
	.list = LIST_HEAD_INIT(trace_bond_dev_queue_xmit_list.list)
};

trace_group_t group_vxlan = {
	.name = "vxlan",
	.desc = "vxlan model",
	.children = LIST_HEAD_INIT(group_vxlan.children),
	.traces = LIST_HEAD_INIT(group_vxlan.traces),
	.list = LIST_HEAD_INIT(group_vxlan.list),
};
trace_t trace___iptunnel_pull_header = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__iptunnel_pull_header",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX___iptunnel_pull_header,
	.prog = "__trace___iptunnel_pull_header",
	.parent = &group_vxlan,
	.rules = LIST_HEAD_INIT(trace___iptunnel_pull_header.rules),
};
trace_list_t trace___iptunnel_pull_header_list = {
	.trace = &trace___iptunnel_pull_header,
	.list = LIST_HEAD_INIT(trace___iptunnel_pull_header_list.list)
};

trace_t trace_vxlan_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "vxlan_rcv",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_vxlan_rcv,
	.prog = "__trace_vxlan_rcv",
	.parent = &group_vxlan,
	.rules = LIST_HEAD_INIT(trace_vxlan_rcv.rules),
};
trace_list_t trace_vxlan_rcv_list = {
	.trace = &trace_vxlan_rcv,
	.list = LIST_HEAD_INIT(trace_vxlan_rcv_list.list)
};

trace_t trace_vxlan_xmit_one = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "vxlan_xmit_one",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_vxlan_xmit_one,
	.prog = "__trace_vxlan_xmit_one",
	.parent = &group_vxlan,
	.rules = LIST_HEAD_INIT(trace_vxlan_xmit_one.rules),
};
trace_list_t trace_vxlan_xmit_one_list = {
	.trace = &trace_vxlan_xmit_one,
	.list = LIST_HEAD_INIT(trace_vxlan_xmit_one_list.list)
};

trace_group_t group_vlan = {
	.name = "vlan",
	.desc = "vlan module",
	.children = LIST_HEAD_INIT(group_vlan.children),
	.traces = LIST_HEAD_INIT(group_vlan.traces),
	.list = LIST_HEAD_INIT(group_vlan.list),
};
trace_t trace_vlan_do_receive = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "vlan_do_receive",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_vlan_do_receive,
	.prog = "__trace_vlan_do_receive",
	.parent = &group_vlan,
	.rules = LIST_HEAD_INIT(trace_vlan_do_receive.rules),
};
trace_list_t trace_vlan_do_receive_list = {
	.trace = &trace_vlan_do_receive,
	.list = LIST_HEAD_INIT(trace_vlan_do_receive_list.list)
};

trace_t trace_vlan_dev_hard_start_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "vlan_dev_hard_start_xmit",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_vlan_dev_hard_start_xmit,
	.prog = "__trace_vlan_dev_hard_start_xmit",
	.parent = &group_vlan,
	.rules = LIST_HEAD_INIT(trace_vlan_dev_hard_start_xmit.rules),
};
trace_list_t trace_vlan_dev_hard_start_xmit_list = {
	.trace = &trace_vlan_dev_hard_start_xmit,
	.list = LIST_HEAD_INIT(trace_vlan_dev_hard_start_xmit_list.list)
};

trace_group_t group_ovs = {
	.name = "ovs",
	.desc = "openvswitch module",
	.children = LIST_HEAD_INIT(group_ovs.children),
	.traces = LIST_HEAD_INIT(group_ovs.traces),
	.list = LIST_HEAD_INIT(group_ovs.list),
};
trace_t trace_netdev_port_receive = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "netdev_port_receive",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_netdev_port_receive,
	.prog = "__trace_netdev_port_receive",
	.parent = &group_ovs,
	.rules = LIST_HEAD_INIT(trace_netdev_port_receive.rules),
};
trace_list_t trace_netdev_port_receive_list = {
	.trace = &trace_netdev_port_receive,
	.list = LIST_HEAD_INIT(trace_netdev_port_receive_list.list)
};

trace_t trace_ovs_vport_receive = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ovs_vport_receive",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ovs_vport_receive,
	.prog = "__trace_ovs_vport_receive",
	.parent = &group_ovs,
	.rules = LIST_HEAD_INIT(trace_ovs_vport_receive.rules),
};
trace_list_t trace_ovs_vport_receive_list = {
	.trace = &trace_ovs_vport_receive,
	.list = LIST_HEAD_INIT(trace_ovs_vport_receive_list.list)
};

trace_t trace_ovs_dp_process_packet = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ovs_dp_process_packet",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ovs_dp_process_packet,
	.prog = "__trace_ovs_dp_process_packet",
	.parent = &group_ovs,
	.rules = LIST_HEAD_INIT(trace_ovs_dp_process_packet.rules),
};
trace_list_t trace_ovs_dp_process_packet_list = {
	.trace = &trace_ovs_dp_process_packet,
	.list = LIST_HEAD_INIT(trace_ovs_dp_process_packet_list.list)
};

trace_group_t group_packet = {
	.name = "packet",
	.desc = "the process of skb of type PF_PACKET",
	.children = LIST_HEAD_INIT(group_packet.children),
	.traces = LIST_HEAD_INIT(group_packet.traces),
	.list = LIST_HEAD_INIT(group_packet.list),
};
trace_group_t group_pkt_in = {
	.name = "pkt-in",
	.desc = "the process of skb of type PF_PACKET",
	.children = LIST_HEAD_INIT(group_pkt_in.children),
	.traces = LIST_HEAD_INIT(group_pkt_in.traces),
	.list = LIST_HEAD_INIT(group_pkt_in.list),
};
trace_t trace_packet_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "packet_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_packet_rcv,
	.prog = "__trace_packet_rcv",
	.parent = &group_pkt_in,
	.rules = LIST_HEAD_INIT(trace_packet_rcv.rules),
};
trace_list_t trace_packet_rcv_list = {
	.trace = &trace_packet_rcv,
	.list = LIST_HEAD_INIT(trace_packet_rcv_list.list)
};

trace_t trace_tpacket_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tpacket_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tpacket_rcv,
	.prog = "__trace_tpacket_rcv",
	.parent = &group_pkt_in,
	.rules = LIST_HEAD_INIT(trace_tpacket_rcv.rules),
};
trace_list_t trace_tpacket_rcv_list = {
	.trace = &trace_tpacket_rcv,
	.list = LIST_HEAD_INIT(trace_tpacket_rcv_list.list)
};

trace_group_t group_pkt_output = {
	.name = "pkt-output",
	.desc = "the process of skb of type PF_PACKET",
	.children = LIST_HEAD_INIT(group_pkt_output.children),
	.traces = LIST_HEAD_INIT(group_pkt_output.traces),
	.list = LIST_HEAD_INIT(group_pkt_output.list),
};
trace_t trace_packet_direct_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "packet_direct_xmit",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_packet_direct_xmit,
	.prog = "__trace_packet_direct_xmit",
	.parent = &group_pkt_output,
	.rules = LIST_HEAD_INIT(trace_packet_direct_xmit.rules),
};
trace_list_t trace_packet_direct_xmit_list = {
	.trace = &trace_packet_direct_xmit,
	.list = LIST_HEAD_INIT(trace_packet_direct_xmit_list.list)
};

trace_group_t group_netfilter = {
	.name = "netfilter",
	.desc = "netfilter process(filter, nat, etc)",
	.children = LIST_HEAD_INIT(group_netfilter.children),
	.traces = LIST_HEAD_INIT(group_netfilter.traces),
	.list = LIST_HEAD_INIT(group_netfilter.list),
};
trace_group_t group_netfilter_1 = {
	.name = "netfilter",
	.desc = "base netfilter entry",
	.children = LIST_HEAD_INIT(group_netfilter_1.children),
	.traces = LIST_HEAD_INIT(group_netfilter_1.traces),
	.list = LIST_HEAD_INIT(group_netfilter_1.list),
};
trace_t trace_nft_do_chain = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(iptable),
	.arg_count = 2,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "nft_do_chain",
	.skb = 1,
	.custom = true,
	.def = true,
	.index = INDEX_nft_do_chain,
	.prog = "__trace_nft_do_chain",
	.parent = &group_netfilter_1,
	.rules = LIST_HEAD_INIT(trace_nft_do_chain.rules),
};
trace_list_t trace_nft_do_chain_list = {
	.trace = &trace_nft_do_chain,
	.list = LIST_HEAD_INIT(trace_nft_do_chain_list.list)
};
rule_t rule_trace_nft_do_chain_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your iptables rule",
	.msg = PFMT_ERROR"packet is dropped by iptables/iptables-nft"PFMT_END,
};
rule_t rule_trace_nft_do_chain_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_t trace_nf_nat_manip_pkt = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.is_backup = false,
	.probe = false,
	.name = "nf_nat_manip_pkt",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_nf_nat_manip_pkt,
	.prog = "__trace_nf_nat_manip_pkt",
	.parent = &group_netfilter_1,
	.rules = LIST_HEAD_INIT(trace_nf_nat_manip_pkt.rules),
};
trace_list_t trace_nf_nat_manip_pkt_list = {
	.trace = &trace_nf_nat_manip_pkt,
	.list = LIST_HEAD_INIT(trace_nf_nat_manip_pkt_list.list)
};
rule_t rule_trace_nf_nat_manip_pkt_0 = {	.level = RULE_WARN,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_WARN"NAT happens (packet address will change)"PFMT_END,
};

trace_t trace_nf_hook_slow = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(nf),
	.arg_count = 4,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "nf_hook_slow",
	.skb = 1,
	.custom = true,
	.def = true,
	.index = INDEX_nf_hook_slow,
	.prog = "__trace_nf_hook_slow",
	.parent = &group_netfilter_1,
	.rules = LIST_HEAD_INIT(trace_nf_hook_slow.rules),
};
trace_list_t trace_nf_hook_slow_list = {
	.trace = &trace_nf_hook_slow,
	.list = LIST_HEAD_INIT(trace_nf_hook_slow_list.list)
};
rule_t rule_trace_nf_hook_slow_0 = {	.level = RULE_ERROR,
	.expected = -1,
	.type = RULE_RETURN_EQ,
	.adv = "check your netfilter rule",
	.msg = PFMT_ERROR"packet is dropped by netfilter (NF_DROP)"PFMT_END,
};

trace_t trace_ipt_do_table = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(iptable),
	.arg_count = 3,
	.is_backup = true,
	.probe = false,
	.monitor = 1,
	.name = "ipt_do_table",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ipt_do_table,
	.prog = "__trace_ipt_do_table",
	.parent = &group_netfilter_1,
	.rules = LIST_HEAD_INIT(trace_ipt_do_table.rules),
};
trace_list_t trace_ipt_do_table_list = {
	.trace = &trace_ipt_do_table,
	.list = LIST_HEAD_INIT(trace_ipt_do_table_list.list)
};
rule_t rule_trace_ipt_do_table_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your iptables rule",
	.msg = PFMT_ERROR"packet is dropped by iptables/iptables-legacy"PFMT_END,
};
rule_t rule_trace_ipt_do_table_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_t trace_ipt_do_table_legacy = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(iptable),
	.arg_count = 3,
	.cond = "[ $(verlte \"$(uname -r)\" \"5.16\") -eq -1 ]",
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "ipt_do_table",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ipt_do_table_legacy,
	.prog = "__trace_ipt_do_table_legacy",
	.parent = &group_netfilter_1,
	.rules = LIST_HEAD_INIT(trace_ipt_do_table_legacy.rules),
};
trace_list_t trace_ipt_do_table_legacy_list = {
	.trace = &trace_ipt_do_table_legacy,
	.list = LIST_HEAD_INIT(trace_ipt_do_table_legacy_list.list)
};
rule_t rule_trace_ipt_do_table_legacy_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your iptables rule",
	.msg = PFMT_ERROR"packet is dropped by iptables/iptables-legacy"PFMT_END,
};
rule_t rule_trace_ipt_do_table_legacy_1 = {	.level = RULE_INFO,
	.expected = 1,
	.type = RULE_RETURN_EQ,
	.msg = PFMT_EMPH"packet is accepted"PFMT_END,
};

trace_group_t group_conntrack = {
	.name = "conntrack",
	.desc = "connection track (used by nat mostly)",
	.children = LIST_HEAD_INIT(group_conntrack.children),
	.traces = LIST_HEAD_INIT(group_conntrack.traces),
	.list = LIST_HEAD_INIT(group_conntrack.list),
};
trace_t trace_ipv4_confirm = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipv4_confirm",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_ipv4_confirm,
	.prog = "__trace_ipv4_confirm",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_ipv4_confirm.rules),
};
trace_list_t trace_ipv4_confirm_list = {
	.trace = &trace_ipv4_confirm,
	.list = LIST_HEAD_INIT(trace_ipv4_confirm_list.list)
};

trace_t trace_nf_confirm = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "nf_confirm",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_nf_confirm,
	.prog = "__trace_nf_confirm",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_nf_confirm.rules),
};
trace_list_t trace_nf_confirm_list = {
	.trace = &trace_nf_confirm,
	.list = LIST_HEAD_INIT(trace_nf_confirm_list.list)
};

trace_t trace_ipv4_conntrack_in = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipv4_conntrack_in",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_ipv4_conntrack_in,
	.prog = "__trace_ipv4_conntrack_in",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_ipv4_conntrack_in.rules),
};
trace_list_t trace_ipv4_conntrack_in_list = {
	.trace = &trace_ipv4_conntrack_in,
	.list = LIST_HEAD_INIT(trace_ipv4_conntrack_in_list.list)
};

trace_t trace_nf_conntrack_in = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "nf_conntrack_in",
	.skb = 4,
	.custom = false,
	.def = false,
	.index = INDEX_nf_conntrack_in,
	.prog = "__trace_nf_conntrack_in",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_nf_conntrack_in.rules),
};
trace_list_t trace_nf_conntrack_in_list = {
	.trace = &trace_nf_conntrack_in,
	.list = LIST_HEAD_INIT(trace_nf_conntrack_in_list.list)
};

trace_t trace_ipv4_pkt_to_tuple = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipv4_pkt_to_tuple",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_ipv4_pkt_to_tuple,
	.prog = "__trace_ipv4_pkt_to_tuple",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_ipv4_pkt_to_tuple.rules),
};
trace_list_t trace_ipv4_pkt_to_tuple_list = {
	.trace = &trace_ipv4_pkt_to_tuple,
	.list = LIST_HEAD_INIT(trace_ipv4_pkt_to_tuple_list.list)
};

trace_t trace_tcp_new = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_new",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_tcp_new,
	.prog = "__trace_tcp_new",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_tcp_new.rules),
};
trace_list_t trace_tcp_new_list = {
	.trace = &trace_tcp_new,
	.list = LIST_HEAD_INIT(trace_tcp_new_list.list)
};

trace_t trace_tcp_pkt_to_tuple = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_pkt_to_tuple",
	.skb = 1,
	.custom = false,
	.def = false,
	.index = INDEX_tcp_pkt_to_tuple,
	.prog = "__trace_tcp_pkt_to_tuple",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_tcp_pkt_to_tuple.rules),
};
trace_list_t trace_tcp_pkt_to_tuple_list = {
	.trace = &trace_tcp_pkt_to_tuple,
	.list = LIST_HEAD_INIT(trace_tcp_pkt_to_tuple_list.list)
};

trace_t trace_resolve_normal_ct = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "resolve_normal_ct",
	.skb = 3,
	.custom = false,
	.def = false,
	.index = INDEX_resolve_normal_ct,
	.prog = "__trace_resolve_normal_ct",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_resolve_normal_ct.rules),
};
trace_list_t trace_resolve_normal_ct_list = {
	.trace = &trace_resolve_normal_ct,
	.list = LIST_HEAD_INIT(trace_resolve_normal_ct_list.list)
};

trace_t trace_tcp_packet = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_packet",
	.skb = 2,
	.custom = false,
	.def = false,
	.index = INDEX_tcp_packet,
	.prog = "__trace_tcp_packet",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_tcp_packet.rules),
};
trace_list_t trace_tcp_packet_list = {
	.trace = &trace_tcp_packet,
	.list = LIST_HEAD_INIT(trace_tcp_packet_list.list)
};

trace_t trace_tcp_in_window = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.arg_count = 7,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "tcp_in_window",
	.skb = 5,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_in_window,
	.prog = "__trace_tcp_in_window",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace_tcp_in_window.rules),
};
trace_list_t trace_tcp_in_window_list = {
	.trace = &trace_tcp_in_window,
	.list = LIST_HEAD_INIT(trace_tcp_in_window_list.list)
};
rule_t rule_trace_tcp_in_window_0 = {	.level = RULE_WARN,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "enable 'nf_conntrack_tcp_be_liberal' with the command\n'echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal'\n",
	.msg = PFMT_WARN"conntrack window check failed (packet out ordering)"PFMT_END,
};

trace_t trace___nf_ct_refresh_acct = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__nf_ct_refresh_acct",
	.skb = 3,
	.custom = false,
	.def = false,
	.index = INDEX___nf_ct_refresh_acct,
	.prog = "__trace___nf_ct_refresh_acct",
	.parent = &group_conntrack,
	.rules = LIST_HEAD_INIT(trace___nf_ct_refresh_acct.rules),
};
trace_list_t trace___nf_ct_refresh_acct_list = {
	.trace = &trace___nf_ct_refresh_acct,
	.list = LIST_HEAD_INIT(trace___nf_ct_refresh_acct_list.list)
};

trace_group_t group_ip = {
	.name = "ip",
	.desc = "ip protocol layer (L3) of the network stack",
	.children = LIST_HEAD_INIT(group_ip.children),
	.traces = LIST_HEAD_INIT(group_ip.traces),
	.list = LIST_HEAD_INIT(group_ip.list),
};
trace_group_t group_ip_in = {
	.name = "ip-in",
	.desc = "ip layer of packet in",
	.children = LIST_HEAD_INIT(group_ip_in.children),
	.traces = LIST_HEAD_INIT(group_ip_in.traces),
	.list = LIST_HEAD_INIT(group_ip_in.list),
};
trace_t trace_ip_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip_rcv,
	.prog = "__trace_ip_rcv",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_rcv.rules),
};
trace_list_t trace_ip_rcv_list = {
	.trace = &trace_ip_rcv,
	.list = LIST_HEAD_INIT(trace_ip_rcv_list.list)
};

trace_t trace_ip_rcv_core = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_rcv_core",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip_rcv_core,
	.prog = "__trace_ip_rcv_core",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_rcv_core.rules),
};
trace_list_t trace_ip_rcv_core_list = {
	.trace = &trace_ip_rcv_core,
	.list = LIST_HEAD_INIT(trace_ip_rcv_core_list.list)
};

trace_t trace_ip_rcv_finish = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_rcv_finish",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip_rcv_finish,
	.prog = "__trace_ip_rcv_finish",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_rcv_finish.rules),
};
trace_list_t trace_ip_rcv_finish_list = {
	.trace = &trace_ip_rcv_finish,
	.list = LIST_HEAD_INIT(trace_ip_rcv_finish_list.list)
};

trace_t trace_ip_local_deliver = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_local_deliver",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip_local_deliver,
	.prog = "__trace_ip_local_deliver",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_local_deliver.rules),
};
trace_list_t trace_ip_local_deliver_list = {
	.trace = &trace_ip_local_deliver,
	.list = LIST_HEAD_INIT(trace_ip_local_deliver_list.list)
};

trace_t trace_ip_local_deliver_finish = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_local_deliver_finish",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip_local_deliver_finish,
	.prog = "__trace_ip_local_deliver_finish",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_local_deliver_finish.rules),
};
trace_list_t trace_ip_local_deliver_finish_list = {
	.trace = &trace_ip_local_deliver_finish,
	.list = LIST_HEAD_INIT(trace_ip_local_deliver_finish_list.list)
};

trace_t trace_ip_forward = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_forward",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip_forward,
	.prog = "__trace_ip_forward",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_forward.rules),
};
trace_list_t trace_ip_forward_list = {
	.trace = &trace_ip_forward,
	.list = LIST_HEAD_INIT(trace_ip_forward_list.list)
};

trace_t trace_ip_forward_finish = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_forward_finish",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip_forward_finish,
	.prog = "__trace_ip_forward_finish",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip_forward_finish.rules),
};
trace_list_t trace_ip_forward_finish_list = {
	.trace = &trace_ip_forward_finish,
	.list = LIST_HEAD_INIT(trace_ip_forward_finish_list.list)
};

trace_t trace_ip6_forward = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_forward",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_forward,
	.prog = "__trace_ip6_forward",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip6_forward.rules),
};
trace_list_t trace_ip6_forward_list = {
	.trace = &trace_ip6_forward,
	.list = LIST_HEAD_INIT(trace_ip6_forward_list.list)
};

trace_t trace_ip6_rcv_finish = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_rcv_finish",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_rcv_finish,
	.prog = "__trace_ip6_rcv_finish",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip6_rcv_finish.rules),
};
trace_list_t trace_ip6_rcv_finish_list = {
	.trace = &trace_ip6_rcv_finish,
	.list = LIST_HEAD_INIT(trace_ip6_rcv_finish_list.list)
};

trace_t trace_ip6_rcv_core = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_rcv_core",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_rcv_core,
	.prog = "__trace_ip6_rcv_core",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ip6_rcv_core.rules),
};
trace_list_t trace_ip6_rcv_core_list = {
	.trace = &trace_ip6_rcv_core,
	.list = LIST_HEAD_INIT(trace_ip6_rcv_core_list.list)
};

trace_t trace_ipv6_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ipv6_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ipv6_rcv,
	.prog = "__trace_ipv6_rcv",
	.parent = &group_ip_in,
	.rules = LIST_HEAD_INIT(trace_ipv6_rcv.rules),
};
trace_list_t trace_ipv6_rcv_list = {
	.trace = &trace_ipv6_rcv,
	.list = LIST_HEAD_INIT(trace_ipv6_rcv_list.list)
};

trace_group_t group_ip_out = {
	.name = "ip-out",
	.desc = "ip layer of packet out",
	.children = LIST_HEAD_INIT(group_ip_out.children),
	.traces = LIST_HEAD_INIT(group_ip_out.traces),
	.list = LIST_HEAD_INIT(group_ip_out.list),
};
trace_t trace___ip_queue_xmit = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__ip_queue_xmit",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX___ip_queue_xmit,
	.prog = "__trace___ip_queue_xmit",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace___ip_queue_xmit.rules),
};
trace_list_t trace___ip_queue_xmit_list = {
	.trace = &trace___ip_queue_xmit,
	.list = LIST_HEAD_INIT(trace___ip_queue_xmit_list.list)
};

trace_t trace___ip_local_out = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__ip_local_out",
	.skb = 3,
	.sk = 2,
	.custom = false,
	.def = true,
	.index = INDEX___ip_local_out,
	.prog = "__trace___ip_local_out",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace___ip_local_out.rules),
};
trace_list_t trace___ip_local_out_list = {
	.trace = &trace___ip_local_out,
	.list = LIST_HEAD_INIT(trace___ip_local_out_list.list)
};

trace_t trace_ip_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_output",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip_output,
	.prog = "__trace_ip_output",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip_output.rules),
};
trace_list_t trace_ip_output_list = {
	.trace = &trace_ip_output,
	.list = LIST_HEAD_INIT(trace_ip_output_list.list)
};

trace_t trace_ip_finish_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_finish_output",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip_finish_output,
	.prog = "__trace_ip_finish_output",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip_finish_output.rules),
};
trace_list_t trace_ip_finish_output_list = {
	.trace = &trace_ip_finish_output,
	.list = LIST_HEAD_INIT(trace_ip_finish_output_list.list)
};

trace_t trace_ip_finish_output_gso = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_finish_output_gso",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip_finish_output_gso,
	.prog = "__trace_ip_finish_output_gso",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip_finish_output_gso.rules),
};
trace_list_t trace_ip_finish_output_gso_list = {
	.trace = &trace_ip_finish_output_gso,
	.list = LIST_HEAD_INIT(trace_ip_finish_output_gso_list.list)
};

trace_t trace_ip_finish_output2 = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip_finish_output2",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip_finish_output2,
	.prog = "__trace_ip_finish_output2",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip_finish_output2.rules),
};
trace_list_t trace_ip_finish_output2_list = {
	.trace = &trace_ip_finish_output2,
	.list = LIST_HEAD_INIT(trace_ip_finish_output2_list.list)
};

trace_t trace_ip6_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_output",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_output,
	.prog = "__trace_ip6_output",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip6_output.rules),
};
trace_list_t trace_ip6_output_list = {
	.trace = &trace_ip6_output,
	.list = LIST_HEAD_INIT(trace_ip6_output_list.list)
};

trace_t trace_ip6_finish_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_finish_output",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_finish_output,
	.prog = "__trace_ip6_finish_output",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip6_finish_output.rules),
};
trace_list_t trace_ip6_finish_output_list = {
	.trace = &trace_ip6_finish_output,
	.list = LIST_HEAD_INIT(trace_ip6_finish_output_list.list)
};

trace_t trace_ip6_finish_output2 = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_finish_output2",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_finish_output2,
	.prog = "__trace_ip6_finish_output2",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip6_finish_output2.rules),
};
trace_list_t trace_ip6_finish_output2_list = {
	.trace = &trace_ip6_finish_output2,
	.list = LIST_HEAD_INIT(trace_ip6_finish_output2_list.list)
};

trace_t trace_ip6_send_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_send_skb",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_send_skb,
	.prog = "__trace_ip6_send_skb",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip6_send_skb.rules),
};
trace_list_t trace_ip6_send_skb_list = {
	.trace = &trace_ip6_send_skb,
	.list = LIST_HEAD_INIT(trace_ip6_send_skb_list.list)
};

trace_t trace_ip6_local_out = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ip6_local_out",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_ip6_local_out,
	.prog = "__trace_ip6_local_out",
	.parent = &group_ip_out,
	.rules = LIST_HEAD_INIT(trace_ip6_local_out.rules),
};
trace_list_t trace_ip6_local_out_list = {
	.trace = &trace_ip6_local_out,
	.list = LIST_HEAD_INIT(trace_ip6_local_out_list.list)
};

trace_group_t group_xfrm = {
	.name = "xfrm",
	.desc = "xfrm module",
	.children = LIST_HEAD_INIT(group_xfrm.children),
	.traces = LIST_HEAD_INIT(group_xfrm.traces),
	.list = LIST_HEAD_INIT(group_xfrm.list),
};
trace_t trace_xfrm4_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_output",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_output,
	.prog = "__trace_xfrm4_output",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm4_output.rules),
};
trace_list_t trace_xfrm4_output_list = {
	.trace = &trace_xfrm4_output,
	.list = LIST_HEAD_INIT(trace_xfrm4_output_list.list)
};

trace_t trace_xfrm_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm_output",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm_output,
	.prog = "__trace_xfrm_output",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm_output.rules),
};
trace_list_t trace_xfrm_output_list = {
	.trace = &trace_xfrm_output,
	.list = LIST_HEAD_INIT(trace_xfrm_output_list.list)
};

trace_t trace_xfrm_output2 = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm_output2",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm_output2,
	.prog = "__trace_xfrm_output2",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm_output2.rules),
};
trace_list_t trace_xfrm_output2_list = {
	.trace = &trace_xfrm_output2,
	.list = LIST_HEAD_INIT(trace_xfrm_output2_list.list)
};

trace_t trace_xfrm_output_gso = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm_output_gso",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm_output_gso,
	.prog = "__trace_xfrm_output_gso",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm_output_gso.rules),
};
trace_list_t trace_xfrm_output_gso_list = {
	.trace = &trace_xfrm_output_gso,
	.list = LIST_HEAD_INIT(trace_xfrm_output_gso_list.list)
};

trace_t trace_xfrm_output_resume = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm_output_resume",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm_output_resume,
	.prog = "__trace_xfrm_output_resume",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm_output_resume.rules),
};
trace_list_t trace_xfrm_output_resume_list = {
	.trace = &trace_xfrm_output_resume,
	.list = LIST_HEAD_INIT(trace_xfrm_output_resume_list.list)
};

trace_t trace_xfrm4_transport_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_transport_output",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_transport_output,
	.prog = "__trace_xfrm4_transport_output",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm4_transport_output.rules),
};
trace_list_t trace_xfrm4_transport_output_list = {
	.trace = &trace_xfrm4_transport_output,
	.list = LIST_HEAD_INIT(trace_xfrm4_transport_output_list.list)
};

trace_t trace_xfrm4_prepare_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_prepare_output",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_prepare_output,
	.prog = "__trace_xfrm4_prepare_output",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm4_prepare_output.rules),
};
trace_list_t trace_xfrm4_prepare_output_list = {
	.trace = &trace_xfrm4_prepare_output,
	.list = LIST_HEAD_INIT(trace_xfrm4_prepare_output_list.list)
};

trace_t trace_xfrm4_policy_check = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_policy_check",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_policy_check,
	.prog = "__trace_xfrm4_policy_check",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm4_policy_check.rules),
};
trace_list_t trace_xfrm4_policy_check_list = {
	.trace = &trace_xfrm4_policy_check,
	.list = LIST_HEAD_INIT(trace_xfrm4_policy_check_list.list)
};

trace_t trace_xfrm4_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_rcv,
	.prog = "__trace_xfrm4_rcv",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm4_rcv.rules),
};
trace_list_t trace_xfrm4_rcv_list = {
	.trace = &trace_xfrm4_rcv,
	.list = LIST_HEAD_INIT(trace_xfrm4_rcv_list.list)
};

trace_t trace_xfrm_input = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm_input",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm_input,
	.prog = "__trace_xfrm_input",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm_input.rules),
};
trace_list_t trace_xfrm_input_list = {
	.trace = &trace_xfrm_input,
	.list = LIST_HEAD_INIT(trace_xfrm_input_list.list)
};

trace_t trace_xfrm4_transport_input = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_transport_input",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_transport_input,
	.prog = "__trace_xfrm4_transport_input",
	.parent = &group_xfrm,
	.rules = LIST_HEAD_INIT(trace_xfrm4_transport_input.rules),
};
trace_list_t trace_xfrm4_transport_input_list = {
	.trace = &trace_xfrm4_transport_input,
	.list = LIST_HEAD_INIT(trace_xfrm4_transport_input_list.list)
};

trace_group_t group_esp = {
	.name = "esp",
	.desc = "ip layer of packet out",
	.children = LIST_HEAD_INIT(group_esp.children),
	.traces = LIST_HEAD_INIT(group_esp.traces),
	.list = LIST_HEAD_INIT(group_esp.list),
};
trace_t trace_ah_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ah_output",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ah_output,
	.prog = "__trace_ah_output",
	.parent = &group_esp,
	.rules = LIST_HEAD_INIT(trace_ah_output.rules),
};
trace_list_t trace_ah_output_list = {
	.trace = &trace_ah_output,
	.list = LIST_HEAD_INIT(trace_ah_output_list.list)
};

trace_t trace_esp_output = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "esp_output",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_esp_output,
	.prog = "__trace_esp_output",
	.parent = &group_esp,
	.rules = LIST_HEAD_INIT(trace_esp_output.rules),
};
trace_list_t trace_esp_output_list = {
	.trace = &trace_esp_output,
	.list = LIST_HEAD_INIT(trace_esp_output_list.list)
};

trace_t trace_esp_output_tail = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "esp_output_tail",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_esp_output_tail,
	.prog = "__trace_esp_output_tail",
	.parent = &group_esp,
	.rules = LIST_HEAD_INIT(trace_esp_output_tail.rules),
};
trace_list_t trace_esp_output_tail_list = {
	.trace = &trace_esp_output_tail,
	.list = LIST_HEAD_INIT(trace_esp_output_tail_list.list)
};

trace_t trace_ah_input = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ah_input",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ah_input,
	.prog = "__trace_ah_input",
	.parent = &group_esp,
	.rules = LIST_HEAD_INIT(trace_ah_input.rules),
};
trace_list_t trace_ah_input_list = {
	.trace = &trace_ah_input,
	.list = LIST_HEAD_INIT(trace_ah_input_list.list)
};

trace_t trace_esp_input = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "esp_input",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_esp_input,
	.prog = "__trace_esp_input",
	.parent = &group_esp,
	.rules = LIST_HEAD_INIT(trace_esp_input.rules),
};
trace_list_t trace_esp_input_list = {
	.trace = &trace_esp_input,
	.list = LIST_HEAD_INIT(trace_esp_input_list.list)
};

trace_group_t group_ip_route = {
	.name = "ip-route",
	.desc = "ip route for packet in and out",
	.children = LIST_HEAD_INIT(group_ip_route.children),
	.traces = LIST_HEAD_INIT(group_ip_route.traces),
	.list = LIST_HEAD_INIT(group_ip_route.list),
};
trace_t trace_fib_validate_source = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 8,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "fib_validate_source",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_fib_validate_source,
	.prog = "__trace_fib_validate_source",
	.parent = &group_ip_route,
	.rules = LIST_HEAD_INIT(trace_fib_validate_source.rules),
};
trace_list_t trace_fib_validate_source_list = {
	.trace = &trace_fib_validate_source,
	.list = LIST_HEAD_INIT(trace_fib_validate_source_list.list)
};
rule_t rule_trace_fib_validate_source_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_NE,
	.adv = "check you ip route config or disable rp_filter with command\n'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'\n",
	.msg = PFMT_ERROR"source address valid failed (properly rp_filter fail)"PFMT_END,
};

trace_t trace_ip_route_input_slow = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 6,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "ip_route_input_slow",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ip_route_input_slow,
	.prog = "__trace_ip_route_input_slow",
	.parent = &group_ip_route,
	.rules = LIST_HEAD_INIT(trace_ip_route_input_slow.rules),
};
trace_list_t trace_ip_route_input_slow_list = {
	.trace = &trace_ip_route_input_slow,
	.list = LIST_HEAD_INIT(trace_ip_route_input_slow_list.list)
};
rule_t rule_trace_ip_route_input_slow_0 = {	.level = RULE_ERROR,
	.expected = 0,
	.type = RULE_RETURN_NE,
	.adv = "check packet address and your route",
	.msg = PFMT_ERROR"failed to route packet in input path"PFMT_END,
};

trace_group_t group_tcp = {
	.name = "tcp",
	.desc = "tcp protocol layer (L4) of the network stack",
	.children = LIST_HEAD_INIT(group_tcp.children),
	.traces = LIST_HEAD_INIT(group_tcp.traces),
	.list = LIST_HEAD_INIT(group_tcp.list),
};
trace_group_t group_tcp_in = {
	.name = "tcp-in",
	.desc = "tcp layer of packet in",
	.children = LIST_HEAD_INIT(group_tcp_in.children),
	.traces = LIST_HEAD_INIT(group_tcp_in.traces),
	.list = LIST_HEAD_INIT(group_tcp_in.list),
};
trace_t trace_tcp_v4_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v4_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_v4_rcv,
	.prog = "__trace_tcp_v4_rcv",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_v4_rcv.rules),
};
trace_list_t trace_tcp_v4_rcv_list = {
	.trace = &trace_tcp_v4_rcv,
	.list = LIST_HEAD_INIT(trace_tcp_v4_rcv_list.list)
};

trace_t trace_tcp_v6_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v6_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_v6_rcv,
	.prog = "__trace_tcp_v6_rcv",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_v6_rcv.rules),
};
trace_list_t trace_tcp_v6_rcv_list = {
	.trace = &trace_tcp_v6_rcv,
	.list = LIST_HEAD_INIT(trace_tcp_v6_rcv_list.list)
};

trace_t trace_tcp_filter = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_filter",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_filter,
	.prog = "__trace_tcp_filter",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_filter.rules),
};
trace_list_t trace_tcp_filter_list = {
	.trace = &trace_tcp_filter,
	.list = LIST_HEAD_INIT(trace_tcp_filter_list.list)
};

trace_t trace_tcp_child_process = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_child_process",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_child_process,
	.prog = "__trace_tcp_child_process",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_child_process.rules),
};
trace_list_t trace_tcp_child_process_list = {
	.trace = &trace_tcp_child_process,
	.list = LIST_HEAD_INIT(trace_tcp_child_process_list.list)
};

trace_t trace_tcp_v4_send_reset = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(reset),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v4_send_reset",
	.skb = 2,
	.sk = 1,
	.custom = true,
	.def = true,
	.index = INDEX_tcp_v4_send_reset,
	.prog = "__trace_tcp_v4_send_reset",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_v4_send_reset.rules),
};
trace_list_t trace_tcp_v4_send_reset_list = {
	.trace = &trace_tcp_v4_send_reset,
	.list = LIST_HEAD_INIT(trace_tcp_v4_send_reset_list.list)
};
rule_t rule_trace_tcp_v4_send_reset_0 = {	.level = RULE_ERROR,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_ERROR"connection reset initiated by transport layer (TCP stack, skb)"PFMT_END,
};

trace_t trace_tcp_v6_send_reset = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(reset),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v6_send_reset",
	.skb = 2,
	.sk = 1,
	.custom = true,
	.def = true,
	.index = INDEX_tcp_v6_send_reset,
	.prog = "__trace_tcp_v6_send_reset",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_v6_send_reset.rules),
};
trace_list_t trace_tcp_v6_send_reset_list = {
	.trace = &trace_tcp_v6_send_reset,
	.list = LIST_HEAD_INIT(trace_tcp_v6_send_reset_list.list)
};
rule_t rule_trace_tcp_v6_send_reset_0 = {	.level = RULE_ERROR,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_ERROR"connection reset initiated by transport layer (TCP stack, skb)"PFMT_END,
};

trace_t trace_tcp_v4_do_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v4_do_rcv",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_v4_do_rcv,
	.prog = "__trace_tcp_v4_do_rcv",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_v4_do_rcv.rules),
};
trace_list_t trace_tcp_v4_do_rcv_list = {
	.trace = &trace_tcp_v4_do_rcv,
	.list = LIST_HEAD_INIT(trace_tcp_v4_do_rcv_list.list)
};

trace_t trace_tcp_v6_do_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v6_do_rcv",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_v6_do_rcv,
	.prog = "__trace_tcp_v6_do_rcv",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_v6_do_rcv.rules),
};
trace_list_t trace_tcp_v6_do_rcv_list = {
	.trace = &trace_tcp_v6_do_rcv,
	.list = LIST_HEAD_INIT(trace_tcp_v6_do_rcv_list.list)
};

trace_t trace_tcp_rcv_established = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_rcv_established",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_rcv_established,
	.prog = "__trace_tcp_rcv_established",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_rcv_established.rules),
};
trace_list_t trace_tcp_rcv_established_list = {
	.trace = &trace_tcp_rcv_established,
	.list = LIST_HEAD_INIT(trace_tcp_rcv_established_list.list)
};

trace_t trace_tcp_rcv_state_process = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_rcv_state_process",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_rcv_state_process,
	.prog = "__trace_tcp_rcv_state_process",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_rcv_state_process.rules),
};
trace_list_t trace_tcp_rcv_state_process_list = {
	.trace = &trace_tcp_rcv_state_process,
	.list = LIST_HEAD_INIT(trace_tcp_rcv_state_process_list.list)
};
rule_t rule_trace_tcp_rcv_state_process_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"TCP socket state has changed"PFMT_END,
};

trace_t trace_tcp_queue_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_queue_rcv",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_queue_rcv,
	.prog = "__trace_tcp_queue_rcv",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_queue_rcv.rules),
};
trace_list_t trace_tcp_queue_rcv_list = {
	.trace = &trace_tcp_queue_rcv,
	.list = LIST_HEAD_INIT(trace_tcp_queue_rcv_list.list)
};

trace_t trace_tcp_data_queue_ofo = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_data_queue_ofo",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_data_queue_ofo,
	.prog = "__trace_tcp_data_queue_ofo",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_data_queue_ofo.rules),
};
trace_list_t trace_tcp_data_queue_ofo_list = {
	.trace = &trace_tcp_data_queue_ofo,
	.list = LIST_HEAD_INIT(trace_tcp_data_queue_ofo_list.list)
};

trace_t trace_tcp_ack_probe = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_ack_probe",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_ack_probe,
	.prog = "__trace_tcp_ack_probe",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_ack_probe.rules),
};
trace_list_t trace_tcp_ack_probe_list = {
	.trace = &trace_tcp_ack_probe,
	.list = LIST_HEAD_INIT(trace_tcp_ack_probe_list.list)
};

trace_t trace_tcp_ack = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_ack",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_ack,
	.prog = "__trace_tcp_ack",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_ack.rules),
};
trace_list_t trace_tcp_ack_list = {
	.trace = &trace_tcp_ack,
	.list = LIST_HEAD_INIT(trace_tcp_ack_list.list)
};

trace_t trace_tcp_probe_timer = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_probe_timer",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_probe_timer,
	.prog = "__trace_tcp_probe_timer",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_probe_timer.rules),
};
trace_list_t trace_tcp_probe_timer_list = {
	.trace = &trace_tcp_probe_timer,
	.list = LIST_HEAD_INIT(trace_tcp_probe_timer_list.list)
};

trace_t trace_tcp_send_probe0 = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_send_probe0",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_send_probe0,
	.prog = "__trace_tcp_send_probe0",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_send_probe0.rules),
};
trace_list_t trace_tcp_send_probe0_list = {
	.trace = &trace_tcp_send_probe0,
	.list = LIST_HEAD_INIT(trace_tcp_send_probe0_list.list)
};
rule_t rule_trace_tcp_send_probe0_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"send zero-window probe packet"PFMT_END,
};

trace_t trace___inet_lookup_listener = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.arg_count = 10,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "__inet_lookup_listener",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX___inet_lookup_listener,
	.prog = "__trace___inet_lookup_listener",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace___inet_lookup_listener.rules),
};
trace_list_t trace___inet_lookup_listener_list = {
	.trace = &trace___inet_lookup_listener,
	.list = LIST_HEAD_INIT(trace___inet_lookup_listener_list.list)
};
rule_t rule_trace___inet_lookup_listener_0 = {	.level = RULE_WARN,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your target tcp port",
	.msg = PFMT_WARN"tcp port is not listened"PFMT_END,
};

trace_t trace_inet6_lookup_listener = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.arg_count = 10,
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "inet6_lookup_listener",
	.skb = 3,
	.custom = false,
	.def = true,
	.index = INDEX_inet6_lookup_listener,
	.prog = "__trace_inet6_lookup_listener",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_inet6_lookup_listener.rules),
};
trace_list_t trace_inet6_lookup_listener_list = {
	.trace = &trace_inet6_lookup_listener,
	.list = LIST_HEAD_INIT(trace_inet6_lookup_listener_list.list)
};
rule_t rule_trace_inet6_lookup_listener_0 = {	.level = RULE_WARN,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "check your target tcp port",
	.msg = PFMT_WARN"tcp port is not listened"PFMT_END,
};

trace_t trace_tcp_bad_csum = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.monitor = 2,
	.name = "tcp_bad_csum",
	.skb = 1,
	.skboffset = 8,
	.custom = false,
	.tp = "tcp/tcp_bad_csum",
	.def = true,
	.index = INDEX_tcp_bad_csum,
	.prog = "__trace_tcp_bad_csum",
	.parent = &group_tcp_in,
	.rules = LIST_HEAD_INIT(trace_tcp_bad_csum.rules),
};
trace_list_t trace_tcp_bad_csum_list = {
	.trace = &trace_tcp_bad_csum,
	.list = LIST_HEAD_INIT(trace_tcp_bad_csum_list.list)
};
rule_t rule_trace_tcp_bad_csum_0 = {	.level = RULE_ERROR,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_ERROR"TCP packet has bad csum"PFMT_END,
};

trace_group_t group_tcp_out = {
	.name = "tcp-out",
	.desc = "tcp layer of packet out",
	.children = LIST_HEAD_INIT(group_tcp_out.children),
	.traces = LIST_HEAD_INIT(group_tcp_out.traces),
	.list = LIST_HEAD_INIT(group_tcp_out.list),
};
trace_t trace_tcp_sendmsg_locked = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_sendmsg_locked",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_sendmsg_locked,
	.prog = "__trace_tcp_sendmsg_locked",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace_tcp_sendmsg_locked.rules),
};
trace_list_t trace_tcp_sendmsg_locked_list = {
	.trace = &trace_tcp_sendmsg_locked,
	.list = LIST_HEAD_INIT(trace_tcp_sendmsg_locked_list.list)
};

trace_t trace_tcp_skb_entail = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_skb_entail",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_skb_entail,
	.prog = "__trace_tcp_skb_entail",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace_tcp_skb_entail.rules),
};
trace_list_t trace_tcp_skb_entail_list = {
	.trace = &trace_tcp_skb_entail,
	.list = LIST_HEAD_INIT(trace_tcp_skb_entail_list.list)
};

trace_t trace_skb_entail = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "skb_entail",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_skb_entail,
	.prog = "__trace_skb_entail",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace_skb_entail.rules),
};
trace_list_t trace_skb_entail_list = {
	.trace = &trace_skb_entail,
	.list = LIST_HEAD_INIT(trace_skb_entail_list.list)
};

trace_t trace___tcp_push_pending_frames = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__tcp_push_pending_frames",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX___tcp_push_pending_frames,
	.prog = "__trace___tcp_push_pending_frames",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace___tcp_push_pending_frames.rules),
};
trace_list_t trace___tcp_push_pending_frames_list = {
	.trace = &trace___tcp_push_pending_frames,
	.list = LIST_HEAD_INIT(trace___tcp_push_pending_frames_list.list)
};

trace_t trace___tcp_transmit_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__tcp_transmit_skb",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX___tcp_transmit_skb,
	.prog = "__trace___tcp_transmit_skb",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace___tcp_transmit_skb.rules),
};
trace_list_t trace___tcp_transmit_skb_list = {
	.trace = &trace___tcp_transmit_skb,
	.list = LIST_HEAD_INIT(trace___tcp_transmit_skb_list.list)
};
rule_t rule_trace___tcp_transmit_skb_0 = {	.level = RULE_WARN,
	.expected = 0,
	.type = RULE_RETURN_NE,
	.msg = PFMT_WARN"failed to xmit skb to ip layer"PFMT_END,
};

trace_t trace___tcp_retransmit_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__tcp_retransmit_skb",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX___tcp_retransmit_skb,
	.prog = "__trace___tcp_retransmit_skb",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace___tcp_retransmit_skb.rules),
};
trace_list_t trace___tcp_retransmit_skb_list = {
	.trace = &trace___tcp_retransmit_skb,
	.list = LIST_HEAD_INIT(trace___tcp_retransmit_skb_list.list)
};

trace_t trace_tcp_rate_skb_delivered = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_rate_skb_delivered",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_rate_skb_delivered,
	.prog = "__trace_tcp_rate_skb_delivered",
	.parent = &group_tcp_out,
	.rules = LIST_HEAD_INIT(trace_tcp_rate_skb_delivered.rules),
};
trace_list_t trace_tcp_rate_skb_delivered_list = {
	.trace = &trace_tcp_rate_skb_delivered,
	.list = LIST_HEAD_INIT(trace_tcp_rate_skb_delivered_list.list)
};

trace_group_t group_udp = {
	.name = "udp",
	.desc = "udp protocol layer (L4) of the network stack",
	.children = LIST_HEAD_INIT(group_udp.children),
	.traces = LIST_HEAD_INIT(group_udp.traces),
	.list = LIST_HEAD_INIT(group_udp.list),
};
trace_group_t group_udp_in = {
	.name = "udp-in",
	.desc = "udp layer of packet in",
	.children = LIST_HEAD_INIT(group_udp_in.children),
	.traces = LIST_HEAD_INIT(group_udp_in.traces),
	.list = LIST_HEAD_INIT(group_udp_in.list),
};
trace_t trace_udp_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "udp_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_udp_rcv,
	.prog = "__trace_udp_rcv",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace_udp_rcv.rules),
};
trace_list_t trace_udp_rcv_list = {
	.trace = &trace_udp_rcv,
	.list = LIST_HEAD_INIT(trace_udp_rcv_list.list)
};

trace_t trace_udp_unicast_rcv_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "udp_unicast_rcv_skb",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_udp_unicast_rcv_skb,
	.prog = "__trace_udp_unicast_rcv_skb",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace_udp_unicast_rcv_skb.rules),
};
trace_list_t trace_udp_unicast_rcv_skb_list = {
	.trace = &trace_udp_unicast_rcv_skb,
	.list = LIST_HEAD_INIT(trace_udp_unicast_rcv_skb_list.list)
};

trace_t trace_udp_queue_rcv_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "udp_queue_rcv_skb",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_udp_queue_rcv_skb,
	.prog = "__trace_udp_queue_rcv_skb",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace_udp_queue_rcv_skb.rules),
};
trace_list_t trace_udp_queue_rcv_skb_list = {
	.trace = &trace_udp_queue_rcv_skb,
	.list = LIST_HEAD_INIT(trace_udp_queue_rcv_skb_list.list)
};

trace_t trace_xfrm4_udp_encap_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_udp_encap_rcv",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_udp_encap_rcv,
	.prog = "__trace_xfrm4_udp_encap_rcv",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace_xfrm4_udp_encap_rcv.rules),
};
trace_list_t trace_xfrm4_udp_encap_rcv_list = {
	.trace = &trace_xfrm4_udp_encap_rcv,
	.list = LIST_HEAD_INIT(trace_xfrm4_udp_encap_rcv_list.list)
};

trace_t trace_xfrm4_rcv_encap = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "xfrm4_rcv_encap",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_xfrm4_rcv_encap,
	.prog = "__trace_xfrm4_rcv_encap",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace_xfrm4_rcv_encap.rules),
};
trace_list_t trace_xfrm4_rcv_encap_list = {
	.trace = &trace_xfrm4_rcv_encap,
	.list = LIST_HEAD_INIT(trace_xfrm4_rcv_encap_list.list)
};

trace_t trace___udp_queue_rcv_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__udp_queue_rcv_skb",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX___udp_queue_rcv_skb,
	.prog = "__trace___udp_queue_rcv_skb",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace___udp_queue_rcv_skb.rules),
};
trace_list_t trace___udp_queue_rcv_skb_list = {
	.trace = &trace___udp_queue_rcv_skb,
	.list = LIST_HEAD_INIT(trace___udp_queue_rcv_skb_list.list)
};

trace_t trace___udp_enqueue_schedule_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__udp_enqueue_schedule_skb",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX___udp_enqueue_schedule_skb,
	.prog = "__trace___udp_enqueue_schedule_skb",
	.parent = &group_udp_in,
	.rules = LIST_HEAD_INIT(trace___udp_enqueue_schedule_skb.rules),
};
trace_list_t trace___udp_enqueue_schedule_skb_list = {
	.trace = &trace___udp_enqueue_schedule_skb,
	.list = LIST_HEAD_INIT(trace___udp_enqueue_schedule_skb_list.list)
};

trace_group_t group_icmp = {
	.name = "icmp",
	.desc = "icmp(ping) protocol layer (L4) of the network stack",
	.children = LIST_HEAD_INIT(group_icmp.children),
	.traces = LIST_HEAD_INIT(group_icmp.traces),
	.list = LIST_HEAD_INIT(group_icmp.list),
};
trace_group_t group_icmp_in = {
	.name = "icmp-in",
	.desc = "icmp layer of packet in",
	.children = LIST_HEAD_INIT(group_icmp_in.children),
	.traces = LIST_HEAD_INIT(group_icmp_in.traces),
	.list = LIST_HEAD_INIT(group_icmp_in.list),
};
trace_t trace_icmp_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "icmp_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_icmp_rcv,
	.prog = "__trace_icmp_rcv",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_icmp_rcv.rules),
};
trace_list_t trace_icmp_rcv_list = {
	.trace = &trace_icmp_rcv,
	.list = LIST_HEAD_INIT(trace_icmp_rcv_list.list)
};

trace_t trace_icmp_echo = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "icmp_echo",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_icmp_echo,
	.prog = "__trace_icmp_echo",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_icmp_echo.rules),
};
trace_list_t trace_icmp_echo_list = {
	.trace = &trace_icmp_echo,
	.list = LIST_HEAD_INIT(trace_icmp_echo_list.list)
};

trace_t trace_icmp_reply = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "icmp_reply",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_icmp_reply,
	.prog = "__trace_icmp_reply",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_icmp_reply.rules),
};
trace_list_t trace_icmp_reply_list = {
	.trace = &trace_icmp_reply,
	.list = LIST_HEAD_INIT(trace_icmp_reply_list.list)
};

trace_t trace_icmpv6_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "icmpv6_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_icmpv6_rcv,
	.prog = "__trace_icmpv6_rcv",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_icmpv6_rcv.rules),
};
trace_list_t trace_icmpv6_rcv_list = {
	.trace = &trace_icmpv6_rcv,
	.list = LIST_HEAD_INIT(trace_icmpv6_rcv_list.list)
};

trace_t trace_icmpv6_echo_reply = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "icmpv6_echo_reply",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_icmpv6_echo_reply,
	.prog = "__trace_icmpv6_echo_reply",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_icmpv6_echo_reply.rules),
};
trace_list_t trace_icmpv6_echo_reply_list = {
	.trace = &trace_icmpv6_echo_reply,
	.list = LIST_HEAD_INIT(trace_icmpv6_echo_reply_list.list)
};

trace_t trace_ping_rcv = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ping_rcv",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_ping_rcv,
	.prog = "__trace_ping_rcv",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_ping_rcv.rules),
};
trace_list_t trace_ping_rcv_list = {
	.trace = &trace_ping_rcv,
	.list = LIST_HEAD_INIT(trace_ping_rcv_list.list)
};

trace_t trace___ping_queue_rcv_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "__ping_queue_rcv_skb",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX___ping_queue_rcv_skb,
	.prog = "__trace___ping_queue_rcv_skb",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace___ping_queue_rcv_skb.rules),
};
trace_list_t trace___ping_queue_rcv_skb_list = {
	.trace = &trace___ping_queue_rcv_skb,
	.list = LIST_HEAD_INIT(trace___ping_queue_rcv_skb_list.list)
};

trace_t trace_ping_queue_rcv_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "ping_queue_rcv_skb",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ping_queue_rcv_skb,
	.prog = "__trace_ping_queue_rcv_skb",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_ping_queue_rcv_skb.rules),
};
trace_list_t trace_ping_queue_rcv_skb_list = {
	.trace = &trace_ping_queue_rcv_skb,
	.list = LIST_HEAD_INIT(trace_ping_queue_rcv_skb_list.list)
};

trace_t trace_ping_lookup = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(ret),
	.is_backup = false,
	.probe = false,
	.name = "ping_lookup",
	.skb = 2,
	.custom = false,
	.def = true,
	.index = INDEX_ping_lookup,
	.prog = "__trace_ping_lookup",
	.parent = &group_icmp_in,
	.rules = LIST_HEAD_INIT(trace_ping_lookup.rules),
};
trace_list_t trace_ping_lookup_list = {
	.trace = &trace_ping_lookup,
	.list = LIST_HEAD_INIT(trace_ping_lookup_list.list)
};
rule_t rule_trace_ping_lookup_0 = {	.level = RULE_WARN,
	.expected = 0,
	.type = RULE_RETURN_EQ,
	.adv = "not support",
	.msg = PFMT_WARN"icmp socket is not founded"PFMT_END,
};

trace_group_t group_socket = {
	.name = "socket",
	.desc = "socket releated hooks",
	.children = LIST_HEAD_INIT(group_socket.children),
	.traces = LIST_HEAD_INIT(group_socket.traces),
	.list = LIST_HEAD_INIT(group_socket.list),
};
trace_group_t group_tcp_state = {
	.name = "tcp-state",
	.desc = "TCP socket state releated hooks",
	.children = LIST_HEAD_INIT(group_tcp_state.children),
	.traces = LIST_HEAD_INIT(group_tcp_state.traces),
	.list = LIST_HEAD_INIT(group_tcp_state.list),
};
trace_t trace_inet_listen = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "inet_listen",
	.sk = 1,
	.custom = true,
	.def = true,
	.index = INDEX_inet_listen,
	.prog = "__trace_inet_listen",
	.parent = &group_tcp_state,
	.rules = LIST_HEAD_INIT(trace_inet_listen.rules),
};
trace_list_t trace_inet_listen_list = {
	.trace = &trace_inet_listen,
	.list = LIST_HEAD_INIT(trace_inet_listen_list.list)
};
rule_t rule_trace_inet_listen_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"TCP socket begin to listen"PFMT_END,
};

trace_t trace_tcp_v4_destroy_sock = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_v4_destroy_sock",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_v4_destroy_sock,
	.prog = "__trace_tcp_v4_destroy_sock",
	.parent = &group_tcp_state,
	.rules = LIST_HEAD_INIT(trace_tcp_v4_destroy_sock.rules),
};
trace_list_t trace_tcp_v4_destroy_sock_list = {
	.trace = &trace_tcp_v4_destroy_sock,
	.list = LIST_HEAD_INIT(trace_tcp_v4_destroy_sock_list.list)
};

trace_t trace_tcp_close = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_close",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_close,
	.prog = "__trace_tcp_close",
	.parent = &group_tcp_state,
	.rules = LIST_HEAD_INIT(trace_tcp_close.rules),
};
trace_list_t trace_tcp_close_list = {
	.trace = &trace_tcp_close,
	.list = LIST_HEAD_INIT(trace_tcp_close_list.list)
};
rule_t rule_trace_tcp_close_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"TCP socket is closed"PFMT_END,
};


trace_list_t trace_tcp_rcv_state_process_list_2 = {
	.trace = &trace_tcp_rcv_state_process,
	.list = LIST_HEAD_INIT(trace_tcp_rcv_state_process_list_2.list)
};
trace_t trace_tcp_send_active_reset = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(reset),
	.is_backup = false,
	.probe = false,
	.name = "tcp_send_active_reset",
	.sk = 1,
	.custom = true,
	.def = true,
	.index = INDEX_tcp_send_active_reset,
	.prog = "__trace_tcp_send_active_reset",
	.parent = &group_tcp_state,
	.rules = LIST_HEAD_INIT(trace_tcp_send_active_reset.rules),
};
trace_list_t trace_tcp_send_active_reset_list = {
	.trace = &trace_tcp_send_active_reset,
	.list = LIST_HEAD_INIT(trace_tcp_send_active_reset_list.list)
};
rule_t rule_trace_tcp_send_active_reset_0 = {	.level = RULE_ERROR,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_ERROR"connection reset initiated by application (active close, sk)"PFMT_END,
};

trace_t trace_tcp_ack_update_rtt = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(rtt),
	.is_backup = false,
	.probe = false,
	.name = "tcp_ack_update_rtt",
	.sk = 1,
	.custom = true,
	.def = true,
	.index = INDEX_tcp_ack_update_rtt,
	.prog = "__trace_tcp_ack_update_rtt",
	.parent = &group_tcp_state,
	.rules = LIST_HEAD_INIT(trace_tcp_ack_update_rtt.rules),
};
trace_list_t trace_tcp_ack_update_rtt_list = {
	.trace = &trace_tcp_ack_update_rtt,
	.list = LIST_HEAD_INIT(trace_tcp_ack_update_rtt_list.list)
};

trace_group_t group_tcp_congestion = {
	.name = "tcp-congestion",
	.desc = "TCP congestion control releated hooks",
	.children = LIST_HEAD_INIT(group_tcp_congestion.children),
	.traces = LIST_HEAD_INIT(group_tcp_congestion.traces),
	.list = LIST_HEAD_INIT(group_tcp_congestion.list),
};
trace_t trace_tcp_write_timer_handler = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_write_timer_handler",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_write_timer_handler,
	.prog = "__trace_tcp_write_timer_handler",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_write_timer_handler.rules),
};
trace_list_t trace_tcp_write_timer_handler_list = {
	.trace = &trace_tcp_write_timer_handler,
	.list = LIST_HEAD_INIT(trace_tcp_write_timer_handler_list.list)
};

trace_t trace_tcp_retransmit_timer = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 1,
	.is_backup = false,
	.probe = false,
	.monitor = 2,
	.name = "tcp_retransmit_timer",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_retransmit_timer,
	.prog = "__trace_tcp_retransmit_timer",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_retransmit_timer.rules),
};
trace_list_t trace_tcp_retransmit_timer_list = {
	.trace = &trace_tcp_retransmit_timer,
	.list = LIST_HEAD_INIT(trace_tcp_retransmit_timer_list.list)
};
rule_t rule_trace_tcp_retransmit_timer_0 = {	.level = RULE_WARN,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_WARN"TCP retransmission timer out"PFMT_END,
};

trace_t trace_tcp_enter_recovery = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_enter_recovery",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_enter_recovery,
	.prog = "__trace_tcp_enter_recovery",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_enter_recovery.rules),
};
trace_list_t trace_tcp_enter_recovery_list = {
	.trace = &trace_tcp_enter_recovery,
	.list = LIST_HEAD_INIT(trace_tcp_enter_recovery_list.list)
};
rule_t rule_trace_tcp_enter_recovery_0 = {	.level = RULE_WARN,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_WARN"TCP enter conguestion recover"PFMT_END,
};

trace_t trace_tcp_enter_loss = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_enter_loss",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_enter_loss,
	.prog = "__trace_tcp_enter_loss",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_enter_loss.rules),
};
trace_list_t trace_tcp_enter_loss_list = {
	.trace = &trace_tcp_enter_loss,
	.list = LIST_HEAD_INIT(trace_tcp_enter_loss_list.list)
};
rule_t rule_trace_tcp_enter_loss_0 = {	.level = RULE_WARN,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_WARN"TCP enter conguestion loss"PFMT_END,
};

trace_t trace_tcp_try_keep_open = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_try_keep_open",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_try_keep_open,
	.prog = "__trace_tcp_try_keep_open",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_try_keep_open.rules),
};
trace_list_t trace_tcp_try_keep_open_list = {
	.trace = &trace_tcp_try_keep_open,
	.list = LIST_HEAD_INIT(trace_tcp_try_keep_open_list.list)
};
rule_t rule_trace_tcp_try_keep_open_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"TCP enter conguestion open state"PFMT_END,
};

trace_t trace_tcp_enter_cwr = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_enter_cwr",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_enter_cwr,
	.prog = "__trace_tcp_enter_cwr",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_enter_cwr.rules),
};
trace_list_t trace_tcp_enter_cwr_list = {
	.trace = &trace_tcp_enter_cwr,
	.list = LIST_HEAD_INIT(trace_tcp_enter_cwr_list.list)
};
rule_t rule_trace_tcp_enter_cwr_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"TCP enter conguestion CWR state"PFMT_END,
};

trace_t trace_tcp_fastretrans_alert = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_fastretrans_alert",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_fastretrans_alert,
	.prog = "__trace_tcp_fastretrans_alert",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_fastretrans_alert.rules),
};
trace_list_t trace_tcp_fastretrans_alert_list = {
	.trace = &trace_tcp_fastretrans_alert,
	.list = LIST_HEAD_INIT(trace_tcp_fastretrans_alert_list.list)
};

trace_t trace_tcp_rearm_rto = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_rearm_rto",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_rearm_rto,
	.prog = "__trace_tcp_rearm_rto",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_rearm_rto.rules),
};
trace_list_t trace_tcp_rearm_rto_list = {
	.trace = &trace_tcp_rearm_rto,
	.list = LIST_HEAD_INIT(trace_tcp_rearm_rto_list.list)
};

trace_t trace_tcp_event_new_data_sent = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_event_new_data_sent",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_event_new_data_sent,
	.prog = "__trace_tcp_event_new_data_sent",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_event_new_data_sent.rules),
};
trace_list_t trace_tcp_event_new_data_sent_list = {
	.trace = &trace_tcp_event_new_data_sent,
	.list = LIST_HEAD_INIT(trace_tcp_event_new_data_sent_list.list)
};

trace_t trace_tcp_schedule_loss_probe = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.is_backup = false,
	.probe = false,
	.name = "tcp_schedule_loss_probe",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_schedule_loss_probe,
	.prog = "__trace_tcp_schedule_loss_probe",
	.parent = &group_tcp_congestion,
	.rules = LIST_HEAD_INIT(trace_tcp_schedule_loss_probe.rules),
};
trace_list_t trace_tcp_schedule_loss_probe_list = {
	.trace = &trace_tcp_schedule_loss_probe,
	.list = LIST_HEAD_INIT(trace_tcp_schedule_loss_probe_list.list)
};

trace_group_t group_tcp_retrans = {
	.name = "tcp-retrans",
	.desc = "TCP retransmission releated hooks",
	.children = LIST_HEAD_INIT(group_tcp_retrans.children),
	.traces = LIST_HEAD_INIT(group_tcp_retrans.traces),
	.list = LIST_HEAD_INIT(group_tcp_retrans.list),
};
trace_t trace_tcp_rtx_synack = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 2,
	.is_backup = false,
	.probe = false,
	.monitor = 2,
	.name = "tcp_rtx_synack",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_rtx_synack,
	.prog = "__trace_tcp_rtx_synack",
	.parent = &group_tcp_retrans,
	.rules = LIST_HEAD_INIT(trace_tcp_rtx_synack.rules),
};
trace_list_t trace_tcp_rtx_synack_list = {
	.trace = &trace_tcp_rtx_synack,
	.list = LIST_HEAD_INIT(trace_tcp_rtx_synack_list.list)
};

trace_t trace_tcp_retransmit_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 3,
	.is_backup = false,
	.probe = false,
	.monitor = 2,
	.name = "tcp_retransmit_skb",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_retransmit_skb,
	.prog = "__trace_tcp_retransmit_skb",
	.parent = &group_tcp_retrans,
	.rules = LIST_HEAD_INIT(trace_tcp_retransmit_skb.rules),
};
trace_list_t trace_tcp_retransmit_skb_list = {
	.trace = &trace_tcp_retransmit_skb,
	.list = LIST_HEAD_INIT(trace_tcp_retransmit_skb_list.list)
};

trace_t trace_tcp_rcv_spurious_retrans = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 2,
	.is_backup = false,
	.probe = false,
	.monitor = 2,
	.name = "tcp_rcv_spurious_retrans",
	.skb = 2,
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_rcv_spurious_retrans,
	.prog = "__trace_tcp_rcv_spurious_retrans",
	.parent = &group_tcp_retrans,
	.rules = LIST_HEAD_INIT(trace_tcp_rcv_spurious_retrans.rules),
};
trace_list_t trace_tcp_rcv_spurious_retrans_list = {
	.trace = &trace_tcp_rcv_spurious_retrans,
	.list = LIST_HEAD_INIT(trace_tcp_rcv_spurious_retrans_list.list)
};

trace_t trace_tcp_dsack_set = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(default),
	.arg_count = 3,
	.is_backup = false,
	.probe = false,
	.monitor = 2,
	.name = "tcp_dsack_set",
	.sk = 1,
	.custom = false,
	.def = true,
	.index = INDEX_tcp_dsack_set,
	.prog = "__trace_tcp_dsack_set",
	.parent = &group_tcp_retrans,
	.rules = LIST_HEAD_INIT(trace_tcp_dsack_set.rules),
};
trace_list_t trace_tcp_dsack_set_list = {
	.trace = &trace_tcp_dsack_set,
	.list = LIST_HEAD_INIT(trace_tcp_dsack_set_list.list)
};
rule_t rule_trace_tcp_dsack_set_0 = {	.level = RULE_WARN,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_WARN"spurious retransmission happened"PFMT_END,
};

trace_group_t group_life = {
	.name = "life",
	.desc = "skb clone and free",
	.children = LIST_HEAD_INIT(group_life.children),
	.traces = LIST_HEAD_INIT(group_life.traces),
	.list = LIST_HEAD_INIT(group_life.list),
};
trace_t trace_skb_clone = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(clone),
	.is_backup = false,
	.probe = false,
	.name = "skb_clone",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_skb_clone,
	.prog = "__trace_skb_clone",
	.parent = &group_life,
	.rules = LIST_HEAD_INIT(trace_skb_clone.rules),
};
trace_list_t trace_skb_clone_list = {
	.trace = &trace_skb_clone,
	.list = LIST_HEAD_INIT(trace_skb_clone_list.list)
};
rule_t rule_trace_skb_clone_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"packet is cloned"PFMT_END,
};

trace_t trace_consume_skb = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(free),
	.is_backup = false,
	.probe = false,
	.name = "consume_skb",
	.skb = 1,
	.skboffset = 8,
	.custom = false,
	.tp = "skb/consume_skb",
	.def = true,
	.index = INDEX_consume_skb,
	.prog = "__trace_consume_skb",
	.parent = &group_life,
	.rules = LIST_HEAD_INIT(trace_consume_skb.rules),
};
trace_list_t trace_consume_skb_list = {
	.trace = &trace_consume_skb,
	.list = LIST_HEAD_INIT(trace_consume_skb_list.list)
};
rule_t rule_trace_consume_skb_0 = {	.level = RULE_INFO,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_EMPH"packet is freed (normally)"PFMT_END,
};

trace_t trace_kfree_skb = {
	.desc = "",
	.type = TRACE_TP,
	.analyzer = &ANALYZER(drop),
	.is_backup = false,
	.probe = false,
	.monitor = 1,
	.name = "kfree_skb",
	.skb = 1,
	.skboffset = 8,
	.custom = true,
	.tp = "skb/kfree_skb",
	.def = true,
	.index = INDEX_kfree_skb,
	.prog = "__trace_kfree_skb",
	.parent = &group_life,
	.rules = LIST_HEAD_INIT(trace_kfree_skb.rules),
};
trace_list_t trace_kfree_skb_list = {
	.trace = &trace_kfree_skb,
	.list = LIST_HEAD_INIT(trace_kfree_skb_list.list)
};
rule_t rule_trace_kfree_skb_0 = {	.level = RULE_ERROR,
	.type = RULE_RETURN_ANY,
	.msg = PFMT_ERROR"packet is dropped by kernel"PFMT_END,
};

trace_t trace___kfree_skb = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(free),
	.is_backup = false,
	.probe = false,
	.name = "__kfree_skb",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX___kfree_skb,
	.prog = "__trace___kfree_skb",
	.parent = &group_life,
	.rules = LIST_HEAD_INIT(trace___kfree_skb.rules),
};
trace_list_t trace___kfree_skb_list = {
	.trace = &trace___kfree_skb,
	.list = LIST_HEAD_INIT(trace___kfree_skb_list.list)
};

trace_t trace_kfree_skb_partial = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(free),
	.is_backup = false,
	.probe = false,
	.name = "kfree_skb_partial",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_kfree_skb_partial,
	.prog = "__trace_kfree_skb_partial",
	.parent = &group_life,
	.rules = LIST_HEAD_INIT(trace_kfree_skb_partial.rules),
};
trace_list_t trace_kfree_skb_partial_list = {
	.trace = &trace_kfree_skb_partial,
	.list = LIST_HEAD_INIT(trace_kfree_skb_partial_list.list)
};

trace_t trace_skb_attempt_defer_free = {
	.desc = "",
	.type = TRACE_FUNCTION,
	.analyzer = &ANALYZER(free),
	.is_backup = false,
	.probe = false,
	.name = "skb_attempt_defer_free",
	.skb = 1,
	.custom = false,
	.def = true,
	.index = INDEX_skb_attempt_defer_free,
	.prog = "__trace_skb_attempt_defer_free",
	.parent = &group_life,
	.rules = LIST_HEAD_INIT(trace_skb_attempt_defer_free.rules),
};
trace_list_t trace_skb_attempt_defer_free_list = {
	.trace = &trace_skb_attempt_defer_free,
	.list = LIST_HEAD_INIT(trace_skb_attempt_defer_free_list.list)
};



trace_t *all_traces[TRACE_MAX];
int trace_count = TRACE_MAX;
LIST_HEAD(trace_list);

void init_trace_group()
{
	list_add_tail(&group_link.list, &root_group.children);
	list_add_tail(&group_link_in.list, &group_link.children);
	list_add_tail(&trace_napi_gro_receive_entry_list.list, &group_link_in.traces);
	all_traces[INDEX_napi_gro_receive_entry] = &trace_napi_gro_receive_entry;
	list_add_tail(&trace_napi_gro_receive_entry.all, &trace_list);
	list_add_tail(&rule_trace_dev_gro_receive_0.list, &trace_dev_gro_receive.rules);
	list_add_tail(&trace_dev_gro_receive_list.list, &group_link_in.traces);
	all_traces[INDEX_dev_gro_receive] = &trace_dev_gro_receive;
	list_add_tail(&trace_dev_gro_receive.all, &trace_list);
	list_add_tail(&rule_trace_enqueue_to_backlog_0.list, &trace_enqueue_to_backlog.rules);
	list_add_tail(&trace_enqueue_to_backlog_list.list, &group_link_in.traces);
	all_traces[INDEX_enqueue_to_backlog] = &trace_enqueue_to_backlog;
	list_add_tail(&trace_enqueue_to_backlog.all, &trace_list);
	list_add_tail(&rule_trace_netif_receive_generic_xdp_0.list, &trace_netif_receive_generic_xdp.rules);
	list_add_tail(&rule_trace_netif_receive_generic_xdp_1.list, &trace_netif_receive_generic_xdp.rules);
	list_add_tail(&rule_trace_netif_receive_generic_xdp_2.list, &trace_netif_receive_generic_xdp.rules);
	list_add_tail(&trace_netif_receive_generic_xdp_list.list, &group_link_in.traces);
	all_traces[INDEX_netif_receive_generic_xdp] = &trace_netif_receive_generic_xdp;
	list_add_tail(&trace_netif_receive_generic_xdp.all, &trace_list);
	list_add_tail(&rule_trace_xdp_do_generic_redirect_0.list, &trace_xdp_do_generic_redirect.rules);
	list_add_tail(&trace_xdp_do_generic_redirect_list.list, &group_link_in.traces);
	all_traces[INDEX_xdp_do_generic_redirect] = &trace_xdp_do_generic_redirect;
	list_add_tail(&trace_xdp_do_generic_redirect.all, &trace_list);
	list_add_tail(&trace___netif_receive_skb_core_list.list, &group_link_in.traces);
	all_traces[INDEX___netif_receive_skb_core] = &trace___netif_receive_skb_core;
	list_add_tail(&trace___netif_receive_skb_core.all, &trace_list);
	list_add_tail(&trace_RtmpOsPktRcvHandle_list.list, &group_link_in.traces);
	all_traces[INDEX_RtmpOsPktRcvHandle] = &trace_RtmpOsPktRcvHandle;
	list_add_tail(&trace_RtmpOsPktRcvHandle.all, &trace_list);
	trace_napi_gro_receive_entry.backup = NULL;
	trace_dev_gro_receive.backup = NULL;
	trace_enqueue_to_backlog.backup = NULL;
	trace_netif_receive_generic_xdp.backup = NULL;
	trace_xdp_do_generic_redirect.backup = NULL;
	trace___netif_receive_skb_core.backup = NULL;
	trace_RtmpOsPktRcvHandle.backup = NULL;
	list_add_tail(&group_link_out.list, &group_link.children);
	list_add_tail(&rule_trace___dev_queue_xmit_0.list, &trace___dev_queue_xmit.rules);
	list_add_tail(&trace___dev_queue_xmit_list.list, &group_link_out.traces);
	all_traces[INDEX___dev_queue_xmit] = &trace___dev_queue_xmit;
	list_add_tail(&trace___dev_queue_xmit.all, &trace_list);
	list_add_tail(&rule_trace_dev_hard_start_xmit_0.list, &trace_dev_hard_start_xmit.rules);
	list_add_tail(&trace_dev_hard_start_xmit_list.list, &group_link_out.traces);
	all_traces[INDEX_dev_hard_start_xmit] = &trace_dev_hard_start_xmit;
	list_add_tail(&trace_dev_hard_start_xmit.all, &trace_list);
	list_add_tail(&rule_trace_fp_send_data_pkt_0.list, &trace_fp_send_data_pkt.rules);
	list_add_tail(&trace_fp_send_data_pkt_list.list, &group_link_out.traces);
	all_traces[INDEX_fp_send_data_pkt] = &trace_fp_send_data_pkt;
	list_add_tail(&trace_fp_send_data_pkt.all, &trace_list);
	trace___dev_queue_xmit.backup = NULL;
	trace_dev_hard_start_xmit.backup = NULL;
	trace_fp_send_data_pkt.backup = NULL;
	list_add_tail(&group_sched.list, &group_link.children);
	list_add_tail(&trace_tcf_classify_list.list, &group_sched.traces);
	all_traces[INDEX_tcf_classify] = &trace_tcf_classify;
	list_add_tail(&trace_tcf_classify.all, &trace_list);
	list_add_tail(&trace_cls_bpf_classify_list.list, &group_sched.traces);
	all_traces[INDEX_cls_bpf_classify] = &trace_cls_bpf_classify;
	list_add_tail(&trace_cls_bpf_classify.all, &trace_list);
	list_add_tail(&trace_tcf_bpf_act_list.list, &group_sched.traces);
	all_traces[INDEX_tcf_bpf_act] = &trace_tcf_bpf_act;
	list_add_tail(&trace_tcf_bpf_act.all, &trace_list);
	list_add_tail(&trace_qdisc_dequeue_list.list, &group_sched.traces);
	all_traces[INDEX_qdisc_dequeue] = &trace_qdisc_dequeue;
	list_add_tail(&trace_qdisc_dequeue.all, &trace_list);
	list_add_tail(&trace_qdisc_enqueue_list.list, &group_sched.traces);
	all_traces[INDEX_qdisc_enqueue] = &trace_qdisc_enqueue;
	list_add_tail(&trace_qdisc_enqueue.all, &trace_list);
	trace_tcf_classify.backup = NULL;
	trace_cls_bpf_classify.backup = NULL;
	trace_tcf_bpf_act.backup = NULL;
	trace_qdisc_dequeue.backup = NULL;
	trace_qdisc_enqueue.backup = NULL;
	list_add_tail(&group_ipvlan.list, &group_link.children);
	list_add_tail(&trace_ipvlan_queue_xmit_list.list, &group_ipvlan.traces);
	all_traces[INDEX_ipvlan_queue_xmit] = &trace_ipvlan_queue_xmit;
	list_add_tail(&trace_ipvlan_queue_xmit.all, &trace_list);
	list_add_tail(&trace_ipvlan_handle_frame_list.list, &group_ipvlan.traces);
	all_traces[INDEX_ipvlan_handle_frame] = &trace_ipvlan_handle_frame;
	list_add_tail(&trace_ipvlan_handle_frame.all, &trace_list);
	list_add_tail(&trace_ipvlan_rcv_frame_list.list, &group_ipvlan.traces);
	all_traces[INDEX_ipvlan_rcv_frame] = &trace_ipvlan_rcv_frame;
	list_add_tail(&trace_ipvlan_rcv_frame.all, &trace_list);
	list_add_tail(&trace_ipvlan_xmit_mode_l3_list.list, &group_ipvlan.traces);
	all_traces[INDEX_ipvlan_xmit_mode_l3] = &trace_ipvlan_xmit_mode_l3;
	list_add_tail(&trace_ipvlan_xmit_mode_l3.all, &trace_list);
	list_add_tail(&trace_ipvlan_process_v4_outbound_list.list, &group_ipvlan.traces);
	all_traces[INDEX_ipvlan_process_v4_outbound] = &trace_ipvlan_process_v4_outbound;
	list_add_tail(&trace_ipvlan_process_v4_outbound.all, &trace_list);
	trace_ipvlan_queue_xmit.backup = NULL;
	trace_ipvlan_handle_frame.backup = NULL;
	trace_ipvlan_rcv_frame.backup = NULL;
	trace_ipvlan_xmit_mode_l3.backup = NULL;
	trace_ipvlan_process_v4_outbound.backup = NULL;
	list_add_tail(&group_bridge.list, &group_link.children);
	list_add_tail(&rule_trace_br_nf_pre_routing_0.list, &trace_br_nf_pre_routing.rules);
	list_add_tail(&rule_trace_br_nf_pre_routing_1.list, &trace_br_nf_pre_routing.rules);
	list_add_tail(&trace_br_nf_pre_routing_list.list, &group_bridge.traces);
	all_traces[INDEX_br_nf_pre_routing] = &trace_br_nf_pre_routing;
	list_add_tail(&trace_br_nf_pre_routing.all, &trace_list);
	list_add_tail(&rule_trace_br_nf_forward_ip_0.list, &trace_br_nf_forward_ip.rules);
	list_add_tail(&rule_trace_br_nf_forward_ip_1.list, &trace_br_nf_forward_ip.rules);
	list_add_tail(&trace_br_nf_forward_ip_list.list, &group_bridge.traces);
	all_traces[INDEX_br_nf_forward_ip] = &trace_br_nf_forward_ip;
	list_add_tail(&trace_br_nf_forward_ip.all, &trace_list);
	list_add_tail(&rule_trace_br_nf_forward_arp_0.list, &trace_br_nf_forward_arp.rules);
	list_add_tail(&rule_trace_br_nf_forward_arp_1.list, &trace_br_nf_forward_arp.rules);
	list_add_tail(&trace_br_nf_forward_arp_list.list, &group_bridge.traces);
	all_traces[INDEX_br_nf_forward_arp] = &trace_br_nf_forward_arp;
	list_add_tail(&trace_br_nf_forward_arp.all, &trace_list);
	list_add_tail(&rule_trace_br_nf_post_routing_0.list, &trace_br_nf_post_routing.rules);
	list_add_tail(&rule_trace_br_nf_post_routing_1.list, &trace_br_nf_post_routing.rules);
	list_add_tail(&trace_br_nf_post_routing_list.list, &group_bridge.traces);
	all_traces[INDEX_br_nf_post_routing] = &trace_br_nf_post_routing;
	list_add_tail(&trace_br_nf_post_routing.all, &trace_list);
	trace_br_nf_pre_routing.backup = NULL;
	trace_br_nf_forward_ip.backup = NULL;
	trace_br_nf_forward_arp.backup = NULL;
	trace_br_nf_post_routing.backup = NULL;
	list_add_tail(&group_arp.list, &group_link.children);
	list_add_tail(&trace_arp_rcv_list.list, &group_arp.traces);
	all_traces[INDEX_arp_rcv] = &trace_arp_rcv;
	list_add_tail(&trace_arp_rcv.all, &trace_list);
	list_add_tail(&trace_arp_process_list.list, &group_arp.traces);
	all_traces[INDEX_arp_process] = &trace_arp_process;
	list_add_tail(&trace_arp_process.all, &trace_list);
	trace_arp_rcv.backup = NULL;
	trace_arp_process.backup = NULL;
	list_add_tail(&group_bonding.list, &group_link.children);
	list_add_tail(&trace_bond_dev_queue_xmit_list.list, &group_bonding.traces);
	all_traces[INDEX_bond_dev_queue_xmit] = &trace_bond_dev_queue_xmit;
	list_add_tail(&trace_bond_dev_queue_xmit.all, &trace_list);
	trace_bond_dev_queue_xmit.backup = NULL;
	list_add_tail(&group_vxlan.list, &group_link.children);
	list_add_tail(&trace___iptunnel_pull_header_list.list, &group_vxlan.traces);
	all_traces[INDEX___iptunnel_pull_header] = &trace___iptunnel_pull_header;
	list_add_tail(&trace___iptunnel_pull_header.all, &trace_list);
	list_add_tail(&trace_vxlan_rcv_list.list, &group_vxlan.traces);
	all_traces[INDEX_vxlan_rcv] = &trace_vxlan_rcv;
	list_add_tail(&trace_vxlan_rcv.all, &trace_list);
	list_add_tail(&trace_vxlan_xmit_one_list.list, &group_vxlan.traces);
	all_traces[INDEX_vxlan_xmit_one] = &trace_vxlan_xmit_one;
	list_add_tail(&trace_vxlan_xmit_one.all, &trace_list);
	trace___iptunnel_pull_header.backup = NULL;
	trace_vxlan_rcv.backup = NULL;
	trace_vxlan_xmit_one.backup = NULL;
	list_add_tail(&group_vlan.list, &group_link.children);
	list_add_tail(&trace_vlan_do_receive_list.list, &group_vlan.traces);
	all_traces[INDEX_vlan_do_receive] = &trace_vlan_do_receive;
	list_add_tail(&trace_vlan_do_receive.all, &trace_list);
	list_add_tail(&trace_vlan_dev_hard_start_xmit_list.list, &group_vlan.traces);
	all_traces[INDEX_vlan_dev_hard_start_xmit] = &trace_vlan_dev_hard_start_xmit;
	list_add_tail(&trace_vlan_dev_hard_start_xmit.all, &trace_list);
	trace_vlan_do_receive.backup = NULL;
	trace_vlan_dev_hard_start_xmit.backup = NULL;
	list_add_tail(&group_ovs.list, &group_link.children);
	list_add_tail(&trace_netdev_port_receive_list.list, &group_ovs.traces);
	all_traces[INDEX_netdev_port_receive] = &trace_netdev_port_receive;
	list_add_tail(&trace_netdev_port_receive.all, &trace_list);
	list_add_tail(&trace_ovs_vport_receive_list.list, &group_ovs.traces);
	all_traces[INDEX_ovs_vport_receive] = &trace_ovs_vport_receive;
	list_add_tail(&trace_ovs_vport_receive.all, &trace_list);
	list_add_tail(&trace_ovs_dp_process_packet_list.list, &group_ovs.traces);
	all_traces[INDEX_ovs_dp_process_packet] = &trace_ovs_dp_process_packet;
	list_add_tail(&trace_ovs_dp_process_packet.all, &trace_list);
	trace_netdev_port_receive.backup = NULL;
	trace_ovs_vport_receive.backup = NULL;
	trace_ovs_dp_process_packet.backup = NULL;
	list_add_tail(&group_packet.list, &root_group.children);
	list_add_tail(&group_pkt_in.list, &group_packet.children);
	list_add_tail(&trace_packet_rcv_list.list, &group_pkt_in.traces);
	all_traces[INDEX_packet_rcv] = &trace_packet_rcv;
	list_add_tail(&trace_packet_rcv.all, &trace_list);
	list_add_tail(&trace_tpacket_rcv_list.list, &group_pkt_in.traces);
	all_traces[INDEX_tpacket_rcv] = &trace_tpacket_rcv;
	list_add_tail(&trace_tpacket_rcv.all, &trace_list);
	trace_packet_rcv.backup = NULL;
	trace_tpacket_rcv.backup = NULL;
	list_add_tail(&group_pkt_output.list, &group_packet.children);
	list_add_tail(&trace_packet_direct_xmit_list.list, &group_pkt_output.traces);
	all_traces[INDEX_packet_direct_xmit] = &trace_packet_direct_xmit;
	list_add_tail(&trace_packet_direct_xmit.all, &trace_list);
	trace_packet_direct_xmit.backup = NULL;
	list_add_tail(&group_netfilter.list, &root_group.children);
	list_add_tail(&group_netfilter_1.list, &group_netfilter.children);
	list_add_tail(&rule_trace_nft_do_chain_0.list, &trace_nft_do_chain.rules);
	list_add_tail(&rule_trace_nft_do_chain_1.list, &trace_nft_do_chain.rules);
	list_add_tail(&trace_nft_do_chain_list.list, &group_netfilter_1.traces);
	all_traces[INDEX_nft_do_chain] = &trace_nft_do_chain;
	list_add_tail(&trace_nft_do_chain.all, &trace_list);
	list_add_tail(&rule_trace_nf_nat_manip_pkt_0.list, &trace_nf_nat_manip_pkt.rules);
	list_add_tail(&trace_nf_nat_manip_pkt_list.list, &group_netfilter_1.traces);
	all_traces[INDEX_nf_nat_manip_pkt] = &trace_nf_nat_manip_pkt;
	list_add_tail(&trace_nf_nat_manip_pkt.all, &trace_list);
	list_add_tail(&rule_trace_nf_hook_slow_0.list, &trace_nf_hook_slow.rules);
	list_add_tail(&trace_nf_hook_slow_list.list, &group_netfilter_1.traces);
	all_traces[INDEX_nf_hook_slow] = &trace_nf_hook_slow;
	list_add_tail(&trace_nf_hook_slow.all, &trace_list);
	list_add_tail(&rule_trace_ipt_do_table_0.list, &trace_ipt_do_table.rules);
	list_add_tail(&rule_trace_ipt_do_table_1.list, &trace_ipt_do_table.rules);
	list_add_tail(&trace_ipt_do_table_list.list, &group_netfilter_1.traces);
	all_traces[INDEX_ipt_do_table] = &trace_ipt_do_table;
	list_add_tail(&trace_ipt_do_table.all, &trace_list);
	list_add_tail(&rule_trace_ipt_do_table_legacy_0.list, &trace_ipt_do_table_legacy.rules);
	list_add_tail(&rule_trace_ipt_do_table_legacy_1.list, &trace_ipt_do_table_legacy.rules);
	list_add_tail(&trace_ipt_do_table_legacy_list.list, &group_netfilter_1.traces);
	all_traces[INDEX_ipt_do_table_legacy] = &trace_ipt_do_table_legacy;
	list_add_tail(&trace_ipt_do_table_legacy.all, &trace_list);
	trace_nft_do_chain.backup = NULL;
	trace_nf_nat_manip_pkt.backup = NULL;
	trace_nf_hook_slow.backup = NULL;
	trace_ipt_do_table.backup = NULL;
	trace_ipt_do_table_legacy.backup = &trace_ipt_do_table;
	list_add_tail(&group_conntrack.list, &group_netfilter.children);
	list_add_tail(&trace_ipv4_confirm_list.list, &group_conntrack.traces);
	all_traces[INDEX_ipv4_confirm] = &trace_ipv4_confirm;
	list_add_tail(&trace_ipv4_confirm.all, &trace_list);
	list_add_tail(&trace_nf_confirm_list.list, &group_conntrack.traces);
	all_traces[INDEX_nf_confirm] = &trace_nf_confirm;
	list_add_tail(&trace_nf_confirm.all, &trace_list);
	list_add_tail(&trace_ipv4_conntrack_in_list.list, &group_conntrack.traces);
	all_traces[INDEX_ipv4_conntrack_in] = &trace_ipv4_conntrack_in;
	list_add_tail(&trace_ipv4_conntrack_in.all, &trace_list);
	list_add_tail(&trace_nf_conntrack_in_list.list, &group_conntrack.traces);
	all_traces[INDEX_nf_conntrack_in] = &trace_nf_conntrack_in;
	list_add_tail(&trace_nf_conntrack_in.all, &trace_list);
	list_add_tail(&trace_ipv4_pkt_to_tuple_list.list, &group_conntrack.traces);
	all_traces[INDEX_ipv4_pkt_to_tuple] = &trace_ipv4_pkt_to_tuple;
	list_add_tail(&trace_ipv4_pkt_to_tuple.all, &trace_list);
	list_add_tail(&trace_tcp_new_list.list, &group_conntrack.traces);
	all_traces[INDEX_tcp_new] = &trace_tcp_new;
	list_add_tail(&trace_tcp_new.all, &trace_list);
	list_add_tail(&trace_tcp_pkt_to_tuple_list.list, &group_conntrack.traces);
	all_traces[INDEX_tcp_pkt_to_tuple] = &trace_tcp_pkt_to_tuple;
	list_add_tail(&trace_tcp_pkt_to_tuple.all, &trace_list);
	list_add_tail(&trace_resolve_normal_ct_list.list, &group_conntrack.traces);
	all_traces[INDEX_resolve_normal_ct] = &trace_resolve_normal_ct;
	list_add_tail(&trace_resolve_normal_ct.all, &trace_list);
	list_add_tail(&trace_tcp_packet_list.list, &group_conntrack.traces);
	all_traces[INDEX_tcp_packet] = &trace_tcp_packet;
	list_add_tail(&trace_tcp_packet.all, &trace_list);
	list_add_tail(&rule_trace_tcp_in_window_0.list, &trace_tcp_in_window.rules);
	list_add_tail(&trace_tcp_in_window_list.list, &group_conntrack.traces);
	all_traces[INDEX_tcp_in_window] = &trace_tcp_in_window;
	list_add_tail(&trace_tcp_in_window.all, &trace_list);
	list_add_tail(&trace___nf_ct_refresh_acct_list.list, &group_conntrack.traces);
	all_traces[INDEX___nf_ct_refresh_acct] = &trace___nf_ct_refresh_acct;
	list_add_tail(&trace___nf_ct_refresh_acct.all, &trace_list);
	trace_ipv4_confirm.backup = NULL;
	trace_nf_confirm.backup = NULL;
	trace_ipv4_conntrack_in.backup = NULL;
	trace_nf_conntrack_in.backup = NULL;
	trace_ipv4_pkt_to_tuple.backup = NULL;
	trace_tcp_new.backup = NULL;
	trace_tcp_pkt_to_tuple.backup = NULL;
	trace_resolve_normal_ct.backup = NULL;
	trace_tcp_packet.backup = NULL;
	trace_tcp_in_window.backup = NULL;
	trace___nf_ct_refresh_acct.backup = NULL;
	list_add_tail(&group_ip.list, &root_group.children);
	list_add_tail(&group_ip_in.list, &group_ip.children);
	list_add_tail(&trace_ip_rcv_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_rcv] = &trace_ip_rcv;
	list_add_tail(&trace_ip_rcv.all, &trace_list);
	list_add_tail(&trace_ip_rcv_core_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_rcv_core] = &trace_ip_rcv_core;
	list_add_tail(&trace_ip_rcv_core.all, &trace_list);
	list_add_tail(&trace_ip_rcv_finish_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_rcv_finish] = &trace_ip_rcv_finish;
	list_add_tail(&trace_ip_rcv_finish.all, &trace_list);
	list_add_tail(&trace_ip_local_deliver_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_local_deliver] = &trace_ip_local_deliver;
	list_add_tail(&trace_ip_local_deliver.all, &trace_list);
	list_add_tail(&trace_ip_local_deliver_finish_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_local_deliver_finish] = &trace_ip_local_deliver_finish;
	list_add_tail(&trace_ip_local_deliver_finish.all, &trace_list);
	list_add_tail(&trace_ip_forward_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_forward] = &trace_ip_forward;
	list_add_tail(&trace_ip_forward.all, &trace_list);
	list_add_tail(&trace_ip_forward_finish_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip_forward_finish] = &trace_ip_forward_finish;
	list_add_tail(&trace_ip_forward_finish.all, &trace_list);
	list_add_tail(&trace_ip6_forward_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip6_forward] = &trace_ip6_forward;
	list_add_tail(&trace_ip6_forward.all, &trace_list);
	list_add_tail(&trace_ip6_rcv_finish_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip6_rcv_finish] = &trace_ip6_rcv_finish;
	list_add_tail(&trace_ip6_rcv_finish.all, &trace_list);
	list_add_tail(&trace_ip6_rcv_core_list.list, &group_ip_in.traces);
	all_traces[INDEX_ip6_rcv_core] = &trace_ip6_rcv_core;
	list_add_tail(&trace_ip6_rcv_core.all, &trace_list);
	list_add_tail(&trace_ipv6_rcv_list.list, &group_ip_in.traces);
	all_traces[INDEX_ipv6_rcv] = &trace_ipv6_rcv;
	list_add_tail(&trace_ipv6_rcv.all, &trace_list);
	trace_ip_rcv.backup = NULL;
	trace_ip_rcv_core.backup = NULL;
	trace_ip_rcv_finish.backup = NULL;
	trace_ip_local_deliver.backup = NULL;
	trace_ip_local_deliver_finish.backup = NULL;
	trace_ip_forward.backup = NULL;
	trace_ip_forward_finish.backup = NULL;
	trace_ip6_forward.backup = NULL;
	trace_ip6_rcv_finish.backup = NULL;
	trace_ip6_rcv_core.backup = NULL;
	trace_ipv6_rcv.backup = NULL;
	list_add_tail(&group_ip_out.list, &group_ip.children);
	list_add_tail(&trace___ip_queue_xmit_list.list, &group_ip_out.traces);
	all_traces[INDEX___ip_queue_xmit] = &trace___ip_queue_xmit;
	list_add_tail(&trace___ip_queue_xmit.all, &trace_list);
	list_add_tail(&trace___ip_local_out_list.list, &group_ip_out.traces);
	all_traces[INDEX___ip_local_out] = &trace___ip_local_out;
	list_add_tail(&trace___ip_local_out.all, &trace_list);
	list_add_tail(&trace_ip_output_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip_output] = &trace_ip_output;
	list_add_tail(&trace_ip_output.all, &trace_list);
	list_add_tail(&trace_ip_finish_output_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip_finish_output] = &trace_ip_finish_output;
	list_add_tail(&trace_ip_finish_output.all, &trace_list);
	list_add_tail(&trace_ip_finish_output_gso_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip_finish_output_gso] = &trace_ip_finish_output_gso;
	list_add_tail(&trace_ip_finish_output_gso.all, &trace_list);
	list_add_tail(&trace_ip_finish_output2_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip_finish_output2] = &trace_ip_finish_output2;
	list_add_tail(&trace_ip_finish_output2.all, &trace_list);
	list_add_tail(&trace_ip6_output_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip6_output] = &trace_ip6_output;
	list_add_tail(&trace_ip6_output.all, &trace_list);
	list_add_tail(&trace_ip6_finish_output_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip6_finish_output] = &trace_ip6_finish_output;
	list_add_tail(&trace_ip6_finish_output.all, &trace_list);
	list_add_tail(&trace_ip6_finish_output2_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip6_finish_output2] = &trace_ip6_finish_output2;
	list_add_tail(&trace_ip6_finish_output2.all, &trace_list);
	list_add_tail(&trace_ip6_send_skb_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip6_send_skb] = &trace_ip6_send_skb;
	list_add_tail(&trace_ip6_send_skb.all, &trace_list);
	list_add_tail(&trace_ip6_local_out_list.list, &group_ip_out.traces);
	all_traces[INDEX_ip6_local_out] = &trace_ip6_local_out;
	list_add_tail(&trace_ip6_local_out.all, &trace_list);
	trace___ip_queue_xmit.backup = NULL;
	trace___ip_local_out.backup = NULL;
	trace_ip_output.backup = NULL;
	trace_ip_finish_output.backup = NULL;
	trace_ip_finish_output_gso.backup = NULL;
	trace_ip_finish_output2.backup = NULL;
	trace_ip6_output.backup = NULL;
	trace_ip6_finish_output.backup = NULL;
	trace_ip6_finish_output2.backup = NULL;
	trace_ip6_send_skb.backup = NULL;
	trace_ip6_local_out.backup = NULL;
	list_add_tail(&group_xfrm.list, &group_ip.children);
	list_add_tail(&trace_xfrm4_output_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm4_output] = &trace_xfrm4_output;
	list_add_tail(&trace_xfrm4_output.all, &trace_list);
	list_add_tail(&trace_xfrm_output_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm_output] = &trace_xfrm_output;
	list_add_tail(&trace_xfrm_output.all, &trace_list);
	list_add_tail(&trace_xfrm_output2_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm_output2] = &trace_xfrm_output2;
	list_add_tail(&trace_xfrm_output2.all, &trace_list);
	list_add_tail(&trace_xfrm_output_gso_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm_output_gso] = &trace_xfrm_output_gso;
	list_add_tail(&trace_xfrm_output_gso.all, &trace_list);
	list_add_tail(&trace_xfrm_output_resume_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm_output_resume] = &trace_xfrm_output_resume;
	list_add_tail(&trace_xfrm_output_resume.all, &trace_list);
	list_add_tail(&trace_xfrm4_transport_output_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm4_transport_output] = &trace_xfrm4_transport_output;
	list_add_tail(&trace_xfrm4_transport_output.all, &trace_list);
	list_add_tail(&trace_xfrm4_prepare_output_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm4_prepare_output] = &trace_xfrm4_prepare_output;
	list_add_tail(&trace_xfrm4_prepare_output.all, &trace_list);
	list_add_tail(&trace_xfrm4_policy_check_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm4_policy_check] = &trace_xfrm4_policy_check;
	list_add_tail(&trace_xfrm4_policy_check.all, &trace_list);
	list_add_tail(&trace_xfrm4_rcv_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm4_rcv] = &trace_xfrm4_rcv;
	list_add_tail(&trace_xfrm4_rcv.all, &trace_list);
	list_add_tail(&trace_xfrm_input_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm_input] = &trace_xfrm_input;
	list_add_tail(&trace_xfrm_input.all, &trace_list);
	list_add_tail(&trace_xfrm4_transport_input_list.list, &group_xfrm.traces);
	all_traces[INDEX_xfrm4_transport_input] = &trace_xfrm4_transport_input;
	list_add_tail(&trace_xfrm4_transport_input.all, &trace_list);
	trace_xfrm4_output.backup = NULL;
	trace_xfrm_output.backup = NULL;
	trace_xfrm_output2.backup = NULL;
	trace_xfrm_output_gso.backup = NULL;
	trace_xfrm_output_resume.backup = NULL;
	trace_xfrm4_transport_output.backup = NULL;
	trace_xfrm4_prepare_output.backup = NULL;
	trace_xfrm4_policy_check.backup = NULL;
	trace_xfrm4_rcv.backup = NULL;
	trace_xfrm_input.backup = NULL;
	trace_xfrm4_transport_input.backup = NULL;
	list_add_tail(&group_esp.list, &group_ip.children);
	list_add_tail(&trace_ah_output_list.list, &group_esp.traces);
	all_traces[INDEX_ah_output] = &trace_ah_output;
	list_add_tail(&trace_ah_output.all, &trace_list);
	list_add_tail(&trace_esp_output_list.list, &group_esp.traces);
	all_traces[INDEX_esp_output] = &trace_esp_output;
	list_add_tail(&trace_esp_output.all, &trace_list);
	list_add_tail(&trace_esp_output_tail_list.list, &group_esp.traces);
	all_traces[INDEX_esp_output_tail] = &trace_esp_output_tail;
	list_add_tail(&trace_esp_output_tail.all, &trace_list);
	list_add_tail(&trace_ah_input_list.list, &group_esp.traces);
	all_traces[INDEX_ah_input] = &trace_ah_input;
	list_add_tail(&trace_ah_input.all, &trace_list);
	list_add_tail(&trace_esp_input_list.list, &group_esp.traces);
	all_traces[INDEX_esp_input] = &trace_esp_input;
	list_add_tail(&trace_esp_input.all, &trace_list);
	trace_ah_output.backup = NULL;
	trace_esp_output.backup = NULL;
	trace_esp_output_tail.backup = NULL;
	trace_ah_input.backup = NULL;
	trace_esp_input.backup = NULL;
	list_add_tail(&group_ip_route.list, &group_ip.children);
	list_add_tail(&rule_trace_fib_validate_source_0.list, &trace_fib_validate_source.rules);
	list_add_tail(&trace_fib_validate_source_list.list, &group_ip_route.traces);
	all_traces[INDEX_fib_validate_source] = &trace_fib_validate_source;
	list_add_tail(&trace_fib_validate_source.all, &trace_list);
	list_add_tail(&rule_trace_ip_route_input_slow_0.list, &trace_ip_route_input_slow.rules);
	list_add_tail(&trace_ip_route_input_slow_list.list, &group_ip_route.traces);
	all_traces[INDEX_ip_route_input_slow] = &trace_ip_route_input_slow;
	list_add_tail(&trace_ip_route_input_slow.all, &trace_list);
	trace_fib_validate_source.backup = NULL;
	trace_ip_route_input_slow.backup = NULL;
	list_add_tail(&group_tcp.list, &root_group.children);
	list_add_tail(&group_tcp_in.list, &group_tcp.children);
	list_add_tail(&trace_tcp_v4_rcv_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_v4_rcv] = &trace_tcp_v4_rcv;
	list_add_tail(&trace_tcp_v4_rcv.all, &trace_list);
	list_add_tail(&trace_tcp_v6_rcv_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_v6_rcv] = &trace_tcp_v6_rcv;
	list_add_tail(&trace_tcp_v6_rcv.all, &trace_list);
	list_add_tail(&trace_tcp_filter_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_filter] = &trace_tcp_filter;
	list_add_tail(&trace_tcp_filter.all, &trace_list);
	list_add_tail(&trace_tcp_child_process_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_child_process] = &trace_tcp_child_process;
	list_add_tail(&trace_tcp_child_process.all, &trace_list);
	list_add_tail(&rule_trace_tcp_v4_send_reset_0.list, &trace_tcp_v4_send_reset.rules);
	list_add_tail(&trace_tcp_v4_send_reset_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_v4_send_reset] = &trace_tcp_v4_send_reset;
	list_add_tail(&trace_tcp_v4_send_reset.all, &trace_list);
	list_add_tail(&rule_trace_tcp_v6_send_reset_0.list, &trace_tcp_v6_send_reset.rules);
	list_add_tail(&trace_tcp_v6_send_reset_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_v6_send_reset] = &trace_tcp_v6_send_reset;
	list_add_tail(&trace_tcp_v6_send_reset.all, &trace_list);
	list_add_tail(&trace_tcp_v4_do_rcv_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_v4_do_rcv] = &trace_tcp_v4_do_rcv;
	list_add_tail(&trace_tcp_v4_do_rcv.all, &trace_list);
	list_add_tail(&trace_tcp_v6_do_rcv_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_v6_do_rcv] = &trace_tcp_v6_do_rcv;
	list_add_tail(&trace_tcp_v6_do_rcv.all, &trace_list);
	list_add_tail(&trace_tcp_rcv_established_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_rcv_established] = &trace_tcp_rcv_established;
	list_add_tail(&trace_tcp_rcv_established.all, &trace_list);
	list_add_tail(&rule_trace_tcp_rcv_state_process_0.list, &trace_tcp_rcv_state_process.rules);
	list_add_tail(&trace_tcp_rcv_state_process_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_rcv_state_process] = &trace_tcp_rcv_state_process;
	list_add_tail(&trace_tcp_rcv_state_process.all, &trace_list);
	list_add_tail(&trace_tcp_queue_rcv_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_queue_rcv] = &trace_tcp_queue_rcv;
	list_add_tail(&trace_tcp_queue_rcv.all, &trace_list);
	list_add_tail(&trace_tcp_data_queue_ofo_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_data_queue_ofo] = &trace_tcp_data_queue_ofo;
	list_add_tail(&trace_tcp_data_queue_ofo.all, &trace_list);
	list_add_tail(&trace_tcp_ack_probe_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_ack_probe] = &trace_tcp_ack_probe;
	list_add_tail(&trace_tcp_ack_probe.all, &trace_list);
	list_add_tail(&trace_tcp_ack_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_ack] = &trace_tcp_ack;
	list_add_tail(&trace_tcp_ack.all, &trace_list);
	list_add_tail(&trace_tcp_probe_timer_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_probe_timer] = &trace_tcp_probe_timer;
	list_add_tail(&trace_tcp_probe_timer.all, &trace_list);
	list_add_tail(&rule_trace_tcp_send_probe0_0.list, &trace_tcp_send_probe0.rules);
	list_add_tail(&trace_tcp_send_probe0_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_send_probe0] = &trace_tcp_send_probe0;
	list_add_tail(&trace_tcp_send_probe0.all, &trace_list);
	list_add_tail(&rule_trace___inet_lookup_listener_0.list, &trace___inet_lookup_listener.rules);
	list_add_tail(&trace___inet_lookup_listener_list.list, &group_tcp_in.traces);
	all_traces[INDEX___inet_lookup_listener] = &trace___inet_lookup_listener;
	list_add_tail(&trace___inet_lookup_listener.all, &trace_list);
	list_add_tail(&rule_trace_inet6_lookup_listener_0.list, &trace_inet6_lookup_listener.rules);
	list_add_tail(&trace_inet6_lookup_listener_list.list, &group_tcp_in.traces);
	all_traces[INDEX_inet6_lookup_listener] = &trace_inet6_lookup_listener;
	list_add_tail(&trace_inet6_lookup_listener.all, &trace_list);
	list_add_tail(&rule_trace_tcp_bad_csum_0.list, &trace_tcp_bad_csum.rules);
	list_add_tail(&trace_tcp_bad_csum_list.list, &group_tcp_in.traces);
	all_traces[INDEX_tcp_bad_csum] = &trace_tcp_bad_csum;
	list_add_tail(&trace_tcp_bad_csum.all, &trace_list);
	trace_tcp_v4_rcv.backup = NULL;
	trace_tcp_v6_rcv.backup = NULL;
	trace_tcp_filter.backup = NULL;
	trace_tcp_child_process.backup = NULL;
	trace_tcp_v4_send_reset.backup = NULL;
	trace_tcp_v6_send_reset.backup = NULL;
	trace_tcp_v4_do_rcv.backup = NULL;
	trace_tcp_v6_do_rcv.backup = NULL;
	trace_tcp_rcv_established.backup = NULL;
	trace_tcp_rcv_state_process.backup = NULL;
	trace_tcp_queue_rcv.backup = NULL;
	trace_tcp_data_queue_ofo.backup = NULL;
	trace_tcp_ack_probe.backup = NULL;
	trace_tcp_ack.backup = NULL;
	trace_tcp_probe_timer.backup = NULL;
	trace_tcp_send_probe0.backup = NULL;
	trace___inet_lookup_listener.backup = NULL;
	trace_inet6_lookup_listener.backup = NULL;
	trace_tcp_bad_csum.backup = NULL;
	list_add_tail(&group_tcp_out.list, &group_tcp.children);
	list_add_tail(&trace_tcp_sendmsg_locked_list.list, &group_tcp_out.traces);
	all_traces[INDEX_tcp_sendmsg_locked] = &trace_tcp_sendmsg_locked;
	list_add_tail(&trace_tcp_sendmsg_locked.all, &trace_list);
	list_add_tail(&trace_tcp_skb_entail_list.list, &group_tcp_out.traces);
	all_traces[INDEX_tcp_skb_entail] = &trace_tcp_skb_entail;
	list_add_tail(&trace_tcp_skb_entail.all, &trace_list);
	list_add_tail(&trace_skb_entail_list.list, &group_tcp_out.traces);
	all_traces[INDEX_skb_entail] = &trace_skb_entail;
	list_add_tail(&trace_skb_entail.all, &trace_list);
	list_add_tail(&trace___tcp_push_pending_frames_list.list, &group_tcp_out.traces);
	all_traces[INDEX___tcp_push_pending_frames] = &trace___tcp_push_pending_frames;
	list_add_tail(&trace___tcp_push_pending_frames.all, &trace_list);
	list_add_tail(&rule_trace___tcp_transmit_skb_0.list, &trace___tcp_transmit_skb.rules);
	list_add_tail(&trace___tcp_transmit_skb_list.list, &group_tcp_out.traces);
	all_traces[INDEX___tcp_transmit_skb] = &trace___tcp_transmit_skb;
	list_add_tail(&trace___tcp_transmit_skb.all, &trace_list);
	list_add_tail(&trace___tcp_retransmit_skb_list.list, &group_tcp_out.traces);
	all_traces[INDEX___tcp_retransmit_skb] = &trace___tcp_retransmit_skb;
	list_add_tail(&trace___tcp_retransmit_skb.all, &trace_list);
	list_add_tail(&trace_tcp_rate_skb_delivered_list.list, &group_tcp_out.traces);
	all_traces[INDEX_tcp_rate_skb_delivered] = &trace_tcp_rate_skb_delivered;
	list_add_tail(&trace_tcp_rate_skb_delivered.all, &trace_list);
	trace_tcp_sendmsg_locked.backup = NULL;
	trace_tcp_skb_entail.backup = NULL;
	trace_skb_entail.backup = NULL;
	trace___tcp_push_pending_frames.backup = NULL;
	trace___tcp_transmit_skb.backup = NULL;
	trace___tcp_retransmit_skb.backup = NULL;
	trace_tcp_rate_skb_delivered.backup = NULL;
	list_add_tail(&group_udp.list, &root_group.children);
	list_add_tail(&group_udp_in.list, &group_udp.children);
	list_add_tail(&trace_udp_rcv_list.list, &group_udp_in.traces);
	all_traces[INDEX_udp_rcv] = &trace_udp_rcv;
	list_add_tail(&trace_udp_rcv.all, &trace_list);
	list_add_tail(&trace_udp_unicast_rcv_skb_list.list, &group_udp_in.traces);
	all_traces[INDEX_udp_unicast_rcv_skb] = &trace_udp_unicast_rcv_skb;
	list_add_tail(&trace_udp_unicast_rcv_skb.all, &trace_list);
	list_add_tail(&trace_udp_queue_rcv_skb_list.list, &group_udp_in.traces);
	all_traces[INDEX_udp_queue_rcv_skb] = &trace_udp_queue_rcv_skb;
	list_add_tail(&trace_udp_queue_rcv_skb.all, &trace_list);
	list_add_tail(&trace_xfrm4_udp_encap_rcv_list.list, &group_udp_in.traces);
	all_traces[INDEX_xfrm4_udp_encap_rcv] = &trace_xfrm4_udp_encap_rcv;
	list_add_tail(&trace_xfrm4_udp_encap_rcv.all, &trace_list);
	list_add_tail(&trace_xfrm4_rcv_encap_list.list, &group_udp_in.traces);
	all_traces[INDEX_xfrm4_rcv_encap] = &trace_xfrm4_rcv_encap;
	list_add_tail(&trace_xfrm4_rcv_encap.all, &trace_list);
	list_add_tail(&trace___udp_queue_rcv_skb_list.list, &group_udp_in.traces);
	all_traces[INDEX___udp_queue_rcv_skb] = &trace___udp_queue_rcv_skb;
	list_add_tail(&trace___udp_queue_rcv_skb.all, &trace_list);
	list_add_tail(&trace___udp_enqueue_schedule_skb_list.list, &group_udp_in.traces);
	all_traces[INDEX___udp_enqueue_schedule_skb] = &trace___udp_enqueue_schedule_skb;
	list_add_tail(&trace___udp_enqueue_schedule_skb.all, &trace_list);
	trace_udp_rcv.backup = NULL;
	trace_udp_unicast_rcv_skb.backup = NULL;
	trace_udp_queue_rcv_skb.backup = NULL;
	trace_xfrm4_udp_encap_rcv.backup = NULL;
	trace_xfrm4_rcv_encap.backup = NULL;
	trace___udp_queue_rcv_skb.backup = NULL;
	trace___udp_enqueue_schedule_skb.backup = NULL;
	list_add_tail(&group_icmp.list, &root_group.children);
	list_add_tail(&group_icmp_in.list, &group_icmp.children);
	list_add_tail(&trace_icmp_rcv_list.list, &group_icmp_in.traces);
	all_traces[INDEX_icmp_rcv] = &trace_icmp_rcv;
	list_add_tail(&trace_icmp_rcv.all, &trace_list);
	list_add_tail(&trace_icmp_echo_list.list, &group_icmp_in.traces);
	all_traces[INDEX_icmp_echo] = &trace_icmp_echo;
	list_add_tail(&trace_icmp_echo.all, &trace_list);
	list_add_tail(&trace_icmp_reply_list.list, &group_icmp_in.traces);
	all_traces[INDEX_icmp_reply] = &trace_icmp_reply;
	list_add_tail(&trace_icmp_reply.all, &trace_list);
	list_add_tail(&trace_icmpv6_rcv_list.list, &group_icmp_in.traces);
	all_traces[INDEX_icmpv6_rcv] = &trace_icmpv6_rcv;
	list_add_tail(&trace_icmpv6_rcv.all, &trace_list);
	list_add_tail(&trace_icmpv6_echo_reply_list.list, &group_icmp_in.traces);
	all_traces[INDEX_icmpv6_echo_reply] = &trace_icmpv6_echo_reply;
	list_add_tail(&trace_icmpv6_echo_reply.all, &trace_list);
	list_add_tail(&trace_ping_rcv_list.list, &group_icmp_in.traces);
	all_traces[INDEX_ping_rcv] = &trace_ping_rcv;
	list_add_tail(&trace_ping_rcv.all, &trace_list);
	list_add_tail(&trace___ping_queue_rcv_skb_list.list, &group_icmp_in.traces);
	all_traces[INDEX___ping_queue_rcv_skb] = &trace___ping_queue_rcv_skb;
	list_add_tail(&trace___ping_queue_rcv_skb.all, &trace_list);
	list_add_tail(&trace_ping_queue_rcv_skb_list.list, &group_icmp_in.traces);
	all_traces[INDEX_ping_queue_rcv_skb] = &trace_ping_queue_rcv_skb;
	list_add_tail(&trace_ping_queue_rcv_skb.all, &trace_list);
	list_add_tail(&rule_trace_ping_lookup_0.list, &trace_ping_lookup.rules);
	list_add_tail(&trace_ping_lookup_list.list, &group_icmp_in.traces);
	all_traces[INDEX_ping_lookup] = &trace_ping_lookup;
	list_add_tail(&trace_ping_lookup.all, &trace_list);
	trace_icmp_rcv.backup = NULL;
	trace_icmp_echo.backup = NULL;
	trace_icmp_reply.backup = NULL;
	trace_icmpv6_rcv.backup = NULL;
	trace_icmpv6_echo_reply.backup = NULL;
	trace_ping_rcv.backup = NULL;
	trace___ping_queue_rcv_skb.backup = NULL;
	trace_ping_queue_rcv_skb.backup = NULL;
	trace_ping_lookup.backup = NULL;
	list_add_tail(&group_socket.list, &root_group.children);
	list_add_tail(&group_tcp_state.list, &group_socket.children);
	list_add_tail(&rule_trace_inet_listen_0.list, &trace_inet_listen.rules);
	list_add_tail(&trace_inet_listen_list.list, &group_tcp_state.traces);
	all_traces[INDEX_inet_listen] = &trace_inet_listen;
	list_add_tail(&trace_inet_listen.all, &trace_list);
	list_add_tail(&trace_tcp_v4_destroy_sock_list.list, &group_tcp_state.traces);
	all_traces[INDEX_tcp_v4_destroy_sock] = &trace_tcp_v4_destroy_sock;
	list_add_tail(&trace_tcp_v4_destroy_sock.all, &trace_list);
	list_add_tail(&rule_trace_tcp_close_0.list, &trace_tcp_close.rules);
	list_add_tail(&trace_tcp_close_list.list, &group_tcp_state.traces);
	all_traces[INDEX_tcp_close] = &trace_tcp_close;
	list_add_tail(&trace_tcp_close.all, &trace_list);
	list_add_tail(&trace_tcp_rcv_state_process_list_2.list, &group_tcp_state.traces);
	list_add_tail(&rule_trace_tcp_send_active_reset_0.list, &trace_tcp_send_active_reset.rules);
	list_add_tail(&trace_tcp_send_active_reset_list.list, &group_tcp_state.traces);
	all_traces[INDEX_tcp_send_active_reset] = &trace_tcp_send_active_reset;
	list_add_tail(&trace_tcp_send_active_reset.all, &trace_list);
	list_add_tail(&trace_tcp_ack_update_rtt_list.list, &group_tcp_state.traces);
	all_traces[INDEX_tcp_ack_update_rtt] = &trace_tcp_ack_update_rtt;
	list_add_tail(&trace_tcp_ack_update_rtt.all, &trace_list);
	trace_inet_listen.backup = NULL;
	trace_tcp_v4_destroy_sock.backup = NULL;
	trace_tcp_close.backup = NULL;
	trace_tcp_rcv_state_process.backup = NULL;
	trace_tcp_send_active_reset.backup = NULL;
	trace_tcp_ack_update_rtt.backup = NULL;
	list_add_tail(&group_tcp_congestion.list, &group_socket.children);
	list_add_tail(&trace_tcp_write_timer_handler_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_write_timer_handler] = &trace_tcp_write_timer_handler;
	list_add_tail(&trace_tcp_write_timer_handler.all, &trace_list);
	list_add_tail(&rule_trace_tcp_retransmit_timer_0.list, &trace_tcp_retransmit_timer.rules);
	list_add_tail(&trace_tcp_retransmit_timer_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_retransmit_timer] = &trace_tcp_retransmit_timer;
	list_add_tail(&trace_tcp_retransmit_timer.all, &trace_list);
	list_add_tail(&rule_trace_tcp_enter_recovery_0.list, &trace_tcp_enter_recovery.rules);
	list_add_tail(&trace_tcp_enter_recovery_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_enter_recovery] = &trace_tcp_enter_recovery;
	list_add_tail(&trace_tcp_enter_recovery.all, &trace_list);
	list_add_tail(&rule_trace_tcp_enter_loss_0.list, &trace_tcp_enter_loss.rules);
	list_add_tail(&trace_tcp_enter_loss_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_enter_loss] = &trace_tcp_enter_loss;
	list_add_tail(&trace_tcp_enter_loss.all, &trace_list);
	list_add_tail(&rule_trace_tcp_try_keep_open_0.list, &trace_tcp_try_keep_open.rules);
	list_add_tail(&trace_tcp_try_keep_open_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_try_keep_open] = &trace_tcp_try_keep_open;
	list_add_tail(&trace_tcp_try_keep_open.all, &trace_list);
	list_add_tail(&rule_trace_tcp_enter_cwr_0.list, &trace_tcp_enter_cwr.rules);
	list_add_tail(&trace_tcp_enter_cwr_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_enter_cwr] = &trace_tcp_enter_cwr;
	list_add_tail(&trace_tcp_enter_cwr.all, &trace_list);
	list_add_tail(&trace_tcp_fastretrans_alert_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_fastretrans_alert] = &trace_tcp_fastretrans_alert;
	list_add_tail(&trace_tcp_fastretrans_alert.all, &trace_list);
	list_add_tail(&trace_tcp_rearm_rto_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_rearm_rto] = &trace_tcp_rearm_rto;
	list_add_tail(&trace_tcp_rearm_rto.all, &trace_list);
	list_add_tail(&trace_tcp_event_new_data_sent_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_event_new_data_sent] = &trace_tcp_event_new_data_sent;
	list_add_tail(&trace_tcp_event_new_data_sent.all, &trace_list);
	list_add_tail(&trace_tcp_schedule_loss_probe_list.list, &group_tcp_congestion.traces);
	all_traces[INDEX_tcp_schedule_loss_probe] = &trace_tcp_schedule_loss_probe;
	list_add_tail(&trace_tcp_schedule_loss_probe.all, &trace_list);
	trace_tcp_write_timer_handler.backup = NULL;
	trace_tcp_retransmit_timer.backup = NULL;
	trace_tcp_enter_recovery.backup = NULL;
	trace_tcp_enter_loss.backup = NULL;
	trace_tcp_try_keep_open.backup = NULL;
	trace_tcp_enter_cwr.backup = NULL;
	trace_tcp_fastretrans_alert.backup = NULL;
	trace_tcp_rearm_rto.backup = NULL;
	trace_tcp_event_new_data_sent.backup = NULL;
	trace_tcp_schedule_loss_probe.backup = NULL;
	list_add_tail(&group_tcp_retrans.list, &group_socket.children);
	list_add_tail(&trace_tcp_rtx_synack_list.list, &group_tcp_retrans.traces);
	all_traces[INDEX_tcp_rtx_synack] = &trace_tcp_rtx_synack;
	list_add_tail(&trace_tcp_rtx_synack.all, &trace_list);
	list_add_tail(&trace_tcp_retransmit_skb_list.list, &group_tcp_retrans.traces);
	all_traces[INDEX_tcp_retransmit_skb] = &trace_tcp_retransmit_skb;
	list_add_tail(&trace_tcp_retransmit_skb.all, &trace_list);
	list_add_tail(&trace_tcp_rcv_spurious_retrans_list.list, &group_tcp_retrans.traces);
	all_traces[INDEX_tcp_rcv_spurious_retrans] = &trace_tcp_rcv_spurious_retrans;
	list_add_tail(&trace_tcp_rcv_spurious_retrans.all, &trace_list);
	list_add_tail(&rule_trace_tcp_dsack_set_0.list, &trace_tcp_dsack_set.rules);
	list_add_tail(&trace_tcp_dsack_set_list.list, &group_tcp_retrans.traces);
	all_traces[INDEX_tcp_dsack_set] = &trace_tcp_dsack_set;
	list_add_tail(&trace_tcp_dsack_set.all, &trace_list);
	trace_tcp_rtx_synack.backup = NULL;
	trace_tcp_retransmit_skb.backup = NULL;
	trace_tcp_rcv_spurious_retrans.backup = NULL;
	trace_tcp_dsack_set.backup = NULL;
	list_add_tail(&group_life.list, &root_group.children);
	list_add_tail(&rule_trace_skb_clone_0.list, &trace_skb_clone.rules);
	list_add_tail(&trace_skb_clone_list.list, &group_life.traces);
	all_traces[INDEX_skb_clone] = &trace_skb_clone;
	list_add_tail(&trace_skb_clone.all, &trace_list);
	list_add_tail(&rule_trace_consume_skb_0.list, &trace_consume_skb.rules);
	list_add_tail(&trace_consume_skb_list.list, &group_life.traces);
	all_traces[INDEX_consume_skb] = &trace_consume_skb;
	list_add_tail(&trace_consume_skb.all, &trace_list);
	list_add_tail(&rule_trace_kfree_skb_0.list, &trace_kfree_skb.rules);
	list_add_tail(&trace_kfree_skb_list.list, &group_life.traces);
	all_traces[INDEX_kfree_skb] = &trace_kfree_skb;
	list_add_tail(&trace_kfree_skb.all, &trace_list);
	list_add_tail(&trace___kfree_skb_list.list, &group_life.traces);
	all_traces[INDEX___kfree_skb] = &trace___kfree_skb;
	list_add_tail(&trace___kfree_skb.all, &trace_list);
	list_add_tail(&trace_kfree_skb_partial_list.list, &group_life.traces);
	all_traces[INDEX_kfree_skb_partial] = &trace_kfree_skb_partial;
	list_add_tail(&trace_kfree_skb_partial.all, &trace_list);
	list_add_tail(&trace_skb_attempt_defer_free_list.list, &group_life.traces);
	all_traces[INDEX_skb_attempt_defer_free] = &trace_skb_attempt_defer_free;
	list_add_tail(&trace_skb_attempt_defer_free.all, &trace_list);
	trace_skb_clone.backup = NULL;
	trace_consume_skb.backup = NULL;
	trace_kfree_skb.backup = NULL;
	trace___kfree_skb.backup = NULL;
	trace_kfree_skb_partial.backup = NULL;
	trace_skb_attempt_defer_free.backup = NULL;

}

