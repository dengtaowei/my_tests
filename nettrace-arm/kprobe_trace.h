#define INDEX_napi_gro_receive_entry 1
#define INDEX_dev_gro_receive 2
#define INDEX_enqueue_to_backlog 3
#define INDEX_netif_receive_generic_xdp 4
#define INDEX_xdp_do_generic_redirect 5
#define INDEX___netif_receive_skb_core 6
#define INDEX_RtmpOsPktRcvHandle 7
#define INDEX___dev_queue_xmit 8
#define INDEX_dev_hard_start_xmit 9
#define INDEX_fp_send_data_pkt 10
#define INDEX_tcf_classify 11
#define INDEX_cls_bpf_classify 12
#define INDEX_tcf_bpf_act 13
#define INDEX_qdisc_dequeue 14
#define INDEX_qdisc_enqueue 15
#define INDEX_ipvlan_queue_xmit 16
#define INDEX_ipvlan_handle_frame 17
#define INDEX_ipvlan_rcv_frame 18
#define INDEX_ipvlan_xmit_mode_l3 19
#define INDEX_ipvlan_process_v4_outbound 20
#define INDEX_br_nf_pre_routing 21
#define INDEX_br_nf_forward_ip 22
#define INDEX_br_nf_forward_arp 23
#define INDEX_br_nf_post_routing 24
#define INDEX_arp_rcv 25
#define INDEX_arp_process 26
#define INDEX_bond_dev_queue_xmit 27
#define INDEX___iptunnel_pull_header 28
#define INDEX_vxlan_rcv 29
#define INDEX_vxlan_xmit_one 30
#define INDEX_vlan_do_receive 31
#define INDEX_vlan_dev_hard_start_xmit 32
#define INDEX_netdev_port_receive 33
#define INDEX_ovs_vport_receive 34
#define INDEX_ovs_dp_process_packet 35
#define INDEX_packet_rcv 36
#define INDEX_tpacket_rcv 37
#define INDEX_packet_direct_xmit 38
#define INDEX_nft_do_chain 39
#define INDEX_nf_nat_manip_pkt 40
#define INDEX_nf_hook_slow 41
#define INDEX_ipt_do_table 42
#define INDEX_ipt_do_table_legacy 43
#define INDEX_ipv4_confirm 44
#define INDEX_nf_confirm 45
#define INDEX_ipv4_conntrack_in 46
#define INDEX_nf_conntrack_in 47
#define INDEX_ipv4_pkt_to_tuple 48
#define INDEX_tcp_new 49
#define INDEX_tcp_pkt_to_tuple 50
#define INDEX_resolve_normal_ct 51
#define INDEX_tcp_packet 52
#define INDEX_tcp_in_window 53
#define INDEX___nf_ct_refresh_acct 54
#define INDEX_ip_rcv 55
#define INDEX_ip_rcv_core 56
#define INDEX_ip_rcv_finish 57
#define INDEX_ip_local_deliver 58
#define INDEX_ip_local_deliver_finish 59
#define INDEX_ip_forward 60
#define INDEX_ip_forward_finish 61
#define INDEX_ip6_forward 62
#define INDEX_ip6_rcv_finish 63
#define INDEX_ip6_rcv_core 64
#define INDEX_ipv6_rcv 65
#define INDEX___ip_queue_xmit 66
#define INDEX___ip_local_out 67
#define INDEX_ip_output 68
#define INDEX_ip_finish_output 69
#define INDEX_ip_finish_output_gso 70
#define INDEX_ip_finish_output2 71
#define INDEX_ip6_output 72
#define INDEX_ip6_finish_output 73
#define INDEX_ip6_finish_output2 74
#define INDEX_ip6_send_skb 75
#define INDEX_ip6_local_out 76
#define INDEX_xfrm4_output 77
#define INDEX_xfrm_output 78
#define INDEX_xfrm_output2 79
#define INDEX_xfrm_output_gso 80
#define INDEX_xfrm_output_resume 81
#define INDEX_xfrm4_transport_output 82
#define INDEX_xfrm4_prepare_output 83
#define INDEX_xfrm4_policy_check 84
#define INDEX_xfrm4_rcv 85
#define INDEX_xfrm_input 86
#define INDEX_xfrm4_transport_input 87
#define INDEX_ah_output 88
#define INDEX_esp_output 89
#define INDEX_esp_output_tail 90
#define INDEX_ah_input 91
#define INDEX_esp_input 92
#define INDEX_fib_validate_source 93
#define INDEX_ip_route_input_slow 94
#define INDEX_tcp_v4_rcv 95
#define INDEX_tcp_v6_rcv 96
#define INDEX_tcp_filter 97
#define INDEX_tcp_child_process 98
#define INDEX_tcp_v4_send_reset 99
#define INDEX_tcp_v6_send_reset 100
#define INDEX_tcp_v4_do_rcv 101
#define INDEX_tcp_v6_do_rcv 102
#define INDEX_tcp_rcv_established 103
#define INDEX_tcp_rcv_state_process 104
#define INDEX_tcp_queue_rcv 105
#define INDEX_tcp_data_queue_ofo 106
#define INDEX_tcp_ack_probe 107
#define INDEX_tcp_ack 108
#define INDEX_tcp_probe_timer 109
#define INDEX_tcp_send_probe0 110
#define INDEX___inet_lookup_listener 111
#define INDEX_inet6_lookup_listener 112
#define INDEX_tcp_bad_csum 113
#define INDEX_tcp_sendmsg_locked 114
#define INDEX_tcp_skb_entail 115
#define INDEX_skb_entail 116
#define INDEX___tcp_push_pending_frames 117
#define INDEX___tcp_transmit_skb 118
#define INDEX___tcp_retransmit_skb 119
#define INDEX_tcp_rate_skb_delivered 120
#define INDEX_udp_rcv 121
#define INDEX_udp_unicast_rcv_skb 122
#define INDEX_udp_queue_rcv_skb 123
#define INDEX_xfrm4_udp_encap_rcv 124
#define INDEX_xfrm4_rcv_encap 125
#define INDEX___udp_queue_rcv_skb 126
#define INDEX___udp_enqueue_schedule_skb 127
#define INDEX_icmp_rcv 128
#define INDEX_icmp_echo 129
#define INDEX_icmp_reply 130
#define INDEX_icmpv6_rcv 131
#define INDEX_icmpv6_echo_reply 132
#define INDEX_ping_rcv 133
#define INDEX___ping_queue_rcv_skb 134
#define INDEX_ping_queue_rcv_skb 135
#define INDEX_ping_lookup 136
#define INDEX_inet_listen 137
#define INDEX_tcp_v4_destroy_sock 138
#define INDEX_tcp_close 139
#define INDEX_tcp_send_active_reset 140
#define INDEX_tcp_ack_update_rtt 141
#define INDEX_tcp_write_timer_handler 142
#define INDEX_tcp_retransmit_timer 143
#define INDEX_tcp_enter_recovery 144
#define INDEX_tcp_enter_loss 145
#define INDEX_tcp_try_keep_open 146
#define INDEX_tcp_enter_cwr 147
#define INDEX_tcp_fastretrans_alert 148
#define INDEX_tcp_rearm_rto 149
#define INDEX_tcp_event_new_data_sent 150
#define INDEX_tcp_schedule_loss_probe 151
#define INDEX_tcp_rtx_synack 152
#define INDEX_tcp_retransmit_skb 153
#define INDEX_tcp_rcv_spurious_retrans 154
#define INDEX_tcp_dsack_set 155
#define INDEX_skb_clone 156
#define INDEX_consume_skb 157
#define INDEX_kfree_skb 158
#define INDEX___kfree_skb 159
#define INDEX_kfree_skb_partial 160
#define INDEX_skb_attempt_defer_free 161

#define TRACE_MAX 162
#define DEFINE_ALL_PROBES(FN, FN_tp, FNC)		\
	FN_tp(napi_gro_receive_entry, net, napi_gro_receive_entry, 3, 24)	\
	FN(dev_gro_receive, 1, , )	\
	FN(enqueue_to_backlog, 0, , 3)	\
	FN(netif_receive_generic_xdp, 0, , )	\
	FN(xdp_do_generic_redirect, 1, , 4)	\
	FN_tp(__netif_receive_skb_core, net, netif_receive_skb, 0, 8)	\
	FN(RtmpOsPktRcvHandle, 0, , )	\
	FN(__dev_queue_xmit, 0, , 2)	\
	FN(dev_hard_start_xmit, 0, , )	\
	FN(fp_send_data_pkt, 2, , )	\
	FN(tcf_classify, 0, , )	\
	FN(cls_bpf_classify, 0, , )	\
	FN(tcf_bpf_act, 0, , )	\
	FNC(qdisc_dequeue)	\
	FNC(qdisc_enqueue)	\
	FN(ipvlan_queue_xmit, 0, , )	\
	FN(ipvlan_handle_frame, 0, , )	\
	FN(ipvlan_rcv_frame, 1, , )	\
	FN(ipvlan_xmit_mode_l3, 0, , )	\
	FN(ipvlan_process_v4_outbound, 0, , )	\
	FN(br_nf_pre_routing, 1, , )	\
	FN(br_nf_forward_ip, 1, , )	\
	FN(br_nf_forward_arp, 1, , )	\
	FN(br_nf_post_routing, 1, , )	\
	FN(arp_rcv, 0, , )	\
	FN(arp_process, 2, , )	\
	FN(bond_dev_queue_xmit, 1, , )	\
	FN(__iptunnel_pull_header, 0, , )	\
	FN(vxlan_rcv, 1, 0, )	\
	FN(vxlan_xmit_one, 0, , )	\
	FN(vlan_do_receive, 0, , )	\
	FN(vlan_dev_hard_start_xmit, 0, , )	\
	FN(netdev_port_receive, 0, , )	\
	FN(ovs_vport_receive, 1, , )	\
	FN(ovs_dp_process_packet, 0, , )	\
	FN(packet_rcv, 0, , )	\
	FN(tpacket_rcv, 0, , )	\
	FN(packet_direct_xmit, 0, , )	\
	FNC(nft_do_chain)	\
	FN(nf_nat_manip_pkt, 0, , )	\
	FNC(nf_hook_slow)	\
	FNC(ipt_do_table)	\
	FNC(ipt_do_table_legacy)	\
	FN(ipv4_confirm, 1, , )	\
	FN(nf_confirm, 0, , )	\
	FN(ipv4_conntrack_in, 1, , )	\
	FN(nf_conntrack_in, 3, , )	\
	FN(ipv4_pkt_to_tuple, 0, , )	\
	FN(tcp_new, 1, , )	\
	FN(tcp_pkt_to_tuple, 0, , )	\
	FN(resolve_normal_ct, 2, , )	\
	FN(tcp_packet, 1, , )	\
	FN(__nf_ct_refresh_acct, 2, , )	\
	FN(ip_rcv, 0, , )	\
	FN(ip_rcv_core, 0, , )	\
	FN(ip_rcv_finish, 2, , )	\
	FN(ip_local_deliver, 0, , )	\
	FN(ip_local_deliver_finish, 2, , )	\
	FN(ip_forward, 0, , )	\
	FN(ip_forward_finish, 0, , )	\
	FN(ip6_forward, 0, , )	\
	FN(ip6_rcv_finish, 2, , )	\
	FN(ip6_rcv_core, 0, , )	\
	FN(ipv6_rcv, 0, , )	\
	FN(__ip_queue_xmit, 1, 0, )	\
	FN(__ip_local_out, 2, 1, )	\
	FN(ip_output, 2, , )	\
	FN(ip_finish_output, 2, , )	\
	FN(ip_finish_output_gso, 2, , )	\
	FN(ip_finish_output2, 2, , )	\
	FN(ip6_output, 2, , )	\
	FN(ip6_finish_output, 2, , )	\
	FN(ip6_finish_output2, 2, , )	\
	FN(ip6_send_skb, 0, , )	\
	FN(ip6_local_out, 2, , )	\
	FN(xfrm4_output, 2, , )	\
	FN(xfrm_output, 1, , )	\
	FN(xfrm_output2, 2, , )	\
	FN(xfrm_output_gso, 2, , )	\
	FN(xfrm_output_resume, 1, , )	\
	FN(xfrm4_transport_output, 1, , )	\
	FN(xfrm4_prepare_output, 1, , )	\
	FN(xfrm4_policy_check, 2, , )	\
	FN(xfrm4_rcv, 0, , )	\
	FN(xfrm_input, 0, , )	\
	FN(xfrm4_transport_input, 1, , )	\
	FN(ah_output, 1, , )	\
	FN(esp_output, 1, , )	\
	FN(esp_output_tail, 1, , )	\
	FN(ah_input, 1, , )	\
	FN(esp_input, 1, , )	\
	FN(fib_validate_source, 0, , 8)	\
	FN(ip_route_input_slow, 0, , 6)	\
	FN(tcp_v4_rcv, 0, , )	\
	FN(tcp_v6_rcv, 0, , )	\
	FN(tcp_filter, 1, , )	\
	FN(tcp_child_process, 2, , )	\
	FNC(tcp_v4_send_reset)	\
	FNC(tcp_v6_send_reset)	\
	FN(tcp_v4_do_rcv, 1, , )	\
	FN(tcp_v6_do_rcv, 1, , )	\
	FN(tcp_rcv_established, 1, 0, )	\
	FN(tcp_rcv_state_process, 1, 0, )	\
	FN(tcp_queue_rcv, 1, 0, )	\
	FN(tcp_data_queue_ofo, 1, 0, )	\
	FN(tcp_ack_probe, , 0, )	\
	FN(tcp_ack, 1, 0, )	\
	FN(tcp_probe_timer, , 0, )	\
	FN(tcp_send_probe0, , 0, )	\
	FN(__inet_lookup_listener, 2, , 10)	\
	FN(inet6_lookup_listener, 2, , 10)	\
	FN_tp(tcp_bad_csum, tcp, tcp_bad_csum, 0, 8)	\
	FN(tcp_sendmsg_locked, , 0, )	\
	FN(tcp_skb_entail, 1, 0, )	\
	FN(skb_entail, 1, 0, )	\
	FN(__tcp_push_pending_frames, , 0, )	\
	FN(__tcp_transmit_skb, 1, 0, )	\
	FN(__tcp_retransmit_skb, 1, 0, )	\
	FN(tcp_rate_skb_delivered, 1, 0, )	\
	FN(udp_rcv, 0, , )	\
	FN(udp_unicast_rcv_skb, 1, , )	\
	FN(udp_queue_rcv_skb, 1, , )	\
	FN(xfrm4_udp_encap_rcv, 1, , )	\
	FN(xfrm4_rcv_encap, 0, , )	\
	FN(__udp_queue_rcv_skb, 1, , )	\
	FN(__udp_enqueue_schedule_skb, 1, , )	\
	FN(icmp_rcv, 0, , )	\
	FN(icmp_echo, 0, , )	\
	FN(icmp_reply, 1, , )	\
	FN(icmpv6_rcv, 0, , )	\
	FN(icmpv6_echo_reply, 0, , )	\
	FN(ping_rcv, 0, , )	\
	FN(__ping_queue_rcv_skb, 1, , )	\
	FN(ping_queue_rcv_skb, 1, , )	\
	FN(ping_lookup, 1, , )	\
	FNC(inet_listen)	\
	FN(tcp_v4_destroy_sock, , 0, )	\
	FN(tcp_close, , 0, )	\
	FNC(tcp_send_active_reset)	\
	FNC(tcp_ack_update_rtt)	\
	FN(tcp_write_timer_handler, , 0, )	\
	FN(tcp_retransmit_timer, , 0, 1)	\
	FN(tcp_enter_recovery, , 0, )	\
	FN(tcp_enter_loss, , 0, )	\
	FN(tcp_try_keep_open, , 0, )	\
	FN(tcp_enter_cwr, , 0, )	\
	FN(tcp_fastretrans_alert, , 0, )	\
	FN(tcp_rearm_rto, , 0, )	\
	FN(tcp_event_new_data_sent, , 0, )	\
	FN(tcp_schedule_loss_probe, , 0, )	\
	FN(tcp_rtx_synack, , 0, 2)	\
	FN(tcp_retransmit_skb, , 0, 3)	\
	FN(tcp_rcv_spurious_retrans, 1, 0, 2)	\
	FN(tcp_dsack_set, , 0, 3)	\
	FN(skb_clone, 0, , )	\
	FN_tp(consume_skb, skb, consume_skb, 0, 8)	\
	FNC(kfree_skb)	\
	FN(__kfree_skb, 0, , )	\
	FN(kfree_skb_partial, 0, , )	\
	FN(skb_attempt_defer_free, 0, , )	\


