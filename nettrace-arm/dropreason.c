#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sys_utils.h"

#include "dropreason.h"

#define REASON_MAX_COUNT	256
#define REASON_MAX_LEN		32

static char drop_reasons[REASON_MAX_COUNT][REASON_MAX_LEN] = {};
static int drop_reason_max;
static bool drop_reason_inited = false;

/* check if drop reason on kfree_skb is supported */
bool drop_reason_support()
{
	return simple_exec("cat /sys/kernel/debug/tracing/events/skb/"
			   "kfree_skb/format 2>/dev/null | "
			   "grep NOT_SPECIFIED") == 0;
}


// cat /sys/kernel/debug/tracing/events/skb/kfree_skb/format 
// name: kfree_skb
// ID: 777
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:void * skbaddr;	offset:8;	size:4;	signed:0;
// 	field:void * location;	offset:12;	size:4;	signed:0;
// 	field:unsigned short protocol;	offset:16;	size:2;	signed:0;
// 	field:enum skb_drop_reason reason;	offset:20;	size:4;	signed:0;

// print fmt: "skbaddr=%p protocol=%u location=%pS reason: %s", REC->skbaddr, REC->protocol, REC->location, __print_symbolic(REC->reason, 
// 	{ 2, "NOT_SPECIFIED" }, { 3, "NO_SOCKET" }, { 4, "PKT_TOO_SMALL" }, { 5, "TCP_CSUM" }, { 6, "SOCKET_FILTER" }, { 7, "UDP_CSUM" }, 
// 	{ 8, "NETFILTER_DROP" }, { 9, "OTHERHOST" }, { 10, "IP_CSUM" }, { 11, "IP_INHDR" }, { 12, "IP_RPFILTER" }, 
// 	{ 13, "UNICAST_IN_L2_MULTICAST" }, { 14, "XFRM_POLICY" }, { 15, "IP_NOPROTO" }, { 16, "SOCKET_RCVBUFF" }, 
// 	{ 17, "PROTO_MEM" }, { 18, "TCP_MD5NOTFOUND" }, { 19, "TCP_MD5UNEXPECTED" }, { 20, "TCP_MD5FAILURE" }, 
// 	{ 21, "SOCKET_BACKLOG" }, { 22, "TCP_FLAGS" }, { 23, "TCP_ZEROWINDOW" }, { 24, "TCP_OLD_DATA" }, { 25, "TCP_OVERWINDOW" }, 
// 	{ 26, "TCP_OFOMERGE" }, { 27, "TCP_RFC7323_PAWS" }, { 28, "TCP_OLD_SEQUENCE" }, { 29, "TCP_INVALID_SEQUENCE" }, { 30, "TCP_RESET" }, 
// 	{ 31, "TCP_INVALID_SYN" }, { 32, "TCP_CLOSE" }, { 33, "TCP_FASTOPEN" }, { 34, "TCP_OLD_ACK" }, { 35, "TCP_TOO_OLD_ACK" }, 
// 	{ 36, "TCP_ACK_UNSENT_DATA" }, { 37, "TCP_OFO_QUEUE_PRUNE" }, { 38, "TCP_OFO_DROP" }, { 39, "IP_OUTNOROUTES" }, 
// 	{ 40, "BPF_CGROUP_EGRESS" }, { 41, "IPV6DISABLED" }, { 42, "NEIGH_CREATEFAIL" }, { 43, "NEIGH_FAILED" }, { 44, "NEIGH_QUEUEFULL" }, 
// 	{ 45, "NEIGH_DEAD" }, { 46, "TC_EGRESS" }, { 47, "QDISC_DROP" }, { 48, "CPU_BACKLOG" }, { 49, "XDP" }, { 50, "TC_INGRESS" }, 
// 	{ 51, "UNHANDLED_PROTO" }, { 52, "SKB_CSUM" }, { 53, "SKB_GSO_SEG" }, { 54, "SKB_UCOPY_FAULT" }, { 55, "DEV_HDR" }, { 56, "DEV_READY" }, 
// 	{ 57, "FULL_RING" }, { 58, "NOMEM" }, { 59, "HDR_TRUNC" }, { 60, "TAP_FILTER" }, { 61, "TAP_TXFILTER" }, { 62, "ICMP_CSUM" }, { 63, "INVALID_PROTO" }, 
// 	{ 64, "IP_INADDRERRORS" }, { 65, "IP_INNOROUTES" }, { 66, "PKT_TOO_BIG" }, { 67, "DUP_FRAG" }, { 68, "FRAG_REASM_TIMEOUT" },
// 	 { 69, "FRAG_TOO_FAR" }, { 70, "TCP_MINTTL" }, { 71, "IPV6_BAD_EXTHDR" }, { 72, "IPV6_NDISC_FRAG" }, { 73, "IPV6_NDISC_HOP_LIMIT" }, 
// 	 { 74, "IPV6_NDISC_BAD_CODE" }, { 75, "IPV6_NDISC_BAD_OPTIONS" }, { 76, "IPV6_NDISC_NS_OTHERHOST" }, { 77, "QUEUE_PURGE" }, { 78, "MAX" })


static int parse_reason_enum()
{
	char name[REASON_MAX_LEN];
	int index = 0;
	FILE *f;

	f = fopen("/sys/kernel/debug/tracing/events/skb/kfree_skb/format",
		 "r");

	if (!f || !fsearch(f, "__print_symbolic")) {
		if (f)
			fclose(f);
		return -1;
	}

	while (true) {
		if (!fsearch(f, "{") ||
		    fscanf(f, "%d, \"%31[A-Z_0-9]", &index, name) != 2)
			break;
		strcpy(drop_reasons[index], name);
	}
	drop_reason_max = index;
	drop_reason_inited = true;

	fclose(f);
	return 0;
}

char *get_drop_reason(int index)
{
	if (!drop_reason_inited && parse_reason_enum())
		return NULL;
	if (index <= 0 || index > drop_reason_max)
		return NULL;

	return drop_reasons[index];
}
