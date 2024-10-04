/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#include <linux/ip.h>  // For struct iphdr (IPv4 header)
#include <linux/icmp.h>  // For struct icmphdr (ICMPv4 header)

#define VLAN_MAX_DEPTH 10

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
    __be16 h_vlan_TCI;                // VLAN Tag Control Information
    __be16 h_vlan_encapsulated_proto;  // Encapsulated protocol
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
    return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}


/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    // Bounds check to ensure Ethernet header fits in the packet
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    // Get the protocol from the Ethernet header
    __u16 h_proto = eth->h_proto;

    // Unroll loop to handle multiple VLAN tags
	#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) { 
        if (proto_is_vlan(h_proto)) {
            struct vlan_hdr *vh = nh->pos;

            // Bounds check for VLAN header
            if (nh->pos + sizeof(*vh) > data_end)
                return -1;

            // Move the cursor beyond the VLAN header
            nh->pos += sizeof(*vh);

            // Update the protocol to the encapsulated protocol inside the VLAN tag
            h_proto = vh->h_vlan_encapsulated_proto;
        }
    }

    return h_proto;  // Return the encapsulated protocol (e.g., ETH_P_IPV6)
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    // Pointer-arithmetic bounds check to ensure the entire IPv6 header fits in the packet
    if (ip6h + 1 > data_end) {
        return -1;
    }

    // Move the cursor position to after the IPv6 header
    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    // Return the next header field (ICMPv6, TCP, etc.)
    return ip6h->nexthdr;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct icmp6hdr **icmp6hdr)
{
    struct icmp6hdr *icmp6h = nh->pos;

    // Bounds check to ensure the ICMPv6 header fits in the packet
    if (icmp6h + 1 > data_end)
        return -1;

    // Move cursor to the end of the ICMPv6 header
    nh->pos = icmp6h + 1;
    *icmp6hdr = icmp6h;

    // Return ICMPv6 type field (e.g., Echo Request, Echo Reply)
    return icmp6h->icmp6_type;
}


static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    // Bounds check for the fixed IPv4 header size
    if (nh->pos + sizeof(*iph) > data_end)
        return -1;

    // Calculate actual header size (ihl * 4)
    hdrsize = iph->ihl * 4;
    if (nh->pos + hdrsize > data_end)
        return -1;

    // Move the cursor beyond the IPv4 header
    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;  // Return the protocol (ICMPv4, TCP, etc.)
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct icmphdr **icmphdr)
{
    struct icmphdr *icmph = nh->pos;

    // Bounds check to ensure the ICMPv4 header fits in the packet
    if (nh->pos + sizeof(*icmph) > data_end)
        return -1;

    // Move the cursor beyond the ICMPv4 header
    nh->pos += sizeof(*icmph);
    *icmphdr = icmph;

    return icmph->type;  // Return ICMPv4 type (e.g., echo request)
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct icmphdr *icmph;
    struct icmp6hdr *icmp6h;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	// Check for IPv4 or IPv6 in the Ethernet header
    if (nh_type == bpf_htons(ETH_P_IPV6)) {
        // Parse IPv6 header
        nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
        if (nh_type != IPPROTO_ICMPV6)
            goto out;  // Not ICMPv6, pass the packet

        // Parse ICMPv6 header
        nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
        if (nh_type == -1)
            goto out;  // Bounds check failed, pass the packet

        // Handle ICMPv6 Echo Requests (drop if sequence is even)
        if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST) {
            __u16 sequence = bpf_ntohs(icmp6h->icmp6_sequence);
            if (sequence % 2 == 0) {
                action = XDP_DROP;
                bpf_printk("Dropping ICMPv6 packet with even sequence number: %d\n", sequence);
            }
        }
    } else if (nh_type == bpf_htons(ETH_P_IP)) {
        // Parse IPv4 header
        nh_type = parse_iphdr(&nh, data_end, &iph);
        if (nh_type != IPPROTO_ICMP)
            goto out;  // Not ICMPv4, pass the packet

        // Parse ICMPv4 header
        nh_type = parse_icmp4hdr(&nh, data_end, &icmph);
        if (nh_type == -1)
            goto out;  // Bounds check failed, pass the packet

        // Handle ICMPv4 Echo Requests (drop if sequence is even)
        if (icmph->type == ICMP_ECHO) {
            __u16 sequence = bpf_ntohs(icmph->un.echo.sequence);
            if (sequence % 2 == 0) {
                action = XDP_DROP;
                bpf_printk("Dropping ICMPv4 packet with even sequence number: %d\n", sequence);
            }
        }
    }
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
