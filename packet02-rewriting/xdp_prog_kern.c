/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	int vlid;

	if (!proto_is_vlan(eth->h_proto))
		return -1;

	/* Careful with the parenthesis here */
	vlh = (void *)(eth + 1);

	/* Still need to do bounds checking */
	if (vlh + 1 > data_end)
		return -1;

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	vlid = bpf_ntohs(vlh->h_vlan_TCI);
	h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (eth + 1 > data_end)
		return -1;

	/* Copy back the old Ethernet header and update the proto type */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
	eth->h_proto = h_proto;

	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
		struct ethhdr *eth, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;

	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Then add space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if (eth + 1 > data_end)
		return -1;

	/* Copy back Ethernet header in the right place, populate VLAN tag with
	 * ID and proto, and set outer Ethernet header to VLAN type.
	 */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

	vlh = (void *)(eth + 1);

	if (vlh + 1 > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;

    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;

    // Parse Ethernet header
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    
    if (nh_type == bpf_htons(ETH_P_IP)) {
        nh_type = parse_iphdr(&nh, data_end, &iph);
        if (nh_type == IPPROTO_TCP) {
            // Parse TCP header and check bounds
            if ((void *)(nh.pos + sizeof(struct tcphdr)) > data_end) {
                return XDP_PASS;  // Bounds check failed, pass the packet
            }

            tcph = nh.pos;
            __u16 old_dest_port = bpf_ntohs(tcph->dest);
            __u16 new_dest_port = old_dest_port - 1;
            tcph->dest = bpf_htons(new_dest_port);

            // Update checksum for TCP
            __u32 old_check = tcph->check;
            __u32 csum = bpf_csum_diff((__be32 *)&old_dest_port, sizeof(old_dest_port),
                                       (__be32 *)&new_dest_port, sizeof(new_dest_port), old_check);
            tcph->check = ~csum;

            bpf_printk("Rewrote TCP dest port from %d to %d\n", old_dest_port, new_dest_port);

        } else if (nh_type == IPPROTO_UDP) {
            // Parse UDP header and check bounds
            if ((void *)(nh.pos + sizeof(struct udphdr)) > data_end) {
                return XDP_PASS;  // Bounds check failed, pass the packet
            }

            udph = nh.pos;
            __u16 old_dest_port = bpf_ntohs(udph->dest);
            __u16 new_dest_port = old_dest_port - 1;
            udph->dest = bpf_htons(new_dest_port);

            // Update checksum for UDP
            if (udph->check) {  // Update checksum only if it's non-zero
                __u32 old_check = udph->check;
                __u32 csum = bpf_csum_diff((__be32 *)&old_dest_port, sizeof(old_dest_port),
                                           (__be32 *)&new_dest_port, sizeof(new_dest_port), old_check);
                udph->check = ~csum;
            }

            bpf_printk("Rewrote UDP dest port from %d to %d\n", old_dest_port, new_dest_port);
        }
    } else if (nh_type == bpf_htons(ETH_P_IPV6)) {
        nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
        if (nh_type == IPPROTO_TCP) {
            // Parse TCP header and check bounds
            if ((void *)(nh.pos + sizeof(struct tcphdr)) > data_end) {
                return XDP_PASS;  // Bounds check failed, pass the packet
            }

            tcph = nh.pos;
            __u16 old_dest_port = bpf_ntohs(tcph->dest);
            __u16 new_dest_port = old_dest_port - 1;
            tcph->dest = bpf_htons(new_dest_port);

            // Update checksum for TCP over IPv6
            __u32 old_check = tcph->check;
            __u32 csum = bpf_csum_diff((__be32 *)&old_dest_port, sizeof(old_dest_port),
                                       (__be32 *)&new_dest_port, sizeof(new_dest_port), old_check);
            tcph->check = ~csum;

            bpf_printk("Rewrote TCP dest port from %d to %d (IPv6)\n", old_dest_port, new_dest_port);

        } else if (nh_type == IPPROTO_UDP) {
            // Parse UDP header and check bounds
            if ((void *)(nh.pos + sizeof(struct udphdr)) > data_end) {
                return XDP_PASS;  // Bounds check failed, pass the packet
            }

            udph = nh.pos;
            __u16 old_dest_port = bpf_ntohs(udph->dest);
            __u16 new_dest_port = old_dest_port - 1;
            udph->dest = bpf_htons(new_dest_port);

            // Update checksum for UDP over IPv6
            if (udph->check) {  // Update checksum only if it's non-zero
                __u32 old_check = udph->check;
                __u32 csum = bpf_csum_diff((__be32 *)&old_dest_port, sizeof(old_dest_port),
                                           (__be32 *)&new_dest_port, sizeof(new_dest_port), old_check);
                udph->check = ~csum;
            }

            bpf_printk("Rewrote UDP dest port from %d to %d (IPv6)\n", old_dest_port, new_dest_port);
        }
    }

    return XDP_PASS;
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	 if (proto_is_vlan(eth->h_proto)) {
        if (vlan_tag_pop(ctx, eth) < 0) {
			bpf_printk("Packet aborted due to failed VLAN operation.\n");
            return XDP_ABORTED; // Abort if VLAN tag pop fails
        }
    } else {
        if (vlan_tag_push(ctx, eth, 1) < 0) {
			bpf_printk("Packet aborted due to failed VLAN operation.\n");
            return XDP_ABORTED; // Abort if VLAN tag push fails
        }
    }

	return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
