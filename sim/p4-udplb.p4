#include <core.p4>
#include <xsa.p4>

#define INCLUDE_IPV6ND 1
#define INCLUDE_ARP 1

struct intrinsic_metadata_t {
    bit<64> ingress_global_timestamp;
    bit<64> egress_global_timestamp;
    bit<16> mcast_grp;
    bit<16> egress_rid;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

#if INCLUDE_ARP

header arp_t {
    bit<16>  htype;
    bit<16>  ptype;
    bit<8>   hlen;
    bit<8>   plen;
    bit<16>  oper;
    bit<48>  sha;
    bit<32>  spa;
    bit<48>  tha;
    bit<32>  tpa;
}

#endif // INCLUDE_ARP

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

#if INCLUDE_IPV6ND

header icmpv6_common_t {
    bit<8>   msg_type;
    bit<8>   code;
    bit<16>  checksum;
}

header ipv6nd_neigh_sol_t {
    bit<32>  rsvd;
    bit<128> target;
}

header ipv6nd_option_common_t {
    bit<8>   option_type;
    bit<8>   length;
}

header ipv6nd_option_lladdr_t {
    bit<48>  ethernet_addr;
}

header ipv6nd_neigh_adv_t {
    bit<1>   router_flag;
    bit<1>   solicited_flag;
    bit<1>   override_flag;
    bit<29>  rsvd;
    bit<128> target;
}
#endif // INCLUDE_IPV6ND

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv4_opt_t {
    varbit<320> options; // IPv4 options - length = (ipv4.hdr_len - 5) * 32
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> totalLen;
    bit<16> checksum;
}

header udplb_t {
    bit<16> magic; 		/* LB */
    bit<8> version;		/* version 0 */
    bit<8> proto;
    bit<64> tick;
}
#define SIZEOF_UDPLB_HDR 12

struct short_metadata {
    bit<64> ingress_global_timestamp;
    bit<2>  dest_port;
    bit<1>  truncate_enable;
    bit<16> packet_length;
    bit<1>  rss_override_enable;
    bit<8>  rss_override;
}

struct headers {
    ethernet_t              ethernet;
#if INCLUDE_ARP
    arp_t                   arp;
#endif // INCLUDE_ARP
    ipv4_t                  ipv4;
    ipv4_opt_t              ipv4_opt;
    ipv6_t                  ipv6;
#if INCLUDE_IPV6ND
    icmpv6_common_t         icmpv6_common;
    ipv6nd_neigh_sol_t      ipv6nd_neigh_sol;
    ipv6nd_neigh_adv_t      ipv6nd_neigh_adv;
    ipv6nd_option_common_t  ipv6nd_option_common;
    ipv6nd_option_lladdr_t  ipv6nd_option_lladdr;
#endif // INCLUDE_IPV6ND
    udp_t                   udp;
    udplb_t                 udplb;
}

// User-defined errors 
error {
#if INCLUDE_ARP
    UnhandledArpHType,
    UnhandledArpPType,
    UnhandledArpHLen,
    UnhandledArpPLen,
    UnhandledArpOper,
#endif // INCLUDE_ARP
    InvalidIPpacket,
    InvalidUDPLBmagic,
    InvalidUDPLBversion
}

parser ParserImpl(packet_in packet, out headers hdr, inout short_metadata short_meta, inout standard_metadata_t smeta) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x0800: parse_ipv4;
#if INCLUDE_ARP
	    16w0x0806: parse_arp;
#endif // INCLUDE_ARP
            16w0x86dd: parse_ipv6;
        }
    }

#if INCLUDE_ARP
    state parse_arp {
	packet.extract(hdr.arp);
	verify(hdr.arp.htype == 1, error.UnhandledArpHType);       // Ethernet
	verify(hdr.arp.ptype == 0x0800, error.UnhandledArpPType);  // IPv4
	verify(hdr.arp.hlen == 6, error.UnhandledArpHLen);         // MAC addr length (6)
	verify(hdr.arp.plen == 4, error.UnhandledArpPLen);         // IPv4 addr length (4)
	verify(hdr.arp.oper == 1, error.UnhandledArpOper);         // Request
	transition accept;
    }
#endif // INCLUDE_ARP

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	verify(hdr.ipv4.version == 4 && hdr.ipv4.ihl >= 5, error.InvalidIPpacket);
        packet.extract(hdr.ipv4_opt, (((bit<32>)hdr.ipv4.ihl - 5) * 32));
        transition select(hdr.ipv4.protocol) {
            8w17: parse_udp;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        verify(hdr.ipv6.version == 6, error.InvalidIPpacket);
        transition select(hdr.ipv6.nextHdr) {
#if INCLUDE_IPV6ND
	    8w58: parse_icmpv6;
#endif // INCLUDE_IPV6ND
            8w17: parse_udp;
        }
    }

#if INCLUDE_IPV6ND
    state parse_icmpv6 {
	packet.extract(hdr.icmpv6_common);
	transition select(hdr.icmpv6_common.msg_type) {
	    8w135: parse_ipv6nd_neigh_sol;
	}
    }

    state parse_ipv6nd_neigh_sol {
	packet.extract(hdr.ipv6nd_neigh_sol);
	transition select(hdr.ipv6.payloadLen) {
	    16w24: accept;                        // No options
	    default: parse_ipv6nd_option;         // Has at least one option
	}
    }

    state parse_ipv6nd_option {
	packet.extract(hdr.ipv6nd_option_common);
	transition select(hdr.ipv6nd_option_common.option_type) {
	    8w1: parse_ipv6nd_option_lladdr;
	    default: accept;
	}
    }

    state parse_ipv6nd_option_lladdr {
	packet.extract(hdr.ipv6nd_option_lladdr);
	transition accept;
    }
#endif // INCLUDE_IPV6ND

    state parse_udp {
        packet.extract(hdr.udp);
	transition select(hdr.udp.dstPort) {
	  16w0x4c42: parse_udplb;
	}
    }

    state parse_udplb {
      packet.extract(hdr.udplb);
      verify(hdr.udplb.magic == 0x4c42, error.InvalidUDPLBmagic);
      verify(hdr.udplb.version == 1, error.InvalidUDPLBversion);
      transition accept;
    }
}

control MatchActionImpl(inout headers hdr, inout short_metadata short_meta, inout standard_metadata_t smeta) {

    //
    // MacDstFilter
    //

    bit<128> meta_ip_da = 0;
    bit<48>  meta_mac_sa = 0;
    bit<128> meta_ip_sa = 0;

    action drop() {
	smeta.drop = 1;
    }

    action set_mac_sa(bit<48> mac_sa) {
	meta_mac_sa = mac_sa;
    }

    table mac_dst_filter_table {
	actions = {
	    drop;
	    set_mac_sa;
	}
	key = {
	    hdr.ethernet.dstAddr : exact;
	}
	size = 64;
	default_action = drop;
    }

    //
    // IPDstFilter
    //

    action set_ip_sa(bit<128> ip_sa) {
	meta_ip_sa = ip_sa;
    }

    table ip_dst_filter_table {
	actions = {
	    drop;
	    set_ip_sa;
	}
	key = {
	    hdr.ethernet.etherType : exact;
	    meta_ip_da : exact;
	}
	size = 64;
	default_action = drop;
    }

    //
    // EpochAssign
    //

    bit<32> meta_epoch = 0;
    
    action do_assign_epoch(bit<32> epoch) {
	meta_epoch = epoch;
    }

    table epoch_assign_table {
	actions = {
	    do_assign_epoch;
	    drop;
	}
	key = {
	    hdr.udplb.tick : lpm;
	}
	size = 128;
	default_action = drop;
    }

    //
    // LoadBalanceCalendar
    //

    // Use lsbs of tick to select a calendar slot
    bit<9> calendar_slot = 0;
    bit<16> meta_member_id = 0;

    action do_assign_member(bit<16> member_id) {
	meta_member_id = member_id;
    }

    table load_balance_calendar_table {
	actions = {
	    do_assign_member;
	    drop;
	}
	key = {
	    meta_epoch : exact;
	    calendar_slot : exact;
	}
	size = 2048;
	default_action = drop;
    }
    
    //
    // MemberInfoLookup
    //

    // Cumulative checksum delta due to field rewrites
    bit<16> ckd = 0;

    bit<48>  new_mac_dst = 0x0;
    bit<32>  new_ip4_dst = 0x0;
    bit<128> new_ip6_dst = 0x0;
    bit<16>  new_udp_dst = 0x0;

    action cksum_sub(inout bit<16> cksum, in bit<16> a) {
	bit<18> sum = 2w00 ++ cksum;
	bit<18> a_x = 2w00 ++ (a ^ 0xFFFF); 

	sum = sum + a_x;
	cksum = sum[15:0] + (15w00 ++ sum[16:16]);
    }

    action cksum_add(inout bit<16> cksum, in bit<16> a) {
	bit<18> sum = 2w00 ++ cksum;
	bit<18> a_x = 2w00 ++ a;
	
	sum = sum + a_x;
	cksum = sum[15:0] + (15w00 ++ sum[16:16]);
    }

    action cksum_swap(inout bit<16> cksum, in bit<16> old, in bit<16> new) {
	cksum_sub(cksum, old);
	cksum_add(cksum, new);
    }

    action do_ipv4_member_rewrite(bit<48> mac_dst, bit<32> ip_dst, bit<16> udp_dst) {
	new_mac_dst = mac_dst;
	new_ip4_dst  = ip_dst;
	new_udp_dst = udp_dst;
    }


    action run_ipv4_member_rewrite(bit<48> mac_dst, bit<32> ip_dst, bit<16> udp_dst) {
	// Calculate IPv4 and UDP pseudo header checksum delta using rfc1624 method

	cksum_swap(ckd, hdr.ipv4.dstAddr[31:16], ip_dst[31:16]);
	cksum_swap(ckd, hdr.ipv4.dstAddr[15:00], ip_dst[15:00]);
	cksum_swap(ckd, hdr.ipv4.totalLen, hdr.ipv4.totalLen - SIZEOF_UDPLB_HDR);

	// Apply the accumulated delta to the IPv4 header checksum
	hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum ^ 0xFFFF;
	cksum_add(hdr.ipv4.hdrChecksum, ckd);
	hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum ^ 0xFFFF;

	hdr.ethernet.dstAddr = mac_dst;
	hdr.ipv4.dstAddr = ip_dst;
	hdr.ipv4.totalLen = hdr.ipv4.totalLen - SIZEOF_UDPLB_HDR;

	new_udp_dst = udp_dst;
    }


    action do_ipv6_member_rewrite(bit<48> mac_dst, bit<128> ip_dst, bit<16> udp_dst) {
	new_mac_dst = mac_dst;
	new_ip6_dst = ip_dst;
	new_udp_dst = udp_dst;
    }


    action run_ipv6_member_rewrite(bit<48> mac_dst, bit<128> ip_dst, bit<16> udp_dst) {
	// Calculate UDP pseudo header checksum delta using rfc1624 method

	cksum_swap(ckd, hdr.ipv6.dstAddr[127:112], ip_dst[127:112]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[111:96],  ip_dst[111:96]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[95:80], ip_dst[95:80]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[79:64], ip_dst[79:64]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[63:48], ip_dst[63:48]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[47:32], ip_dst[47:32]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[31:16], ip_dst[31:16]);
	cksum_swap(ckd, hdr.ipv6.dstAddr[15:00], ip_dst[15:00]);

	cksum_swap(ckd, hdr.ipv6.payloadLen, hdr.ipv6.payloadLen - SIZEOF_UDPLB_HDR);

	hdr.ethernet.dstAddr = mac_dst;
	hdr.ipv6.dstAddr = ip_dst;
	hdr.ipv6.payloadLen = hdr.ipv6.payloadLen - 12;
	new_udp_dst = udp_dst;
    }


    table member_info_lookup_table {
	actions = {
	    do_ipv4_member_rewrite;
	    do_ipv6_member_rewrite;
	    drop;
	}
	key = {
	    hdr.ethernet.etherType : exact;
	    meta_member_id : exact;
	}
	size = 1024;
	default_action = drop;
    }

    // Entry Point
    apply {
	bool hit;

	// Drop all packets that failed the parse stage
	if (smeta.parser_error != error.NoError) {
	    drop();
	    return;
	}

	//
	// MacDstFilter
	//

	hit = mac_dst_filter_table.apply().hit;
	if (!hit) {
	    return;
	}

	//
	// IPDstFilter
	//

	// Normalize the IP destination address
	if (hdr.ipv4.isValid()) {
	    meta_ip_da = (bit<96>) 0 ++ (bit<32>) hdr.ipv4.dstAddr;
	} else if (hdr.ipv6.isValid()) {
	    meta_ip_da = hdr.ipv6.dstAddr;
#if INCLUDE_ARP
	} else if (hdr.arp.isValid()) {
	    meta_ip_da = (bit<96>) 0 ++ (bit<32>) hdr.arp.tpa;
#endif // INCLUDE_ARP
	}

	hit = ip_dst_filter_table.apply().hit;
	if (!hit) {
	    return;
	}

#if INCLUDE_ARP
	// Handle ARP/ND requests
	if (hdr.arp.isValid()) {
	    // Make sure this is an ARP specifically for our unicast IPv4 address
	    if (hdr.arp.tpa != meta_ip_sa[31:0]) {
		drop();
		return;
	    }

	    // Convert the request into a reply
	    hdr.arp.oper = 2;
	    // Swap sender/target HW address and fill in our unicast MAC as the sha
	    hdr.arp.tha = hdr.arp.sha;
	    hdr.arp.sha = meta_mac_sa;
	    // Swap sender/target IP addresses
	    bit<32> tmp_ip = hdr.arp.tpa;
	    hdr.arp.tpa = hdr.arp.spa;
	    hdr.arp.spa = tmp_ip;

	    // Send the ethernet frame back to the originator
	    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	    hdr.ethernet.srcAddr = meta_mac_sa;
	    return;
#else  // INCLUDE_ARP
        if (false) {
#endif // INCLUDE_ARP
#if INCLUDE_IPV6ND
	} else if (hdr.ipv6nd_neigh_sol.isValid()) {
	    bit<128> new_ip_da;
	    bit<48>  new_mac_da;

	    // Make sure this is an ND solicitation for our unicast IPv6 address
	    if (hdr.ipv6nd_neigh_sol.target != meta_ip_sa) {
		drop();
		return;
	    }

	    // Figure out what our destination addresses should be based on the type of query we've received
	    if (hdr.ipv6.srcAddr == 128w0) {
		// Source is the unspecified address so reply to the all-nodes multicast IP
		new_ip_da = 0xff02_0000_0000_0000_0000_0000_0000_0001;  // ff02::1
		new_mac_da = 0x3333_0000_0001;  // 33:33:00:00:00:01
	    } else {
		// Reply to the originating source IP
		new_ip_da = hdr.ipv6.srcAddr;

		if (hdr.ipv6nd_option_lladdr.isValid()) {
		    // The request includes a link-layer address for the originator, reply to that
		    new_mac_da = hdr.ipv6nd_option_lladdr.ethernet_addr;
		} else {
		    // No link-layer address option, reply to the unicast MAC from the original frame
		    new_mac_da = hdr.ethernet.srcAddr;
		}
	    }

	    // Update our ethernet header addresses
	    hdr.ethernet.dstAddr = new_mac_da;
	    hdr.ethernet.srcAddr = meta_mac_sa;

	    // Update our ipv6 header addresses
	    hdr.ipv6.dstAddr = new_ip_da;
	    hdr.ipv6.srcAddr = meta_ip_sa;

	    // Reset our hop limit
	    hdr.ipv6.hopLimit = 255;  // Required by RFC4860 ICMPv6

	    // Set our new payload length
	    hdr.ipv6.payloadLen = 32;  // ICMPv6 + target IP + lladdr option

	    // Fill out the ICMPv6 common header
	    hdr.icmpv6_common.setValid();
	    hdr.icmpv6_common.msg_type = 136;   // ND Advertisement
	    hdr.icmpv6_common.code     = 0;
	    hdr.icmpv6_common.checksum = 0;     // This will be fixed up below

	    // Fill out our ND advertisement
	    hdr.ipv6nd_neigh_adv.setValid();
	    hdr.ipv6nd_neigh_adv.router_flag    = 0;
	    hdr.ipv6nd_neigh_adv.solicited_flag = 1;
	    hdr.ipv6nd_neigh_adv.override_flag  = 0;
	    hdr.ipv6nd_neigh_adv.rsvd           = 0;
	    hdr.ipv6nd_neigh_adv.target         = hdr.ipv6nd_neigh_sol.target;

	    // Fill out the ND advertisement option common header
	    hdr.ipv6nd_option_common.setValid();
	    hdr.ipv6nd_option_common.option_type   = 2;   // Target Link-Layer Address
	    hdr.ipv6nd_option_common.length        = 1;

	    // Fill out the ND advertisement lladdr common header
	    hdr.ipv6nd_option_lladdr.setValid();
	    hdr.ipv6nd_option_lladdr.ethernet_addr = meta_mac_sa;

	    // Calculate the checksum over the pseudo header + payload
	    cksum_add(ckd, hdr.ipv6.srcAddr[127:112]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[111:96]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[95:80]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[79:64]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[63:48]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[47:32]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[31:16]);
	    cksum_add(ckd, hdr.ipv6.srcAddr[15:00]);

	    cksum_add(ckd, hdr.ipv6.dstAddr[127:112]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[111:96]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[95:80]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[79:64]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[63:48]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[47:32]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[31:16]);
	    cksum_add(ckd, hdr.ipv6.dstAddr[15:00]);

	    cksum_add(ckd, hdr.ipv6.payloadLen);
	    cksum_add(ckd, 8w0 ++ hdr.ipv6.nextHdr);

	    cksum_add(ckd, hdr.icmpv6_common.msg_type ++ hdr.icmpv6_common.code);

	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.router_flag ++ hdr.ipv6nd_neigh_adv.solicited_flag ++ hdr.ipv6nd_neigh_adv.override_flag ++ hdr.ipv6nd_neigh_adv.rsvd[28:16]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[127:112]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[111:96]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[95:80]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[79:64]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[63:48]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[47:32]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[31:16]);
	    cksum_add(ckd, hdr.ipv6nd_neigh_adv.target[15:00]);

	    cksum_add(ckd, hdr.ipv6nd_option_common.option_type ++ hdr.ipv6nd_option_common.length);

	    cksum_add(ckd, hdr.ipv6nd_option_lladdr.ethernet_addr[47:32]);
	    cksum_add(ckd, hdr.ipv6nd_option_lladdr.ethernet_addr[31:16]);
	    cksum_add(ckd, hdr.ipv6nd_option_lladdr.ethernet_addr[15:00]);

	    // Write the final checksum to the packet
	    hdr.icmpv6_common.checksum = hdr.icmpv6_common.checksum ^ 0xFFFF;
	    cksum_add(hdr.icmpv6_common.checksum, ckd);
	    hdr.icmpv6_common.checksum = hdr.icmpv6_common.checksum ^ 0xFFFF;
	    return;
#endif // INCLUDE_IPV6ND
	}

	// Any packets that make it past here should be from our assigned unicast MAC addresses
	hdr.ethernet.srcAddr = meta_mac_sa;

	// Technically, we just want to rewrite the IP Src to be the load-balancer IP but that would require header
	// checksum fixups.  Instead, we'll *Swap* the IP Dst and IP Src so that we are neutral on the IP/UDP checksums,
	// knowing that the rest of the pipeline will eventually overwrite the (now bogus IP Dst) and fix up all checksums
	// before sending the packet out.
	if (hdr.ipv4.isValid()) {
	    // Swap the IPv4 addresses using an intermediate temp var
	    bit<32> tmpAddr;
	    tmpAddr = hdr.ipv4.srcAddr;
	    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
	    hdr.ipv4.dstAddr = tmpAddr;
	} else if (hdr.ipv6.isValid()) {
	    // Swap the IPv6 addresses using an intermediate temp var
	    bit<128> tmpAddr;
	    tmpAddr = hdr.ipv6.srcAddr;
	    hdr.ipv6.srcAddr = hdr.ipv6.dstAddr;
	    hdr.ipv6.dstAddr = tmpAddr;
	}

	//
	// EpochAssign
	//

	hit = epoch_assign_table.apply().hit;
	if (!hit) {
	    return;
	}

	//
	// LoadBalanceCalendar
	//

	calendar_slot = (bit<9>) hdr.udplb.tick & 0x1FF;
	hit = load_balance_calendar_table.apply().hit;
	if (!hit) {
	    return;
	}

	//
	// MemberInfoLookup
	//

	hit = member_info_lookup_table.apply().hit;
	if (!hit) {
	    return;
	} else {
	  if (hdr.ipv4.isValid()) {
            run_ipv4_member_rewrite(new_mac_dst,new_ip4_dst,new_udp_dst);
	  }
	  if (hdr.ipv6.isValid()) {
	    run_ipv6_member_rewrite(new_mac_dst,new_ip6_dst,new_udp_dst);
	  }
        }

	//
	// UpdateUDPChecksum
	//

	// Calculate UDP pseudo header checksum delta using rfc1624 method

	cksum_swap(ckd, hdr.udp.dstPort, new_udp_dst);
	cksum_swap(ckd, hdr.udp.totalLen, hdr.udp.totalLen - SIZEOF_UDPLB_HDR);

	// Subtract out the bytes of the UDP load-balance header
	cksum_sub(ckd, hdr.udplb.magic);
	cksum_sub(ckd, hdr.udplb.version ++ hdr.udplb.proto);
	cksum_sub(ckd, hdr.udplb.tick[63:48]);
	cksum_sub(ckd, hdr.udplb.tick[47:32]);
	cksum_sub(ckd, hdr.udplb.tick[31:16]);
	cksum_sub(ckd, hdr.udplb.tick[15:00]);

	// Write the updated checksum back into the packet
	hdr.udp.checksum = hdr.udp.checksum ^ 0xFFFF;
	cksum_add(hdr.udp.checksum, ckd);
	hdr.udp.checksum = hdr.udp.checksum ^ 0xFFFF;

	// Update the destination port and fix up the length to adapt to the dropped udplb header
	hdr.udp.dstPort = new_udp_dst;
	hdr.udp.totalLen = hdr.udp.totalLen - SIZEOF_UDPLB_HDR;
    }
}

control DeparserImpl(packet_out packet, in headers hdr, inout short_metadata short_meta, inout standard_metadata_t smeta) {
    apply {
        packet.emit(hdr.ethernet);
#if INCLUDE_ARP
	packet.emit(hdr.arp);
#endif // INCLUDE_ARP
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_opt);
        packet.emit(hdr.ipv6);
#if INCLUDE_IPV6ND
	packet.emit(hdr.icmpv6_common);
	packet.emit(hdr.ipv6nd_neigh_adv);
	packet.emit(hdr.ipv6nd_option_common);
	packet.emit(hdr.ipv6nd_option_lladdr);
#endif // INCLUDE_IPV6ND
        packet.emit(hdr.udp);
    }
}

XilinxPipeline(
  ParserImpl(),
  MatchActionImpl(),
  DeparserImpl()
) main;

