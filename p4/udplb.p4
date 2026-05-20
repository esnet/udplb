#include <core.p4>
#include <xsa.p4>

// Temporarily operate in a compatibility mode where a miss in the L2 interface map simply
// assigns the packet into L2 interface 0 with an undefined UC MAC, expecting the old control
// plane code to be unaware of multiple L2 interfaces, and also to assign the UC MAC in the MAC
// DA lookup table rather than in the L2 interface map table.
#define L2_IFACE_MAP_COMPAT_MODE 1

#define INCLUDE_L2_PROC          1
#define INCLUDE_L3_PROC          1
#define INCLUDE_ARP_PROC         1
#define INCLUDE_ICMPV4_PROC      1
#define INCLUDE_ICMPV6_PROC      1
#define INCLUDE_ICMPV6_ECHO_PROC 1
#define INCLUDE_ICMPV6_ND_PROC   1
#define INCLUDE_EJFAT_PROC       1

struct smartnic_metadata {
    bit<64> timestamp_ns;    // 64b timestamp (in nanoseconds). Set at packet arrival time.
    bit<16> pid;             // 16b packet id used by platform (READ ONLY - DO NOT EDIT).
    bit<4>  ingress_port;    // bit<0>   port_num (0:P0, 1:P1).
                             // bit<3:1> port_typ (0:PHY, 1:PF, 2:VF, 3:APP, 4-7:reserved).
    bit<4>  egress_port;     // bit<0>   port_num (0:P0, 1:P1).
                             // bit<3:1> port_typ (0:PHY, 1:PF, 2:VF, 3:APP, 4-6:reserved, 7:UNSET).
    bit<1>  truncate_enable; // 1b set to 1 to enable truncation of egress packet to 'truncate_length'.
    bit<16> truncate_length; // 16b set to desired length of egress packet (used when 'truncate_enable' == 1).
    bit<1>  rss_enable;      // 1b set to 1 to override open-nic-shell rss hash result with 'rss_entropy' value.
    bit<12> rss_entropy;     // 12b set to rss_entropy hash value (used for open-nic-shell qdma qid selection).
    bit<4>  drop_reason;     // reserved (tied to 0).
    bit<32> scratch;         // reserved (tied to 0).
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header vlan_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

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

header icmpv6_common_t {
    bit<16>  msg_type_code;
    bit<16>  checksum;
}

header icmpv6_echo_t {
    bit<16>  identifier;
    bit<16>  sequence;
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

header ipv6nd_adv_option_common_t {
    bit<8>   option_type;
    bit<8>   length;
}

header ipv6nd_adv_option_lladdr_t {
    bit<48>  ethernet_addr;
}

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

header icmpv4_common_t {
    bit<16> msg_type_code;
    bit<16> checksum;
}

header icmpv4_echo_t {
    bit<16>  identifier;
    bit<16>  sequence;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> totalLen;
    bit<16> checksum;
}

header udplb_common_t {
    bit<16> magic; 		/* LB */
    bit<8> version;
    bit<8> proto;
}

header udplb_v2_t {
    bit<16> rsvd;
    bit<16> entropy;
    bit<64> tick;
}

header udplb_v3_t {
    bit<16> slot_select;
    bit<16> port_select;
    bit<64> tick;
}
#define SIZEOF_UDPLB_HDR 16

struct headers {
    ethernet_t              ethernet;
    vlan_t                  vlan;
    arp_t                   arp;
    ipv4_t                  ipv4;
    ipv4_opt_t              ipv4_opt;
    icmpv4_common_t         icmpv4_common;
    icmpv4_echo_t           icmpv4_echo;
    ipv6_t                  ipv6;
    icmpv6_common_t         icmpv6_common;
    icmpv6_echo_t           icmpv6_echo;
    ipv6nd_neigh_sol_t      ipv6nd_neigh_sol;
    ipv6nd_option_common_t  ipv6nd_option_common;
    ipv6nd_option_lladdr_t  ipv6nd_option_lladdr;

    ipv6nd_neigh_adv_t      ipv6nd_neigh_adv;
    ipv6nd_adv_option_common_t  ipv6nd_adv_option_common;
    ipv6nd_adv_option_lladdr_t  ipv6nd_adv_option_lladdr;
    udp_t                   udp;
    udplb_common_t          udplb_common;
    udplb_v2_t              udplb_v2;
    udplb_v3_t              udplb_v3;
}

// User-defined errors 
error {
    UnhandledArpHType,
    UnhandledArpPType,
    UnhandledArpHLen,
    UnhandledArpPLen,
    UnhandledArpOper,
    InvalidIPpacket,
    InvalidUDPLBmagic
}

parser ParserImpl(packet_in packet, out headers hdr, inout smartnic_metadata snmeta, inout standard_metadata_t smeta) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x0800: parse_ipv4;
	    16w0x0806: parse_arp;
            16w0x8100: parse_dot1q; // 802.1q C-tag
            16w0x86dd: parse_ipv6;
        }
    }

    state parse_dot1q {
	packet.extract(hdr.vlan);
	transition select(hdr.vlan.etherType) {
            16w0x0800: parse_ipv4;
	    16w0x0806: parse_arp;
            16w0x86dd: parse_ipv6;
	}
    }

    state parse_arp {
	packet.extract(hdr.arp);
	verify(hdr.arp.htype == 1, error.UnhandledArpHType);       // Ethernet
	verify(hdr.arp.ptype == 0x0800, error.UnhandledArpPType);  // IPv4
	verify(hdr.arp.hlen == 6, error.UnhandledArpHLen);         // MAC addr length (6)
	verify(hdr.arp.plen == 4, error.UnhandledArpPLen);         // IPv4 addr length (4)
	verify(hdr.arp.oper == 1, error.UnhandledArpOper);         // Request
	transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	verify(hdr.ipv4.version == 4 && hdr.ipv4.ihl >= 5, error.InvalidIPpacket);
        packet.extract(hdr.ipv4_opt, (((bit<32>)hdr.ipv4.ihl - 5) * 32));
        transition select(hdr.ipv4.protocol) {
	    8w1: parse_icmpv4;
            8w17: parse_udp;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        verify(hdr.ipv6.version == 6, error.InvalidIPpacket);
        transition select(hdr.ipv6.nextHdr) {
	    8w58: parse_icmpv6;
            8w17: parse_udp;
        }
    }

    state parse_icmpv6 {
	packet.extract(hdr.icmpv6_common);
	transition select(hdr.icmpv6_common.msg_type_code) {
	    8w128 ++ 8w0: parse_icmpv6_echo;
	    8w135 ++ 8w0: parse_ipv6nd_neigh_sol;
	}
    }

    state parse_icmpv6_echo {
	packet.extract(hdr.icmpv6_echo);
	transition accept;
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

    state parse_icmpv4 {
	packet.extract(hdr.icmpv4_common);
	transition select(hdr.icmpv4_common.msg_type_code) {
	    8w8 ++ 8w0: parse_icmpv4_echo;
	    default: accept;	// Will be rejected during packet processing
	}
    }

    state parse_icmpv4_echo {
	packet.extract(hdr.icmpv4_echo);
	transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
	transition select(hdr.udp.dstPort) {
	    16w0x4000 &&& 16w0xC000: parse_udplb_common;
	    default: accept;	// Will be rejected during packet processing
	}
    }

    state parse_udplb_common {
	packet.extract(hdr.udplb_common);
	verify(hdr.udplb_common.magic == 0x4c42, error.InvalidUDPLBmagic);
	transition select(hdr.udplb_common.version) {
            8w2: parse_udplb_v2;
	    8w3: parse_udplb_v3;
	}
    }

    state parse_udplb_v2 {
	packet.extract(hdr.udplb_v2);
	transition accept;
    }

    state parse_udplb_v3 {
	packet.extract(hdr.udplb_v3);
	transition accept;
    }
}

#if INCLUDE_L2_PROC

control L2IfaceMap(
inout headers hdr,
inout smartnic_metadata snmeta,
inout standard_metadata_t smeta,
out bool ok,
out bit<4> ingress_l2_iface_id,
out bit<48> ingress_l2_iface_uc_mac,
out bool tx_ready)
{
    //
    // VLANInterface
    //

    // Normalized VID with 0 meaning untagged or priority tagged
    bit<12> vlan_id;

    action set_l2_iface(bit<4> l2_iface_id, bit<48> l2_iface_uc_mac) {
	ingress_l2_iface_id = l2_iface_id;
	ingress_l2_iface_uc_mac = l2_iface_uc_mac;
    }

    table l2_iface_table {
	actions = {
	    set_l2_iface;
	}
	key = {
	    vlan_id : field_mask;
	}
	size = 17;  // 16 l2 sub interfaces + wildcard
    }

    //
    // MacDstFilter
    //

    // Deprecated action -- use l2_dst_allow
    // Old control plane software will use this action to
    // set the unicast MAC addr for this layer 2 interface.
    // New control plane software should add entries to the
    // l2_interface_table and use the l2_dst_allow action
    // in this table.
    action set_mac_sa(bit<48> mac_sa) {
	ingress_l2_iface_uc_mac = mac_sa;
    }

    action l2_dst_allow() {
	// MAC DA matched an expected unicast or multicast MAC address for this L2 interface
    }

    table mac_dst_filter_table {
	actions = {
	    set_mac_sa;
	    l2_dst_allow;
	}
	key = {
	    ingress_l2_iface_id : field_mask;
	    hdr.ethernet.dstAddr : exact;
	}
	size = 64;
    }

    action drop_1() {
	smeta.drop = 1;
    }

#if !L2_IFACE_MAP_COMPAT_MODE
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) packet_rx_l2_iface_drop_counter;
#endif // L2_IFACE_MAP_COMPAT_MODE
    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) packet_rx_l2_iface_allow_counter;

    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) packet_rx_l2_dst_drop_counter;
    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) packet_rx_l2_dst_allow_counter;

    apply {
	// Assign this packet to a layer 2 sub interface

	// Normalize untagged and tagged packets to a common vlan_id space
	// with untagged packets being assigned to vlan_id 0
	if (hdr.vlan.isValid()) {
	    // VLAN tagged packet
	    vlan_id = hdr.vlan.vid;
	    // Mark the VLAN header as invalid (pop it) now that we've processed it.
	    // If a tag is required again at egress, it will be pushed there.
	    hdr.vlan.setInvalid();
	} else {
	    // Untagged packet, use VID 0
	    vlan_id = 0;
	}

	bool l2_iface_hit = l2_iface_table.apply().hit;
	if (!l2_iface_hit) {
#if L2_IFACE_MAP_COMPAT_MODE
	    ingress_l2_iface_id = 0;
	    ingress_l2_iface_uc_mac = 0x000000_000000;
#else
	    packet_rx_l2_iface_drop_counter.count(0);
	    drop_1();
	    ok = false;
	    ingress_l2_iface_id = 4w0;
	    ingress_l2_iface_uc_mac = 48w0;
	    tx_ready = false;
	    return;
#endif
	}

	// Packet was received on a valid, configured L2 tagged or untagged interface
	packet_rx_l2_iface_allow_counter.count(ingress_l2_iface_id);

	// Check if this packet is destined to any of our configured unicast or
	// multicast MAC addresses for the physical interface that it arrived on.
	bool l2_mac_dst_hit = mac_dst_filter_table.apply().hit;
	if (!l2_mac_dst_hit) {
	    packet_rx_l2_dst_drop_counter.count(ingress_l2_iface_id);
	    drop_1();
	    ok = false;
	    ingress_l2_iface_id = 4w0;
	    ingress_l2_iface_uc_mac = 48w0;
	    tx_ready = false;
	    return;
	}

	// Packet is destined for a configured MAC address on the ingress interface
	packet_rx_l2_dst_allow_counter.count(ingress_l2_iface_id);
	ok = true;

	// This layer doesn't currently fully process any of its rx'd packets
	tx_ready = false;

	return;
    }
}

#endif // INCLUDE_L2_PROC

#if INCLUDE_L3_PROC

control L3IfaceMap(
inout headers hdr,
inout smartnic_metadata snmeta,
inout standard_metadata_t smeta,
in bit<4> ingress_l2_iface_id,
in bit<48> ingress_l2_iface_uc_mac,
out bool ok,
out bit<128> ingress_l3_iface_uc_ip,
out bit<8> ingress_lb_id,
out bool tx_ready)
{
    bit<128> meta_ip_da = 0;

    //
    // IPDstFilter
    //

    action set_ip_sa(bit<128> ip_sa, bit<3> lb_id) {
	ingress_l3_iface_uc_ip = ip_sa;
	ingress_lb_id = 5w0 ++ lb_id;
    }

    table ip_dst_filter_table {
	actions = {
	    set_ip_sa;
	}
	key = {
	    ingress_l2_iface_id : field_mask;
	    hdr.ethernet.etherType : exact;
	    meta_ip_da : exact;
	}
	size = 64;
    }

    action drop_2() {
	smeta.drop = 1;
	ok = false;
	tx_ready = false;
    }

    action rx_done() {
	ok = true;
	tx_ready = true;
    }

    action rx_continue() {
	ok = true;
	tx_ready = false;
    }

    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) packet_rx_l2_iface_drop_notip_counter;
    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) packet_rx_l2_iface_drop_badip_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_allow_counter;

#if INCLUDE_ARP_PROC
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_arp_ok;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_arp_tpa_nomatch;
#endif

#if INCLUDE_ICMPV4_PROC
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_icmpv4_unhandled;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_icmpv4_echo_ok;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_icmpv4_echo_dst_nomatch;
#endif // INCLUDE_ICMPV4_PROC

#if INCLUDE_ICMPV6_PROC
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_icmpv6_unhandled;

    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_icmpv6_echo_ok;

#if INCLUDE_ICMPV6_ND_PROC
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_ipv6nd_neigh_sol_ok;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) packet_rx_l3_ipv6nd_neigh_sol_target_nomatch;
#endif // INCLUDE_ICMPV6_ND_PROC
#endif // INCLUDE_ICMPV6_PROC

#if INCLUDE_ICMPV4_PROC || INCLUDE_ICMPV6_PROC
    InternetChecksum() icmp_cksum;
#endif // INCLUDE_ICMPV4_PROC || INCLUDE_ICMPV6_PROC

    apply {
	if (!hdr.ipv4.isValid() &&
	    !hdr.ipv6.isValid() &&
	    !hdr.arp.isValid()) {
	    // Not an IPv4 or IPv6 packet, no further processing
	    packet_rx_l2_iface_drop_notip_counter.count(ingress_l2_iface_id);
	    drop_2();
	    ingress_l3_iface_uc_ip = 128w0;
	    ingress_lb_id = 8w0;
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
	} else if (hdr.arp.isValid()) {
	    meta_ip_da = (bit<96>) 0 ++ (bit<32>) hdr.arp.tpa;
	}

	bool ip_dst_hit = ip_dst_filter_table.apply().hit;
	if (!ip_dst_hit) {
	    // Not destined to any of our IP addresses for this interface
	    packet_rx_l2_iface_drop_badip_counter.count(ingress_l2_iface_id);
	    drop_2();
	    ingress_l3_iface_uc_ip = 128w0;
	    ingress_lb_id = 8w0;
	    return;
	}

	// Packet is destined to a valid IP for this interface so from here, we have an LB instance context
	packet_rx_l3_allow_counter.count(ingress_lb_id);

	if (false) {
#if INCLUDE_ARP_PROC
	} else if (hdr.arp.isValid()) {
	    // Handle ARP/ND requests
	    // Make sure this is an ARP specifically for our unicast IPv4 address
	    if (hdr.arp.tpa != ingress_l3_iface_uc_ip[31:0]) {
		packet_rx_l3_arp_tpa_nomatch.count(ingress_lb_id);
		drop_2();
	    } else {
		// Convert the request into a reply
		hdr.arp.oper = 2;
		// Swap sender/target HW address and fill in our unicast MAC as the sha
		hdr.arp.tha = hdr.arp.sha;
		hdr.arp.sha = ingress_l2_iface_uc_mac;
		// Swap sender/target IP addresses
		hdr.arp.tpa = hdr.arp.spa;
		hdr.arp.spa = ingress_l3_iface_uc_ip[31:0];

		// Send the ethernet frame back to the originator
		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
		hdr.ethernet.srcAddr = ingress_l2_iface_uc_mac;

		packet_rx_l3_arp_ok.count(ingress_lb_id);
		rx_done();
		return;
	    }
#endif // INCLUDE_ARP_PROC
#if INCLUDE_ICMPV4_PROC
	} else if (hdr.icmpv4_common.isValid()) {
	    if (hdr.icmpv4_echo.isValid()) {
		// Remove the old headers from the checksum
		icmp_cksum.clear();
		icmp_cksum.subtract({
		    // IPv4 pseudo-header
		    hdr.ipv4.srcAddr,
		    hdr.ipv4.dstAddr,
		    hdr.ipv4.totalLen,
		    8w0 ++ hdr.ipv4.protocol,
		    // ICMPv4 common header (including previous checksum)
		    hdr.icmpv4_common,
		    // ICMPv4 echo header
		    hdr.icmpv4_echo
		});

		// Make sure this is a unicast ping for our unicast IPv4 address
		if (hdr.ipv4.dstAddr != ingress_l3_iface_uc_ip[31:0]) {
		    packet_rx_l3_icmpv4_echo_dst_nomatch.count(ingress_lb_id);
		    drop_2();
		    return;
		} else {
		    // Update our ethernet header
		    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
		    hdr.ethernet.srcAddr = ingress_l2_iface_uc_mac;

		    // Update our ipv4 header addresses
		    // Note: since we're swapping src/dst here, no need to change the IPv4 header checksum
		    // TODO: should we be resetting the TTL on our replies?  Probably yes but that will require checksum fixup
		    hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
		    hdr.ipv4.srcAddr = ingress_l3_iface_uc_ip[31:0];

		    // Change the type to be a reply, fixing up the header checksum
		    hdr.icmpv4_common.msg_type_code = 8w0 ++ 8w0;   // Echo Reply

		    // Add in the new pseudo header and ICMP headers after zero'ing out the previous checksum
		    hdr.icmpv4_common.checksum = 0;
		    icmp_cksum.add({
			// IPv6 pseudo-header
			hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr,
			hdr.ipv4.totalLen,
			8w0 ++ hdr.ipv4.protocol,
			// ICMPv4 common header fields
			hdr.icmpv4_common,
			// ICMPv4 echo header fields
			hdr.icmpv4_echo
		    });
		    icmp_cksum.get(hdr.icmpv4_common.checksum);

		    packet_rx_l3_icmpv4_echo_ok.count(ingress_lb_id);
		    rx_done();
		    return;
		}
	    } else {
		// Unhandled ICMPv4 packet type
		packet_rx_l3_icmpv4_unhandled.count(ingress_lb_id);
		drop_2();
		return;
	    }
#endif // INCLUDE_ICMPV4_PROC
#if INCLUDE_ICMPV6_PROC
	} else if (hdr.icmpv6_common.isValid()) {
	    if (false) {
#if INCLUDE_ICMPV6_ECHO_PROC
	    } else if (hdr.icmpv6_echo.isValid()) {
		// Remove the old headers from the checksum
		icmp_cksum.clear();
		icmp_cksum.subtract({
		    // IPv6 pseudo-header
		    hdr.ipv6.srcAddr,
		    hdr.ipv6.dstAddr,
		    16w0 ++ hdr.ipv6.payloadLen,
		    24w0 ++ hdr.ipv6.nextHdr,
		    // ICMPv6 common header (including previous checksum)
		    hdr.icmpv6_common,
		    // ICMPv6 echo header
		    hdr.icmpv6_echo
		});

		// Update our ethernet header
		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
		hdr.ethernet.srcAddr = ingress_l2_iface_uc_mac;

		// Swap src and dst IPv6 addresses
		bit<128> tmp_ip;
		tmp_ip = hdr.ipv6.srcAddr;
		hdr.ipv6.srcAddr = hdr.ipv6.dstAddr;
		hdr.ipv6.dstAddr = tmp_ip;

		// Make sure we always reply from our unicast IP address
		if (hdr.ipv6.srcAddr != ingress_l3_iface_uc_ip) {
		    // This was sent to a multicast IP that we listen on, fix to reply from our unicast IP
		    hdr.ipv6.srcAddr = ingress_l3_iface_uc_ip;
		}

		// Change the type to be a reply, fixing up the header checksum
		hdr.icmpv6_common.msg_type_code = 8w129 ++ 8w0;   // Echo Reply

		// Add in the new pseudo header and ICMP headers after zero'ing out the previous checksum
		hdr.icmpv6_common.checksum = 0;
		icmp_cksum.add({
		    // IPv6 pseudo-header
		    hdr.ipv6.srcAddr,
		    hdr.ipv6.dstAddr,
		    16w0 ++ hdr.ipv6.payloadLen,
		    24w0 ++ hdr.ipv6.nextHdr,
		    // ICMP common header fields
		    hdr.icmpv6_common,
		    // ICMPv6 echo header
		    hdr.icmpv6_echo
		});
		icmp_cksum.get(hdr.icmpv6_common.checksum);

		packet_rx_l3_icmpv6_echo_ok.count(ingress_lb_id);
		rx_done();
		return;
#endif // INCLUDE_ICMPV6_ECHO_PROC
#if INCLUDE_ICMPV6_ND_PROC
	    } else if (hdr.ipv6nd_neigh_sol.isValid()) {
		bit<128> new_ip_da;
		bit<48>  new_mac_da;
		bit<1>   solicited;

		// Make sure this is an ND solicitation for our unicast IPv6 address
		if (hdr.ipv6nd_neigh_sol.target != ingress_l3_iface_uc_ip) {
		    packet_rx_l3_ipv6nd_neigh_sol_target_nomatch.count(ingress_lb_id);
		    drop_2();
		    return;
		} else {
		    // Figure out what our destination addresses should be based on the type of query we've received
		    if (hdr.ipv6.srcAddr == 128w0) {
			// Source is the unspecified address so reply to the all-nodes multicast IP and clear solicited flag
			new_ip_da = 0xff02_0000_0000_0000_0000_0000_0000_0001;  // ff02::1
			new_mac_da = 0x3333_0000_0001;  // 33:33:00:00:00:01
			solicited = 0;
		    } else {
			// Reply to the originating source IP and set the solicited flag
			new_ip_da = hdr.ipv6.srcAddr;

			if (hdr.ipv6nd_option_lladdr.isValid()) {
			    // The request includes a link-layer address for the originator, reply to that
			    new_mac_da = hdr.ipv6nd_option_lladdr.ethernet_addr;
			} else {
			    // No link-layer address option, reply to the unicast MAC from the original frame
			    new_mac_da = hdr.ethernet.srcAddr;
			}
			solicited = 1;
		    }

		    // Update our ethernet header addresses
		    hdr.ethernet.dstAddr = new_mac_da;
		    hdr.ethernet.srcAddr = ingress_l2_iface_uc_mac;

		    // Update our ipv6 header addresses
		    hdr.ipv6.dstAddr = new_ip_da;
		    hdr.ipv6.srcAddr = ingress_l3_iface_uc_ip;

		    // Reset our hop limit
		    hdr.ipv6.hopLimit = 255;  // Required by RFC4860 ICMPv6

		    // Set our new payload length
		    hdr.ipv6.payloadLen = 32;  // ICMPv6 + target IP + lladdr option

		    // Fill out the ICMPv6 common header
		    hdr.icmpv6_common.setValid();
		    hdr.icmpv6_common.msg_type_code = 8w136 ++ 8w0;   // ND Advertisement
		    hdr.icmpv6_common.checksum = 0;     // This will be fixed up below

		    // Fill out our ND advertisement
		    hdr.ipv6nd_neigh_adv.setValid();
		    hdr.ipv6nd_neigh_adv.router_flag    = 0;
		    hdr.ipv6nd_neigh_adv.solicited_flag = solicited;
		    hdr.ipv6nd_neigh_adv.override_flag  = 0;
		    hdr.ipv6nd_neigh_adv.rsvd           = 0;
		    hdr.ipv6nd_neigh_adv.target         = hdr.ipv6nd_neigh_sol.target;

		    // Fill out the ND advertisement option common header
		    hdr.ipv6nd_adv_option_common.setValid();
		    hdr.ipv6nd_adv_option_common.option_type   = 2;   // Target Link-Layer Address
		    hdr.ipv6nd_adv_option_common.length        = 1;

		    // Fill out the ND advertisement lladdr common header
		    hdr.ipv6nd_adv_option_lladdr.setValid();
		    hdr.ipv6nd_adv_option_lladdr.ethernet_addr = ingress_l2_iface_uc_mac;

		    // Calculate the checksum over the pseudo header + payload
		    icmp_cksum.clear();
		    icmp_cksum.add({
			// IPv6 pseudo-header
			hdr.ipv6.srcAddr,
			hdr.ipv6.dstAddr,
			16w0 ++ hdr.ipv6.payloadLen,
			24w0 ++ hdr.ipv6.nextHdr,
			// ICMP common header fields
			hdr.icmpv6_common,
			// ICMP neighbour advertisement header
			hdr.ipv6nd_neigh_adv,
			// ICMP neighbour advertisement option common header fields
			hdr.ipv6nd_adv_option_common,
			// ICMP neighbour advertisement LLADDR header fields
			hdr.ipv6nd_adv_option_lladdr
		    });
		    icmp_cksum.get(hdr.icmpv6_common.checksum);

		    packet_rx_l3_ipv6nd_neigh_sol_ok.count(ingress_lb_id);
		    rx_done();
		    return;
		}
#endif // INCLUDE_ICMPV6_ND_PROC
	    } else {
		// Unhandled ICMPv6 packet type
		packet_rx_l3_icmpv6_unhandled.count(ingress_lb_id);
		drop_2();
		return;
	    }
#endif // INCLUDE_ICMPV6_PROC
	}
	rx_continue();
	return;
    }
}
#endif // INCLUDE_L3_PROC

#if INCLUDE_EJFAT_PROC

control EJFAT(
inout headers hdr,
inout smartnic_metadata snmeta,
inout standard_metadata_t smeta,
in bit<48> ingress_l2_iface_uc_mac,
out bool ok,
out bit<128> ingress_l3_iface_uc_ip,
out bit<8> ingress_lb_id,
out bool tx_ready)
{
    //
    // IPSrcFilter
    //

    action allow_ip_src() {
	// Nothing to do here, basically a no-op
    }

    table ipv4_src_filter_table {
	actions = {
	    allow_ip_src;
	}
	key = {
	    ingress_lb_id : exact;
	    hdr.ipv4.srcAddr : exact;
	}
	size = 256;
    }

    table ipv6_src_filter_table {
	actions = {
	    allow_ip_src;
	}
	key = {
	    ingress_lb_id : exact;
	    hdr.ipv6.srcAddr : exact;
	}
	size = 256;
    }

    //
    // EpochAssign
    //

    bit<64> tick = 0;
    bit<32> meta_epoch = 0;
    bit<5> meta_slot_select_bit_cnt = 0;
    bit<16> meta_slot_select_xor = 0;

    action do_assign_epoch(bit<32> epoch) {
	meta_epoch = epoch;
	meta_slot_select_bit_cnt = 9;
	meta_slot_select_xor = 0;
    }

    action do_assign_epoch_with_slot_sel_opts(bit<32> epoch, bit<5> slot_select_bit_cnt, bit<16> slot_select_xor) {
	meta_epoch = epoch;
	meta_slot_select_bit_cnt = slot_select_bit_cnt;
	meta_slot_select_xor = slot_select_xor;
    }

    table epoch_assign_table {
	actions = {
	    do_assign_epoch;
	    do_assign_epoch_with_slot_sel_opts;
	}
	key = {
	    ingress_lb_id : exact;
	    tick : lpm;
	}
	size = 1024;
    }

    //
    // LoadBalanceCalendar
    //

    bit<16> calendar_slot = 0;
    bit<16> meta_member_id = 0;

    action do_assign_member(bit<16> member_id) {
	meta_member_id = member_id;
    }

    table load_balance_calendar_table {
	actions = {
	    do_assign_member;
	}
	key = {
	    ingress_lb_id : exact;
	    meta_epoch : exact;
	    calendar_slot : exact;
	}
	size = 16384;
    }

    //
    // MemberInfoLookup
    //

    bit<48>  new_mac_dst              = 0;
    bit<32>  new_ip4_dst              = 0;
    bit<128> new_ip6_dst              = 0;
    bit<16>  meta_udp_base            = 0;
    bit<5>   meta_port_select_bit_cnt = 0;
    bool     meta_keep_lb_header      = false;
    bit<2>   member_drop_reason       = 0;  // default to not dropped

    action do_ipv4_member_rewrite(bit<48> mac_dst, bit<32> ip_dst, bit<16> udp_base, bit<5> port_select_bit_cnt, bit<1> keep_lb_header) {
	new_mac_dst              = mac_dst;
	new_ip4_dst              = ip_dst;
	meta_udp_base            = udp_base;
	meta_port_select_bit_cnt = port_select_bit_cnt;
	meta_keep_lb_header      = (keep_lb_header == 1w1);
    }

    action do_ipv6_member_rewrite(bit<48> mac_dst, bit<128> ip_dst, bit<16> udp_base, bit<5> port_select_bit_cnt, bit<1> keep_lb_header) {
	new_mac_dst              = mac_dst;
	new_ip6_dst              = ip_dst;
	meta_udp_base            = udp_base;
	meta_port_select_bit_cnt = port_select_bit_cnt;
	meta_keep_lb_header      = (keep_lb_header == 1w1);
    }

    action drop_soft_evicted() {
	member_drop_reason = 1;
    }

    action drop_deregistered() {
	member_drop_reason = 2;
    }

    // Deprecated action for backward compatibility only
    // Use more specific "drop_soft_evicted" or "drop_deregistered" action
    action drop() {
    }

    table member_info_lookup_table {
	actions = {
	    do_ipv4_member_rewrite;
	    do_ipv6_member_rewrite;
	    drop;
	    drop_soft_evicted;
	    drop_deregistered;
	}
	key = {
	    ingress_lb_id : exact;
	    hdr.ethernet.etherType : exact;
	    meta_member_id : exact;
	}
	size = 1024;
    }

    action drop_3() {
	smeta.drop = 1;
    }

    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_rx_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.BYTES) lb_ctx_rx_byte_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_blocked_src_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_not_ip_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_no_udplb_hdr_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_rx_v2_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_rx_v3_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_bad_udplb_version_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_epoch_assign_miss_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_lb_calendar_miss_pkt_counter;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) lb_ctx_drop_mbr_info_miss_pkt_counter;
    Counter<bit<64>, bit<10>>(1024, CounterType_t.PACKETS) lb_mbr_drop_soft_evicted_counter;
    Counter<bit<64>, bit<10>>(1024, CounterType_t.PACKETS) lb_mbr_drop_deregistered_counter;
    Counter<bit<64>, bit<10>>(1024, CounterType_t.PACKETS) lb_mbr_tx_pkt_counter;
    Counter<bit<64>, bit<10>>(1024, CounterType_t.BYTES) lb_mbr_tx_byte_counter;

    InternetChecksum() l3_cksum;
    InternetChecksum() l4_cksum;

    apply {
	// Packets making it this far are destined for the load balancer offload path
	lb_ctx_rx_pkt_counter.count(ingress_lb_id);
	lb_ctx_rx_byte_counter.count(ingress_lb_id);

	//
	// IP source filter
	//   Only allow forwarding packets from explicitly allowed source IPs
	//

	bool ip_src_hit = false;
	if (hdr.ipv4.isValid() || hdr.ipv6.isValid()) {
	    if (hdr.ipv4.isValid()) {
		ip_src_hit = ipv4_src_filter_table.apply().hit;
	    } else if (hdr.ipv6.isValid()) {
		ip_src_hit = ipv6_src_filter_table.apply().hit;
	    }
	    if (!ip_src_hit) {
		lb_ctx_drop_blocked_src_pkt_counter.count(ingress_lb_id);
		drop_3();
		return;
	    }
	} else {
	    // Drop all non-IP packets
	    lb_ctx_drop_not_ip_pkt_counter.count(ingress_lb_id);
	    drop_3();
	    return;
	}

	// Only allow UDP LB packets past this point
	//
	// Packets missing this header should have failed at the parser but this will double check
	// before processing further.
	if (!hdr.udplb_common.isValid()) {
	    lb_ctx_drop_no_udplb_hdr_pkt_counter.count(ingress_lb_id);
	    drop_3();
	    return;
	}

	// Make sure we have a supported udplb version header
	if (hdr.udplb_v2.isValid()) {
	    lb_ctx_rx_v2_counter.count(ingress_lb_id);
	} else if (hdr.udplb_v3.isValid()) {
	    lb_ctx_rx_v3_counter.count(ingress_lb_id);
	} else {
	    lb_ctx_drop_bad_udplb_version_pkt_counter.count(ingress_lb_id);
	    drop_3();
	    return;
	}

	// NOTE  NOTE  NOTE  NOTE
	//
	// All packets past this point are confirmed to be
	//   (IPv4 or IPv6) and UDP and (UDPLBv2 or UDPLBv3)
	// all remaining checks below will rely on this
	//
	// NOTE  NOTE  NOTE  NOTE

	// Subtract the old IPv4 header from the l3 checksum (if present) before modifying it
	// NOTE: This is to avoid having to keep track of the checksum over the IPv4 options
	l3_cksum.clear();
	if (hdr.ipv4.isValid()) {
	    l3_cksum.subtract({
		// IPv4 base header (incl old checksum)
		hdr.ipv4
	    });
	}

	l4_cksum.clear();
	// Subtract the old IPv4 or IPv6 pseudo-header from the UDP checksum
	if (hdr.ipv4.isValid()) {
	    l4_cksum.subtract({
		// IPv4 pseudo-header
		hdr.ipv4.srcAddr,
		hdr.ipv4.dstAddr,
		hdr.ipv4.totalLen,
		8w0 ++ hdr.ipv4.protocol
	    });
	} else if (hdr.ipv6.isValid()) {
	    l4_cksum.subtract({
		// IPv6 pseudo-header
		hdr.ipv6.srcAddr,
		hdr.ipv6.dstAddr,
		16w0 ++ hdr.ipv6.payloadLen,
		24w0 ++ hdr.ipv6.nextHdr
	    });
	}

	// Subtract the old UDP header (incl. the old checksum) from the UDP checksum
	l4_cksum.subtract(hdr.udp);

	// Subtract the old EJFAT LB header from the UDP checksum
	if (hdr.udplb_v2.isValid()) {
	    l4_cksum.subtract({
		hdr.udplb_common,
		hdr.udplb_v2
	    });
	} else if (hdr.udplb_v3.isValid()) {
	    l4_cksum.subtract({
		hdr.udplb_common,
		hdr.udplb_v3
	    });
	}

	// All packets must be originated with our assigned unicast MAC address

	// TODO: with VLAN support, this MAC should be the *egress* L2 interface's MAC maybe?? Or do we have exactly 1 ucast MAC
	//       across all of the VLANs?
	hdr.ethernet.srcAddr = ingress_l2_iface_uc_mac;

	// All packets must be originated with our assigned unicast IP address
	if (hdr.ipv4.isValid()) {
	    hdr.ipv4.srcAddr = ingress_l3_iface_uc_ip[31:0];
	} else if (hdr.ipv6.isValid()) {
	    hdr.ipv6.srcAddr = ingress_l3_iface_uc_ip;
	}

	//
	// EpochAssign
	//

	// Normalize the tick value across the different LB protocol versions
	if (hdr.udplb_v2.isValid()) {
	    tick = hdr.udplb_v2.tick;
	} else if (hdr.udplb_v3.isValid()) {
	    tick = hdr.udplb_v3.tick;
	}

	bool epoch_assign_hit = epoch_assign_table.apply().hit;
	if (!epoch_assign_hit) {
	    lb_ctx_drop_epoch_assign_miss_pkt_counter.count(ingress_lb_id);
	    drop_3();
	    return;
	}

	//
	// LoadBalanceCalendar
	//


	// Normalize the slot_select value across the different LB protocol versions
	bit<16> slot_select = 0;

	if (hdr.udplb_v2.isValid()) {
	    // v2 uses lsbs of tick field as the slot selector
	    slot_select = hdr.udplb_v2.tick[15:0];
	} else if (hdr.udplb_v3.isValid()) {
	    // v3 uses a dedicated field as the slot selector
	    slot_select = hdr.udplb_v3.slot_select[15:0];
	}

	// The number of significant bits for the calendar lookup can vary dynamically by epoch
	bit<16> slot_select_mask = (bit<16>)(((bit<16>)1 << meta_slot_select_bit_cnt)-1);

	// Pick the calendar slot for this packet
	calendar_slot = (slot_select ^ meta_slot_select_xor) & slot_select_mask;

	bool lb_calendar_hit = load_balance_calendar_table.apply().hit;
	if (!lb_calendar_hit) {
	    lb_ctx_drop_lb_calendar_miss_pkt_counter.count(ingress_lb_id);
	    drop_3();
	    return;
	}

	//
	// MemberInfoLookup
	//

	bool member_info_hit = member_info_lookup_table.apply().hit;
	if (!member_info_hit) {
	    lb_ctx_drop_mbr_info_miss_pkt_counter.count(ingress_lb_id);
	    drop_3();
	    return;
	}

	if (member_drop_reason == 1) {
	    // Found an entry, but packet was dropped due to soft-eviction
	    lb_mbr_drop_soft_evicted_counter.count((bit<10>)meta_member_id);
	    drop_3();
	    return;
	} else if (member_drop_reason == 2) {
	    // Found an entry, but packet was dropped due to deregistered
	    lb_mbr_drop_deregistered_counter.count((bit<10>)meta_member_id);
	    drop_3();
	    return;
	} else {
	    // Not dropped, continue processing, will be counted later
	}

	// Set the MAC DA to point to the next hop at L2
	hdr.ethernet.dstAddr = new_mac_dst;

	// Set the IP Dst to point to the L3 destination

	if (hdr.ipv4.isValid()) {
	    hdr.ipv4.dstAddr = new_ip4_dst;

	    if (!meta_keep_lb_header) {
		hdr.ipv4.totalLen = hdr.ipv4.totalLen - SIZEOF_UDPLB_HDR;
	    }

	    // Update the checksum in our IPv4 header
	    // NOTE: Any previously valid IPV4 options header bytes have had their checksum preserved in l3_cksum state
	    hdr.ipv4.hdrChecksum = 0;
	    l3_cksum.add(hdr.ipv4);
	    l3_cksum.get(hdr.ipv4.hdrChecksum);
	} else if (hdr.ipv6.isValid()) {
	    hdr.ipv6.dstAddr = new_ip6_dst;

	    if (!meta_keep_lb_header) {
		hdr.ipv6.payloadLen = hdr.ipv6.payloadLen - SIZEOF_UDPLB_HDR;
	    }
	}

	// Normalize the port_select value across the different LB protocol versions
	bit<16> port_select = 0;

	if (hdr.udplb_v2.isValid()) {
	    port_select = hdr.udplb_v2.entropy;
	} else if (hdr.udplb_v3.isValid()) {
	    port_select = hdr.udplb_v3.port_select;
	}

	// The number of significant bits for the port offset varies by LB member
	bit<16> port_select_mask = (bit<16>)(((bit<16>)1 << meta_port_select_bit_cnt)-1);

	// Compute the UDP dst_port between [base, base+2^port_select_bit_count) by mixing in some of the provided entropy
	bit<16> new_udp_dst = meta_udp_base + (port_select & port_select_mask);

	// Update the destination port
	hdr.udp.dstPort = new_udp_dst;

	if (!meta_keep_lb_header) {
	    hdr.udplb_common.setInvalid();
	    if (hdr.udplb_v2.isValid()) {
		hdr.udplb_v2.setInvalid();
	    } else if (hdr.udplb_v3.isValid()) {
		hdr.udplb_v3.setInvalid();
	    }

	    // Fix up the length to adapt to the dropped udplb header
	    hdr.udp.totalLen = hdr.udp.totalLen - SIZEOF_UDPLB_HDR;
	}

	// Do not update the udp checksum if the incoming value is zero (ie. no checksum computed at transmitter)
	if (hdr.udp.checksum != 16w0) {
	    // Update the UDP checksum
	    // NOTE: the original payload checksum is preserved in the l4_cksum state

	    // Add the pseudo-header for the appropriate L3 protocol
	    if (hdr.ipv4.isValid()) {
		l4_cksum.add({
		    hdr.ipv4.srcAddr,
		    hdr.ipv4.dstAddr,
		    hdr.ipv4.totalLen,
		    8w0 ++ hdr.ipv4.protocol
		});
	    } else if (hdr.ipv6.isValid()) {
		l4_cksum.add({
		    hdr.ipv6.srcAddr,
		    hdr.ipv6.dstAddr,
		    16w0 ++ hdr.ipv6.payloadLen,
		    24w0 ++ hdr.ipv6.nextHdr
		});
	    }

	    // Zero out the UDP checksum field and add in the UDP header
	    hdr.udp.checksum = 0;
	    l4_cksum.add(hdr.udp);

	    // Add in the EJFAT LB (udplb) headers
	    if (hdr.udplb_common.isValid()) {
		l4_cksum.add(hdr.udplb_common);
	    }

	    if (hdr.udplb_v2.isValid()) {
		l4_cksum.add(hdr.udplb_v2);
	    } else if (hdr.udplb_v3.isValid()) {
		l4_cksum.add(hdr.udplb_v3);
	    }

	    // Retrieve the computed UDP checksum
	    l4_cksum.get(hdr.udp.checksum);

	    // If the final checksum is computed to be zero, it must be inverted
	    // Ref: https://www.rfc-editor.org/rfc/rfc768.html
	    if (hdr.udp.checksum == 16w0) {
		hdr.udp.checksum = 16w0xffff;
	    }
	}

	lb_mbr_tx_pkt_counter.count((bit<10>)meta_member_id);
	lb_mbr_tx_byte_counter.count((bit<10>)meta_member_id);
    }
}

#endif // INCLUDE_EJFAT_PROC

control MatchActionImpl(
inout headers hdr,
inout smartnic_metadata snmeta,
inout standard_metadata_t smeta)
{
    action drop_0() {
	smeta.drop = 1;
    }

    // Raw counter of all received packets
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS_AND_BYTES) packet_rx_counter;

    // Raw counter or all received packets by physical port
    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS_AND_BYTES) packet_rx_phys_counter;

    // Raw counter or all received packets by physical port
    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) packet_rx_phys_parsefail_counter;

    apply {

	// Count all received packets and bytes
	packet_rx_counter.count(0);
	// Count received packets and bytes by physical ingress port
	packet_rx_phys_counter.count(snmeta.ingress_port);

	if (smeta.parser_error != error.NoError) {
	    packet_rx_phys_parsefail_counter.count(snmeta.ingress_port);
	    drop_0();
	    return;
	}

	// Set default egress physical port to the ingress physical port to ensure that we always
	// have tx BW available any time we had rx BW available -- no re-hashing across the tx LAG
	snmeta.egress_port = snmeta.ingress_port;

	bool ok = false;
	bool tx_ready = false;
	bit<4> ingress_l2_iface_id;
	bit<48> ingress_l2_iface_uc_mac;

#if INCLUDE_L2_PROC
	L2IfaceMap.apply(hdr, snmeta, smeta, ok, ingress_l2_iface_id, ingress_l2_iface_uc_mac, tx_ready);
	if (!ok || tx_ready) return;
#endif // INCLUDE_L2_PROC

#if INCLUDE_L3_PROC
	bit<128> ingress_l3_iface_uc_ip;
	bit<8> ingress_lb_id;
	L3IfaceMap.apply(hdr, snmeta, smeta, ingress_l2_iface_id, ingress_l2_iface_uc_mac, ok, ingress_l3_iface_uc_ip, ingress_lb_id, tx_ready);
	if (!ok || tx_ready) return;
#endif // INCLUDE_L3_PROC

#if INCLUDE_EJFAT_PROC
	EJFAT.apply(hdr, snmeta, smeta, ingress_l2_iface_uc_mac, ok, ingress_l3_iface_uc_ip, ingress_lb_id, tx_ready);
	if (!ok || tx_ready) return;
#endif // INCLUDE_EJFAT_PROC

	// How did we get here?!?
	return;
    }
}

control DeparserImpl(packet_out packet, in headers hdr, inout smartnic_metadata snmeta, inout standard_metadata_t smeta) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.vlan);
	packet.emit(hdr.arp);

        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_opt);

	packet.emit(hdr.icmpv4_common);
	packet.emit(hdr.icmpv4_echo);

        packet.emit(hdr.ipv6);

	packet.emit(hdr.icmpv6_common);
	packet.emit(hdr.icmpv6_echo);

	packet.emit(hdr.ipv6nd_neigh_adv);
	packet.emit(hdr.ipv6nd_adv_option_common);
	packet.emit(hdr.ipv6nd_adv_option_lladdr);

        packet.emit(hdr.udp);

	packet.emit(hdr.udplb_common);
	packet.emit(hdr.udplb_v2);
	packet.emit(hdr.udplb_v3);
    }
}

XilinxPipeline(
  ParserImpl(),
  MatchActionImpl(),
  DeparserImpl()
) main;

