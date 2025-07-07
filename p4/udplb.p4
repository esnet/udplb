#include <core.p4>
#include <xsa.p4>

// Decide if we want a checksum implementation that uses actions or uses macros
#define CKSUM_MODE_USE_MACROS  1
#define CKSUM_MODE_USE_ACTIONS 2
#define CKSUM_MODE_OMITTED     3

#define CKSUM_MODE CKSUM_MODE_USE_MACROS

#define INCLUDE_ICMPV4ECHO 1
#define INCLUDE_ICMPV6ECHO 1
#define INCLUDE_IPV6ND 1
#define INCLUDE_ARP 1
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

#if INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO

header icmpv6_common_t {
    bit<16>  msg_type_code;
    bit<16>  checksum;
}

#endif  // INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO

#if INCLUDE_ICMPV6ECHO

header icmpv6_echo_t {
    bit<16>  identifier;
    bit<16>  sequence;
}

#endif  // INCLUDE_ICMPV6ECHO

#if INCLUDE_IPV6ND
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

#if INCLUDE_ICMPV4ECHO
header icmpv4_common_t {
    bit<16> msg_type_code;
    bit<16> checksum;
}

header icmpv4_echo_t {
    bit<16>  identifier;
    bit<16>  sequence;
}
#endif  // INCLUDE_ICMPV4ECHO

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
#if INCLUDE_ARP
    arp_t                   arp;
#endif // INCLUDE_ARP
    ipv4_t                  ipv4;
    ipv4_opt_t              ipv4_opt;
#if INCLUDE_ICMPV4ECHO
    icmpv4_common_t         icmpv4_common;
    icmpv4_echo_t           icmpv4_echo;
#endif  // INCLUDE_ICMPV4ECHO
    ipv6_t                  ipv6;
#if INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO
    icmpv6_common_t         icmpv6_common;
#endif  // INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO
#if INCLUDE_ICMPV6ECHO
    icmpv6_echo_t           icmpv6_echo;
#endif  // INCLUDE_ICMPV6ECHO
#if INCLUDE_IPV6ND
    ipv6nd_neigh_sol_t      ipv6nd_neigh_sol;
    ipv6nd_option_common_t  ipv6nd_option_common;
    ipv6nd_option_lladdr_t  ipv6nd_option_lladdr;

    ipv6nd_neigh_adv_t      ipv6nd_neigh_adv;
    ipv6nd_adv_option_common_t  ipv6nd_adv_option_common;
    ipv6nd_adv_option_lladdr_t  ipv6nd_adv_option_lladdr;
#endif // INCLUDE_IPV6ND
    udp_t                   udp;
    udplb_common_t          udplb_common;
    udplb_v2_t              udplb_v2;
    udplb_v3_t              udplb_v3;
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
    InvalidUDPLBmagic
}

#if (CKSUM_MODE == CKSUM_MODE_OMITTED)
#define cksum_update_header(h, cksum_delta) ;
#define cksum_add_bit16(cksum, v) ;
#define cksum_sub_bit16(cksum, v) ;
#define cksum_swap_bit16(cksum, old, new) ;
#define cksum_add_bit32(cksum, v) ;
#define cksum_sub_bit32(cksum, v) ;
#define cksum_swap_bit32(cksum, old, new) ;
#define cksum_add_bit48(cksum, v) ;
#define cksum_sub_bit48(cksum, v) ;
#define cksum_swap_bit48(cksum, old, new) ;
#define cksum_add_bit64(cksum, v) ;
#define cksum_sub_bit64(cksum, v) ;
#define cksum_swap_bit64(cksum, old, new) ;
#define cksum_add_bit128(cksum, v) ;
#define cksum_sub_bit128(cksum, v) ;
#define cksum_swap_bit128(cksum, old, new) ;

#elif (CKSUM_MODE == CKSUM_MODE_USE_MACROS)
#define cksum_update_header(h, cksum_delta) \
h = h ^ 0xffff; \
cksum_add_bit16(h, cksum_delta); \
h = h ^ 0xffff;

#define cksum_swap_bit16(cksum, old, new) \
cksum_sub_bit16(cksum, old); \
cksum_add_bit16(cksum, new);

#define cksum_add_bit32(cksum, v) \
cksum_add_bit16(cksum, v[31:16]); \
cksum_add_bit16(cksum, v[15:00]);

#define cksum_sub_bit32(cksum, v) \
cksum_sub_bit16(cksum, v[31:16]); \
cksum_sub_bit16(cksum, v[15:00]);

#define cksum_swap_bit32(cksum, old, new) \
cksum_sub_bit32(cksum, old); \
cksum_add_bit32(cksum, new);

#define cksum_add_bit48(cksum, v) \
cksum_add_bit16(cksum, v[47:32]); \
cksum_add_bit32(cksum, v[31:00]);

#define cksum_sub_bit48(cksum, v) \
cksum_sub_bit16(cksum, v[47:32]); \
cksum_sub_bit32(cksum, v[31:00]);

#define cksum_swap_bit48(cksum, old, new) \
cksum_sub_bit48(cksum, old); \
cksum_add_bit48(cksum, new);

#define cksum_add_bit64(cksum, v) \
cksum_add_bit32(cksum, v[63:32]); \
cksum_add_bit32(cksum, v[31:00]);

#define cksum_sub_bit64(cksum, v) \
cksum_sub_bit32(cksum, v[63:32]); \
cksum_sub_bit32(cksum, v[31:00]);

#define cksum_swap_bit64(cksum, old, new) \
cksum_sub_bit64(cksum, old); \
cksum_add_bit64(cksum, new);

#define cksum_add_bit128(cksum, v) \
cksum_add_bit64(cksum, v[127:64]); \
cksum_add_bit64(cksum, v[63:0]);

#define cksum_sub_bit128(cksum, v) \
cksum_sub_bit64(cksum, v[127:64]); \
cksum_sub_bit64(cksum, v[63:0]);

#define cksum_swap_bit128(cksum, old, new) \
cksum_sub_bit128(cksum, old); \
cksum_add_bit128(cksum, new);
#endif // CKSUM_MODE

parser ParserImpl(packet_in packet, out headers hdr, inout smartnic_metadata snmeta, inout standard_metadata_t smeta) {
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
	    8w1: parse_icmpv4;
            8w17: parse_udp;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        verify(hdr.ipv6.version == 6, error.InvalidIPpacket);
        transition select(hdr.ipv6.nextHdr) {
#if INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO
	    8w58: parse_icmpv6;
#endif // INCLUDE_IPV6ND
            8w17: parse_udp;
        }
    }

#if INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO
    state parse_icmpv6 {
	packet.extract(hdr.icmpv6_common);
	transition select(hdr.icmpv6_common.msg_type_code) {
#if INCLUDE_ICMPV6ECHO
	    8w128 ++ 8w0: parse_icmpv6_echo;
#endif  // INCLUDE_ICMPV6ECHO
#if INCLUDE_IPV6ND
	    8w135 ++ 8w0: parse_ipv6nd_neigh_sol;
#endif  // INCLUDE_IPV6NS
	}
    }
#endif  // INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO

#if INCLUDE_ICMPV6ECHO
    state parse_icmpv6_echo {
	packet.extract(hdr.icmpv6_echo);
	transition accept;
    }
#endif  // INCLUDE_ICMPV6ECHO

#if INCLUDE_IPV6ND
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

#if INCLUDE_ICMPV4ECHO
    state parse_icmpv4 {
	packet.extract(hdr.icmpv4_common);
	transition select(hdr.icmpv4_common.msg_type_code) {
	    8w8 ++ 8w0: parse_icmpv4_echo;
	}
    }

    state parse_icmpv4_echo {
	packet.extract(hdr.icmpv4_echo);
	transition accept;
    }
#endif  // INCLUDE_ICMPV4ECHO

    state parse_udp {
        packet.extract(hdr.udp);
	transition select(hdr.udp.dstPort) {
	  16w0x4000 &&& 16w0xC000: parse_udplb_common;
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

control MatchActionImpl(inout headers hdr, inout smartnic_metadata snmeta, inout standard_metadata_t smeta) {

    // Raw counter of all received packets
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS_AND_BYTES) packet_rx_counter;

    // Counter block to count the types of Rx'd packets
    Counter<bit<64>, bit<4>>(14, CounterType_t.PACKETS) rx_rslt_counter;
    const bit<4> rx_rslt_drop_parse_fail                  = 0;
    const bit<4> rx_rslt_drop_mac_dst_miss                = 1;
    const bit<4> rx_rslt_drop_not_ip                      = 2;
    const bit<4> rx_rslt_drop_ip_dst_miss                 = 3;
    const bit<4> rx_rslt_drop_arp_bad_tpa                 = 4;
    const bit<4> rx_rslt_drop_icmpv4_echo_bad_dst         = 5;
    //const bit<4> rx_rslt_drop_icmpv6_echo_bad_dst         = 6;
    const bit<4> rx_rslt_drop_ipv6nd_neigh_sol_bad_target = 7;
    const bit<4> rx_rslt_ok_arp_req                       = 8;
    const bit<4> rx_rslt_ok_icmpv4_echo                   = 9;
    const bit<4> rx_rslt_ok_icmpv6_echo                   = 10;
    const bit<4> rx_rslt_ok_ipv6nd_neigh_sol              = 11;
    //const bit<4> rx_rslt_ok_host                          = 12;
    const bit<4> rx_rslt_ok_lb                            = 13;

    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_rx_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.BYTES)   lb_ctx_rx_byte_counter;

    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_blocked_src_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_not_ip_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_no_udplb_hdr_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_bad_udplb_version_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_epoch_assign_miss_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_lb_calendar_miss_pkt_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_drop_mbr_info_miss_pkt_counter;

    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_rx_v2_counter;
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS) lb_ctx_rx_v3_counter;

    Counter<bit<64>, bit<13>>(8192, CounterType_t.PACKETS) lb_mbr_tx_pkt_counter;
    Counter<bit<64>, bit<13>>(8192, CounterType_t.BYTES)   lb_mbr_tx_byte_counter;

    //
    // MacDstFilter
    //

    bit<128> meta_ip_da = 0;
    bit<48>  meta_mac_sa = 0;
    bit<128> meta_ip_sa = 0;
    bit<3>   meta_lb_id = 0;

    action drop() {
	smeta.drop = 1;
    }

    action set_mac_sa(bit<48> mac_sa) {
	meta_mac_sa = mac_sa;
        snmeta.egress_port = snmeta.ingress_port;
    }

    table mac_dst_filter_table {
	actions = {
	    drop;
	    set_mac_sa;
	}
	key = {
	    snmeta.ingress_port : field_mask;
	    hdr.ethernet.dstAddr : exact;
	}
	size = 64;
	default_action = drop;
    }

    //
    // IPDstFilter
    //

    action set_ip_sa(bit<128> ip_sa, bit<3> lb_id) {
	meta_ip_sa = ip_sa;
	meta_lb_id = lb_id;
        snmeta.egress_port = snmeta.ingress_port;
    }

    table ip_dst_filter_table {
	actions = {
	    drop;
	    set_ip_sa;
	}
	key = {
	    snmeta.ingress_port : field_mask;
	    hdr.ethernet.etherType : exact;
	    meta_ip_da : exact;
	}
	size = 64;
	default_action = drop;
    }

    //
    // IPSrcFilter
    //

    action allow_ip_src() {
	// Nothing to do here, basically a no-op
    }

    table ipv4_src_filter_table {
	actions = {
	    drop;
	    allow_ip_src;
	}
	key = {
	    meta_lb_id : exact;
	    hdr.ipv4.srcAddr : exact;
	}
	size = 256;
	default_action = drop;
    }

    table ipv6_src_filter_table {
	actions = {
	    drop;
	    allow_ip_src;
	}
	key = {
	    meta_lb_id : exact;
	    hdr.ipv6.srcAddr : exact;
	}
	size = 256;
	default_action = drop;
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
	    drop;
	}
	key = {
	    meta_lb_id : exact;
	    tick : lpm;
	}
	size = 1024;
	default_action = drop;
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
	    drop;
	}
	key = {
	    meta_lb_id : exact;
	    meta_epoch : exact;
	    calendar_slot : exact;
	}
	size = 16384;
	default_action = drop;
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

    table member_info_lookup_table {
	actions = {
	    do_ipv4_member_rewrite;
	    do_ipv6_member_rewrite;
	    drop;
	}
	key = {
	    meta_lb_id : exact;
	    hdr.ethernet.etherType : exact;
	    meta_member_id : exact;
	}
	size = 8192;
	default_action = drop;
    }

#if (CKSUM_MODE != CKSUM_MODE_OMITTED)
    // Checksum ops for bit<16>
    action cksum_sub_bit16(inout bit<16> cksum, in bit<16> v) {
	bit<18> sum = 2w00 ++ cksum;
	bit<18> v_x = 2w00 ++ (v ^ 0xFFFF);

	sum = sum + v_x;
	cksum = sum[15:0] + (15w00 ++ sum[16:16]);
    }

    action cksum_add_bit16(inout bit<16> cksum, in bit<16> v) {
	bit<18> sum = 2w00 ++ cksum;
	bit<18> v_x = 2w00 ++ v;
	
	sum = sum + v_x;
	cksum = sum[15:0] + (15w00 ++ sum[16:16]);
    }
#endif // CKSUM_MODE

#if (CKSUM_MODE == CKSUM_MODE_USE_ACTIONS)
    action cksum_swap_bit16(inout bit<16> cksum, in bit<16> old, in bit<16> new) {
	cksum_sub_bit16(cksum, old);
	cksum_add_bit16(cksum, new);
    }

    // Checksum ops for bit<32>
    action cksum_sub_bit32(inout bit<16> cksum, in bit<32> v) {
	cksum_sub_bit16(cksum, v[31:16]);
	cksum_sub_bit16(cksum, v[15:00]);
    }

    action cksum_add_bit32(inout bit<16> cksum, in bit<32> v) {
	cksum_add_bit16(cksum, v[31:16]);
	cksum_add_bit16(cksum, v[15:00]);
    }

    action cksum_swap_bit32(inout bit<16> cksum, in bit<32> old, in bit<32> new) {
	cksum_sub_bit32(cksum, old);
	cksum_add_bit32(cksum, new);
    }

    // Checksum ops for bit<48>
    action cksum_sub_bit48(inout bit<16> cksum, in bit<48> v) {
	cksum_sub_bit16(cksum, v[47:32]);
	cksum_sub_bit32(cksum, v[31:00]);
    }

    action cksum_add_bit48(inout bit<16> cksum, in bit<48> v) {
	cksum_add_bit16(cksum, v[47:32]);
	cksum_add_bit32(cksum, v[31:00]);
    }

    action cksum_swap_bit48(inout bit<16> cksum, in bit<48> old, in bit<48> new) {
	cksum_sub_bit48(cksum, old);
	cksum_add_bit48(cksum, new);
    }

    // Checksum ops for bit<64>
    action cksum_sub_bit64(inout bit<16> cksum, in bit<64> v) {
	cksum_sub_bit32(cksum, v[63:32]);
	cksum_sub_bit32(cksum, v[31:00]);
    }

    action cksum_add_bit64(inout bit<16> cksum, in bit<64> v) {
	cksum_add_bit32(cksum, v[63:32]);
	cksum_add_bit32(cksum, v[31:00]);
    }

    action cksum_swap_bit64(inout bit<16> cksum, in bit<64> old, in bit<64> new) {
	cksum_sub_bit64(cksum, old);
	cksum_add_bit64(cksum, new);
    }

    // Checksum ops for bit<128>
    action cksum_sub_bit128(inout bit<16> cksum, in bit<128> v) {
	cksum_sub_bit64(cksum, v[127:64]);
	cksum_sub_bit64(cksum, v[63:00]);
    }

    action cksum_add_bit128(inout bit<16> cksum, in bit<128> v) {
	cksum_add_bit64(cksum, v[127:64]);
	cksum_add_bit64(cksum, v[63:00]);
    }

    action cksum_swap_bit128(inout bit<16> cksum, in bit<128> old, in bit<128> new) {
	cksum_sub_bit128(cksum, old);
	cksum_add_bit128(cksum, new);
    }

    // Apply an accumulated delta to a header field
    action cksum_update_header(inout bit<16> header_field, in bit<16> cksum_delta) {
	header_field = header_field ^ 0xFFFF;
	cksum_add_bit16(header_field, cksum_delta);
	header_field = header_field ^ 0xFFFF;
    }
#endif // CKSUM_MODE

    // Entry Point
    apply {
	bool hit;

	// Count all received packets and bytes
	packet_rx_counter.count(0);

	// Drop all packets that failed the parse stage
	if (smeta.parser_error != error.NoError) {
	    rx_rslt_counter.count(rx_rslt_drop_parse_fail);
	    drop();
	    return;
	}

	//
	// MacDstFilter
	//

	hit = mac_dst_filter_table.apply().hit;
	if (!hit) {
	    rx_rslt_counter.count(rx_rslt_drop_mac_dst_miss);
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
	} else {
	    rx_rslt_counter.count(rx_rslt_drop_not_ip);
	    drop();
	    return;
	}

	hit = ip_dst_filter_table.apply().hit;
	if (!hit) {
	    rx_rslt_counter.count(rx_rslt_drop_ip_dst_miss);
	    return;
	}

	if (false) {
#if INCLUDE_ARP
	// Handle ARP/ND requests
	} else if (hdr.arp.isValid()) {
	    // Make sure this is an ARP specifically for our unicast IPv4 address
	    if (hdr.arp.tpa != meta_ip_sa[31:0]) {
		rx_rslt_counter.count(rx_rslt_drop_arp_bad_tpa);
		drop();
		return;
	    }

	    // Convert the request into a reply
	    hdr.arp.oper = 2;
	    // Swap sender/target HW address and fill in our unicast MAC as the sha
	    hdr.arp.tha = hdr.arp.sha;
	    hdr.arp.sha = meta_mac_sa;
	    // Swap sender/target IP addresses
	    hdr.arp.tpa = hdr.arp.spa;
	    hdr.arp.spa = meta_ip_sa[31:0];

	    // Send the ethernet frame back to the originator
	    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	    hdr.ethernet.srcAddr = meta_mac_sa;

	    rx_rslt_counter.count(rx_rslt_ok_arp_req);
	    return;
#endif // INCLUDE_ARP
#if INCLUDE_ICMPV4ECHO
	} else if (hdr.icmpv4_echo.isValid()) {
	    bit<16> v4echo_ckd = 0;

	    // Make sure this is a unicast ping for our unicast IPv4 address
	    if (hdr.ipv4.dstAddr != meta_ip_sa[31:0]) {
		rx_rslt_counter.count(rx_rslt_drop_icmpv4_echo_bad_dst);
		drop();
		return;
	    }

	    // Update our ethernet header
	    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	    hdr.ethernet.srcAddr = meta_mac_sa;

	    // Update our ipv4 header addresses
	    hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
	    hdr.ipv4.srcAddr = meta_ip_sa[31:0];

	    // Change the type to be a reply, fixing up the header checksum
	    cksum_sub_bit16(v4echo_ckd, hdr.icmpv4_common.msg_type_code);
	    hdr.icmpv4_common.msg_type_code = 8w0 ++ 8w0;   // Echo Reply
	    cksum_add_bit16(v4echo_ckd, hdr.icmpv4_common.msg_type_code);
	    cksum_update_header(hdr.icmpv4_common.checksum, v4echo_ckd);

	    rx_rslt_counter.count(rx_rslt_ok_icmpv4_echo);
	    return;
#endif  // INCLUDE_ICMPV4ECHO
#if INCLUDE_ICMPV6ECHO
        } else if (hdr.icmpv6_echo.isValid()) {
	    bit<16> v6echo_ckd = 0;

	    // Update our ethernet header
	    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	    hdr.ethernet.srcAddr = meta_mac_sa;

	    // Swap src and dst IPv6 addresses
	    bit<128> tmp_ip;
	    tmp_ip = hdr.ipv6.srcAddr;
	    hdr.ipv6.srcAddr = hdr.ipv6.dstAddr;
	    hdr.ipv6.dstAddr = tmp_ip;

	    // Make sure we always reply from our unicast IP address
	    if (hdr.ipv6.srcAddr != meta_ip_sa) {
		// This was sent to a multicast IP that we listen on, fix to reply from our unicast IP
		cksum_swap_bit128(v6echo_ckd, hdr.ipv6.srcAddr, meta_ip_sa);
		hdr.ipv6.srcAddr = meta_ip_sa;
	    }

            // Change the type to be a reply, fixing up the header checksum
	    cksum_sub_bit16(v6echo_ckd, hdr.icmpv6_common.msg_type_code);
	    hdr.icmpv6_common.msg_type_code = 8w129 ++ 8w0;   // Echo Reply
	    cksum_add_bit16(v6echo_ckd, hdr.icmpv6_common.msg_type_code);
	    cksum_update_header(hdr.icmpv6_common.checksum, v6echo_ckd);

	    rx_rslt_counter.count(rx_rslt_ok_icmpv6_echo);
	    return;
#endif  // INCLUDE_ICMPV6ECHO
#if INCLUDE_IPV6ND
	} else if (hdr.ipv6nd_neigh_sol.isValid()) {
	    bit<128> new_ip_da;
	    bit<48>  new_mac_da;
	    bit<1>   solicited;

	    // Make sure this is an ND solicitation for our unicast IPv6 address
	    if (hdr.ipv6nd_neigh_sol.target != meta_ip_sa) {
		rx_rslt_counter.count(rx_rslt_drop_ipv6nd_neigh_sol_bad_target);
		drop();
		return;
	    }

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
	    hdr.ipv6nd_adv_option_lladdr.ethernet_addr = meta_mac_sa;

	    // Calculate the checksum over the pseudo header + payload
	    bit<16>  v6nd0_ckd = 0;
	    cksum_add_bit128(v6nd0_ckd, hdr.ipv6.srcAddr);
	    bit<16>  v6nd1_ckd = v6nd0_ckd;
	    cksum_add_bit128(v6nd1_ckd, hdr.ipv6.dstAddr);

	    bit<16> v6nd2_ckd = v6nd1_ckd;

	    cksum_add_bit16(v6nd2_ckd, hdr.ipv6.payloadLen);
	    cksum_add_bit16(v6nd2_ckd, 8w0 ++ hdr.ipv6.nextHdr);

	    cksum_add_bit16(v6nd2_ckd, hdr.icmpv6_common.msg_type_code);

	    cksum_add_bit16(v6nd2_ckd, hdr.ipv6nd_neigh_adv.router_flag ++ hdr.ipv6nd_neigh_adv.solicited_flag ++ hdr.ipv6nd_neigh_adv.override_flag ++ hdr.ipv6nd_neigh_adv.rsvd[28:16]);
	    bit<16> v6nd3_ckd = v6nd2_ckd;
	    cksum_add_bit128(v6nd3_ckd, hdr.ipv6nd_neigh_adv.target);

	    bit<16> v6nd4_ckd = v6nd3_ckd;

	    cksum_add_bit16(v6nd4_ckd, hdr.ipv6nd_adv_option_common.option_type ++ hdr.ipv6nd_adv_option_common.length);

	    cksum_add_bit48(v6nd4_ckd, hdr.ipv6nd_adv_option_lladdr.ethernet_addr);

	    // Write the final checksum to the packet
	    cksum_update_header(hdr.icmpv6_common.checksum, v6nd4_ckd);

	    rx_rslt_counter.count(rx_rslt_ok_ipv6nd_neigh_sol);
	    return;
#endif // INCLUDE_IPV6ND
	}

	// Packets making it this far are destined for the load balancer offload path
	rx_rslt_counter.count(rx_rslt_ok_lb);

	lb_ctx_rx_pkt_counter.count(meta_lb_id);
	lb_ctx_rx_byte_counter.count(meta_lb_id);

	//
	// IP source filter
	//   Only allow forwarding packets from explicitly allowed source IPs
	//

	if (hdr.ipv4.isValid()) {
	    hit = ipv4_src_filter_table.apply().hit;
	    if (!hit) {
		lb_ctx_drop_blocked_src_pkt_counter.count(meta_lb_id);
		return;
	    }
	} else if (hdr.ipv6.isValid()) {
	    hit = ipv6_src_filter_table.apply().hit;
	    if (!hit) {
		lb_ctx_drop_blocked_src_pkt_counter.count(meta_lb_id);
		return;
	    }
	} else {
	    // Drop all non-IP packets
	    lb_ctx_drop_not_ip_pkt_counter.count(meta_lb_id);
	    drop();
	    return;
	}

	// Only allow UDP LB packets past this point
	//
	// Packets missing this header should have failed at the parser but this will double check
	// before processing further.
	if (!hdr.udplb_common.isValid()) {
	    lb_ctx_drop_no_udplb_hdr_pkt_counter.count(meta_lb_id);
	    drop();
	    return;
	}

	// Make sure we have a supported udplb version header
	if (hdr.udplb_v2.isValid()) {
	    lb_ctx_rx_v2_counter.count(meta_lb_id);
	} else if (hdr.udplb_v3.isValid()) {
	    lb_ctx_rx_v3_counter.count(meta_lb_id);
	} else {
	    lb_ctx_drop_bad_udplb_version_pkt_counter.count(meta_lb_id);
	    drop();
	    return;
	}

	bit<16> udplb_ckd = 0;

	// All packets must be originated with our assigned unicast MAC address
	hdr.ethernet.srcAddr = meta_mac_sa;

	// All packets must be originated with our assigned unicast IP address
	// Keep track of how our edit has affected the IP/pseudo-header checksums
	if (hdr.ipv4.isValid()) {
	    cksum_swap_bit32(udplb_ckd, hdr.ipv4.srcAddr, meta_ip_sa[31:0]);
	    hdr.ipv4.srcAddr = meta_ip_sa[31:0];
	} else if (hdr.ipv6.isValid()) {
	    cksum_swap_bit128(udplb_ckd, hdr.ipv6.srcAddr, meta_ip_sa);
	    hdr.ipv6.srcAddr = meta_ip_sa;
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

	hit = epoch_assign_table.apply().hit;
	if (!hit) {
	    lb_ctx_drop_epoch_assign_miss_pkt_counter.count(meta_lb_id);
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

	hit = load_balance_calendar_table.apply().hit;
	if (!hit) {
	    lb_ctx_drop_lb_calendar_miss_pkt_counter.count(meta_lb_id);
	    return;
	}

	//
	// MemberInfoLookup
	//

	hit = member_info_lookup_table.apply().hit;
	if (!hit) {
	    lb_ctx_drop_mbr_info_miss_pkt_counter.count(meta_lb_id);
	    return;
	}

	// Set the MAC DA to point to the next hop at L2
	hdr.ethernet.dstAddr = new_mac_dst;

	// Set the IP Dst to point to the L3 destination

	if (hdr.ipv4.isValid()) {
	    // Calculate IPv4 and UDP pseudo header checksum delta using rfc1624 method
	    cksum_swap_bit32(udplb_ckd, hdr.ipv4.dstAddr, new_ip4_dst);
	    hdr.ipv4.dstAddr = new_ip4_dst;

	    if (!meta_keep_lb_header) {
		cksum_swap_bit16(udplb_ckd, hdr.ipv4.totalLen, hdr.ipv4.totalLen - SIZEOF_UDPLB_HDR);
		hdr.ipv4.totalLen = hdr.ipv4.totalLen - SIZEOF_UDPLB_HDR;
	    }

	    // Apply the accumulated delta to the IPv4 header checksum
	    cksum_update_header(hdr.ipv4.hdrChecksum, udplb_ckd);
	} else if (hdr.ipv6.isValid()) {
	    // Calculate UDP pseudo header checksum delta using rfc1624 method
	    cksum_swap_bit128(udplb_ckd, hdr.ipv6.dstAddr, new_ip6_dst);
	    hdr.ipv6.dstAddr = new_ip6_dst;

	    if (!meta_keep_lb_header) {
		cksum_swap_bit16(udplb_ckd, hdr.ipv6.payloadLen, hdr.ipv6.payloadLen - SIZEOF_UDPLB_HDR);
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

	//
	// UpdateUDPChecksum
	//

	// Calculate UDP pseudo header checksum delta using rfc1624 method

	// Update the destination port and adjust the checksum
	cksum_swap_bit16(udplb_ckd, hdr.udp.dstPort, new_udp_dst);
	hdr.udp.dstPort = new_udp_dst;

	if (!meta_keep_lb_header) {
	    // Subtract out the bytes of the UDP load-balance header
	    cksum_sub_bit16(udplb_ckd, hdr.udplb_common.magic);
	    cksum_sub_bit16(udplb_ckd, hdr.udplb_common.version ++ hdr.udplb_common.proto);
	    hdr.udplb_common.setInvalid();
	    if (hdr.udplb_v2.isValid()) {
		cksum_sub_bit16(udplb_ckd, hdr.udplb_v2.rsvd);
		cksum_sub_bit16(udplb_ckd, hdr.udplb_v2.entropy);
		cksum_sub_bit64(udplb_ckd, hdr.udplb_v2.tick);
		hdr.udplb_v2.setInvalid();
	    } else if (hdr.udplb_v3.isValid()) {
		cksum_sub_bit16(udplb_ckd, hdr.udplb_v3.slot_select);
		cksum_sub_bit16(udplb_ckd, hdr.udplb_v3.port_select);
		cksum_sub_bit64(udplb_ckd, hdr.udplb_v3.tick);
		hdr.udplb_v3.setInvalid();
	    }

	    // Fix up the length to adapt to the dropped udplb header and adjust the checksum using the new length
	    cksum_swap_bit16(udplb_ckd, hdr.udp.totalLen, hdr.udp.totalLen - SIZEOF_UDPLB_HDR);
	    hdr.udp.totalLen = hdr.udp.totalLen - SIZEOF_UDPLB_HDR;
	}

	// Write the updated checksum back into the packet
	cksum_update_header(hdr.udp.checksum, udplb_ckd);

	lb_mbr_tx_pkt_counter.count((bit<13>)meta_member_id);
	lb_mbr_tx_byte_counter.count((bit<13>)meta_member_id);
    }
}

control DeparserImpl(packet_out packet, in headers hdr, inout smartnic_metadata snmeta, inout standard_metadata_t smeta) {
    apply {
        packet.emit(hdr.ethernet);
#if INCLUDE_ARP
	packet.emit(hdr.arp);
#endif // INCLUDE_ARP
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_opt);
#if INCLUDE_ICMPV4ECHO
	packet.emit(hdr.icmpv4_common);
	packet.emit(hdr.icmpv4_echo);
#endif  // INCLUDE_ICMPV4ECHO

        packet.emit(hdr.ipv6);
#if INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO
	packet.emit(hdr.icmpv6_common);
#endif // INCLUDE_IPV6ND || INCLUDE_ICMPV6ECHO
#if INCLUDE_ICMPV6ECHO
	packet.emit(hdr.icmpv6_echo);
#endif // INCLUDE_ICMPV6ECHO
#if INCLUDE_IPV6ND
	packet.emit(hdr.ipv6nd_neigh_adv);
	packet.emit(hdr.ipv6nd_adv_option_common);
	packet.emit(hdr.ipv6nd_adv_option_lladdr);
#endif // INCLUDE_IPV6ND
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

