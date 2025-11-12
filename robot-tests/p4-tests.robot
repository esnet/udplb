*** Settings ***
Documentation  P4 Pipeline Test Suite
Resource  p4_robot.resource
Resource  lb_robot.resource
Resource  packet_robot.resource
Resource  packet_lb_robot.resource
Library  Collections
Library  OperatingSystem

Suite Setup     Per Suite Setup
Suite Teardown  Per Suite Teardown

Test Setup      Per Test Setup
Test Teardown   Per Test Teardown

*** Variables ***
${LB_UDP_DST_PORT_DEFAULT}  ${19522}
${LB_UDP_DST_PORT_MIN}  ${16384}
${LB_UDP_DST_PORT_MAX}  ${32767}

#${LB_IPV4_NET}   10.1.2.0/24
#${LB_IPV6_NET}   fd9f:53b7:a261:48ed/64

*** Test Cases ***

LB0 ICMPv4 Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=10.1.2.2  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet ICMP  type=${8}  id=${33}  seq=${9}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=payload goes here
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  9

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  IP  dst  10.1.2.2
    Packet Field Equal  ${pkt}  IP  src  ${LB0_UCAST_IPV4}
    Packet Field Equal  ${pkt}  ICMP  type  ${0}
    Packet Field Equal  ${pkt}  Raw  load  ${{b'payload goes here'}}

LB0 ICMPv6Echo Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=fe80::1  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet ICMPv6EchoRequest  data=abcdef
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  10

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  IPv6  dst  fe80::1
    Packet Field Equal  ${pkt}  IPv6  src  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  ICMPv6EchoReply  data  ${{b'abcdef'}}

LB0 ARP Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=ff:ff:ff:ff:ff:ff
    ${pkt}  Packet Extend  ${pkt}  Packet ARP  op=${1}  psrc=10.1.2.2  pdst=${LB0_UCAST_IPV4}
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  8

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  ARP  op  ${2}
    Packet Field Equal  ${pkt}  ARP  hwsrc  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  ARP  psrc  ${LB0_UCAST_IPV4}

LB0 ICMPv6ND_NS Unicast Source Test
    [Documentation]
    ${packets_in}  Create List

    ${ipv6_sol_node_mcast_addr}  LB IPv6 to Solicited Node Mcast  ${LB0_UCAST_IPV6}
    ${ipv6_sol_node_mcast_mac}  LB IPv6 Mcast Addr to MAC  ${ipv6_sol_node_mcast_addr}

    ${pkt}  Packet Ether  dst=${ipv6_sol_node_mcast_mac}  src=00:11:22:33:44:55
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=fe80::1  dst=${ipv6_sol_node_mcast_addr}
    ${pkt}  Packet Extend  ${pkt}  Packet ICMPv6ND_NS  tgt=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet ICMPv6NDOptSrcLLAddr  lladdr=00:11:22:33:44:aa
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  11

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  00:11:22:33:44:aa
    Packet Field Equal  ${pkt}  IPv6  dst  fe80::1
    Packet Field Equal  ${pkt}  IPv6  src  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  IPv6  hlim  ${255}
    Packet Field Equal  ${pkt}  ICMPv6ND_NA  S  ${1}
    Packet Field Equal  ${pkt}  ICMPv6ND_NA  tgt  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  ICMPv6NDOptDstLLAddr  lladdr  ${LB_UCAST_MAC}

LB0 ICMPv6ND_NS Unspecified Source Test
    [Documentation]
    ${packets_in}  Create List

    ${ipv6_sol_node_mcast_addr}  LB IPv6 to Solicited Node Mcast  ${LB0_UCAST_IPV6}
    ${ipv6_sol_node_mcast_mac}  LB IPv6 Mcast Addr to MAC  ${ipv6_sol_node_mcast_addr}

    ${ipv6_unspecified_addr}  Set Variable  ::

    ${ipv6_all_nodes_mcast_addr}  Set Variable  ff02::1
    ${ipv6_all_nodes_mcast_mac}  LB IPv6 Mcast Addr to MAC  ${ipv6_all_nodes_mcast_addr}

    ${pkt}  Packet Ether  dst=${ipv6_sol_node_mcast_mac}  src=00:11:22:33:44:55
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${ipv6_unspecified_addr}  dst=${ipv6_sol_node_mcast_addr}
    ${pkt}  Packet Extend  ${pkt}  Packet ICMPv6ND_NS  tgt=${LB0_UCAST_IPV6}
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  11

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${ipv6_all_nodes_mcast_mac}
    Packet Field Equal  ${pkt}  IPv6  dst  ${ipv6_all_nodes_mcast_addr}
    Packet Field Equal  ${pkt}  IPv6  src  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  IPv6  hlim  ${255}
    Packet Field Equal  ${pkt}  ICMPv6ND_NA  S  ${0}
    Packet Field Equal  ${pkt}  ICMPv6ND_NA  tgt  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  ICMPv6NDOptDstLLAddr  lladdr  ${LB_UCAST_MAC}

TCP IPv4 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet TCP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

TCP IPv6 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB0_ALLOWED_SRC_IPV6}  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet TCP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

Default UDP Port No LB Header IPv4 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    # Missing LB Header
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

Default UDP Port No LB Header IPv6 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB0_ALLOWED_SRC_IPV6}  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    # Missing LB Header
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

Low Invalid UDP Port UDPLBv2 IPv4 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_MIN - 1}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

High Invalid UDP Port UDPLBv2 IPv4 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_MAX + 1}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

Invalid UDPLB version IPv4 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_MAX + 1}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  version=${99}  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

LB0 Default UDP Port UDPLBv2 IPv4 Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${LB0_MBR0_MAC}
    Packet Field Equal  ${pkt}  IP  dst  ${LB0_MBR0_IPV4}
    Packet Field Equal  ${pkt}  IP  src  ${LB0_UCAST_IPV4}
    Packet Field Equal  ${pkt}  UDP  sport  ${1234}
    Packet Field Equal  ${pkt}  UDP  dport  ${17750 + 1}

LB0 Min UDP Port UDPLBv2 IPv4 Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_MIN}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${LB0_MBR0_MAC}
    Packet Field Equal  ${pkt}  IP  dst  ${LB0_MBR0_IPV4}
    Packet Field Equal  ${pkt}  IP  src  ${LB0_UCAST_IPV4}
    Packet Field Equal  ${pkt}  UDP  sport  ${1234}
    Packet Field Equal  ${pkt}  UDP  dport  ${17750 + 1}

LB0 Max UDP Port UDPLBv2 IPv4 Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_MAX}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${LB0_MBR0_MAC}
    Packet Field Equal  ${pkt}  IP  dst  ${LB0_MBR0_IPV4}
    Packet Field Equal  ${pkt}  IP  src  ${LB0_UCAST_IPV4}
    Packet Field Equal  ${pkt}  UDP  sport  ${1234}
    Packet Field Equal  ${pkt}  UDP  dport  ${17750 + 1}

LB0 Default UDP Port UDPLBv2 IPv6 Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB0_ALLOWED_SRC_IPV6}  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  1  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${LB0_MBR0_MAC}
    Packet Field Equal  ${pkt}  IPv6  dst  ${LB0_MBR0_IPV6}
    Packet Field Equal  ${pkt}  IPv6  src  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  UDP  sport  ${1234}
    Packet Field Equal  ${pkt}  UDP  dport  ${17750 + 1}

LB0 Random UDP Ports UDPLBv3 IPv6 Test
    [Documentation]
    # Note: in UDPLBv3, the tick field is no longer used for slot selection and that the slotselect field is now used for that
    #       ensure that this test verifies the independence of those two fields (tick/slotselect) by making them different

    ${num_random}  Set Variable  ${9}
    ${random_ports}  Evaluate  random.sample(range(${LB_UDP_DST_PORT_MIN}, ${LB_UDP_DST_PORT_MAX}), ${num_random})  random

    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB0_ALLOWED_SRC_IPV6}  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${random_ports}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${3}  slotselect=${10}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  ${num_random}  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  ${num_random}  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  ${num_random}  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  ${num_random}  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  ${num_random}  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  ${num_random}

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${LB0_MBR0_MAC}
    Packet Field Equal  ${pkt}  IPv6  dst  ${LB0_MBR0_IPV6}
    Packet Field Equal  ${pkt}  IPv6  src  ${LB0_UCAST_IPV6}
    Packet Field Equal  ${pkt}  UDP  sport  ${1234}
    Packet Field Equal  ${pkt}  UDP  dport  ${17750 + 1}

LB1 Random UDP Port UDPLBv3 IPv6 Test
    [Documentation]
    # Note: in UDPLBv3, the tick field is no longer used for slot selection and that the slotselect field is now used for that
    #       ensure that this test verifies the independence of those two fields (tick/slotselect) by making them different
    # Note: LB1 does not pop the UDPLB header on the way to the next hop

    ${random_port}  Evaluate  random.randint(${LB_UDP_DST_PORT_MIN}, ${LB_UDP_DST_PORT_MAX})  random

    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB1_ALLOWED_SRC_IPV6}  dst=${LB1_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${random_port}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${16}  slotselect=${511}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  1
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  1

    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v2_counter  1
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v3_counter  1

    P4 Counter Packets Equal  1  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  1

    ${pkt}  Set Variable  ${packets_out[0]}
    Packet Field Equal  ${pkt}  Ethernet  src  ${LB_UCAST_MAC}
    Packet Field Equal  ${pkt}  Ethernet  dst  ${LB1_MBR0_MAC}
    Packet Field Equal  ${pkt}  IPv6  dst  ${LB1_MBR0_IPV6}
    Packet Field Equal  ${pkt}  IPv6  src  ${LB1_UCAST_IPV6}
    Packet Field Equal  ${pkt}  UDP  sport  ${1234}
    Packet Field Equal  ${pkt}  UDP  dport  ${19522}
    Packet Field Equal  ${pkt}  UDPLBShim  magic  ${0x4C42}
    Packet Field Equal  ${pkt}  UDPLBShim  version  ${3}
    Packet Field Equal  ${pkt}  UDPLBv3  slotselect  ${511}
    Packet Field Equal  ${pkt}  UDPLBv3  portselect  ${1}
    Packet Field Equal  ${pkt}  UDPLBv3  tick  ${16}
    Packet Field Equal  ${pkt}  Raw  load  ${{b'some payload'}}

LB0 Checksum Sweep UDPLBv2 IPv4 Test
    [Documentation]

    [Tags]  robot:skip

    ${packets_in}  Create List

    FOR  ${sport}  IN RANGE  ${0}  ${65536}
    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${sport}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv2  tick=${10}  entropy=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}
    END

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  65536  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  65536  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  65536  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  65536  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  65536  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    #Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  ${65536}

LB0 Checksum Sweep UDPLBv3 IPv6 Test
    [Documentation]
    # Note: in UDPLBv3, the tick field is no longer used for slot selection and that the slotselect field is now used for that
    #       ensure that this test verifies the independence of those two fields (tick/slotselect) by making them different
    [Tags]  robot:skip

    ${packets_in}  Create List

    FOR  ${sport}  IN RANGE  ${0}  ${65536}
    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB0_ALLOWED_SRC_IPV6}  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${sport}  dport=${19522}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${3}  slotselect=${10}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}
    END

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  65536  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  65536  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  65536  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  65536  MatchActionImpl.lb_ctx_rx_v3_counter  0

    P4 Counter Packets Equal  65536  MatchActionImpl.lb_mbr_tx_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    #Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  ${65536}

LB0 UDPLBv3 Sent from Allowed Src for LB1 IPv4 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB1_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${16}  slotselect=${511}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

LB0 UDPLBv3 Sent from Allowed Src for LB1 IPv6 Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IPv6  src=${LB1_ALLOWED_SRC_IPV6}  dst=${LB0_UCAST_IPV6}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${16}  slotselect=${511}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

LB0 UDPLBv3 Epoch Assign Miss Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${9999999}  slotselect=${20}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v3_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

LB0 UDPLBv3 LB Calendar Miss Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${16}  slotselect=${99}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v3_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

LB0 UDPLBv3 Member Info Miss Drop Test
    [Documentation]
    ${packets_in}  Create List

    ${pkt}  Packet Ether  dst=${LB_UCAST_MAC}
    ${pkt}  Packet Extend  ${pkt}  Packet IP  src=${LB0_ALLOWED_SRC_IPV4}  dst=${LB0_UCAST_IPV4}
    ${pkt}  Packet Extend  ${pkt}  Packet UDP  sport=${1234}  dport=${LB_UDP_DST_PORT_DEFAULT}
    ${pkt}  Packet Extend  ${pkt}  Packet UDPLBv3  tick=${16}  slotselect=${21}  portselect=${1}
    ${pkt}  Packet Extend  ${pkt}  Packet Payload  payload=some payload
    Append To List  ${packets_in}  ${pkt}

    Packet Write Pcap  ${test_dir}/packets_in.pcap  ${packets_in}

    P4 Counter Reset All

    # Create a calendar slot (2) pointing at a nonexistent member info (1)
    # LB0 Epoch 1 (ticks 16-31) has slot_select_bit_cnt = 3 and slot_select_xor = 0xffff
    # Packet has tick=16, slotselect=21
    #   (21 ^ 0xffff) & 0b0111 = 2
    # Create a LB Calendar entry with: LB=0, epoch=1, min_slot=2, max_slot=2, member=1 (nonexistent)
    #
    LB SetCalendarSlotRange  0  1  2  2  1

    P4 Run Traffic  ${test_dir}/packets

    P4 Counter Packets Equal  1  MatchActionImpl.packet_rx_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.rx_rslt_counter  13
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_blocked_src_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_not_ip_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_no_udplb_hdr_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_bad_udplb_version_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_epoch_assign_miss_pkt_counter  0
    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_drop_lb_calendar_miss_pkt_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_drop_mbr_info_miss_pkt_counter  0

    P4 Counter Packets Equal  0  MatchActionImpl.lb_ctx_rx_v2_counter  0
    P4 Counter Packets Equal  1  MatchActionImpl.lb_ctx_rx_v3_counter  0

    ${packets_out}  Packet Read Pcap  ${test_dir}/packets_out.pcap
    Packet Log Packets  ${packets_out}

    Length Should Be  ${packets_out}  0

*** Keywords ***

Per Suite Setup
    P4 Start Server  p4/udplb.json
    P4 Get Config

    P4 Reset State
    P4 Reset Cmd Log

    Set Suite Variable  ${LB_UCAST_MAC}  00:aa:bb:cc:dd:ee

    LB SetupL2Common  ${LB_UCAST_MAC}

    Set Suite Variable  ${LB0_UCAST_IPV4}  10.1.2.3
    Set Suite Variable  ${LB0_UCAST_IPV6}  fd9f:53b7:a261:48ed:2aa:bbff:fecc:ddee

    Set Suite Variable  ${LB0_ALLOWED_SRC_IPV4}  10.1.2.2
    Set Suite Variable  ${LB0_ALLOWED_SRC_IPV6}  fe80::1

    Set Suite Variable  ${LB0_MBR0_MAC}  11:22:33:44:55:66
    Set Suite Variable  ${LB0_MBR0_IPV4}  170.187.204.221
    Set Suite Variable  ${LB0_MBR0_IPV6}  fe80::3

    LB SetupInstanceL2L3        0  ${LB_UCAST_MAC}  ${LB0_UCAST_IPV4}  ${LB0_UCAST_IPV6}
    LB AddAllowedSrcIPv4        0  ${LB0_ALLOWED_SRC_IPV4}
    LB AddAllowedSrcIPv6        0  ${LB0_ALLOWED_SRC_IPV6}
    LB AddEpochWithSlotSelOpts  0  0   15  0  3  0xffff
    LB AddEpochWithSlotSelOpts  0  16  31  1  3  0xffff
    LB SetCalendarSlotRange     0  0  5  5  0
    LB SetCalendarSlotRange     0  1  3  3  0
    LB SetMemberInfoIPv4        0  0  ${LB0_MBR0_MAC}  ${LB0_MBR0_IPV4}  17750  4  False
    LB SetMemberInfoIPv6        0  0  ${LB0_MBR0_MAC}  ${LB0_MBR0_IPV6}  17750  4  False

    Set Suite Variable  ${LB1_UCAST_IPV4}  10.1.2.4
    Set Suite Variable  ${LB1_UCAST_IPV6}  fd9f:53b7:a261:48ed::1

    Set Suite Variable  ${LB1_ALLOWED_SRC_IPV4}  10.1.2.10
    Set Suite Variable  ${LB1_ALLOWED_SRC_IPV6}  fe80::10

    Set Suite Variable  ${LB1_MBR0_MAC}  99:88:77:66:55:44
    Set Suite Variable  ${LB1_MBR0_IPV4}  10.11.12.13
    Set Suite Variable  ${LB1_MBR0_IPV6}  fe80::3

    LB SetupInstanceL2L3        1  ${LB_UCAST_MAC}  ${LB1_UCAST_IPV4}  ${LB1_UCAST_IPV6}
    LB AddAllowedSrcIPv4        1  ${LB1_ALLOWED_SRC_IPV4}
    LB AddAllowedSrcIPv6        1  ${LB1_ALLOWED_SRC_IPV6}
    LB AddEpoch                 1  0   15  0
    LB AddEpoch                 1  16  31  1
    LB SetCalendarSlotRange     1  0  10  10  0
    LB SetCalendarSlotRange     1  1  511  511  0
    LB SetMemberInfoIPv4        1  0  ${LB1_MBR0_MAC}  ${LB1_MBR0_IPV4}  19522  0  True
    LB SetMemberInfoIPv6        1  0  ${LB1_MBR0_MAC}  ${LB1_MBR0_IPV6}  19522  0  True

    P4 Counter Reset All

Per Suite Teardown
    #No Operation
    P4 Stop Server

Per Test Setup
    Set Test Variable  ${test_dir}  ${OUTPUT_DIR}/${TEST_NAME.translate(str.maketrans(" ", "_"))}
    Create Directory  ${test_dir}

    P4 Counter Reset All

Per Test Teardown
    P4 Write Cmd Log  ${test_dir}/cli_commands.txt
