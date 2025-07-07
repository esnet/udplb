*** Settings ***
Library  lb_robot.Library

*** Keywords ***

LB SetupL2Common
    [Arguments]  ${ucast_mac}

    ${ucast_mac_hex}  LB MAC to Hex  ${ucast_mac}

    #
    # MAC DST FILTER (common)
    #

    # Unicast
    P4 Cmd  table_add mac_dst_filter_table set_mac_sa 0&&&0 ${ucast_mac_hex} => ${ucast_mac_hex} 0
    # Broadcast
    P4 Cmd  table_add mac_dst_filter_table set_mac_sa 0&&&0 0xffffffffffff => ${ucast_mac_hex} 0
    # IPv6 All Nodes Link-Local Multicast
    P4 Cmd  table_add mac_dst_filter_table set_mac_sa 0&&&0 0x333300000001 => ${ucast_mac_hex} 0
    
LB SetupInstanceL2L3
    [Arguments]  ${lb_id}  ${ucast_mac}  ${ipv4_addr}  ${ipv6_addr}

    ${ucast_mac_hex}  LB MAC to Hex  ${ucast_mac}
    ${ipv4_hex}  LB IPv4 to Hex  ${ipv4_addr}
    ${ipv6_hex}  LB IPv6 to Hex  ${ipv6_addr}

    ${ipv6_sol_node_mcast_addr}  LB IPv6 to Solicited Node Mcast  ${ipv6_addr}
    ${ipv6_sol_node_mcast_hex}  LB IPv6 to Hex  ${ipv6_sol_node_mcast_addr}
    ${ipv6_sol_node_mcast_mac}  LB IPv6 Mcast Addr to MAC  ${ipv6_sol_node_mcast_addr}
    ${ipv6_sol_node_mcast_mac_hex}  LB MAC to Hex  ${ipv6_sol_node_mcast_mac}

    #
    # MAC DST FILTER
    #

    # IPv6 Solicited Node Multicast Address
    P4 Cmd  table_add mac_dst_filter_table set_mac_sa 0&&&0 ${ipv6_sol_node_mcast_mac_hex} => ${ucast_mac_hex} 0

    #
    # IP DST FILTER
    #

    # IPv4 Unicast
    P4 Cmd  table_add ip_dst_filter_table set_ip_sa 0&&&0 0x0800 ${ipv4_hex} => ${ipv4_hex} ${lb_id} 0

    # ARP Target Protocol Address
    P4 Cmd  table_add ip_dst_filter_table set_ip_sa 0&&&0 0x0806 ${ipv4_hex} => ${ipv4_hex} ${lb_id} 0

    # IPv6 Unicast
    P4 Cmd  table_add ip_dst_filter_table set_ip_sa 0&&&0 0x86dd ${ipv6_hex} => ${ipv6_hex} ${lb_id} 0

    # IPv6 Solicited Node Multicast Address
    P4 Cmd  table_add ip_dst_filter_table set_ip_sa 0&&&0 0x86dd ${ipv6_sol_node_mcast_hex} => ${ipv6_hex} ${lb_id} 0

LB AddAllowedSrcIPv4
    [Arguments]  ${lb_id}  ${ipv4_addr}
    ${ipv4_hex}=  LB IPv4 to Hex  ${ipv4_addr}
    P4 Cmd  table_add ipv4_src_filter_table allow_ip_src ${lb_id} ${ipv4_hex} =>

LB AddAllowedSrcIPv6
    [Arguments]  ${lb_id}  ${ipv6_addr}
    ${ipv6_hex}=  LB IPv6 to Hex  ${ipv6_addr}
    P4 Cmd  table_add ipv6_src_filter_table allow_ip_src ${lb_id} ${ipv6_hex} =>

LB AddEpoch
    [Arguments]  ${lb_id}  ${tick_min}  ${tick_max}  ${epoch}
    ${masks}=  LB Compute Epoch Masks  ${tick_min}  ${tick_max}
    FOR  ${item}  IN  @{masks}
        ${mask}=  Set Variable  ${item}[0]
	${prio}=  Set Variable  ${item}[1]
        P4 Cmd  table_add epoch_assign_table do_assign_epoch ${lb_id} ${mask} => ${epoch} ${prio}
    END

LB AddEpochWithSlotSelOpts
    [Arguments]  ${lb_id}  ${tick_min}  ${tick_max}  ${epoch}  ${slot_select_bit_cnt}  ${slot_select_xor}
    ${masks}=  LB Compute Epoch Masks  ${tick_min}  ${tick_max}
    FOR  ${item}  IN  @{masks}
        ${mask}=  Set Variable  ${item}[0]
	${prio}=  Set Variable  ${item}[1]
        P4 Cmd  table_add epoch_assign_table do_assign_epoch_with_slot_sel_opts ${lb_id} ${mask} => ${epoch} ${slot_select_bit_cnt} ${slot_select_xor} ${prio}
    END

LB SetCalendarSlotRange
    [Arguments]  ${lb_id}  ${epoch}  ${slot_min}  ${slot_max}  ${member_id}
    FOR  ${slot}  IN RANGE  ${slot_min}  ${slot_max}+1
        P4 Cmd  table_add load_balance_calendar_table do_assign_member ${lb_id} ${epoch} ${slot} => ${member_id}
    END

LB SetMemberInfoIPv4
    [Arguments]  ${lb_id}  ${member_id}  ${mac_dst}  ${ipv4_dst}  ${udp_base}  ${port_select_bit_cnt}  ${keep_lb_header}
    ${mac_dst_hex}=  LB MAC to Hex  ${mac_dst}
    ${ipv4_hex}=  LB IPv4 to Hex  ${ipv4_dst}
    ${keep_lb_header_int}=  LB Bool to Int  ${keep_lb_header}

    P4 Cmd  table_add member_info_lookup_table do_ipv4_member_rewrite ${lb_id} 0x0800 ${member_id} => ${mac_dst_hex} ${ipv4_hex} ${udp_base} ${port_select_bit_cnt} ${keep_lb_header_int}

LB SetMemberInfoIPv6
    [Arguments]  ${lb_id}  ${member_id}  ${mac_dst}  ${ipv6_dst}  ${udp_base}  ${port_select_bit_cnt}  ${keep_lb_header}
    ${mac_dst_hex}=  LB MAC to Hex  ${mac_dst}
    ${ipv6_hex}=  LB IPv6 to Hex  ${ipv6_dst}
    ${keep_lb_header_int}=  LB Bool to Int  ${keep_lb_header}

    P4 Cmd  table_add member_info_lookup_table do_ipv6_member_rewrite ${lb_id} 0x86dd ${member_id} => ${mac_dst_hex} ${ipv6_hex} ${udp_base} ${port_select_bit_cnt} ${keep_lb_header_int}

