from robot.api.deco import keyword, library

import operator
import ipaddress

#---------------------------------------------------------------------------------------------------
@library
class Library:
    def __init__(self):
        pass

    @keyword
    def lb_mac_to_hex(self, mac):
        mac_hex_str = mac.translate({ord(':'):None})
        return("0x{:s}".format(mac_hex_str))

    @keyword
    def lb_ipv4_to_hex(self, ipv4_addr):
        return("{:#x}".format(ipaddress.IPv4Address(ipv4_addr)))

    @keyword
    def lb_ipv6_to_hex(self, ipv6_addr):
        return("{:#x}".format(ipaddress.IPv6Address(ipv6_addr)))

    @keyword
    def lb_ipv6_to_solicited_node_mcast(self, ipv6_addr):
        # See: RFC 4291
        ucast_ipv6 = ipaddress.IPv6Address(ipv6_addr)
        sol_node_mcast_network = ipaddress.IPv6Network('ff02::1:ff00:0/104')
        # ucast_ipv6 & sol_node_mcast_network.hostmask | sol_node_mcast_network.network_address
        sol_node_mcast_addr = ipaddress.IPv6Address(bytes(
            map(operator.or_,
                sol_node_mcast_network.network_address.packed,
                map(operator.and_,
                    ucast_ipv6.packed,
                    sol_node_mcast_network.hostmask.packed))))
        return sol_node_mcast_addr.compressed

    @keyword
    def lb_ipv6_mcast_addr_to_mac(self, ipv6_addr):
        # See: RFC 2464
        ipv6 = ipaddress.IPv6Address(ipv6_addr)
        mac = [0x33, 0x33, *ipv6.packed[-4:]]
        return ':'.join(["{:02x}".format(b) for b in mac])

    # @keyword
    # def lb_ipv6_mcast_addr_to_mac_hex(self, ipv6_addr):
    #     # See: RFC 2464
    #     ipv6 = ipaddress.IPv6Address(ipv6_addr)
    #     return "0x3333{:x}".format(int.from_bytes(ipv6.packed[-4:], 'big'))

    @keyword
    def lb_bool_to_int(self, true_false):
        if true_false == 'True':
            return 1
        else:
            return 0

    @keyword
    def lb_compute_epoch_masks(self, tick_min, tick_max):
        rules = []
        start = int(tick_min)
        end = int(tick_max)

        curr = start
        while curr <= end:
            covered_lsbs = 0
            while curr <= end:
                bit = 1 << covered_lsbs
                if ((curr & bit) == 0) and ((curr | bit) <= end):
                    covered_lsbs += 1
                    curr |= bit
                else:
                    lsb_mask = (1 << covered_lsbs) - 1
                    rules.append(("0x{:016x}".format(curr & ~lsb_mask)+"/"+str(64-covered_lsbs), covered_lsbs))
                    curr += 1
                    covered_lsbs = 0
                    break
        print(rules)
        return rules
