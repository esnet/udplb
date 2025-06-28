from robot.api.deco import keyword, library

import scapy
from scapy.all import Packet, UDP, bind_layers, XShortField, XByteField, XLongField, XIntField, FlagsField, BitField

class UDPLBShim(Packet):
    name = "UDPLBShim"
    fields_desc = [
        XShortField("magic", 0x4C42),
        XByteField("version", 0),
    ]

class UDPLBv2(Packet):
    name = "UDPLBv2"
    fields_desc = [
        XByteField("proto", 0),
        XShortField("rsvd", 0),
        XShortField("entropy", 0),
        XLongField("tick", 0),
    ]

class UDPLBv3(Packet):
    name = "UDPLBv3"
    fields_desc = [
        XByteField("proto", 0),
        XShortField("slotselect", 0),
        XShortField("portselect", 0),
        XLongField("tick", 0),
    ]

class EVIO6Seg(Packet):
    name = "EVIO6 Segment"
    fields_desc = [
        BitField("version", 0, 4),
        BitField("reserved", 0, 10),
        FlagsField("flags", 0, 2,
                   ["last",
                    "first",]),
        XShortField("rocid", 0),
        XIntField("offset", 0),]

bind_layers(UDPLBShim, UDPLBv2, {'version': 2})
bind_layers(UDPLBShim, UDPLBv3, {'version': 3})

bind_layers(UDPLBv2, EVIO6Seg, {'proto': 1})
bind_layers(UDPLBv3, EVIO6Seg, {'proto': 1})

bind_layers(UDP, UDPLBShim, {'dport': 0x4C42})

#---------------------------------------------------------------------------------------------------
@library
class Library:
    def __init__(self):
        pass

    @keyword
    def packet_udplbv2(self, version=2, **kwargs):
        return UDPLBShim(version=version) / UDPLBv2(**kwargs)

    @keyword
    def packet_udplbv3(self, version=3, **kwargs):
        return UDPLBShim(version=version) / UDPLBv3(**kwargs)

