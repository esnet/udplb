--
local p_udplbshim = Proto("udplb", "UDP Load Balancer Protocol")

local f_magic = ProtoField.string("udplb.magic", "Magic", base.ASCII)
local f_version = ProtoField.uint8("udplb.version", "Version", base.DEC)
local f_proto = ProtoField.uint8("udplb.proto", "Protocol", base.HEX)

p_udplbshim.fields = {
   f_magic,
   f_version,
   f_proto,
}

local version = Field.new("udplb.version")

local p_udplbshim_version_table = DissectorTable.new("udplb.version", "UDP-LB Version", ftypes.UINT8, base.DEC, p_udplbshim)
local p_udplb_encap_table = DissectorTable.new("udplb.proto", "UDP-LB Encap", ftypes.UINT8, base.DEC, p_udplbshim)

function udplbshim_heuristic_checker(buf, pkt, tree)
   length = buf:len()
   if length < 4 then return false end

   local maybe_magic = buf(0,2):string()
   if maybe_magic ~= "LB" then return false end

   p_udplbshim.dissector(buf, pkt, tree)
   return true
end
p_udplbshim:register_heuristic("udp", udplbshim_heuristic_checker)

function p_udplbshim.dissector(buf, pkt, tree)
   local t = tree:add(p_udplbshim, buf(0, 4))
   t:add(f_magic, buf(0,2))
   t:add(f_version, buf(2,1))
   t:add(f_proto, buf(3,1))

   local dissector = p_udplbshim_version_table:get_dissector(version()())

   if dissector ~= nil then
      -- found a dissector
      dissector:call(buf(4):tvb(), pkt, tree)
   else
      pkt.cols.protocol:set("UDP-LB")
      pkt.cols.packet_len:set(buf:len())
      pkt.cols.info:set("Version: " .. version()())
   end
end

---

local p_udplbv2 = Proto("udplbv2", "UDP Load Balancer Protocol v2")

local f_rsvd = ProtoField.uint16("udplbv2.rsvd", "Reserved", base.HEX)
local f_entropy = ProtoField.uint16("udplbv2.entropy", "Entropy", base.HEX)
local f_tick = ProtoField.uint64("udplbv2.tick", "Tick", base.HEX)

p_udplbv2.fields = {
   f_rsvd,
   f_entropy,
   f_tick,
}

local proto = Field.new("udplb.proto")
local tick = Field.new("udplbv2.tick")

function p_udplbv2.dissector(buf, pkt, tree)
   local t = tree:add(p_udplbv2, buf(0, 12))
   t:add(f_rsvd, buf(0,2))
   t:add(f_entropy, buf(2,2))
   t:add(f_tick, buf(4,8))

   local dissector = p_udplb_encap_table:get_dissector(proto()())

   if dissector ~= nil then
      -- found a dissector
      dissector:call(buf(12):tvb(), pkt, tree)
   else
      pkt.cols.protocol:set("UDP-LBv2")
      pkt.cols.packet_len:set(buf:len())
      pkt.cols.info:set("Tick: " .. tick()())
   end
end

p_udplbshim_version_table:add(2, p_udplbv2)

---

local p_udplbv3 = Proto("udplbv3", "UDP Load Balancer Protocol v3")

local f_slotselect = ProtoField.uint16("udplbv3.slotselect", "Slot Select", base.HEX)
local f_portselect = ProtoField.uint16("udplbv3.portselect", "Port Select", base.HEX)
local f_tick = ProtoField.uint64("udplbv3.tick", "Tick", base.HEX)

p_udplbv3.fields = {
   f_slotselect,
   f_portselect,
   f_tick,
}

local proto = Field.new("udplb.proto")
local tick = Field.new("udplbv3.tick")

function p_udplbv3.dissector(buf, pkt, tree)
   local t = tree:add(p_udplbv3, buf(0, 12))
   t:add(f_slotselect, buf(0,2))
   t:add(f_portselect, buf(2,2))
   t:add(f_tick, buf(4,8))

   local dissector = p_udplb_encap_table:get_dissector(proto()())

   if dissector ~= nil then
      -- found a dissector
      dissector:call(buf(12):tvb(), pkt, tree)
   else
      pkt.cols.protocol:set("UDP-LBv3")
      pkt.cols.packet_len:set(buf:len())
      pkt.cols.info:set("Tick: " .. tick()())
   end
end

p_udplbshim_version_table:add(3, p_udplbv3)
