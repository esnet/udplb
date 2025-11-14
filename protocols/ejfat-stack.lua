--
local p_ejfatlbshim = Proto("ejfatlb", "EJFAT Load Balancer Protocol")

local f_magic = ProtoField.string("ejfatlb.magic", "Magic", base.ASCII)
local f_version = ProtoField.uint8("ejfatlb.version", "Version", base.DEC)
local f_proto = ProtoField.uint8("ejfatlb.proto", "Protocol", base.HEX)

p_ejfatlbshim.fields = {
   f_magic,
   f_version,
   f_proto,
}

local version = Field.new("ejfatlb.version")

local p_ejfatlbshim_version_table = DissectorTable.new("ejfatlb.version", "EJFAT-LB Version", ftypes.UINT8, base.DEC, p_ejfatlbshim)
local p_ejfatlb_encap_table = DissectorTable.new("ejfatlb.proto", "EJFAT-LB Encap", ftypes.UINT8, base.DEC, p_ejfatlbshim)

function ejfatlbshim_heuristic_checker(buf, pkt, tree)
   length = buf:len()
   if length < 4 then return false end

   local maybe_magic = buf(0,2):string()
   if maybe_magic ~= "LB" then return false end

   p_ejfatlbshim.dissector(buf, pkt, tree)
   return true
end
p_ejfatlbshim:register_heuristic("udp", ejfatlbshim_heuristic_checker)

function p_ejfatlbshim.dissector(buf, pkt, tree)
   local t = tree:add(p_ejfatlbshim, buf(0, 4))
   t:add(f_magic, buf(0,2))
   t:add(f_version, buf(2,1))
   t:add(f_proto, buf(3,1))

   local dissector = p_ejfatlbshim_version_table:get_dissector(version()())

   if dissector ~= nil then
      -- found a dissector
      dissector:call(buf(4):tvb(), pkt, tree)
   else
      pkt.cols.protocol:set("EJFAT-LB")
      pkt.cols.packet_len:set(buf:len())
      pkt.cols.info:set("Version: " .. version()())
   end
end



local p_ejfatlbv2 = Proto("ejfatlbv2", "EJFAT Load Balancer Protocol v2")

local f_rsvd = ProtoField.uint16("ejfatlbv2.rsvd", "Reserved", base.HEX)
local f_entropy = ProtoField.uint16("ejfatlbv2.entropy", "Entropy", base.HEX)
local f_tick = ProtoField.uint64("ejfatlbv2.tick", "Tick", base.HEX)

p_ejfatlbv2.fields = {
   f_rsvd,
   f_entropy,
   f_tick,
}

local proto = Field.new("ejfatlb.proto")
local tick = Field.new("ejfatlbv2.tick")

function p_ejfatlbv2.dissector(buf, pkt, tree)
   local t = tree:add(p_ejfatlbv2, buf(0, 12))
   t:add(f_rsvd, buf(0,2))
   t:add(f_entropy, buf(2,2))
   t:add(f_tick, buf(4,8))

   local dissector = p_ejfatlb_encap_table:get_dissector(proto()())

   if dissector ~= nil then
      -- found a dissector
      dissector:call(buf(12):tvb(), pkt, tree)
   else
      pkt.cols.protocol:set("EJFAT-LBv2")
      pkt.cols.packet_len:set(buf:len())
      pkt.cols.info:set("Tick: " .. tick()())
   end
end

p_ejfatlbshim_version_table:add(2, p_ejfatlbv2)

---

local p_ejfatlbv3 = Proto("ejfatlbv3", "EJFAT Load Balancer Protocol v3")

local f_slotselect = ProtoField.uint16("ejfatlbv3.slotselect", "Slot Select", base.HEX)
local f_portselect = ProtoField.uint16("ejfatlbv3.portselect", "Port Select", base.HEX)
local f_tick = ProtoField.uint64("ejfatlbv3.tick", "Tick", base.HEX)

p_ejfatlbv3.fields = {
   f_slotselect,
   f_portselect,
   f_tick,
}

local proto = Field.new("ejfatlb.proto")
local tick = Field.new("ejfatlbv3.tick")

function p_ejfatlbv3.dissector(buf, pkt, tree)
   local t = tree:add(p_ejfatlbv3, buf(0, 12))
   t:add(f_slotselect, buf(0,2))
   t:add(f_portselect, buf(2,2))
   t:add(f_tick, buf(4,8))

   local dissector = p_ejfatlb_encap_table:get_dissector(proto()())

   if dissector ~= nil then
      -- found a dissector
      dissector:call(buf(12):tvb(), pkt, tree)
   else
      pkt.cols.protocol:set("EJFAT-LBv3")
      pkt.cols.packet_len:set(buf:len())
      pkt.cols.info:set("Tick: " .. tick()())
   end
end

p_ejfatlbshim_version_table:add(3, p_ejfatlbv3)


--
local p_e2sarseg = Proto("e2sarseg", "E2SAR Segmentation")

local f_version = ProtoField.uint8("e2sarseg.version", "Version", base.DEC, nil, 0xF0)
local f_rsvd = ProtoField.uint16("e2sarseg.rsvd", "Reserved", base.HEX, nil, 0x0FFF)
local f_dataid = ProtoField.uint16("e2sarseg.dataid", "Data ID", base.DEC)
local f_offset = ProtoField.uint32("e2sarseg.offset", "Offset", base.DEC)
local f_length = ProtoField.uint32("e2sarseg.length", "Length", base.DEC)
local f_eventid = ProtoField.uint64("e2sarseg.eventid", "Event ID", base.DEC)

p_e2sarseg.fields = {
   f_version,
   f_rsvd,
   f_dataid,
   f_offset,
   f_length,
   f_eventid,
}

-- field accessor function, used in the dissector
local offset = Field.new("e2sarseg.offset")
local dataid = Field.new("e2sarseg.dataid")
local eventid = Field.new("e2sarseg.eventid")

local data_dis = Dissector.get("data")

function p_e2sarseg.dissector(buf, pkt, tree)
   local t = tree:add(p_e2sarseg, buf(0,20))
   t:add(f_version, buf(0,1))

   local trsvd = t:add(f_rsvd, buf(0,2))

   t:add(f_dataid, buf(2,2))
   t:add(f_offset, buf(4,4))
   t:add(f_length, buf(8,4))
   t:add(f_eventid, buf(12,8))

   data_dis:call(buf(20):tvb(), pkt, tree)

   pkt.cols.protocol:set("E2SARSEG")
   pkt.cols.packet_len:set(buf(20):tvb():reported_length_remaining())
   --pkt.cols.info:set("DATAID: " .. string.format("0x%X", dataid()()) .. " Event: " .. eventid()() .. " Offset: " .. offset()())
   pkt.cols.info:set("DATAID: " .. dataid()() .. " Event: " .. eventid()() .. " Offset: " .. offset()())
			    
end

local ejfatlb_encap_table = DissectorTable.get("ejfatlb.proto")
ejfatlb_encap_table:add(1, p_e2sarseg)

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add("10000-10255", p_e2sarseg)
