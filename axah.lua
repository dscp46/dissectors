-- axah.lua - AX.25 Authentication Header

-- Some module-specific constants
local proto_shortname = "axah"
local proto_fullname  = "AX.25 Authentication Header"

-- Protocol Definition
p_axah = Proto ( proto_shortname, proto_fullname)

-- Fields
local f_ax25_dst = Field.new("ax25.dst")
local f_ax25_src = Field.new("ax25.src")

-- ProtoFields
local pf_axah_ctl  = ProtoField.bytes ( proto_shortname .. ".next_ctl", "Next Control")
local pf_axah_e    = ProtoField.uint8 ( proto_shortname .. ".e", "Extended Control", base.DEC, yesno, 0x80)
local pf_axah_icv  = ProtoField.bytes ( proto_shortname .. ".icv", "AX.AH ICV")
local pf_axah_len  = ProtoField.uint8 ( proto_shortname .. ".length", "Payload length", base.DEC, nil, 0x7F)
local pf_axah_pad  = ProtoField.uint8 ( proto_shortname .. ".padding", "Padding", base.HEX)
local pf_axah_pid  = ProtoField.uint8 ( proto_shortname .. ".pid", "Next Protocol ID", base.HEX)
local pf_axah_seq  = ProtoField.uint32( proto_shortname .. ".sequence", "AX.AH Sequence")
local pf_axah_spi  = ProtoField.uint32( proto_shortname .. ".spi", "AX.AH SPI", base.HEX)

p_axah.fields = {
	pf_axah_ctl, pf_axah_e, pf_axah_icv, pf_axah_len, pf_axah_pad,
	pf_axah_pid, pf_axah_seq, pf_axah_spi
}

-- Dissector
function p_axah.dissector( buffer, pinfo, tree)
	local length = buffer:len()
	if ( length < 12 ) then return end
	
	local subtree = tree:add( p_axah, buffer())
	local payload_len = bit.band( buffer( 3, 1):uint(), 0x7F)
	local extended_ctl = bit.rshift( bit.band( buffer( 3, 1):uint(), 0x80), 7)
	
	local inner_frame = ByteArray.new()
	inner_frame:append( f_ax25_dst().range:bytes() )
	inner_frame:append( f_ax25_src().range:bytes() )
	
	if ( (length < ((payload_len+2)*4)) or (payload_len == 0) ) then
		subtree:add_expert_info( PI_PROTOCOL, PI_ERROR, "Malformed AX.AH frame");
		return
	end
	
	local ctl_data
	if( extended_ctl == 0 ) then
		subtree:add( pf_axah_pad, buffer(0,1))
		ctl_data = buffer(1,1)
	else
		ctl_data = buffer(0,2)
	end
	subtree:add( pf_axah_ctl, ctl_data)
	inner_frame:append( ctl_data:bytes())
	pinfo.private.ax25_ctl = ctl_data:uint()
	
	subtree:add( pf_axah_pid, buffer(2,1))
	local subtree_len = subtree:add( buffer(3,1), "Length fields")
	subtree_len:add( pf_axah_e,   buffer(3,1))
	subtree_len:add( pf_axah_len, buffer(3,1)) -- "Length: " .. payload_len .. " (" .. ((payload_len+2)*4) .. " bytes)")
	subtree:add( pf_axah_spi, buffer(4,4))
	subtree:add( pf_axah_seq, buffer(8,4))
	subtree:add( pf_axah_icv, buffer(12, (payload_len-1)*4))
	
	if ( bit.band( buffer(1,1):uint(), 0x13 ) ~= 0x13 ) then 
		inner_frame:append( buffer(2,1):bytes())
	end
	
	local payload_offset = 8 + (payload_len*4)
	if ( length-payload_offset > 0 ) then
		inner_frame:append( buffer(payload_offset):bytes())
	end
	
	local protected_frame = inner_frame:tvb("Reconstructed Frame")
	Dissector.get("ax25"):call( protected_frame, pinfo, tree)
	
	return false
end

-- Register for PID 0x33
DissectorTable.get("ax25.pid"):add( 0x33, p_axah)

