-- adsb.lua - Automatic Dependent Surveillance - Broadcast
local proto_shortname = "adsb"
local proto_colname = "ADS-B"
local proto_longname = "Automatic Dependent Surveillance - Broadcast"
p_adsb = Proto ( proto_shortname, proto_longname)

local ADSB_PORT = 30005
local ESC_CHAR = 0x1a

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

local p_adsb_frame_len = {
	[0x31] = 11,
	[0x32] = 16,
	[0x33] = 23,
	[0x34] = 11
}

local p_adsb_frame_type_name = {
	[0x31] = "Mode-AC",
	[0x32] = "Mode-S short",
	[0x33] = "Mode-S long",
	[0x34] = "DIP switch config, timestamp error"
}

local function p_adsb_dissect_short( buffer, pinfo, tree, parent)
end

local function p_adsb_dissect_long( buffer, pinfo, tree, parent)
end

function p_adsb.dissector ( buffer, pinfo, tree)
	local len = buffer():len()
	if ( len < 2 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = proto_colname
	
	local subtree = tree:add( p_adsb, buffer(), proto_fullname)
	
	local offset = 0
	local frame_len = 0
	local extra_bytes = 0
	local frame_type = 0
	local decoded_frames = 0
		
	while (offset < len) do
		extra_bytes = 0
		if( buffer( offset, 1):uint() ~= ESC_CHAR ) then break end
		if( len-offset < 11 ) then break end
		
		frame_type = buffer( offset+1, 1):uint()
		frame_len = p_adsb_frame_len[frame_type]
		if( frame_len == nil ) then break end
		
		local i = 2
		while ( i < frame_len ) do
			if( buffer( offset+i, 1):uint() == ESC_CHAR ) then
				extra_bytes = extra_bytes + 1
			    i = i + 1
			end
			i = i + 1
		end
		-- FIXME: unescape subframe
		
		local frame_tree = subtree:add( p_adsb, buffer( offset, frame_len+extra_bytes), p_adsb_frame_type_name[frame_type])
		frame_tree:add( p_adsb, buffer( offset, 1), "Escape character")
		frame_tree:add( p_adsb, buffer( offset+1, 1), "Frame type")
		frame_tree:add( p_adsb, buffer( offset+2, 6), "MLAT timestamp")
		frame_tree:add( p_adsb, buffer( offset+8, 1), "Signal level")
		local payload_tree = frame_tree:add( p_adsb, buffer( offset+9, frame_len+extra_bytes-9), "Payload")
		
		-- Loop iteration
		offset = offset + frame_len + extra_bytes
		decoded_frames = decoded_frames + 1
	end
	pinfo.cols.info = "ADS-B Binary format, " .. decoded_frames .. " decoded frame(s)"
end

DissectorTable.get("tcp.port"):add( ADSB_PORT, p_adsb)
