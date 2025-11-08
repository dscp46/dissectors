-- adsb.lua - Automatic Dependent Surveillance - Broadcast
-- Beast binary documentation based on https://wiki.jetvision.de/wiki/Mode-S_Beast:Data_Output_Formats
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

local downlink_fmt = {
	[17] = "Civil aircraft",
	[18] = "Civil aircraft, non interrogatable (TIS-B)"
}

local transponder_cap = {
	[0] = "Level 1 transponder",
	[1] = "Reserved",
	[2] = "Reserved",
	[3] = "Reserved",
	[4] = "Level 2+ transponder, on-ground",
	[5] = "Level 2+ transponder, airborne",
	[6] = "Level 2+ transponder, either on-ground or airborne",
	[7] = "Downlink Request = 0, or Flight Status = 2~5",
}

local adsb_mesg_type = {
	[1] = "Aircraft identification",
	[2] = "Aircraft identification",
	[3] = "Aircraft identification",
	[4] = "Aircraft identification",
	[5] = "Surface position",
	[6] = "Surface position",
	[7] = "Surface position",
	[8] = "Surface position",
	[9] = "Airborne position (w/Baro Altitude)",
	[10] = "Airborne position (w/Baro Altitude)",
	[11] = "Airborne position (w/Baro Altitude)",
	[12] = "Airborne position (w/Baro Altitude)",
	[13] = "Airborne position (w/Baro Altitude)",
	[14] = "Airborne position (w/Baro Altitude)",
	[15] = "Airborne position (w/Baro Altitude)",
	[16] = "Airborne position (w/Baro Altitude)",
	[17] = "Airborne position (w/Baro Altitude)",
	[18] = "Airborne position (w/Baro Altitude)",
	[19] = "Airborne velocities",
	[20] = "Airborne position (w/GNSS Height)",
	[21] = "Airborne position (w/GNSS Height)",
	[22] = "Airborne position (w/GNSS Height)",
	[23] = "Reserved",
	[24] = "Reserved",
	[25] = "Reserved",
	[26] = "Reserved",
	[27] = "Reserved",
	[28] = "Aircraft status",
	[29] = "Target state and status information",
	[31] = "Aircraft operation status",
}

-- Fields
local pf_adsb_df   = ProtoField.uint8( proto_shortname .. ".df", "Downlink Format"       , base.DEC, downlink_fmt   , 0xF8)
local pf_adsb_ca   = ProtoField.uint8( proto_shortname .. ".ca", "Transponder capability", base.DEC, transponder_cap, 0x07)
local pf_adsb_icao = ProtoField.uint32( proto_shortname .. ".addr", "ICAO Aircraft Address", base.HEX)
local pf_adsb_tc   = ProtoField.uint8( proto_shortname .. ".tc", "ADS-B Message Type Code", base.DEC, adsb_mesg_type, 0xF8)

p_adsb.fields = { pf_adsb_df, pf_adsb_ca, pf_adsb_icao, pf_adsb_tc}

local function p_adsb_dissect_ac( buffer, pinfo, tree, parent)
	tree:add_expert_info( PI_UNDECODED, PI_WARN, "Dissection not yet implemented")
end

local function p_adsb_dissect_s_short( buffer, pinfo, tree, parent)
	tree:add( pf_adsb_df, buffer(0,1))
	tree:add( pf_adsb_ca, buffer(0,1))
	tree:add( pf_adsb_icao, buffer(1,3))
end

local function p_adsb_dissect_s_long( buffer, pinfo, tree, parent)
	tree:add( pf_adsb_df, buffer(0,1))
	tree:add( pf_adsb_ca, buffer(0,1))
	tree:add( pf_adsb_icao, buffer(1,3))
	tree:add( pf_adsb_tc, buffer(4,1))
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
		if( buffer( offset, 1):uint() ~= ESC_CHAR ) then break end
		if( len-offset < 11 ) then break end
		
		frame_type = buffer( offset+1, 1):uint()
		frame_len = p_adsb_frame_len[frame_type]
		if( frame_len == nil ) then break end
		
		local i = 2
		extra_bytes = 0
		
		local raw_frame = ByteArray.new()
		
		while ( i < frame_len ) do
		    if( i-extra_bytes >= 9 ) then
				raw_frame:append( buffer( offset+i, 1):bytes())
			end
			
			if( buffer( offset+i, 1):uint() == ESC_CHAR ) then
			    if ( (i+1 >= frame_len) or ( buffer( offset+i+1, 1):uint() ~= ESC_CHAR )) then error("Malformed frame") end
				extra_bytes = extra_bytes + 1
			    i = i + 1
			end
			i = i + 1
		end
		
		local frame_tree = subtree:add( p_adsb, buffer( offset, frame_len+extra_bytes), p_adsb_frame_type_name[frame_type])
		frame_tree:add( p_adsb, buffer( offset, 1), "Escape character")
		frame_tree:add( p_adsb, buffer( offset+1, 1), "Frame type")
		frame_tree:add( p_adsb, buffer( offset+2, 6), "MLAT timestamp")
		frame_tree:add( p_adsb, buffer( offset+8, 1), "Signal level")
		local payload_tree = frame_tree:add( p_adsb, buffer( offset+9, frame_len+extra_bytes-9), "Payload")
		local payload = raw_frame:tvb("Decoded ADSB Frame")
		
		-- Dissect payload
		if     ( frame_type == 0x31 ) then
			p_adsb_dissect_ac( payload, pinfo, payload_tree, frame_tree)
			
		elseif ( frame_type == 0x32 ) then
			p_adsb_dissect_s_short( payload, pinfo, payload_tree, frame_tree)
			
		elseif ( frame_type == 0x33 ) then
		    p_adsb_dissect_s_long( payload, pinfo, payload_tree, frame_tree)
		    
		elseif ( frame_type == 0x34 ) then
		    payload_tree:add_expert_info( PI_UNDECODED, PI_WARN, "Dissection not yet implemented")
		    
		else
		    payload_tree:add_expert_info( PI_PROTOCOL, PI_WARN, "Unknown Beast frame type")
		end
		
		-- Loop iteration
		offset = offset + frame_len + extra_bytes
		decoded_frames = decoded_frames + 1
	end
	pinfo.cols.info = "ADS-B Binary format, " .. decoded_frames .. " decoded frame(s)"
end

DissectorTable.get("tcp.port"):add( ADSB_PORT, p_adsb)
