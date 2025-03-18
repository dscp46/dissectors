 -- dsvt.lua - D-Star Voice Streaming Protocol
 
local proto_shortname = "dsvt"
local proto_longname =  "D-Star Voice Streaming Protocol"
p_dsvt = Proto ( proto_shortname, proto_longname)

-------------------------------------------------------------------------------
-- Enums
-------------------------------------------------------------------------------
local miniheader_types = {
	[0x3]=" Simple Data (D-PRS / PC-to-PC)",
	[0x4]=" Message Function (radio to radio)",
	[0x5]=" Radio header retransmission",
	[0x6]=" Reserved",
	[0x8]=" Fast Data",
	[0x9]=" Fast Data",
}

-------------------------------------------------------------------------------
-- Fields
-------------------------------------------------------------------------------

-- My own fields
local pf_dsvt_header = ProtoField.string ( proto_shortname .. ".sig" , "Signature", base.ASCII)
local pf_dsvt_mh = ProtoField.uint8 ( proto_shortname .. ".data.mini" , "Miniheader", base.HEX)
local pf_dsvt_mh_number = ProtoField.uint8 ( proto_shortname .. ".data.mini.number" , "Miniheader Number", base.HEX, miniheader_types, 0xF0)
local pf_dsvt_mh_sequence = ProtoField.uint8 ( proto_shortname .. ".data.mini.seq" , "Miniheader Sequence", base.HEX, nil, 0x0F)
local pf_dsvt_dv_data = ProtoField.bytes ( proto_shortname .. ".dv.data" , "DV Data")

p_dsvt.fields = {
	pf_dsvt_header, pf_dsvt_mh, pf_dsvt_mh_number, pf_dsvt_mh_sequence, pf_dsvt_dv_data
}

local function is_config_frame( buffer)
	return buffer(4,1):uint() == 0x10 
end

local function is_ambe_voice_frame( buffer)
	return buffer(4,1):uint() == 0x20
end

local function is_voice_stream( buffer)
	return buffer(8,1):uint() == 0x20
end

local function get_frame_type_string( buffer)
	if ( is_config_frame(buffer) ) then return "Configuration" end
	if ( is_ambe_voice_frame(buffer) ) then return "AMBE Voice" end
	return "Unknown"
end

local function get_stream_type_string( buffer)
	if ( is_voice_stream(buffer) ) then return "Voice" end
	return "Unknown"
end

local function decode_data_miniheader( buffer, tree)
	local len = buffer():len()
	local miniheader = buffer(0,1):uint()
	local mh_tree = tree:add( pf_dsvt_mh, buffer(0,1))
	mh_tree:add( pf_dsvt_mh_number, buffer(0,1))
	
	if ( miniheader >= 0x31 and miniheader <= 0x35 ) then
		--mh_tree.text = mh_tree.text .. ""
		
	elseif ( miniheader >= 0x40 and miniheader <= 0x43 ) then
		--mh_tree.text = mh_tree.text .. "Message Function (radio to radio)"
		
	elseif ( miniheader >= 0x51 and miniheader <= 0x55 ) then
		--mh_tree.text = mh_tree.text .. "Radio header retransmission"
		tree:add( p_dsvt, buffer(1,2), "Radio header data")
		
	elseif ( miniheader == 0x66 ) then
		--mh_tree.text = mh_tree.text .. "No Data"
		
	elseif ( miniheader >= 0x81 and miniheader <= 0x9C ) then
		--mh_tree.text = mh_tree.text .. "Fast Data"
		tree:add( p_dsvt, buffer(1,2), "Payload")
		
	elseif ( miniheader == 0xC2 ) then
		--mh_tree.text = mh_tree.text .. "Code squelch"
		tree:add( p_dsvt, buffer(1,2), "2 digits for code squelch")
		
	else
		-- mh_tree.text = mh_tree.text .. " Reserved"
		if ( len > 1 ) then
			local unk = tree:add( p_dsvt, buffer(1), "Undocumented data")
			unk:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data format")
		end
		
	end
end

local p_dsvt_stream_attrs = {}

function p_dsvt.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	--if ( buffer:len() ~= 27 or buffer:len() ~= 56 ) then return end
	
	-- Validate signature field
	if( buffer(0,4):string() ~= "DSVT" ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = "DSVT"
	pinfo.cols.info = "DSVT"
	
	-- Variables
	local stream_id = buffer(12,2):uint();
	local seq_num = buffer(14,1):uint();
	local internal_seq = nil
	
	-- Allocate Sequence number
	if ( p_dsvt_stream_attrs[stream_id] == nil ) then
		p_dsvt_stream_attrs[stream_id] = {}
		p_dsvt_stream_attrs[stream_id]["seq"] = 0
	end
	
	-- Initialize stream attributes, allocate internal sequence number, to re-aggregate data
	if ( pinfo.private["dvst_seq"] == nil ) then
		pinfo.private["dvst_seq"] = p_dsvt_stream_attrs[stream_id]["seq"]
		internal_seq = p_dsvt_stream_attrs[stream_id]["seq"]
		p_dsvt_stream_attrs[stream_id][internal_seq] = {}
		
		p_dsvt_stream_attrs[stream_id]["seq"] = p_dsvt_stream_attrs[stream_id]["seq"] + 1
	end
	
	-- Fill the diagnostic tree
	local subtree = tree:add( p_dsvt, buffer(), "Digital Voice Streaming Protocol")
	subtree:add( pf_dsvt_header, buffer(0,4))
	subtree:add( buffer(4,1) , "Frame Type: " .. get_frame_type_string( buffer() ) .. " (0x" .. buffer(4,1) .. ")")
	subtree:add( buffer(5,3) , "Reserved: " .. buffer(5,3))
	subtree:add( buffer(8,1) , "Stream type: " .. get_stream_type_string( buffer() ) .. " (0x" .. buffer(8,1) .. ")")
	subtree:add( buffer(9,3) , "Reserved: " .. buffer(9,3))
	subtree:add( buffer(12,2), string.format( "Stream id: 0x%04X", stream_id))
	subtree:add( buffer(14,1), string.format( "Sequence: 0x%02X", seq_num))
	
	-- Configuration Frame
	if ( is_voice_stream(buffer()) and is_config_frame(buffer()) ) then
		pinfo.cols.info = string.format( "Stream Configuration SID=0x%04X", stream_id)
		-- subtree:add( buffer(,8), ": " .. buffer(,):string())
		-- Subtree for the flag fields
		--local subtree_flags = subtree:add( buffer(15,3) , "D-Star flags" )
		Dissector.get("dstarflags"):call( buffer(15,3):tvb(), pinfo, subtree)
		
		-- Next fields
		subtree:add( buffer(18,8), "RPT1: " .. buffer(18,8):string())
		subtree:add( buffer(26,8), "RPT2: " .. buffer(26,8):string())
		subtree:add( buffer(34,8), "UR: " .. buffer(34,8):string())
		subtree:add( buffer(42,12), "MY: " .. buffer(42,8):string() .. "/" .. buffer(50,4):string())
		subtree:add( buffer(54,2), "Checksum: " .. buffer(54,2))
	end
	
	-- AMBE Voice Frame
	if ( is_voice_stream(buffer()) and is_ambe_voice_frame(buffer()) ) then
		pinfo.cols.info = string.format( "Voice Fragment SID=0x%04X SEQ=0x%02X [Codec: AMBE]", stream_id, seq_num)
		local voice_subtree = subtree:add( buffer(15,9), "AMBE voice fragment: " .. buffer(15,9))
		subtree:add( p_dsvt, buffer(24,3), "[DV data fragment]")
		
		if( bit.band( seq_num, 0x01) == 1 ) then
			p_dsvt_stream_attrs[stream_id][internal_seq]["data"] = buffer(24,3):bytes():tohex()
		else
			if ( p_dsvt_stream_attrs[stream_id][internal_seq-1] ~= nil and p_dsvt_stream_attrs[stream_id][internal_seq-1]["data"] ~= nil ) then
				local dv_data = ByteArray.new( p_dsvt_stream_attrs[stream_id][internal_seq-1]["data"] )
				dv_data:append( buffer(24,3):bytes())
				local tvb_data = dv_data:tvb()
				local data_subtree = subtree:add( pf_dsvt_dv_data, tvb_data())
				decode_data_miniheader( tvb_data, data_subtree)
			end
		end
	end
end
