-- dsvt.lua
-- D-Star Voice Streaming Protocol
p_dsvt = Proto ( "dsvt", "D-Star Voice Streaming Protocol")

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
	local mh_tree = tree:add( p_dsvt, buffer(0,1), "Miniheader: ")
	
	if ( miniheader >= 0x31 and miniheader <= 0x35 ) then
		mh_tree.text = mh_tree.text .. "Simple Data (D-PRS / PC-to-PC)"
		
	elseif ( miniheader >= 0x40 and miniheader <= 0x43 ) then
		mh_tree.text = mh_tree.text .. "Message Function (radio to radio)"
		
	elseif ( miniheader >= 0x51 and miniheader <= 0x55 ) then
		mh_tree.text = mh_tree.text .. "Radio header retransmission"
		tree:add( p_dsvt, buffer(1,2), "Radio header data")
		
	elseif ( miniheader == 0x66 ) then
		mh_tree.text = mh_tree.text .. "No Data"
		
	elseif ( miniheader >= 0x81 and miniheader <= 0x9C ) then
		mh_tree.text = mh_tree.text .. "Fast Data"
		tree:add( p_dsvt, buffer(1,2), "Payload")
		
	elseif ( miniheader == 0xC2 ) then
		mh_tree.text = mh_tree.text .. "Code squelch"
		tree:add( p_dsvt, buffer(1,2), "2 digits for code squelch")
		
	else
		mh_tree.text = mh_tree.text .. "Reserved"
		if ( len > 1 ) then
			local unk = tree:add( p_dsvt, buffer(1), "Undocumented data")
			unk:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data format")
		end
		
	end
end

function p_dsvt.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	--if ( buffer:len() ~= 27 or buffer:len() ~= 56 ) then return end
	
	-- Validate signature field
	if( buffer(0,4):string() ~= "DSVT" ) then return end
	
	-- Set protocol name
	--pinfo.cols.protocol = "DPLUS"
	pinfo.cols.info = "DSVT"
	
	-- Variables
	local stream_id = buffer(12,2);
	local seq_num = buffer(14,1);
	
	-- Fill the diagnostic tree
	local subtree = tree:add( p_dsvt, buffer(), "Digital Voice Streaming Protocol")
	subtree:add( buffer(0,4) , "Signature: " .. buffer(0,4):string())
	subtree:add( buffer(4,1) , "Frame Type: " .. get_frame_type_string( buffer() ) .. " (0x" .. buffer(4,1) .. ")")
	subtree:add( buffer(5,3) , "Reserved: " .. buffer(5,3))
	subtree:add( buffer(8,1) , "Stream type: " .. get_stream_type_string( buffer() ) .. " (0x" .. buffer(8,1) .. ")")
	subtree:add( buffer(9,3) , "Reserved: " .. buffer(9,3))
	subtree:add( buffer(12,2), "Stream id: 0x" .. stream_id)
	subtree:add( buffer(14,1), "Sequence: 0x" .. seq_num)
	
	-- Configuration Frame
	if ( is_voice_stream(buffer()) and is_config_frame(buffer()) ) then
		pinfo.cols.info = "Stream Configuration SID=" .. stream_id:uint() 
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
		pinfo.cols.info = " Voice Fragment SID=" .. stream_id:uint() .. " SEQ=0x" .. seq_num .. " [Codec: AMBE]"
		local voice_subtree = subtree:add( buffer(15,9), "AMBE voice fragment: " .. buffer(15,9))
		local data_subtree = subtree:add( buffer(24,3), "DV data fragment: " .. buffer(24,3))
		decode_data_miniheader( buffer(24,3), data_subtree)
	end
end
