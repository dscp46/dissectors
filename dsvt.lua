 -- dsvt.lua - D-Star Voice Streaming Protocol
 -- Reference: https://www.jarl.com/d-star/STD6_0a.pdf
 
local proto_shortname = "dsvt"
local proto_longname =  "D-Star Voice Streaming Protocol"
p_dsvt = Proto ( proto_shortname, proto_longname)

-------------------------------------------------------------------------------
-- Enums / Constants
-------------------------------------------------------------------------------
local miniheader_types = {
	[0x3]=" Simple Data (D-PRS / PC-to-PC)",
	[0x4]=" Message Function (radio to radio)",
	[0x5]=" Radio header retransmission",
	[0x6]=" Reserved",
	[0x8]=" Fast Data",
	[0x9]=" Fast Data",
}

local flag_type = {
	[0x1]="Wireless Header Packet",
	[0x2]="Data Section Packet",
}

local trunk_type = {
	[0x1]="DV Transmission",
	[0x2]="DD Transmission",
	[0x7]="Reserved",
}

local flag_hole_punch = {
	[0x0000] = "Disabled",
	[0x0001] = "Enabled", 
}

local trk_mgm_type = {
	[0]="DV Segment",
	[1]="Last DV Segment",
	[2]="DV Header",
	[3]="Reserved",
}

local trk_error = {
	[0]="Normal",
	[1]="Header error",
}

local MITIGATION_BYTE = 0x02

-------------------------------------------------------------------------------
-- Fields
-------------------------------------------------------------------------------

-- My own fields
local pf_dsvt_header          = ProtoField.string ( proto_shortname .. ".sig" , "Signature", base.ASCII)
local pf_dvst_flag            = ProtoField.uint16 ( proto_shortname .. ".flag" , "Flag", base.HEX)
local pf_dvst_flag_type       = ProtoField.uint16 ( proto_shortname .. ".flag.type" , "Flag", base.HEX, flag_type, 0xF000)
local pf_dvst_flag_reserved   = ProtoField.uint16 ( proto_shortname .. ".flag.reserved" , "Reserved", base.HEX, nil, 0x0FFE)
local pf_dvst_flag_hp         = ProtoField.uint16 ( proto_shortname .. ".flag.hole_punch" , "Hole punch", base.HEX, flag_hole_punch, 0x0001)
local pf_dsvt_resv            = ProtoField.bytes  ( proto_shortname .. ".reserved" , "Reserved", base.SPACE)
local pf_dsvt_mh              = ProtoField.uint8  ( proto_shortname .. ".data.mini" , "Miniheader", base.HEX)
local pf_dsvt_mh_number       = ProtoField.uint8  ( proto_shortname .. ".data.mini.number" , "Miniheader Number", base.HEX, miniheader_types, 0xF0)
local pf_dsvt_mh_sequence     = ProtoField.uint8  ( proto_shortname .. ".data.mini.seq" , "Miniheader Sequence", base.DEC, nil, 0x0F)
local pf_dsvt_mh_size         = ProtoField.uint8  ( proto_shortname .. ".data.size" , "Payload size (bytes)", base.DEC, nil, 0x0F)
local pf_dsvt_mh_fd_size      = ProtoField.uint8  ( proto_shortname .. ".fastdata.size" , "Payload size (bytes)", base.DEC, nil, 0x1F)
local pf_dsvt_trunk           = ProtoField.bytes  ( proto_shortname .. ".trunk" , "Trunk Header", base.SPACE)
local pf_dsvt_trunk_txtype    = ProtoField.uint8  ( proto_shortname .. ".trunk.tx_type" , "Transmission type", base.HEX, trunk_type, 0xE0)
local pf_dsvt_trunk_dst       = ProtoField.uint8  ( proto_shortname .. ".trunk.dst" , "Destination Repeater ID", base.HEX)
local pf_dsvt_trunk_src_rpt   = ProtoField.uint8  ( proto_shortname .. ".trunk.src.rpt" , "Source Repeater ID", base.HEX)
local pf_dsvt_trunk_src_term  = ProtoField.uint8  ( proto_shortname .. ".trunk.src.term" , "Source Terminal ID", base.HEX)
local pf_dsvt_trunk_call      = ProtoField.uint16 ( proto_shortname .. ".trunk.call" , "Call ID", base.HEX)
local pf_dsvt_trunk_mgmt      = ProtoField.uint8  ( proto_shortname .. ".trunk.mgmt" , "Management Information", base.HEX)
local pf_dsvt_trunk_mgmt_type = ProtoField.uint8  ( proto_shortname .. ".trunk.mgmt.type" , "Type", base.HEX, trk_mgm_type, 0xC0)
local pf_dsvt_trunk_mgmt_err  = ProtoField.uint8  ( proto_shortname .. ".trunk.mgmt.err" , "Header Health", base.HEX, trk_error, 0x20)
local pf_dsvt_trunk_mgmt_seq  = ProtoField.uint8  ( proto_shortname .. ".trunk.mgmt.seq" , "Sequence", base.HEX, nil, 0x1F)
local pf_dsvt_dv_data         = ProtoField.bytes  ( proto_shortname .. ".dv.data" , "DV S-Data Block", base.SPACE)
local pf_dsvt_dv_message      = ProtoField.string ( proto_shortname .. ".dv.message" , "DV Message (Radio-to-Radio)", base.ASCII)

p_dsvt.fields = {
	pf_dsvt_header, pf_dvst_flag, pf_dvst_flag_type, pf_dvst_flag_reserved, pf_dvst_flag_hp, pf_dsvt_resv,
	pf_dsvt_mh, pf_dsvt_mh_number, pf_dsvt_mh_sequence, pf_dsvt_mh_size, pf_dsvt_mh_fd_size,
	pf_dsvt_trunk, pf_dsvt_trunk_txtype, pf_dsvt_trunk_dst, pf_dsvt_trunk_src_rpt, pf_dsvt_trunk_src_term, pf_dsvt_trunk_call,
	pf_dsvt_trunk_mgmt, pf_dsvt_trunk_mgmt_type, pf_dsvt_trunk_mgmt_err, pf_dsvt_trunk_mgmt_seq,
	pf_dsvt_dv_data, pf_dsvt_dv_message
}

-- Frame number
local f_fnum       = Field.new("frame.number")

-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

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

-- Descramble D-Star data, values pulled from :
-- https://github.com/g4klx/MMDVM/blob/824c9b985228ebf0538bd2b6f443c3aac9ce4318/DStarRX.cpp#L191-L202
-- FIXME: Study DStar's spec and explain how we're falling on those values

local function descramble( bytearray)
	local scrambler_seq = { [0]=0x70, [1]=0x4f, [2]=0x93, [3]=0x40, [4]=0x64, [5]=0x74, [6]=0x6d, [7]=0x30, [8]=0x2b, }
	local len = bytearray:len()
	
	local i=0
	while ( i < len and i < 3 ) do
		bytearray:set_index( i, bit.bxor( bytearray:get_index(i), scrambler_seq[i]) )
		i = i + 1
	end
	return bytearray
end

local function decode_fastdata_firstblock( buffer, tree)
	local len = buffer():len()
	
	local fd_block = ByteArray.new()
	fd_block:append( descramble(buffer( 21, 3):bytes()) )
	fd_block:append( descramble(buffer( 33, 3):bytes()) )
	fd_block:append( descramble(buffer( 12, 3):bytes()) )
	fd_block:append( descramble(buffer( 24, 3):bytes()) )
	fd_block:append( descramble(buffer( 0, 3):bytes()) ) 	
	local tvb_block = fd_block:tvb("DV Fast Data Block")
	local subtree = tree:add( p_dsvt, tvb_block(), "DV Fast Data Block")
	local payload = tvb_block(1,2) .. tvb_block( 4,6) .. tvb_block( 11, 8) .. tvb_block( 20, 8) .. tvb_block( 29, 4)
	local mitigation = tvb_block( 10, 1) .. tvb_block( 19, 1) .. tvb_block( 28, 1)
	
	local mh = subtree:add( pf_dsvt_mh, tvb_block( 0, 1) )
	mh:add( pf_dsvt_mh_number, tvb_block( 0, 1) )
	mh:add( pf_dsvt_mh_fd_size, tvb_block( 0, 1) )
	subtree:add( pf_dsvt_guard, tvb_block( 2, 1) )
	local mt_tree = subtree:add( p_dsvt, mitigation , "Mitigation Bytes" )
	if ( mitigation:string() ~= "\x02\x02\x02" ) then
		mt_tree:add_expert_info( PI_PROTOCOL, PI_WARN, "Unexpected value in mitigation bytes (should be 0x02)")
	end
	subtree:add( p_dsvt, payload, "Payload")
	mh:add( pf_dsvt_mh_number, tvb_block( 0, 1) )
	return payload
end

local function decode_fastdata_block( buffer, tree)
	local len = buffer():len()
	
	local fd_block = ByteArray.new()
	fd_block:append( descramble(buffer( 9, 3):bytes()) )
	fd_block:append( descramble(buffer( 21, 3):bytes()) )
	fd_block:append( descramble(buffer( 0, 9):bytes()) )
	fd_block:append( descramble(buffer( 12, 9):bytes()) )
	local tvb_block = fd_block:tvb("DV Fast Data Block")
	local subtree = tree:add( p_dsvt, tvb_block(), "DV Fast Data Block")
	local payload = tvb_block(1,2) .. tvb_block( 4,6) .. tvb_block( 11, 8) .. tvb_block( 20, 4)
	local mitigation = tvb_block( 10, 1) .. tvb_block( 19, 1)
	
	local mh = subtree:add( pf_dsvt_mh, tvb_block( 0, 1) )
	mh:add( pf_dsvt_mh_number, tvb_block( 0, 1) )
	mh:add( pf_dsvt_mh_fd_size, tvb_block( 0, 1) )
	
	return payload
end

local function decode_data_miniheader( buffer, tree)
	local len = buffer():len()
	local miniheader = buffer(0,1):uint()
	local mh_tree = tree:add( pf_dsvt_mh, buffer(0,1))
	
	if ( miniheader ~= 0x66 ) then
		mh_tree:add( pf_dsvt_mh_number, buffer(0,1))
	else
		mh_tree:add( p_dsvt, buffer(0,1), "Padding / No Data")
		mh_tree.text = mh_tree.text .. " (Padding)"
	end
	
	if ( miniheader >= 0x31 and miniheader <= 0x35 ) then
		mh_tree:add( pf_dsvt_mh_size, buffer(0, 1))
		tree:add( p_dsvt, buffer(1, bit.band( buffer(0, 1):uint(), 0x0F)), "Payload")
		
	elseif ( miniheader >= 0x40 and miniheader <= 0x43 ) then
		mh_tree:add( pf_dsvt_mh_sequence, buffer(0,1))
		tree:add( p_dsvt, buffer(1,5), "Payload")
		
	elseif ( miniheader >= 0x51 and miniheader <= 0x55 ) then
		mh_tree:add( pf_dsvt_mh_size, buffer(0, 1))
		tree:add( p_dsvt, buffer(1, bit.band( buffer(0, 1):uint(), 0x0F)), "Payload")
		
	elseif ( miniheader == 0x66 ) then
		-- No operation
		
	elseif ( miniheader == 0xC2 ) then
		--mh_tree.text = mh_tree.text .. "Code squelch"
		tree:add( p_dsvt, buffer(1,2), "2 digits for code squelch")
		
	else
		-- mh_tree.text = mh_tree.text .. " Reserved"
		if ( len > 1 ) then
			local unk = tree:add( p_dsvt, buffer(1), "Undocumented type")
			unk:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data format")
		end
		
	end
end

local p_dsvt_stream_attrs = {}
local p_dsvt_frame_attrs = {}

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
	local frame_num = f_fnum().value
	
	-- Allocate Sequence number
	if ( p_dsvt_stream_attrs[stream_id] == nil ) then
		p_dsvt_stream_attrs[stream_id] = {}
		p_dsvt_stream_attrs[stream_id]["seq"] = 0
		p_dsvt_stream_attrs[stream_id]["sf"] = {}
		p_dsvt_stream_attrs[stream_id]["sf"]["count"] = 0
	end
	
	-- Initialize stream attributes, allocate internal sequence number, to re-aggregate data
	if ( p_dsvt_frame_attrs[frame_num] == nil ) then p_dsvt_frame_attrs[frame_num] = {} end
	if ( p_dsvt_frame_attrs[frame_num]["seq"] == nil ) then
		p_dsvt_frame_attrs[frame_num]["seq"] = p_dsvt_stream_attrs[stream_id]["seq"]
		internal_seq = p_dsvt_stream_attrs[stream_id]["seq"]
		p_dsvt_stream_attrs[stream_id][internal_seq] = {}
		
		p_dsvt_stream_attrs[stream_id]["seq"] = p_dsvt_stream_attrs[stream_id]["seq"] + 1
	else
		internal_seq = p_dsvt_frame_attrs[frame_num]["seq"]
	end
	
	-- Fill the diagnostic tree
	local subtree = tree:add( p_dsvt, buffer(), "Digital Voice Streaming Protocol")
	subtree:add( p_dsvt, string.format( "[Internal sequence number: %d]", internal_seq))
	subtree:add( pf_dsvt_header, buffer(0,4))
	local flag_subtree =  subtree:add( pf_dvst_flag, buffer(4,2))
	flag_subtree:add( pf_dvst_flag_type, buffer(4,2))
	flag_subtree:add( pf_dvst_flag_reserved, buffer(4,2))
	flag_subtree:add( pf_dvst_flag_hp, buffer(4,2))
	subtree:add( pf_dsvt_resv, buffer(6,2))
	local trunk_subtree = subtree:add( pf_dsvt_trunk, buffer(8,7))
	trunk_subtree:add( pf_dsvt_trunk_txtype, buffer(8,1))
	trunk_subtree:add( pf_dsvt_trunk_dst, buffer(9,1))
	trunk_subtree:add( pf_dsvt_trunk_src_rpt, buffer(10,1))
	trunk_subtree:add( pf_dsvt_trunk_src_term, buffer(11,1))
	trunk_subtree:add( pf_dsvt_trunk_call, buffer(12,2))
	local mgm_subtree = trunk_subtree:add( pf_dsvt_trunk_mgmt, buffer(14,1))
	mgm_subtree:add( pf_dsvt_trunk_mgmt_type, buffer(14,1))
	mgm_subtree:add( pf_dsvt_trunk_mgmt_err, buffer(14,1))
	mgm_subtree:add( pf_dsvt_trunk_mgmt_seq, buffer(14,1))
	
	-- Configuration Frame
	if ( is_voice_stream(buffer()) and is_config_frame(buffer()) ) then
		pinfo.cols.info = string.format( "Stream Configuration SID=0x%04X", stream_id)
		-- subtree:add( buffer(,8), ": " .. buffer(,):string())
		-- Subtree for the flag fields
		--local subtree_flags = subtree:add( buffer(15,3) , "D-Star flags" )
		--Dissector.get("dstarflags"):call( buffer(15,3):tvb(), pinfo, subtree)
		
		-- Next fields
		--tree:add( buffer(18)
		subtree:add( buffer(18,8), "RPT1: " .. buffer(18,8):string())
		subtree:add( buffer(26,8), "RPT2: " .. buffer(26,8):string())
		subtree:add( buffer(34,8), "UR: " .. buffer(34,8):string())
		subtree:add( buffer(42,12), "MY: " .. buffer(42,8):string() .. "/" .. buffer(50,4):string())
		subtree:add( buffer(54,2), "Checksum: " .. buffer(54,2))
	end
	
	-- AMBE Voice Frame
	if ( is_voice_stream(buffer()) and is_ambe_voice_frame(buffer()) ) then
		local superframe_id
		
		if ( p_dsvt_frame_attrs[frame_num]["sf"] == nil ) then
			-- FIXME: Improve rules to detect new superframe
			if( seq_num == 0x00 ) then
				p_dsvt_stream_attrs[stream_id]["sf"]["count"] = p_dsvt_stream_attrs[stream_id]["sf"]["count"] + 1
			end
					
			superframe_id = p_dsvt_stream_attrs[stream_id]["sf"]["count"]
			p_dsvt_frame_attrs[frame_num]["sf"] = superframe_id
		else
			superframe_id = p_dsvt_frame_attrs[frame_num]["sf"] 
		end
		
		subtree:add( p_dsvt, string.format("[Internal Superframe ID: %d]", superframe_id))
		
		-- TODO: Detect Fast data frame
		
		pinfo.cols.info = string.format( "Voice Fragment SID=0x%04X SEQ=0x%02X [Codec: AMBE]", stream_id, seq_num)
		local voice_subtree = subtree:add( buffer(15,9), "AMBE voice fragment: " .. buffer(15,9))
		
		subtree:add( p_dsvt, buffer(24,3), fif( seq_num ~= 0, "[Scrambled DV slow data fragment]", "Sync Pattern (not scrambled)"))
		
		-- Initialize the radio to radio messages store
		if ( p_dsvt_stream_attrs[stream_id]["messages"] == nil ) then p_dsvt_stream_attrs[stream_id]["messages"] = {} end
		
		-- Initialize the simple data store
		if ( p_dsvt_stream_attrs[stream_id]["data"] == nil ) then 
			p_dsvt_stream_attrs[stream_id]["data"] = ByteArray.new() 
			p_dsvt_stream_attrs[stream_id]["data_chunks"] = {}
			p_dsvt_stream_attrs[stream_id]["data_chunks"]["seq"] = {}
		end
		
		if( bit.band( seq_num, 0xC0) > 0x14 ) then
			-- TODO: End of stream?
		
		elseif( seq_num == 0x00 ) then
			-- Sync Pattern
			
		elseif( bit.band( seq_num, 0x01) == 1 ) then
			p_dsvt_stream_attrs[stream_id][internal_seq]["data"] = descramble( buffer(24,3):bytes()):tohex()
		else
			if ( p_dsvt_stream_attrs[stream_id][internal_seq-1] ~= nil and p_dsvt_stream_attrs[stream_id][internal_seq-1]["data"] ~= nil ) then
				local dv_data = ByteArray.new( p_dsvt_stream_attrs[stream_id][internal_seq-1]["data"] )
				dv_data:append( descramble( buffer(24,3):bytes()) )
				local tvb_data = dv_data:tvb("DV S-Data Block")
				local data_subtree = subtree:add( pf_dsvt_dv_data, tvb_data())
				decode_data_miniheader( tvb_data, data_subtree)
				
				local miniheader = bit.band( tvb_data( 0, 1):uint(), 0xF0)
				local arg = bit.band( tvb_data( 0, 1):uint(), 0x0F)
				
				if ( miniheader == 0x40 ) then
					-- Message, accumulate in superframe
					if ( p_dsvt_stream_attrs[stream_id]["messages"][superframe_id] == nil ) then 
						p_dsvt_stream_attrs[stream_id]["messages"][superframe_id] = ByteArray.new()
						p_dsvt_stream_attrs[stream_id]["messages"][superframe_id]:set_size( 20 )
					end
					
					for i=0, 4, 1 do
						p_dsvt_stream_attrs[stream_id]["messages"][superframe_id]:set_index( arg*5+i, tvb_data( 1+i, 1):uint())
					end
					
				elseif ( miniheader == 0x30 ) then
					-- Simple Data (PC to PC)
					
				elseif ( miniheader == 0x50 ) then
				end
			end
		end
		
		if ( seq_num == 0x14 ) then
			-- Display display
			if ( p_dsvt_stream_attrs[stream_id]["messages"][superframe_id] ~= nil ) then
				local tvb_message = p_dsvt_stream_attrs[stream_id]["messages"][superframe_id]:tvb("DV Message (Radio2Radio)")
				local dvslow_tree = tree:add( p_dsvt, "DV Slow Data")
				dvslow_tree:add( pf_dsvt_dv_message, tvb_message())
				p_dsvt_stream_attrs[stream_id]["last_mesg"] = tvb_message():string()
			end
		end
	end
end
