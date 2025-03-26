-- dplus.lua - DPlus Protocol
local proto_shortname = "dplus"
local proto_longname = "DPlus Protocol"
p_dplus = Proto ( proto_shortname, proto_longname)

local ascp_type = {
	[0]=> "Control Item",
	[1]=> "Current Control Item",
	[2]=> "Control Item Range",
	[3]=> "Data ACK",
	[4]=> "D-Star Voice Trunk data",
	[5]=> "Data Item 1",
	[6]=> "Query",
	[7]=> "Data Item 3",
}

local ctl_types = {
	[0x0018] = "State transition"
}

local query_types = {
	[0x0004] = "Authentication"
}

local state_trans = {
	[0] => "Idle"
	[1] => "Active"
}

local auth_result = {
	["OKRO"] = "Success (read-only)",
	["OKRW"] = "Success",
	["BUSY"] = "No available slot",
	["FAIL"] = "Failure"
}

-- Fields
local pf_dplus_ascp_type      = ProtoField.uint16 ( proto_shortname .. ".ascp.type" , "ASCP Type", base.DEC, ascp_type, 0xE000)
local pf_dplus_ascp_length    = ProtoField.uint16 ( proto_shortname .. ".ascp.length" , "Payload Length", base.DEC, nil, 0x1FFF)
local pf_dplus_keepalive       = ProtoField.uint8 ( proto_shortname .. ".keepalive" , "Keepalive", base.DEC)
local pf_dplus_ctl_code       = ProtoField.uint16 ( proto_shortname .. ".ctl" , "Control Code", base.HEX)
local pf_dplus_ctl_state       = ProtoField.uint8 ( proto_shortname .. ".state" , "New state", base.HEX, state_trans)
local pf_dplus_query_type     = ProtoField.uint16 ( proto_shortname .. ".query.type" , "Type", base.HEX, query_types)
local pf_dplus_auth           = ProtoField.string ( proto_shortname .. ".auth" , "Authentication Result", base.ASCII, auth_result)
local pf_dplus_dongle_serial  = ProtoField.string ( proto_shortname .. ".dongle.sn" , "Dongle Serial Number", base.ASCII)

p_dplus.fields = {
	pf_dplus_ascp_type, pf_dplus_ascp_length, pf_dplus_keepalive, pf_dplus_ctl_code, pf_dplus_ctl_state, 
	pf_dplus_query_type, pf_dplus_auth, pf_dplus_dongle_serial,
}

function p_dplus.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 3 ) then return end
	
	local len = buffer:len()
	local inner_len = bit.band( buffer( 0, 2):le_uint(), 0x1FFF)
	local ascp_header = buffer( 0, 2)
	local ascp_type = bit.band( buffer( 1,1):uint(), 0xE0)
		
	-- Validate length
	if ( len ~= inner_len ) then return end;
	
	-- Set protocol name
	pinfo.cols.protocol = "DPLUS"
	
	-- Subtree
	local subtree = tree:add( p_dplus, buffer(), "DPlus Protocol")
	local ascp_tree = subtree:add_le ( ascp_header, "Amateur Station Control Protocol Header" )
	ascp_tree:add_le( pf_dplus_ascp_type, ascp_header)
	ascp_tree:add_le( pf_dplus_ascp_length, ascp_header)

	
	if ( ascp_type == 4 ) then
		-- Pass the information to the DSVT dissector
		Dissector.get("dsvt"):call( buffer(2):tvb(), pinfo, tree)

	if ( ascp_type == 3 and len == 3 ) then
		-- Keepalive
		pinfo.cols.info = "Keepalive"
		subtree:add( pf_dplus_keepalive, buffer(2,1))
		return

	elseif ( ascp_type == 0 and len >= 4 ) then
		-- Commands
		local command = buffer(2,2):le_uint()
		subtree:add_le( pf_dplus_ctl_code, buffer( 2, 2))
		
		if ( command == 0x18 and length == 5 ) then
			-- Repeater state transition
			local state = buffer( 4,1):uint()
			subtree:add( pf_dplus_ctl_state, buffer( 4, 1))
			pinfo.cols.info = "Repeater new state: " .. state_trans[state]
			
		else
			local uncomm = subtree:add( buffer(2,1), "Unknown command")
			uncomm:add_expert_info( PI_UNDECODED, PI_WARN, "Unknown command")
		end
	elseif ( ascp_type == 6 ) then
		-- Queries
		local qtype = buffer( 2, 2):le_uint()
		subtree:add_le( pf_dplus_query_type, buffer( 2, 2))
		
		if ( qtype == 0x0004 ) then
			-- Authentication result
			subtree:add( pf_dplus_auth, buffer(4))
			
		else
			local unkquery = subtree:( buffer( 4), "Unknown Query")
			unkquery:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data")
		end
		
	else
		local undoc = subtree:add( buffer(2), "Undocumented data")
		undoc:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data")
	end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add( 20001, p_dplus)


